# main.py
from flask import Flask, render_template, request, jsonify, send_from_directory, session, redirect, url_for
import time
from flask_cors import CORS
from functools import wraps
import os
import io
import json
import secrets
import firebase_admin
from firebase_admin import credentials, auth, storage, firestore
from pydub import AudioSegment
import whisper
import tempfile
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import gc
import torch
import logging
from threading import Lock
import numpy as np
from pathlib import Path
import soundfile as sf
import concurrent.futures
import psutil

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__, static_folder='static')
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(24))
CORS(app, supports_credentials=True)

# Initialize Firebase Admin SDK
if os.getenv('FIREBASE_CREDENTIALS'):
    cred_dict = json.loads(os.getenv('FIREBASE_CREDENTIALS'))
    cred = credentials.Certificate(cred_dict)
else:
    cred = credentials.Certificate("serviceAccountKey.json")

firebase_admin.initialize_app(cred, {
    'storageBucket': os.getenv('FIREBASE_STORAGE_BUCKET', 'imagetotext-4c3e3.appspot.com')
})

# Initialize Firestore
db = firestore.client()

# Global variables
model = None
model_lock = Lock()
MAX_MEMORY_PERCENT = 80  # Maximum memory usage threshold

class MemoryError(Exception):
    pass

def check_memory():
    """Check if memory usage is too high"""
    process = psutil.Process(os.getpid())
    memory_percent = process.memory_percent()
    if memory_percent > MAX_MEMORY_PERCENT:
        cleanup_memory()
        if process.memory_percent() > MAX_MEMORY_PERCENT:
            raise MemoryError(f"Memory usage too high: {memory_percent}%")

def cleanup_memory():
    """Aggressive memory cleanup"""
    gc.collect()
    torch.cuda.empty_cache() if torch.cuda.is_available() else None
    
    # Force Python to return memory to the OS
    import ctypes
    libc = ctypes.CDLL("libc.so.6")
    libc.malloc_trim(0)

def get_model():
    """Get or initialize the Whisper model with memory optimization"""
    global model
    with model_lock:
        if model is None:
            # Set PyTorch memory optimization
            torch.set_num_threads(1)
            if torch.cuda.is_available():
                torch.cuda.set_per_process_memory_fraction(0.3)  # Limit GPU memory usage
            
            # Load model with minimal memory footprint
            model = whisper.load_model("tiny", device="cpu", download_root="/tmp")
            model.eval()  # Set to evaluation mode
            # Disable gradient computation
            for param in model.parameters():
                param.requires_grad = False
    return model

def process_audio_in_chunks(audio_path, chunk_duration_ms=10000):
    """Process audio file in small chunks"""
    try:
        transcription_pieces = []
        
        # Load audio file
        audio = AudioSegment.from_file(audio_path)
        total_duration = len(audio)
        
        # Process in small chunks
        for start_ms in range(0, total_duration, chunk_duration_ms):
            check_memory()
            
            end_ms = min(start_ms + chunk_duration_ms, total_duration)
            chunk = audio[start_ms:end_ms]
            
            # Export chunk to temporary WAV file
            with tempfile.NamedTemporaryFile(suffix='.wav', delete=True) as tmp_wav:
                chunk.export(tmp_wav.name, format='wav')
                
                # Get model and transcribe chunk
                current_model = get_model()
                result = current_model.transcribe(
                    tmp_wav.name,
                    fp16=False,
                    language='en',
                    task='transcribe'
                )
                
                transcription_pieces.append(result['text'].strip())
            
            # Cleanup after each chunk
            cleanup_memory()
        
        return ' '.join(transcription_pieces)
    
    except Exception as e:
        logger.error(f"Error in process_audio_in_chunks: {str(e)}")
        raise

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_token' not in session:
            return redirect(url_for('login'))
        try:
            decoded_token = auth.verify_id_token(session['user_token'])
            session['user_id'] = decoded_token['uid']
        except Exception as e:
            logger.error(f"Auth error: {e}")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/health')
def health_check():
    process = psutil.Process(os.getpid())
    memory_info = {
        "memory_percent": process.memory_percent(),
        "memory_mb": process.memory_info().rss / 1024 / 1024,
        "cpu_percent": process.cpu_percent()
    }
    return jsonify({"status": "healthy", "memory_info": memory_info}), 200

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@app.route('/upload', methods=['POST'])
@login_required
def upload_audio():
    try:
        # Check authorization
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "No authorization token provided"}), 401
        
        token = auth_header.split(' ')[1]
        try:
            decoded_token = auth.verify_id_token(token)
            user_id = decoded_token['uid']
        except Exception as e:
            return jsonify({"error": "Invalid authorization token"}), 401

        if 'audio_file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        audio_file = request.files['audio_file']
        if audio_file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        # Create temporary directory for processing
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = os.path.join(temp_dir, secure_filename(audio_file.filename))
            audio_file.save(temp_path)
            
            try:
                # Process audio with memory checks
                check_memory()
                transcription = process_audio_in_chunks(temp_path)
                
                # Store in Firestore
                doc_ref = db.collection('transcriptions').document()
                doc_ref.set({
                    'user_id': user_id,
                    'transcription': transcription,
                    'timestamp': firestore.SERVER_TIMESTAMP,
                    'filename': audio_file.filename
                })

                # Final cleanup
                cleanup_memory()

                return jsonify({
                    "transcription": transcription,
                    "status": "success",
                    "document_id": doc_ref.id
                })

            except MemoryError as me:
                logger.error(f"Memory error during processing: {str(me)}")
                return jsonify({
                    "error": "Insufficient memory to process audio",
                    "status": "error"
                }), 507  # Insufficient Storage

            except Exception as e:
                logger.error(f"Transcription error: {str(e)}")
                return jsonify({
                    "error": "Error processing audio file",
                    "status": "error"
                }), 500

    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({
            "error": str(e),
            "status": "error"
        }), 500

# Include your existing routes (signup, login, verify-token, logout) here...
# [Previous route implementations remain unchanged]

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(507)
def insufficient_storage_error(error):
    return jsonify({"error": "Insufficient storage"}), 507

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8000))
    app.run(host='0.0.0.0', port=port)
