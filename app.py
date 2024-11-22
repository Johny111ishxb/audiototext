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
import numpy as np
from pydub.utils import make_chunks
import logging

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

# Global variable for Whisper model
model = None

def initialize_whisper():
    """Initialize Whisper model with memory optimizations"""
    global model
    if model is None:
        try:
            # Set PyTorch memory optimizations
            torch.set_num_threads(1)
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
            
            # Load the smallest model variant
            model = whisper.load_model("tiny", device="cpu", download_root="/tmp")
            
            # Force model to use FP32
            model.eval()
            for param in model.parameters():
                param.requires_grad = False
        except Exception as e:
            logger.error(f"Error loading Whisper model: {e}")
            return False
    return True

def cleanup_memory():
    """Force garbage collection and clear CUDA cache"""
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    gc.collect()

def process_audio_chunk(chunk, temp_dir):
    """Process a single chunk of audio"""
    try:
        # Export chunk to temporary WAV file
        chunk_path = os.path.join(temp_dir, "chunk.wav")
        chunk.export(chunk_path, format='wav')
        
        # Transcribe chunk
        result = model.transcribe(chunk_path, fp16=False)
        
        # Clean up
        os.remove(chunk_path)
        cleanup_memory()
        
        return result.get('text', '').strip()
    except Exception as e:
        logger.error(f"Error processing chunk: {e}")
        return ''

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
    return jsonify({"status": "healthy", "memory_usage": f"{psutil.Process().memory_info().rss / 1024 / 1024:.2f}MB"}), 200

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
@login_required
def upload_audio():
    if not initialize_whisper():
        return jsonify({"error": "Could not initialize Whisper model"}), 500

    try:
        # Verify authentication
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

        # Process audio in chunks
        with tempfile.TemporaryDirectory() as temp_dir:
            # Save uploaded file
            temp_path = os.path.join(temp_dir, secure_filename(audio_file.filename))
            audio_file.save(temp_path)
            
            try:
                # Load audio file
                if audio_file.filename.lower().endswith('.mp3'):
                    audio = AudioSegment.from_mp3(temp_path)
                else:
                    audio = AudioSegment.from_wav(temp_path)

                # Remove original file to free memory
                os.remove(temp_path)

                # Split audio into 30-second chunks
                chunk_length = 30 * 1000  # 30 seconds
                chunks = make_chunks(audio, chunk_length)

                # Process chunks and combine transcriptions
                transcriptions = []
                for chunk in chunks:
                    transcript = process_audio_chunk(chunk, temp_dir)
                    if transcript:
                        transcriptions.append(transcript)
                    cleanup_memory()

                final_transcription = ' '.join(transcriptions)

                # Store transcription in Firestore
                doc_ref = db.collection('transcriptions').document()
                doc_ref.set({
                    'user_id': user_id,
                    'transcription': final_transcription,
                    'timestamp': firestore.SERVER_TIMESTAMP,
                    'filename': audio_file.filename
                })

                cleanup_memory()

                return jsonify({
                    "transcription": final_transcription,
                    "status": "success",
                    "document_id": doc_ref.id
                })

            except Exception as e:
                logger.error(f"Transcription error: {e}")
                return jsonify({
                    "error": "Error processing audio file",
                    "status": "error"
                }), 500

    except Exception as e:
        logger.error(f"Error processing audio: {str(e)}")
        return jsonify({
            "error": f"Error processing audio: {str(e)}",
            "status": "error"
        }), 500

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8000))
    app.run(host='0.0.0.0', port=port)
