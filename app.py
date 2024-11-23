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
CHUNK_DURATION = 10000  # 10 seconds
MAX_AUDIO_LENGTH = 300000  # 5 minutes
MODEL_NAME = "tiny"

def cleanup_memory():
    """Aggressive memory cleanup"""
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    gc.collect()
    if 'model' in globals():
        global model
        model = None
    gc.collect()

def lazy_load_model():
    """Lazy load the model only when needed"""
    global model
    if model is None:
        try:
            # Set memory-efficient PyTorch settings
            torch.set_num_threads(1)
            torch.set_num_interop_threads(1)
            torch.backends.cudnn.enabled = False
            
            # Create cache directory if it doesn't exist
            cache_dir = Path("/tmp/whisper_cache")
            cache_dir.mkdir(parents=True, exist_ok=True)
            
            # Load model with minimal memory footprint
            model = whisper.load_model(
                MODEL_NAME,
                device="cpu",
                download_root=str(cache_dir),
                in_memory=False
            )
            
            # Force model to use less memory
            model.eval()
            torch.set_grad_enabled(False)
            
            for param in model.parameters():
                param.requires_grad = False
                if hasattr(param, 'grad'):
                    param.grad = None
                    
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            cleanup_memory()
            raise

def get_memory_usage():
    """Get current memory usage in MB"""
    import psutil
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / 1024 / 1024

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

def process_audio_chunk(audio_segment):
    """Process a single audio chunk"""
    try:
        with tempfile.NamedTemporaryFile(suffix='.wav', delete=True) as temp_wav:
            audio_segment.export(temp_wav.name, format='wav')
            
            with model_lock:
                lazy_load_model()
                if model is None:
                    raise Exception("Failed to load model")
                
                result = model.transcribe(
                    temp_wav.name,
                    fp16=False,
                    language='en',
                    task='transcribe'
                )
                
            return result.get('text', '').strip()
    except Exception as e:
        logger.error(f"Error processing chunk: {e}")
        raise
    finally:
        cleanup_memory()

def split_audio(audio_segment, max_chunk_size=CHUNK_DURATION):
    """Split audio into smaller chunks"""
    chunks = []
    for i in range(0, len(audio_segment), max_chunk_size):
        chunk = audio_segment[i:i + max_chunk_size]
        chunks.append(chunk)
    return chunks

@app.route('/upload', methods=['POST'])
@login_required
def upload_audio():
    try:
        # Check memory usage before starting
        initial_memory = get_memory_usage()
        logger.info(f"Initial memory usage: {initial_memory:.2f}MB")

        # Verify authorization
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

        # Process the audio file
        try:
            with tempfile.NamedTemporaryFile(suffix=os.path.splitext(audio_file.filename)[1], delete=True) as temp_file:
                audio_file.save(temp_file.name)
                
                # Load audio with memory-efficient settings
                audio = AudioSegment.from_file(
                    temp_file.name,
                    format=os.path.splitext(audio_file.filename)[1].lstrip('.')
                )

                # Check audio length
                if len(audio) > MAX_AUDIO_LENGTH:
                    return jsonify({
                        "error": "Audio file too long. Maximum length is 5 minutes.",
                        "status": "error"
                    }), 400

                # Process audio in chunks
                chunks = split_audio(audio)
                transcription_parts = []

                for i, chunk in enumerate(chunks):
                    logger.info(f"Processing chunk {i+1}/{len(chunks)}")
                    try:
                        text = process_audio_chunk(chunk)
                        if text:
                            transcription_parts.append(text)
                    except Exception as e:
                        logger.error(f"Error processing chunk {i+1}: {e}")
                        cleanup_memory()
                        continue

                transcription = ' '.join(transcription_parts)

                # Store in Firestore
                doc_ref = db.collection('transcriptions').document()
                doc_ref.set({
                    'user_id': user_id,
                    'transcription': transcription,
                    'timestamp': firestore.SERVER_TIMESTAMP,
                    'filename': audio_file.filename
                })

                final_memory = get_memory_usage()
                logger.info(f"Final memory usage: {final_memory:.2f}MB")

                return jsonify({
                    "transcription": transcription,
                    "status": "success",
                    "document_id": doc_ref.id,
                    "memory_usage": f"{final_memory:.2f}MB"
                })

        except Exception as e:
            logger.error(f"Error processing audio: {e}")
            cleanup_memory()
            return jsonify({
                "error": f"Error processing audio: {str(e)}",
                "status": "error"
            }), 500

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        cleanup_memory()
        return jsonify({
            "error": "An unexpected error occurred",
            "status": "error"
        }), 500

    finally:
        cleanup_memory()

# Routes from previous implementation remain the same
@app.route('/health')
def health_check():
    return jsonify({
        "status": "healthy",
        "memory_usage": f"{get_memory_usage():.2f}MB"
    }), 200

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            data = request.json
            email = data.get('email')
            password = data.get('password')
            firstname = data.get('firstname')

            if not all([email, password, firstname]):
                return jsonify({
                    'status': 'error',
                    'message': 'Missing required fields'
                }), 400

            user = auth.create_user(
                email=email,
                password=password,
                display_name=firstname
            )

            db.collection('users').document(user.uid).set({
                'firstname': firstname,
                'email': email,
                'createdAt': firestore.SERVER_TIMESTAMP
            })

            custom_token = auth.create_custom_token(user.uid)
            
            return jsonify({
                'status': 'success',
                'message': 'User created successfully',
                'token': custom_token.decode()
            })

        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 400

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            data = request.json
            email = data.get('email')
            password = data.get('password')

            if not all([email, password]):
                return jsonify({
                    'status': 'error',
                    'message': 'Missing email or password'
                }), 400

            user = auth.get_user_by_email(email)
            custom_token = auth.create_custom_token(user.uid)
            
            return jsonify({
                'status': 'success',
                'token': custom_token.decode()
            })

        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': 'Invalid credentials'
            }), 401

    return render_template('login.html')

@app.route('/verify-token', methods=['POST'])
def verify_token():
    try:
        data = request.get_json()
        if not data or 'token' not in data:
            return jsonify({'status': 'error', 'message': 'No token provided'}), 400
        
        token = data.get('token')
        decoded_token = auth.verify_id_token(token)
        session['user_token'] = token
        session['user_id'] = decoded_token['uid']
        return jsonify({'status': 'success', 'uid': decoded_token['uid']})
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        return jsonify({'status': 'error', 'message': 'Invalid token'}), 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

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
