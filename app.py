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
import psutil
import threading

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
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
model_lock = threading.Lock()

def log_memory_usage():
    """Log current memory usage"""
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    logger.info(f"Memory usage: {mem_info.rss / 1024 / 1024:.2f} MB")

def initialize_whisper():
    """Initialize Whisper model with memory optimizations"""
    global model
    with model_lock:
        if model is None:
            try:
                # Log memory before loading
                log_memory_usage()
                
                # Set PyTorch memory optimizations
                torch.set_num_threads(1)
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
                
                # Load the smallest model variant
                model = whisper.load_model("tiny", device="cpu", download_root="/tmp")
                
                # Force model to use FP32 and disable gradients
                model.eval()
                for param in model.parameters():
                    param.requires_grad = False
                
                # Log memory after loading
                log_memory_usage()
                
                return True
            except Exception as e:
                logger.error(f"Error loading Whisper model: {e}")
                return False
    return True

def cleanup_memory():
    """Force garbage collection and clear CUDA cache"""
    try:
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        gc.collect()
        log_memory_usage()
    except Exception as e:
        logger.error(f"Error during memory cleanup: {e}")

def process_audio_chunk(chunk, temp_dir):
    """Process a single chunk of audio"""
    try:
        # Export chunk to temporary WAV file
        chunk_path = os.path.join(temp_dir, f"chunk_{secrets.token_hex(8)}.wav")
        chunk.export(chunk_path, format='wav')
        
        # Log memory before transcription
        log_memory_usage()
        
        # Transcribe chunk
        with model_lock:
            result = model.transcribe(chunk_path, fp16=False)
        
        # Clean up
        os.remove(chunk_path)
        cleanup_memory()
        
        return result.get('text', '').strip()
    except Exception as e:
        logger.error(f"Error processing chunk: {e}")
        return ''
    finally:
        cleanup_memory()

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
    """Health check endpoint with memory usage information"""
    try:
        process = psutil.Process(os.getpid())
        mem_info = process.memory_info()
        return jsonify({
            "status": "healthy",
            "memory_usage_mb": f"{mem_info.rss / 1024 / 1024:.2f}",
            "cpu_percent": process.cpu_percent(),
            "whisper_model_loaded": model is not None
        }), 200
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500

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

            # Create user in Firebase
            user = auth.create_user(
                email=email,
                password=password,
                display_name=firstname
            )

            # Create user document in Firestore
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
            logger.error(f"Signup error: {e}")
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
            logger.error(f"Login error: {e}")
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

@app.route('/upload', methods=['POST'])
@login_required
def upload_audio():
    """Handle audio upload and transcription"""
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
            logger.error(f"Auth error in upload: {e}")
            return jsonify({"error": "Invalid authorization token"}), 401

        if 'audio_file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        audio_file = request.files['audio_file']
        if audio_file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        # Create temporary directory for processing
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                # Log initial memory usage
                log_memory_usage()
                
                # Save uploaded file
                temp_path = os.path.join(temp_dir, secure_filename(audio_file.filename))
                audio_file.save(temp_path)
                
                # Load audio file
                if audio_file.filename.lower().endswith('.mp3'):
                    audio = AudioSegment.from_mp3(temp_path)
                else:
                    audio = AudioSegment.from_wav(temp_path)

                # Remove original file to free memory
                os.remove(temp_path)
                cleanup_memory()

                # Split audio into 30-second chunks
                chunk_length = 30 * 1000  # 30 seconds
                chunks = make_chunks(audio, chunk_length)
                
                # Clear audio object to free memory
                audio = None
                cleanup_memory()

                # Process chunks and combine transcriptions
                transcriptions = []
                for i, chunk in enumerate(chunks):
                    logger.info(f"Processing chunk {i+1}/{len(chunks)}")
                    transcript = process_audio_chunk(chunk, temp_dir)
                    if transcript:
                        transcriptions.append(transcript)
                    chunk = None  # Clear chunk from memory
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
                logger.error(f"Error processing audio file: {e}")
                return jsonify({
                    "error": "Error processing audio file",
                    "details": str(e),
                    "status": "error"
                }), 500

    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({
            "error": f"Error processing audio: {str(e)}",
            "status": "error"
        }), 500
    finally:
        cleanup_memory()

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled exception: {e}")
    return jsonify({
        "error": "Internal server error",
        "details": str(e)
    }), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8000))
    app.run(host='0.0.0.0', port=port)
