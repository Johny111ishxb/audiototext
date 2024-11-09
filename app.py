import os
import secrets
import time
import json
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_from_directory, session, redirect, url_for
from flask_cors import CORS
from functools import wraps
import firebase_admin
from firebase_admin import credentials, auth, storage, firestore
from pydub import AudioSegment
import whisper
import tempfile
import gc
import logging
from threading import Lock
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, static_folder='static', template_folder='templates')
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)  # Handle proxy headers
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(24))

# Configure CORS
CORS(app, supports_credentials=True, resources={
    r"/*": {
        "origins": os.environ.get('ALLOWED_ORIGINS', '*').split(','),
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Global variables
firebase_initialized = False
firebase_init_lock = Lock()
whisper_model = None
whisper_model_lock = Lock()

def load_firebase_credentials():
    """Load Firebase credentials from environment variable or file."""
    creds_str = os.environ.get('FIREBASE_CREDENTIALS')
    if creds_str:
        try:
            return json.loads(creds_str)
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing Firebase credentials from environment: {e}")
    
    creds_path = os.environ.get('FIREBASE_CREDENTIALS_PATH')
    if creds_path and os.path.exists(creds_path):
        try:
            with open(creds_path) as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading Firebase credentials from file: {e}")
    
    return None

def initialize_firebase():
    """Initialize Firebase with proper error handling."""
    global firebase_initialized
    
    if firebase_initialized:
        return True
        
    with firebase_init_lock:
        if firebase_initialized:
            return True
            
        try:
            cred_dict = load_firebase_credentials()
            if not cred_dict:
                logger.error("Firebase credentials not found")
                return False

            if not firebase_admin._apps:
                cred = credentials.Certificate(cred_dict)
                firebase_admin.initialize_app(cred, {
                    'storageBucket': f"{cred_dict.get('project_id')}.appspot.com"
                })
                
                # Verify Firebase connection
                db = firestore.client()
                db.collection('health_check').limit(1).get()  # Test query
                
                logger.info("Firebase initialized and connected successfully")
                firebase_initialized = True
                return True
            
        except Exception as e:
            logger.error(f"Firebase initialization error: {e}")
            return False

def get_whisper_model():
    """Load Whisper model with proper error handling."""
    global whisper_model
    
    if whisper_model is not None:
        return whisper_model
        
    with whisper_model_lock:
        if whisper_model is not None:
            return whisper_model
            
        try:
            whisper_model = whisper.load_model("base")
            logger.info("Whisper model loaded successfully")
            return whisper_model
        except Exception as e:
            logger.error(f"Whisper model loading error: {e}")
            return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not initialize_firebase():
            return jsonify({'error': 'Service temporarily unavailable'}), 503
            
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'No valid authorization token'}), 401
            
        try:
            token = auth_header.split('Bearer ')[1]
            decoded_token = auth.verify_id_token(token)
            request.user_id = decoded_token['uid']
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return jsonify({'error': 'Invalid authorization token'}), 401
            
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """Root endpoint to confirm service is running."""
    return jsonify({
        "status": "running",
        "version": "1.0",
        "endpoints": ["/health", "/upload"]
    })

@app.route('/health')
def health_check():
    """Enhanced health check endpoint."""
    status = {
        "service": "audio-transcription",
        "timestamp": time.time(),
        "components": {
            "app": "running",
            "firebase": "not_initialized",
            "whisper_model": "not_loaded"
        }
    }
    
    # Check Firebase
    if initialize_firebase():
        try:
            db = firestore.client()
            db.collection('health_check').limit(1).get()
            status["components"]["firebase"] = "connected"
        except Exception as e:
            status["components"]["firebase"] = f"error: {str(e)}"
    
    # Check Whisper model
    if get_whisper_model() is not None:
        status["components"]["whisper_model"] = "loaded"
    
    # Determine overall health
    status["healthy"] = all(v in ["running", "connected", "loaded"] 
                          for v in status["components"].values())
    
    return jsonify(status), 200 if status["healthy"] else 503

@app.route('/upload', methods=['POST'])
@login_required
def upload_audio():
    """Handle audio file upload and transcription."""
    if not initialize_firebase():
        return jsonify({"error": "Service unavailable"}), 503

    try:
        if 'audio_file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        audio_file = request.files['audio_file']
        if audio_file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        # Validate file type
        allowed_extensions = {'mp3', 'wav', 'ogg', 'flac'}
        if not ('.' in audio_file.filename and 
                audio_file.filename.rsplit('.', 1)[1].lower() in allowed_extensions):
            return jsonify({"error": "Invalid file type"}), 400

        # Process audio file
        with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as temp_wav:
            try:
                if audio_file.filename.lower().endswith('.mp3'):
                    with tempfile.NamedTemporaryFile(suffix='.mp3', delete=False) as temp_mp3:
                        audio_file.save(temp_mp3.name)
                        audio = AudioSegment.from_mp3(temp_mp3.name)
                        audio.export(temp_wav.name, format='wav')
                        os.unlink(temp_mp3.name)
                else:
                    audio_file.save(temp_wav.name)

                model = get_whisper_model()
                if model is None:
                    return jsonify({"error": "Transcription service unavailable"}), 503

                result = model.transcribe(temp_wav.name)
                transcription = result['text']

                # Store in Firestore
                db = firestore.client()
                doc_ref = db.collection('transcriptions').document()
                doc_ref.set({
                    'userId': request.user_id,
                    'transcription': transcription,
                    'timestamp': firestore.SERVER_TIMESTAMP,
                    'filename': audio_file.filename,
                    'status': 'completed'
                })

                # Clean up
                del result
                gc.collect()

                return jsonify({
                    "transcription": transcription,
                    "status": "success",
                    "docId": doc_ref.id
                })

            except Exception as e:
                logger.error(f"Audio processing error: {e}")
                return jsonify({
                    "error": "Error processing audio file",
                    "status": "error"
                }), 500
            finally:
                if os.path.exists(temp_wav.name):
                    os.unlink(temp_wav.name)

    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({
            "error": "Internal server error",
            "status": "error"
        }), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8000))
    debug = os.environ.get("FLASK_ENV") == "development"
    
    # Initialize services on startup
    initialize_firebase()
    get_whisper_model()
    
    app.run(host='0.0.0.0', port=port, debug=debug)
