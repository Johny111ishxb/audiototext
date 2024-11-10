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

# Enhanced logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app with enhanced security
app = Flask(__name__, static_folder='static', template_folder='templates')
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# Ensure strong secret key
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    logger.warning("No SECRET_KEY set in environment, generating random key")
    app.secret_key = secrets.token_hex(32)

# Enhanced CORS configuration
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', '').split(',')
if not ALLOWED_ORIGINS or ALLOWED_ORIGINS == ['']:
    ALLOWED_ORIGINS = ['https://your-railway-domain.up.railway.app']
    logger.warning(f"No ALLOWED_ORIGINS set, defaulting to: {ALLOWED_ORIGINS}")

CORS(app, supports_credentials=True, resources={
    r"/*": {
        "origins": ALLOWED_ORIGINS,
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True,
        "expose_headers": ["Content-Range", "X-Content-Range"]
    }
})

# Global variables with proper locking
firebase_initialized = False
firebase_init_lock = Lock()
whisper_model = None
whisper_model_lock = Lock()

def load_firebase_credentials():
    """Load and validate Firebase credentials with enhanced error checking."""
    try:
        # Try environment variable first
        creds_json = os.environ.get('FIREBASE_CREDENTIALS')
        if creds_json:
            try:
                creds_dict = json.loads(creds_json)
                required_fields = ['type', 'project_id', 'private_key_id', 'private_key', 'client_email']
                missing_fields = [field for field in required_fields if field not in creds_dict]
                
                if missing_fields:
                    logger.error(f"Missing required Firebase credential fields: {missing_fields}")
                    return None
                    
                logger.info("Successfully loaded Firebase credentials from environment")
                return creds_dict
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse FIREBASE_CREDENTIALS JSON: {e}")
                return None
        
        # Fallback to file
        creds_path = os.environ.get('FIREBASE_CREDENTIALS_PATH')
        if creds_path and os.path.exists(creds_path):
            try:
                with open(creds_path) as f:
                    creds_dict = json.load(f)
                logger.info("Successfully loaded Firebase credentials from file")
                return creds_dict
            except Exception as e:
                logger.error(f"Failed to load Firebase credentials from file: {e}")
                return None
        
        logger.error("No Firebase credentials found in environment or file")
        return None
    except Exception as e:
        logger.error(f"Unexpected error loading Firebase credentials: {e}")
        return None

def initialize_firebase():
    """Initialize Firebase with enhanced error handling and validation."""
    global firebase_initialized
    
    if firebase_initialized:
        return True
        
    with firebase_init_lock:
        if firebase_initialized:
            return True
            
        try:
            cred_dict = load_firebase_credentials()
            if not cred_dict:
                logger.error("Failed to load Firebase credentials")
                return False

            if not firebase_admin._apps:
                cred = credentials.Certificate(cred_dict)
                firebase_admin.initialize_app(cred, {
                    'storageBucket': f"{cred_dict.get('project_id')}.appspot.com"
                })
                
                # Verify Firebase connection
                db = firestore.client()
                db.collection('health_check').limit(1).get()
                
                logger.info("Firebase initialized and connected successfully")
                firebase_initialized = True
                return True
                
        except Exception as e:
            logger.error(f"Firebase initialization error: {e}")
            return False

def get_whisper_model():
    """Load Whisper model with proper error handling and resource management."""
    global whisper_model
    
    if whisper_model is not None:
        return whisper_model
        
    with whisper_model_lock:
        if whisper_model is not None:
            return whisper_model
            
        try:
            logger.info("Loading Whisper model...")
            whisper_model = whisper.load_model("base")
            logger.info("Whisper model loaded successfully")
            return whisper_model
        except Exception as e:
            logger.error(f"Whisper model loading error: {e}")
            return None

def check_auth():
    """Enhanced authentication check with detailed error handling."""
    try:
        if 'user_token' not in session:
            logger.debug("No user token in session")
            return None
            
        token = session['user_token']
        try:
            decoded_token = auth.verify_id_token(token)
            logger.debug(f"Successfully verified token for user {decoded_token['uid']}")
            return decoded_token['uid']
        except auth.InvalidIdTokenError as e:
            logger.error(f"Invalid token in session: {e}")
            session.clear()
            return None
        except auth.ExpiredIdTokenError:
            logger.error("Token has expired")
            session.clear()
            return None
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            session.clear()
            return None
            
    except Exception as e:
        logger.error(f"Unexpected error in auth check: {e}")
        session.clear()
        return None

def login_required(f):
    """Enhanced decorator for requiring authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not initialize_firebase():
            return jsonify({'error': 'Service unavailable', 'details': 'Firebase initialization failed'}), 503
            
        user_id = check_auth()
        if not user_id:
            if request.is_json:
                return jsonify({'error': 'Authentication required', 'details': 'Invalid or missing token'}), 401
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function

# Frontend Routes with enhanced error handling
@app.route('/')
def index():
    """Enhanced main page route."""
    try:
        user_id = check_auth()
        if not user_id:
            return redirect(url_for('login'))
        return render_template('index.html')
    except Exception as e:
        logger.error(f"Error in index route: {e}")
        return render_template('500.html'), 500

@app.route('/login')
def login():
    """Enhanced login route."""
    try:
        if check_auth():
            return redirect(url_for('index'))
        return render_template('login.html')
    except Exception as e:
        logger.error(f"Error in login route: {e}")
        return render_template('500.html'), 500

@app.route('/signup')
def signup():
    """Enhanced signup route."""
    try:
        if check_auth():
            return redirect(url_for('index'))
        return render_template('signup.html')
    except Exception as e:
        logger.error(f"Error in signup route: {e}")
        return render_template('500.html'), 500

# Enhanced Authentication API Routes
@app.route('/api/auth/token', methods=['POST'])
def store_token():
    """Enhanced token storage with detailed error handling."""
    if not initialize_firebase():
        return jsonify({'error': 'Service unavailable', 'details': 'Firebase initialization failed'}), 503
        
    try:
        data = request.get_json()
        if not data or 'token' not in data:
            return jsonify({'error': 'No token provided'}), 400
        
        token = data['token']
        try:
            decoded_token = auth.verify_id_token(token)
            session['user_token'] = token
            session['user_id'] = decoded_token['uid']
            
            logger.info(f"User {decoded_token['uid']} authenticated successfully")
            return jsonify({
                'status': 'success',
                'uid': decoded_token['uid']
            })
        except auth.InvalidIdTokenError as e:
            logger.error(f"Invalid token: {e}")
            return jsonify({'error': 'Invalid token', 'details': str(e)}), 401
        except auth.ExpiredIdTokenError:
            logger.error("Token expired")
            return jsonify({'error': 'Token expired'}), 401
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return jsonify({'error': 'Authentication failed', 'details': str(e)}), 500
            
    except Exception as e:
        logger.error(f"Unexpected error in token storage: {e}")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Enhanced logout with session cleanup."""
    try:
        session.clear()
        return jsonify({'status': 'success'})
    except Exception as e:
        logger.error(f"Error during logout: {e}")
        return jsonify({'error': 'Logout failed', 'details': str(e)}), 500

# Testing and Debug Routes
@app.route('/api/auth/test')
def test_auth():
    """Test endpoint for Firebase and session configuration."""
    status = {
        'firebase_initialized': firebase_initialized,
        'session_enabled': app.secret_key is not None,
        'allowed_origins': ALLOWED_ORIGINS,
    }
    
    if not initialize_firebase():
        status['error'] = 'Firebase initialization failed'
        return jsonify(status), 503
        
    try:
        db = firestore.client()
        db.collection('test').limit(1).get()
        status['firebase_connection'] = 'success'
    except Exception as e:
        status['firebase_connection'] = f'error: {str(e)}'
        
    return jsonify(status)

@app.route('/api/session/test')
def test_session():
    """Test endpoint for session functionality."""
    try:
        session['test'] = 'test_value'
        return jsonify({
            'status': 'success',
            'session_working': session.get('test') == 'test_value',
            'session_id': session.get('user_id'),
            'has_token': 'user_token' in session
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

# Enhanced API Routes
@app.route('/api/health')
def health_check():
    """Enhanced health check endpoint."""
    status = {
        "service": "audio-transcription",
        "timestamp": time.time(),
        "components": {
            "app": "running",
            "firebase": "not_initialized",
            "whisper_model": "not_loaded",
            "session": "enabled" if app.secret_key else "disabled"
        },
        "config": {
            "debug": app.debug,
            "testing": app.testing,
            "cors_origins": ALLOWED_ORIGINS
        }
    }
    
    if initialize_firebase():
        try:
            db = firestore.client()
            db.collection('health_check').limit(1).get()
            status["components"]["firebase"] = "connected"
        except Exception as e:
            status["components"]["firebase"] = f"error: {str(e)}"
    
    if get_whisper_model() is not None:
        status["components"]["whisper_model"] = "loaded"
    
    status["healthy"] = all(v in ["running", "connected", "loaded", "enabled"] 
                           for v in status["components"].values())
    
    return jsonify(status), 200 if status["healthy"] else 503

@app.route('/api/upload', methods=['POST'])
@login_required
def upload_audio():
    """Enhanced audio upload and transcription endpoint."""
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

                user_id = check_auth()
                # Store in Firestore
                db = firestore.client()
                doc_ref = db.collection('transcriptions').document()
                doc_ref.set({
                    'userId': user_id,
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
                    "details": str(e)
                }), 500
            finally:
                if os.path.exists(temp_wav.name):
                    os.unlink(temp_wav.name)

    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({
            "error": "Internal server error",
