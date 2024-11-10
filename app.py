import os
import secrets
import time
import json
import logging
import tempfile
import gc
from datetime import datetime, timedelta
from pathlib import Path
from threading import Lock
from functools import wraps
from flask import Flask, render_template, request, jsonify, send_from_directory, session, redirect, url_for
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
import firebase_admin
from firebase_admin import credentials, auth, storage, firestore
from pydub import AudioSegment
import whisper

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, static_folder='static', template_folder='templates')
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# Load secret key from environment
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(24))
app.permanent_session_lifetime = timedelta(hours=1)  # Set session lifetime

# Configure CORS with specific origins
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', '').split(',')
if not ALLOWED_ORIGINS or ALLOWED_ORIGINS[0] == '':
    ALLOWED_ORIGINS = ['https://audiototext-production.up.railway.app']

CORS(app, supports_credentials=True, resources={
    r"/*": {
        "origins": ALLOWED_ORIGINS,
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

# Global variables
firebase_initialized = False
firebase_init_lock = Lock()
whisper_model = None
whisper_model_lock = Lock()

def initialize_firebase():
    """Initialize Firebase with proper error handling."""
    global firebase_initialized
    
    if firebase_initialized:
        return True
        
    with firebase_init_lock:
        if firebase_initialized:
            return True
            
        try:
            if not firebase_admin._apps:
                creds_json = os.environ.get('FIREBASE_CREDENTIALS')
                if not creds_json:
                    logger.error("FIREBASE_CREDENTIALS environment variable not found")
                    return False
                
                try:
                    cred_dict = json.loads(creds_json)
                    cred = credentials.Certificate(cred_dict)
                    firebase_admin.initialize_app(cred, {
                        'storageBucket': f"{cred_dict['project_id']}.appspot.com"
                    })
                    
                    # Verify Firebase connection
                    db = firestore.client()
                    db.collection('users').limit(1).get()
                    
                    logger.info("Firebase initialized successfully")
                    firebase_initialized = True
                    return True
                    
                except json.JSONDecodeError:
                    logger.error("Invalid JSON in FIREBASE_CREDENTIALS")
                    return False
        except Exception as e:
            logger.error(f"Firebase initialization error: {str(e)}")
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
            logger.error(f"Whisper model loading error: {str(e)}")
            return None

def check_auth():
    """Check if user is authenticated and verify token expiration."""
    if 'user_token' not in session:
        return None
    
    try:
        # Check token expiration
        if 'token_exp' in session:
            exp_time = datetime.fromtimestamp(session['token_exp'])
            if exp_time < datetime.utcnow():
                logger.info("Token expired, clearing session")
                session.clear()
                return None

        decoded_token = auth.verify_id_token(session['user_token'])
        return decoded_token['uid']
    except Exception as e:
        logger.error(f"Auth verification error: {str(e)}")
        session.clear()
        return None

def login_required(f):
    """Decorator to require authentication for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not initialize_firebase():
            logger.error("Firebase not initialized")
            return jsonify({'error': 'Service unavailable'}), 503
            
        user_id = check_auth()
        if not user_id:
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function

# Frontend Routes
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    if check_auth():
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/signup')
def signup():
    if check_auth():
        return redirect(url_for('index'))
    return render_template('signup.html')

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

# Authentication API Routes
@app.route('/api/auth/token', methods=['POST'])
def store_token():
    """Store Firebase ID token in session with enhanced error handling."""
    if not initialize_firebase():
        logger.error("Firebase not initialized")
        return jsonify({'error': 'Service unavailable'}), 503
        
    try:
        data = request.get_json()
        if not data or 'token' not in data:
            logger.error("No token provided in request")
            return jsonify({'error': 'No token provided'}), 400
        
        # Verify the token is valid
        decoded_token = auth.verify_id_token(data['token'])
        
        # Check token expiration
        exp = datetime.fromtimestamp(decoded_token['exp'])
        if exp < datetime.utcnow():
            logger.error("Token expired")
            return jsonify({'error': 'Token expired'}), 401
        
        # Store token and user data in session
        session.permanent = True
        session['user_token'] = data['token']
        session['user_id'] = decoded_token['uid']
        session['token_exp'] = exp.timestamp()
        
        logger.info(f"User {decoded_token['uid']} authenticated successfully")
        return jsonify({
            'status': 'success',
            'uid': decoded_token['uid'],
            'exp': exp.timestamp()
        })
        
    except auth.InvalidIdTokenError as e:
        logger.error(f"Invalid Firebase token: {str(e)}")
        return jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        logger.error(f"Token verification error: {str(e)}")
        return jsonify({'error': 'Authentication failed'}), 500

@app.route('/api/auth/refresh', methods=['POST'])
def refresh_token():
    """Refresh the session token."""
    try:
        data = request.get_json()
        if not data or 'token' not in data:
            return jsonify({'error': 'No token provided'}), 400
            
        # Verify new token
        decoded_token = auth.verify_id_token(data['token'])
        
        # Update session
        session['user_token'] = data['token']
        session['token_exp'] = datetime.fromtimestamp(decoded_token['exp']).timestamp()
        
        return jsonify({'status': 'success'})
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        return jsonify({'error': 'Token refresh failed'}), 500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Clear session data with proper error handling."""
    try:
        session.clear()
        return jsonify({'status': 'success'})
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({'error': 'Logout failed'}), 500

# Audio Processing Routes
@app.route('/api/upload', methods=['POST'])
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
                logger.error(f"Audio processing error: {str(e)}")
                return jsonify({
                    "error": "Error processing audio file",
                    "details": str(e)
                }), 500
            finally:
                if os.path.exists(temp_wav.name):
                    os.unlink(temp_wav.name)

    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({
            "error": "Internal server error",
            "details": str(e)
        }), 500

@app.route('/api/transcriptions', methods=['GET'])
@login_required
def get_transcriptions():
    """Get user's transcription history."""
    try:
        user_id = check_auth()
        db = firestore.client()
        docs = db.collection('transcriptions')\
                 .where('userId', '==', user_id)\
                 .order_by('timestamp', direction=firestore.Query.DESCENDING)\
                 .limit(50)\
                 .stream()
        
        transcriptions = []
        for doc in docs:
            data = doc.to_dict()
            data['id'] = doc.id
            if 'timestamp' in data and data['timestamp']:
                data['timestamp'] = data['timestamp'].isoformat()
            transcriptions.append(data)
            
        return jsonify(transcriptions)
    except Exception as e:
        logger.error(f"Error fetching transcriptions: {str(e)}")
        return jsonify({
            "error": "Failed to fetch transcriptions",
            "details": str(e)
        }), 500

# Health Check Route
@app.route('/api/health')
def health_check():
    """Health check endpoint."""
    status = {
        "service": "audio-transcription",
        "timestamp": time.time(),
        "components": {
            "app": "running",
            "firebase": "not_initialized",
            "whisper_model": "not_loaded"
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
    
    status["healthy"] = all(v in ["running", "connected", "loaded"] 
                           for v in status["components"].values())
    
    return jsonify(status), 200 if status["healthy"] else 503

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    if request.is_json:
        return jsonify({"error": "Not found"}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    if request.is_json:
        return jsonify({"error": "Internal server error"}), 500
    return render_template('500.html'), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    # Initialize services on startup
    if not initialize_firebase():
        logger.error("Failed to initialize Firebase. Check your credentials.")
    
    # Load Whisper model
    if get_whisper_model() is None:
        logger.error("Failed to load Whisper model")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
