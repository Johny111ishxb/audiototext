
getting authentication failed try again error signIn while deploying in railway.
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
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(24))

# Configure CORS with specific origins
CORS(app, supports_credentials=True, resources={
    r"/*": {
        "origins": os.environ.get('ALLOWED_ORIGINS', 'https://your-railway-domain.up.railway.app').split(','),
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

def load_firebase_credentials():
    """Load Firebase credentials from environment variable or file."""
    try:
        # First try environment variable
        creds_json = os.environ.get('FIREBASE_CREDENTIALS')
        if creds_json:
            return json.loads(creds_json)
            
        # Fallback to file
        creds_path = os.environ.get('FIREBASE_CREDENTIALS_PATH')
        if creds_path and os.path.exists(creds_path):
            with open(creds_path) as f:
                return json.load(f)
                
        logger.error("No Firebase credentials found")
        return None
    except Exception as e:
        logger.error(f"Error loading Firebase credentials: {e}")
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
                db.collection('health_check').limit(1).get()
                
                logger.info("Firebase initialized successfully")
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

def check_auth():
    """Check if user is authenticated and return user ID."""
    if 'user_token' not in session:
        return None
        
    try:
        decoded_token = auth.verify_id_token(session['user_token'])
        return decoded_token['uid']
    except Exception as e:
        logger.error(f"Auth verification error: {e}")
        session.clear()
        return None

def login_required(f):
    """Decorator to require authentication for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not initialize_firebase():
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
def index():
    """Render main page."""
    user_id = check_auth()
    if not user_id:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login')
def login():
    """Render login page."""
    if check_auth():
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/signup')
def signup():
    """Render signup page."""
    if check_auth():
        return redirect(url_for('index'))
    return render_template('signup.html')

# Authentication API Routes
@app.route('/api/auth/token', methods=['POST'])
def store_token():
    """Store Firebase ID token in session."""
    if not initialize_firebase():
        return jsonify({'error': 'Service unavailable'}), 503
        
    try:
        data = request.get_json()
        if not data or 'token' not in data:
            return jsonify({'error': 'No token provided'}), 400
        
        # Verify the token is valid
        decoded_token = auth.verify_id_token(data['token'])
        session['user_token'] = data['token']
        session['user_id'] = decoded_token['uid']
        
        logger.info(f"User {decoded_token['uid']} authenticated successfully")
        return jsonify({
            'status': 'success',
            'uid': decoded_token['uid']
        })
    except auth.InvalidIdTokenError:
        logger.error("Invalid Firebase token")
        return jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        return jsonify({'error': 'Authentication failed'}), 500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Clear session data."""
    session.clear()
    return jsonify({'status': 'success'})

# API Routes
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
            # Convert timestamp to string to make it JSON serializable
            if 'timestamp' in data and data['timestamp']:
                data['timestamp'] = data['timestamp'].isoformat()
            transcriptions.append(data)
            
        return jsonify(transcriptions)
    except Exception as e:
        logger.error(f"Error fetching transcriptions: {e}")
        return jsonify({
            "error": "Failed to fetch transcriptions",
            "details": str(e)
        }), 500

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    if request.is_json:
        return jsonify({"error": "Not found"}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    if request.is_json:
        return jsonify({"error": "Internal server error"}), 500
    return render_template('500.html'), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    # Initialize services on startup
    initialize_firebase()
    get_whisper_model()
    
    app.run(host='0.0.0.0', port=port, debug=debug)
