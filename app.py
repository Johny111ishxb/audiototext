import os
import secrets
import time
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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    logger.warning("SECRET_KEY not set in environment variables. Generating random key...")
    app.secret_key = secrets.token_hex(24)

# Configure CORS
CORS(app, supports_credentials=True)

# Validate required environment variables
required_env_vars = [
    'FIREBASE_PROJECT_ID',
    'FIREBASE_PRIVATE_KEY_ID',
    'FIREBASE_PRIVATE_KEY',
    'FIREBASE_CLIENT_EMAIL',
    'FIREBASE_CLIENT_ID',
    'FIREBASE_CLIENT_CERT_URL',
    'FIREBASE_STORAGE_BUCKET'
]

missing_vars = [var for var in required_env_vars if not os.environ.get(var)]
if missing_vars:
    raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

# Initialize Firebase Admin SDK
cred_dict = {
    "type": "service_account",
    "project_id": os.environ.get('FIREBASE_PROJECT_ID'),
    "private_key_id": os.environ.get('FIREBASE_PRIVATE_KEY_ID'),
    "private_key": os.environ.get('FIREBASE_PRIVATE_KEY'),
    "client_email": os.environ.get('FIREBASE_CLIENT_EMAIL'),
    "client_id": os.environ.get('FIREBASE_CLIENT_ID'),
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": os.environ.get('FIREBASE_CLIENT_CERT_URL')
}

try:
    cred = credentials.Certificate(cred_dict)
    firebase_admin.initialize_app(cred, {
        'storageBucket': os.environ.get('FIREBASE_STORAGE_BUCKET')
    })
    logger.info("Firebase initialized successfully")
    
    # Initialize Firestore
    db = firestore.client()
    logger.info("Firestore client initialized successfully")
except Exception as e:
    logger.error(f"Error initializing Firebase: {e}")
    raise

# Initialize Whisper model (lazy loading)
model = None

def get_whisper_model():
    global model
    if model is None:
        try:
            model = whisper.load_model("base")
            logger.info("Whisper model loaded successfully")
        except Exception as e:
            logger.error(f"Error loading Whisper model: {e}")
            raise
    return model

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
            session.clear()
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

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
            data = request.get_json()
            if not data:
                return jsonify({'status': 'error', 'message': 'No data provided'}), 400
            
            email = data.get('email')
            password = data.get('password')
            firstname = data.get('firstname')
            
            if not all([email, password, firstname]):
                return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400

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

            # Create custom token
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
            data = request.get_json()
            if not data:
                return jsonify({'status': 'error', 'message': 'No data provided'}), 400
            
            email = data.get('email')
            password = data.get('password')
            
            if not all([email, password]):
                return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400

            # Get user by email
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
                'message': str(e)
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
        return jsonify({'status': 'error', 'message': str(e)}), 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_audio():
    try:
        # Verify authorization
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "No authorization token provided"}), 401
        
        token = auth_header.split(' ')[1]
        try:
            decoded_token = auth.verify_id_token(token)
            user_id = decoded_token['uid']
        except Exception as e:
            logger.error(f"Token verification error in upload: {e}")
            return jsonify({"error": "Invalid authorization token"}), 401

        # Check for file
        if 'audio_file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        audio_file = request.files['audio_file']
        if audio_file.filename == '':
            return jsonify({"error": "No file selected"}), 400

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

                # Get the Whisper model and transcribe
                model = get_whisper_model()
                result = model.transcribe(temp_wav.name)
                transcription = result['text']

                # Store transcription in Firestore
                doc_ref = db.collection('transcriptions').document()
                doc_ref.set({
                    'userId': user_id,
                    'transcription': transcription,
                    'timestamp': firestore.SERVER_TIMESTAMP,
                    'filename': audio_file.filename
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
                logger.error(f"Error processing audio: {e}")
                return jsonify({
                    "error": f"Error processing audio: {str(e)}",
                    "status": "error"
                }), 500
            finally:
                # Ensure temporary file is removed
                if os.path.exists(temp_wav.name):
                    os.unlink(temp_wav.name)

    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({
            "error": f"Upload error: {str(e)}",
            "status": "error"
        }), 500

@app.route('/health')
def health_check():
    try:
        # Check Firebase connection
        db.collection('users').limit(1).get()
        return jsonify({
            "status": "healthy",
            "firebase": "connected"
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            "status": "unhealthy",
            "error": str(e)
        }), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8000))
    app.run(host='0.0.0.0', port=port)
