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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(24))

# Configure CORS
CORS(app, supports_credentials=True)

# Global variables
firebase_initialized = False
firebase_init_lock = Lock()
whisper_model = None
whisper_model_lock = Lock()

def initialize_firebase():
    global firebase_initialized
    
    if firebase_initialized:
        return True
        
    with firebase_init_lock:
        if firebase_initialized:
            return True
            
        try:
            firebase_creds_str = os.environ.get('FIREBASE_CREDENTIALS')
            if not firebase_creds_str:
                logger.error("FIREBASE_CREDENTIALS environment variable is not set")
                return False
            
            try:
                cred_dict = json.loads(firebase_creds_str)
            except json.JSONDecodeError as e:
                logger.error(f"Error parsing Firebase credentials JSON: {e}")
                return False

            if not firebase_admin._apps:
                cred = credentials.Certificate(cred_dict)
                firebase_admin.initialize_app(cred, {
                    'storageBucket': f"{cred_dict.get('project_id')}.appspot.com"
                })
                logger.info("Firebase initialized successfully")
            
            firebase_initialized = True
            return True
            
        except Exception as e:
            logger.error(f"Error initializing Firebase: {e}")
            return False

def get_whisper_model():
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
            logger.error(f"Error loading Whisper model: {e}")
            return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not initialize_firebase():
            return jsonify({'error': 'Firebase initialization failed'}), 500
            
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

@app.route('/health')
def health_check():
    status = {
        "app": "running",
        "firebase_initialized": firebase_initialized,
        "whisper_model_loaded": whisper_model is not None
    }
    
    try:
        if initialize_firebase():
            # Quick Firebase test
            db = firestore.client()
            db.collection('health_check').limit(1).get()
            status["firebase_connection"] = "working"
        else:
            status["firebase_connection"] = "failed"
    except Exception as e:
        status["firebase_connection"] = f"error: {str(e)}"
    
    if all(v in [True, "working"] for v in status.values()):
        return jsonify(status), 200
    else:
        return jsonify(status), 503

@app.route('/upload', methods=['POST'])
@login_required
def upload_audio():
    if not initialize_firebase():
        return jsonify({"error": "Service unavailable"}), 503

    try:
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

                model = get_whisper_model()
                if model is None:
                    return jsonify({"error": "Failed to load transcription model"}), 503

                result = model.transcribe(temp_wav.name)
                transcription = result['text']

                # Store transcription in Firestore
                db = firestore.client()
                doc_ref = db.collection('transcriptions').document()
                doc_ref.set({
                    'userId': session['user_id'],
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
                if os.path.exists(temp_wav.name):
                    os.unlink(temp_wav.name)

    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({
            "error": f"Upload error: {str(e)}",
            "status": "error"
        }), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8000))
    initialize_firebase()  # Initialize Firebase on startup
    app.run(host='0.0.0.0', port=port)
