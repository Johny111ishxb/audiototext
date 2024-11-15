from flask import Flask, render_template, request, jsonify, send_from_directory, session, redirect, url_for
import time
from flask_cors import CORS
from functools import wraps
import os
import io
import json
import secrets
from werkzeug.utils import secure_filename
import firebase_admin
from firebase_admin import credentials, auth, storage, firestore
from pydub import AudioSegment
import whisper
import tempfile
from dotenv import load_dotenv

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

# Initialize Whisper model with error handling
try:
    model = whisper.load_model("base")  # Changed from "tiny" to "base"
except Exception as e:
    print(f"Error loading Whisper model: {e}")
    model = None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_token' not in session:
            return jsonify({'status': 'error', 'message': 'Not authenticated'}), 401
        try:
            decoded_token = auth.verify_id_token(session['user_token'])
            session['user_id'] = decoded_token['uid']
            session.modified = True  # Force session update
        except Exception as e:
            print(f"Auth error: {e}")
            session.clear()  # Clear invalid session
            return jsonify({'status': 'error', 'message': 'Authentication failed'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/upload', methods=['POST'])
@login_required
def upload_audio():
    if not model:
        return jsonify({"error": "Whisper model not initialized"}), 500

    try:
        # Get user ID from session instead of token
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({"error": "User not authenticated"}), 401

        if 'audio_file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        audio_file = request.files['audio_file']
        if audio_file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        # Create user-specific temporary directory
        temp_dir = f"temp_audio/{user_id}"
        os.makedirs(temp_dir, exist_ok=True)
        
        # Generate unique filename
        unique_filename = f"audio_{int(time.time())}_{secure_filename(audio_file.filename)}"
        temp_path = os.path.join(temp_dir, unique_filename)
        
        try:
            # Save uploaded file
            audio_file.save(temp_path)
            
            # Convert to WAV if MP3
            if audio_file.filename.lower().endswith('.mp3'):
                audio = AudioSegment.from_mp3(temp_path)
                wav_path = f"{temp_path}.wav"
                audio.export(wav_path, format='wav')
            else:
                wav_path = temp_path

            # Transcribe audio
            result = model.transcribe(wav_path)
            transcription = result['text']

            # Store transcription in Firestore
            doc_ref = db.collection('transcriptions').document()
            doc_ref.set({
                'user_id': user_id,
                'transcription': transcription,
                'timestamp': firestore.SERVER_TIMESTAMP,
                'filename': audio_file.filename
            })

            # Clean up temporary files
            if os.path.exists(temp_path):
                os.remove(temp_path)
            if os.path.exists(wav_path) and wav_path != temp_path:
                os.remove(wav_path)

            return jsonify({
                "transcription": transcription,
                "status": "success",
                "document_id": doc_ref.id
            })

        finally:
            # Ensure cleanup happens even if there's an error
            if os.path.exists(temp_path):
                os.remove(temp_path)
            if 'wav_path' in locals() and os.path.exists(wav_path) and wav_path != temp_path:
                os.remove(wav_path)

    except Exception as e:
        print(f"Error processing audio: {str(e)}")
        return jsonify({
            "error": "Error processing audio. Please try again.",
            "details": str(e),
            "status": "error"
        }), 500

# Modified login route to handle session properly
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

            # Get user and create custom token
            user = auth.get_user_by_email(email)
            id_token = auth.create_custom_token(user.uid)
            
            # Store token in session
            session['user_token'] = id_token.decode()
            session['user_id'] = user.uid
            session.modified = True  # Force session update
            
            return jsonify({
                'status': 'success',
                'token': id_token.decode(),
                'user': {
                    'uid': user.uid,
                    'email': user.email,
                    'displayName': user.display_name
                }
            })

        except Exception as e:
            print(f"Login error: {e}")
            return jsonify({
                'status': 'error',
                'message': 'Invalid credentials'
            }), 401

    return render_template('login.html')

# Modified session configuration
@app.before_request
def before_request():
    session.permanent = True  # Make session permanent
    app.permanent_session_lifetime = timedelta(days=5)  # Set session lifetime to 5 days
