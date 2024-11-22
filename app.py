import os
import io
import json
import secrets
import tempfile
from functools import wraps

from flask import Flask, render_template, request, jsonify, send_from_directory, session, redirect, url_for
from flask_cors import CORS
from dotenv import load_dotenv
from werkzeug.utils import secure_filename 

import firebase_admin
from firebase_admin import credentials, auth, firestore, storage

import torch
import whisper
from pydub import AudioSegment

# Minimize memory usage
torch.set_num_threads(1)
torch.set_float32_matmul_precision('high')

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__, static_folder='static')
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(16))
CORS(app, supports_credentials=True)

# Firebase initialization
if os.getenv('FIREBASE_CREDENTIALS'):
    cred_dict = json.loads(os.getenv('FIREBASE_CREDENTIALS'))
    cred = credentials.Certificate(cred_dict)
else:
    cred = credentials.Certificate("serviceAccountKey.json")

firebase_admin.initialize_app(cred, {
    'storageBucket': os.getenv('FIREBASE_STORAGE_BUCKET', 'default-bucket')
})

# Initialize Firestore
db = firestore.client()

# Lazy load Whisper model with memory optimization
def load_whisper_model():
    try:
        return whisper.load_model("tiny", device="cpu")
    except Exception as e:
        print(f"Whisper model load error: {e}")
        return None

model = None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_token' not in session:
            return redirect(url_for('login'))
        try:
            decoded_token = auth.verify_id_token(session['user_token'])
            session['user_id'] = decoded_token['uid']
        except Exception as e:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def index():
    return render_template('index.html')

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

            # Create custom token
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

            # Get user and create custom token
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
        print(f"Token verification error: {e}")
        return jsonify({'status': 'error', 'message': 'Invalid token'}), 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_audio():
    global model
    if not model:
        model = load_whisper_model()
    
    if not model:
        return jsonify({"error": "Whisper model not initialized"}), 500

    try:
        # Token verification
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "No authorization token"}), 401
        
        token = auth_header.split(' ')[1]
        try:
            decoded_token = auth.verify_id_token(token)
            user_id = decoded_token['uid']
        except Exception as e:
            return jsonify({"error": "Invalid token"}), 401

        if 'audio_file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        audio_file = request.files['audio_file']
        if audio_file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        # Use context manager for temp files
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = os.path.join(temp_dir, secure_filename(audio_file.filename))
            audio_file.save(input_path)
            
            wav_path = input_path
            if input_path.lower().endswith('.mp3'):
                try:
                    audio = AudioSegment.from_mp3(input_path)
                    wav_path = os.path.join(temp_dir, "converted.wav")
                    audio.export(wav_path, format='wav')
                except Exception as e:
                    return jsonify({"error": f"Audio conversion error: {str(e)}"}), 500

            try:
                # Perform transcription with minimal memory overhead
                result = model.transcribe(wav_path, fp16=False)
                transcription = result['text']

                # Store transcription
                doc_ref = db.collection('transcriptions').document()
                doc_ref.set({
                    'user_id': user_id,
                    'transcription': transcription,
                    'timestamp': firestore.SERVER_TIMESTAMP,
                    'filename': audio_file.filename
                })

                return jsonify({
                    "transcription": transcription,
                    "status": "success",
                    "document_id": doc_ref.id
                })

            except Exception as e:
                return jsonify({
                    "error": f"Transcription failed: {str(e)}",
                    "status": "error"
                }), 500

    except Exception as e:
        return jsonify({
            "error": f"Processing error: {str(e)}",
            "status": "error"
        }), 500

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8000))
    app.run(host='0.0.0.0', port=port)
