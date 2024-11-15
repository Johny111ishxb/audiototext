from flask import Flask, render_template, request, jsonify, send_from_directory, session, redirect, url_for
import os
import json
import secrets
import tempfile
import logging
from flask_cors import CORS
from functools import wraps
import firebase_admin
from firebase_admin import credentials, auth, storage, firestore
from pydub import AudioSegment
import whisper

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)a# main.py
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
    model = whisper.load_model("base")
except Exception as e:
    print(f"Error loading Whisper model: {e}")
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
            print(f"Auth error: {e}")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/health')
def health_check():
    return jsonify({"status": "healthy"}), 200

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
    if not model:
        return jsonify({"error": "Whisper model not initialized"}), 500

    try:
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

        # Create temporary directory using tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = os.path.join(temp_dir, secure_filename(audio_file.filename))
            audio_file.save(temp_path)
            
            try:
                if audio_file.filename.lower().endswith('.mp3'):
                    audio = AudioSegment.from_mp3(temp_path)
                    wav_path = os.path.join(temp_dir, "converted.wav")
                    audio.export(wav_path, format='wav')
                else:
                    wav_path = temp_path

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

                return jsonify({
                    "transcription": transcription,
                    "status": "success",
                    "document_id": doc_ref.id
                })

            except Exception as e:
                print(f"Transcription error: {e}")
                return jsonify({
                    "error": "Error processing audio file",
                    "status": "error"
                }), 500

    except Exception as e:
        print(f"Error processing audio: {str(e)}")
        return jsonify({
            "error": f"Error processing audio: {str(e)}",
            "status": "error"
        }), 500

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

# Initialize Flask app
app = Flask(__name__, static_folder='static')
app.secret_key = secrets.token_hex(24)
# Increase session lifetime
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=5)
CORS(app, supports_credentials=True)

# Initialize Firebase Admin SDK from environment variable
firebase_credential_data = json.loads(os.environ['FIREBASE_SERVICE_ACCOUNT'])
cred = credentials.Certificate(firebase_credential_data)
firebase_admin.initialize_app(cred, {'storageBucket': 'imagetotext-4c3e3.appspot.com'})

# Initialize Firestore
db = firestore.client()

# Initialize Whisper model
model = whisper.load_model("tiny")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_token' not in session:
            logger.warning("No user_token in session")
            return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
        
        try:
            decoded_token = auth.verify_id_token(session['user_token'])
            session['user_id'] = decoded_token['uid']
            # Make session permanent
            session.permanent = True
        except Exception as e:
            logger.error(f"Auth error: {e}")
            session.clear()
            return jsonify({'status': 'error', 'message': 'Invalid or expired token'}), 401
            
        return f(*args, **kwargs)
    return decorated_function

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

            # Create ID token
            custom_token = auth.create_custom_token(user.uid)
            
            # Set session data
            session['user_token'] = custom_token.decode()
            session['user_id'] = user.uid
            session.permanent = True

            return jsonify({
                'status': 'success',
                'message': 'User created successfully',
                'token': custom_token.decode(),
                'user': {
                    'uid': user.uid,
                    'email': email,
                    'firstname': firstname
                }
            })

        except Exception as e:
            logger.error(f"Signup error: {e}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 400

    return render_template('signup.html')

@app.route('/upload', methods=['POST'])
@login_required
def upload_audio():
    try:
        if 'audio_file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        audio_file = request.files['audio_file']
        if audio_file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        # Create temp directory if it doesn't exist
        temp_dir = tempfile.mkdtemp()
        
        try:
            # Save uploaded file
            temp_input_path = os.path.join(temp_dir, "input_audio")
            audio_file.save(temp_input_path)
            
            # Convert audio if needed
            temp_wav_path = os.path.join(temp_dir, "converted.wav")
            
            try:
                if audio_file.filename.lower().endswith('.mp3'):
                    logger.debug("Converting MP3 to WAV")
                    audio = AudioSegment.from_mp3(temp_input_path)
                    audio.export(temp_wav_path, format='wav')
                else:
                    # Copy the file if it's already WAV
                    logger.debug("Using original WAV file")
                    os.rename(temp_input_path, temp_wav_path)

                logger.debug("Starting transcription")
                result = model.transcribe(temp_wav_path)
                transcription = result['text']
                
                logger.debug(f"Transcription successful: {transcription[:50]}...")
                
                return jsonify({
                    "transcription": transcription,
                    "status": "success"
                })

            except Exception as e:
                logger.error(f"Error during audio processing: {str(e)}")
                return jsonify({
                    "error": f"Error processing audio: {str(e)}",
                    "status": "error"
                }), 500

        finally:
            # Clean up temporary files
            try:
                import shutil
                shutil.rmtree(temp_dir)
            except Exception as e:
                logger.error(f"Error cleaning up temp files: {e}")

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return jsonify({
            "error": "An unexpected error occurred",
            "status": "error"
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8000)))
