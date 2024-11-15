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
logger = logging.getLogger(__name__)

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
