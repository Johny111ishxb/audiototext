from flask import Flask, render_template, request, jsonify, send_from_directory, session, redirect, url_for
import os
import json
import secrets
import tempfile
from flask_cors import CORS
from functools import wraps
import firebase_admin
from firebase_admin import credentials, auth, storage, firestore
from pydub import AudioSegment
import whisper

# Initialize Flask app
app = Flask(__name__, static_folder='static')
app.secret_key = secrets.token_hex(24)
CORS(app, supports_credentials=True)

# Initialize Firebase Admin SDK from environment variable
firebase_credential_data = json.loads(os.environ['FIREBASE_SERVICE_ACCOUNT'])
cred = credentials.Certificate(firebase_credential_data)
firebase_admin.initialize_app(cred, {'storageBucket': 'imagetotext-4c3e3.appspot.com'})

# Initialize Firestore
db = firestore.client()

# Initialize Whisper model
model = whisper.load_model("base")

# Login required decorator
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

            # Verify user credentials (you'll need to implement this)
            user = auth.get_user_by_email(email)
            custom_token = auth.create_custom_token(user.uid)
            
            return jsonify({
                'status': 'success',
                'token': custom_token.decode()
            })

        except Exception as e:
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
        print(f"Token verification error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_audio():
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

        # Use a temporary file for audio processing
        with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as temp_audio_file:
            audio_file.save(temp_audio_file.name)
            wav_path = temp_audio_file.name

        # Convert if MP3, otherwise use as-is
        try:
            if audio_file.filename.lower().endswith('.mp3'):
                audio = AudioSegment.from_mp3(wav_path)
                with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as converted_file:
                    audio.export(converted_file.name, format='wav')
                    wav_path = converted_file.name

            result = model.transcribe(wav_path)
            transcription = result['text']

            # Clean up temporary files
            os.remove(wav_path)

            return jsonify({
                "transcription": transcription,
                "status": "success"
            })

        except Exception as e:
            if os.path.exists(wav_path):
                os.remove(wav_path)
            return jsonify({"error": f"Error processing audio: {str(e)}", "status": "error"}), 500

    except Exception as e:
        print(f"Error processing audio: {str(e)}")
        return jsonify({
            "error": f"Error processing audio: {str(e)}",
            "status": "error"
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8000)))
