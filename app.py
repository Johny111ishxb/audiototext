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

# Initialize Flask app
app = Flask(__name__, static_folder='static')
app.secret_key = secrets.token_hex(24)
CORS(app, supports_credentials=True)

# Initialize Firebase Admin SDK
cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred, {
    'storageBucket': 'imagetotext-4c3e3.appspot.com'
})

# Initialize Firestore
db = firestore.client()

# Initialize Whisper model
model = whisper.load_model("base")

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
            # For now, we'll just create a custom token
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

        temp_dir = f"temp_audio/{user_id}"
        os.makedirs(temp_dir, exist_ok=True)
        unique_filename = f"audio_{int(time.time())}"
        temp_path = os.path.join(temp_dir, unique_filename)
        
        audio_file.save(temp_path)
        
        try:
            if audio_file.filename.lower().endswith('.mp3'):
                audio = AudioSegment.from_mp3(temp_path)
                wav_path = f"{temp_path}.wav"
                audio.export(wav_path, format='wav')
            else:
                wav_path = temp_path

            result = model.transcribe(wav_path)
            transcription = result['text']

            if os.path.exists(temp_path):
                os.remove(temp_path)
            if os.path.exists(wav_path) and wav_path != temp_path:
                os.remove(wav_path)

            return jsonify({
                "transcription": transcription,
                "status": "success"
            })

        except Exception as e:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            if 'wav_path' in locals() and os.path.exists(wav_path):
                os.remove(wav_path)
            raise e

    except Exception as e:
        print(f"Error processing audio: {str(e)}")
        return jsonify({
            "error": f"Error processing audio: {str(e)}",
            "status": "error"
        }), 500

if __name__ == '__main__':
    print(f"Generated secret key: {app.secret_key}")
    app.run(host='0.0.0.0', port=8000, debug=True)