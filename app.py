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

# Configure session for production
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=86400  # 24 hours
)

# Configure CORS with proper origins
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', 'https://audiototext-production.up.railway.app').split(',')
CORS(app, supports_credentials=True, resources={
    r"/*": {
        "origins": ALLOWED_ORIGINS,
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "expose_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

# Global variables
firebase_initialized = False
firebase_init_lock = Lock()

def load_firebase_credentials():
    """Load Firebase credentials from environment variable."""
    try:
        creds_json = os.environ.get('FIREBASE_CREDENTIALS')
        if creds_json:
            return json.loads(creds_json)
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
                firebase_admin.initialize_app(cred)
                
                # Verify Firebase connection
                auth.get_user_by_email("test@test.com")  # This will fail but verify connection
            except auth.UserNotFoundError:
                pass  # Expected error, connection is working
                
            logger.info("Firebase initialized successfully")
            firebase_initialized = True
            return True
                
        except Exception as e:
            logger.error(f"Firebase initialization error: {e}")
            return False

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
@app.route('/api/auth/signup', methods=['POST'])
def signup_api():
    """Handle signup API request"""
    if not initialize_firebase():
        return jsonify({'error': 'Service unavailable'}), 503
        
    try:
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({'error': 'Email and password required'}), 400

        try:
            # Create user in Firebase
            user = auth.create_user(
                email=data['email'],
                password=data['password'],
                display_name=data.get('displayName', '')
            )

            # Create user document in Firestore
            db = firestore.client()
            db.collection('users').document(user.uid).set({
                'email': data['email'],
                'displayName': data.get('displayName', ''),
                'createdAt': firestore.SERVER_TIMESTAMP
            })

            # Generate ID token for the new user
            custom_token = auth.create_custom_token(user.uid)
            
            return jsonify({
                'status': 'success',
                'uid': user.uid,
                'email': user.email,
                'displayName': user.display_name,
                'customToken': custom_token.decode()
            })

        except auth.EmailAlreadyExistsError:
            return jsonify({'error': 'Email already exists'}), 409
        except Exception as e:
            logger.error(f"User creation error: {e}")
            return jsonify({'error': 'Failed to create user'}), 500

    except Exception as e:
        logger.error(f"Signup error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login_api():
    """Handle login API request"""
    if not initialize_firebase():
        return jsonify({'error': 'Service unavailable'}), 503
        
    try:
        data = request.get_json()
        if not data or 'idToken' not in data:
            return jsonify({'error': 'ID token required'}), 400

        try:
            # Verify the ID token
            decoded_token = auth.verify_id_token(data['idToken'])
            
            # Store the token in session
            session['user_token'] = data['idToken']
            session['user_id'] = decoded_token['uid']
            
            return jsonify({
                'status': 'success',
                'uid': decoded_token['uid']
            })

        except auth.InvalidIdTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        except Exception as e:
            logger.error(f"Login error: {e}")
            return jsonify({'error': 'Authentication failed'}), 500

    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Authentication failed'}), 500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Clear session data."""
    session.clear()
    return jsonify({'status': 'success'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    # Initialize Firebase on startup
    initialize_firebase()
    
    app.run(host='0.0.0.0', port=port, debug=debug)
