import os
import secrets
import time
import json
from pathlib import Path
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
from functools import wraps
import firebase_admin
from firebase_admin import credentials, auth, firestore
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
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(24))

# Configure session for production
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=86400,  # 24 hours
    SESSION_COOKIE_DOMAIN=os.environ.get('COOKIE_DOMAIN', None)  # Add this line
)

# Configure CORS with explicit origins
CORS(app, 
     supports_credentials=True,
     resources={
         r"/*": {
             "origins": os.environ.get('ALLOWED_ORIGINS', 'https://audiototext-production.up.railway.app').split(','),
             "methods": ["GET", "POST", "OPTIONS"],
             "allow_headers": ["Content-Type", "Authorization"],
             "expose_headers": ["Content-Type"],
             "supports_credentials": True
         }
     })

# Global variables
firebase_initialized = False
firebase_init_lock = Lock()

def load_firebase_credentials():
    """Load Firebase credentials with better error handling."""
    try:
        creds_json = os.environ.get('FIREBASE_CREDENTIALS')
        if creds_json:
            return json.loads(creds_json)
        
        logger.error("No Firebase credentials found in environment")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Invalid Firebase credentials JSON: {e}")
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
                db = firestore.client()
                db.collection('users').limit(1).get()  # Test connection
                
                logger.info("Firebase initialized successfully")
                firebase_initialized = True
                return True
                
        except Exception as e:
            logger.error(f"Firebase initialization error: {e}")
            return False

def check_auth():
    """Check if user is authenticated with detailed logging."""
    if 'user_token' not in session:
        logger.debug("No user token in session")
        return None
        
    try:
        decoded_token = auth.verify_id_token(session['user_token'])
        return decoded_token['uid']
    except auth.ExpiredIdTokenError:
        logger.warning("Token expired")
        session.clear()
        return None
    except auth.InvalidIdTokenError:
        logger.warning("Invalid token")
        session.clear()
        return None
    except Exception as e:
        logger.error(f"Auth verification error: {e}")
        session.clear()
        return None

def login_required(f):
    """Decorator to require authentication with better error handling."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not initialize_firebase():
            logger.error("Firebase initialization failed")
            return jsonify({'error': 'Service unavailable'}), 503
            
        user_id = check_auth()
        if not user_id:
            logger.warning("Authentication required")
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/auth/login', methods=['POST'])
def login_api():
    """Handle login with improved error handling and logging."""
    if not initialize_firebase():
        return jsonify({'error': 'Service unavailable'}), 503
        
    try:
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({'error': 'Email and password required'}), 400

        try:
            # Get user by email
            user = auth.get_user_by_email(data['email'])
            
            # Create custom token for client-side auth
            custom_token = auth.create_custom_token(user.uid)
            
            # Log successful login
            logger.info(f"Successful login for user: {user.email}")
            
            return jsonify({
                'status': 'success',
                'token': custom_token.decode(),
                'uid': user.uid
            })

        except auth.UserNotFoundError:
            logger.warning(f"Login attempt for non-existent user: {data.get('email')}")
            return jsonify({'error': 'Invalid email or password'}), 401
        except Exception as e:
            logger.error(f"Login error for user {data.get('email')}: {e}")
            return jsonify({'error': 'Authentication failed'}), 500

    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Authentication failed'}), 500

@app.route('/api/auth/verify-token', methods=['POST'])
def verify_token():
    """Verify and store Firebase ID token with improved validation."""
    if not initialize_firebase():
        return jsonify({'error': 'Service unavailable'}), 503
        
    try:
        data = request.get_json()
        if not data or 'token' not in data:
            return jsonify({'error': 'No token provided'}), 400
        
        # Verify the token
        decoded_token = auth.verify_id_token(data['token'])
        
        # Store in session
        session['user_token'] = data['token']
        session['user_id'] = decoded_token['uid']
        
        # Set session cookie options
        session.permanent = True
        
        return jsonify({
            'status': 'success',
            'uid': decoded_token['uid']
        })
    except auth.ExpiredIdTokenError:
        logger.warning("Expired token verification attempt")
        return jsonify({'error': 'Token expired'}), 401
    except auth.InvalidIdTokenError:
        logger.warning("Invalid token verification attempt")
        return jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        return jsonify({'error': 'Authentication failed'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    # Initialize Firebase on startup
    if not initialize_firebase():
        logger.error("Failed to initialize Firebase. Exiting.")
        exit(1)
    
    app.run(host='0.0.0.0', port=port, debug=debug)
