# app.py
from flask import Flask, request, jsonify, session, render_template
from functools import wraps
import firebase_admin
from firebase_admin import credentials, auth
import json
from flask_cors import CORS
import os

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default-secret-key')

# Enable CORS
CORS(app, supports_credentials=True, resources={
    r"/*": {
        "origins": os.getenv('ALLOWED_ORIGINS', 'http://localhost:5000').split(','),
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

# Initialize Firebase Admin
try:
    firebase_credentials = json.loads(os.getenv('FIREBASE_CREDENTIALS'))
    cred = credentials.Certificate(firebase_credentials)
    firebase_admin.initialize_app(cred)
except Exception as e:
    print(f"Firebase initialization error: {e}")
    # Create a more detailed error message
    error_details = {
        'error': str(e),
        'credentials_type': type(firebase_credentials).__name__ if 'firebase_credentials' in locals() else 'Not defined',
        'env_var_exists': 'FIREBASE_CREDENTIALS' in os.environ
    }
    print(f"Error details: {error_details}")
    raise

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'No token provided'}), 401
        
        token = auth_header.split('Bearer ')[1]
        try:
            decoded_token = auth.verify_id_token(token)
            request.user = decoded_token
            return f(*args, **kwargs)
        except Exception as e:
            print(f"Token verification error: {e}")
            return jsonify({'error': 'Invalid token'}), 401
            
    return decorated_function

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/verify-token', methods=['POST'])
def verify_token():
    try:
        # Get token from request
        data = request.get_json()
        if not data or 'token' not in data:
            return jsonify({'error': 'No token provided'}), 400
        
        token = data['token']
        
        # Verify the Firebase token
        decoded_token = auth.verify_id_token(token)
        
        # Create session
        session['user_id'] = decoded_token['uid']
        
        # Return success response
        return jsonify({
            'success': True,
            'uid': decoded_token['uid'],
            'email': decoded_token.get('email', ''),
        })
    except auth.InvalidIdTokenError:
        return jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        print(f"Token verification error: {str(e)}")
        return jsonify({'error': f'Token verification failed: {str(e)}'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.getenv('PORT', 8000)))
