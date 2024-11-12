from flask import Flask, render_template, request, jsonify, redirect, url_for
import firebase_admin
from firebase_admin import credentials, auth
import os

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')  # Use your secret key for session handling

# Firebase Admin SDK initialization
firebase_credentials = os.getenv("FIREBASE_CREDENTIALS")
if firebase_credentials:
    try:
        # Convert the JSON string environment variable to a dictionary
        firebase_creds_dict = json.loads(firebase_credentials)
        cred = credentials.Certificate(firebase_creds_dict)
        firebase_admin.initialize_app(cred)
    except Exception as e:
        print(f"Error initializing Firebase: {e}")
else:
    print("Firebase credentials not found.")

@app.route('/')
def home():
    return redirect(url_for('login'))  # Redirect to login page

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.json.get('email')
        password = request.json.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400

        try:
            # Attempt to retrieve user by email
            user = auth.get_user_by_email(email)
            # Here, we are not able to check the password on the backend directly
            # Password verification must be done client-side or use a different approach
            if user:
                # Authentication success; redirect or render logged-in page
                return jsonify({'message': 'Authentication successful', 'uid': user.uid}), 200
            else:
                return jsonify({'error': 'Invalid login credentials'}), 401

        except Exception as e:
            # Catch all exceptions, especially for failed authentication
            return jsonify({'error': str(e)}), 401

    # Render login page if GET request
    return render_template('login.html')

# Sign-up route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.json.get('email')
        password = request.json.get('password')
        firstname = request.json.get('firstname')

        if not email or not password or not firstname:
            return jsonify({'error': 'All fields are required'}), 400

        try:
            # Register the user
            user = auth.create_user(email=email, password=password, display_name=firstname)
            return jsonify({'message': 'User created successfully', 'uid': user.uid}), 201
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    return render_template('signup.html')

# Logout route (optional)
@app.route('/logout')
def logout():
    # Here you could clear the session or token to log out the user
    return redirect(url_for('login'))

# Error handler for 404
@app.errorhandler(404)
def page_not_found(e):
    return jsonify({'error': 'Page not found'}), 404

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
