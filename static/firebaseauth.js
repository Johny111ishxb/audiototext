// Import the necessary Firebase modules
import { initializeApp } from 'https://www.gstatic.com/firebasejs/9.23.0/firebase-app.js';
import { getAuth, createUserWithEmailAndPassword, signInWithEmailAndPassword, signInWithPopup, GoogleAuthProvider, onAuthStateChanged } from 'https://www.gstatic.com/firebasejs/9.23.0/firebase-auth.js';
import { getFirestore, doc, setDoc, getDoc } from 'https://www.gstatic.com/firebasejs/9.23.0/firebase-firestore.js';

// Firebase configuration
const firebaseConfig = {
    apiKey: "AIzaSyBk24eVfBQoPQ8Adiw9mA2sS_tpzwJ-ksk",
    authDomain: "imagetotext-4c3e3.firebaseapp.com",
    projectId: "imagetotext-4c3e3",
    storageBucket: "imagetotext-4c3e3.appspot.com",
    messagingSenderId: "643977043225",
    appId: "1:643977043225:web:9d648f58d7098a0c78f988",
    measurementId: "G-XRQFS9KGR0"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

// Function to display error messages
function displayErrorMessage(message) {
    const errorMessage = document.getElementById("error-message");
    if (errorMessage) {
        errorMessage.textContent = message;
        errorMessage.style.display = 'block';
        setTimeout(() => {
            errorMessage.style.display = 'none';
        }, 5000);
    }
}

// Function to display success messages
function displaySuccessMessage(message) {
    const successMessage = document.getElementById("success-message");
    if (successMessage) {
        successMessage.textContent = message;
        successMessage.style.display = 'block';
        setTimeout(() => {
            successMessage.style.display = 'none';
        }, 5000);
    }
}

// Function to verify token with backend
async function verifyTokenWithBackend(token) {
    try {
        const response = await fetch('/verify-token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ token: token }),
            credentials: 'include'
        });
        
        if (!response.ok) {
            throw new Error('Token verification failed');
        }
        
        return await response.json();
    } catch (error) {
        console.error('Token verification error:', error);
        throw error;
    }
}

// Handle successful authentication
async function handleAuthSuccess(user, isNewUser = false) {
    try {
        const token = await user.getIdToken();
        await verifyTokenWithBackend(token);
        
        if (isNewUser) {
            // For new users, ensure we have their data in Firestore
            const userDoc = await getDoc(doc(db, "users", user.uid));
            if (!userDoc.exists()) {
                await setDoc(doc(db, "users", user.uid), {
                    firstname: user.displayName || user.email.split('@')[0],
                    email: user.email,
                    createdAt: new Date().toISOString()
                });
            }
        }
        
        displaySuccessMessage("Authentication successful! Redirecting...");
        setTimeout(() => {
            window.location.href = '/';
        }, 1000);
    } catch (error) {
        console.error('Authentication error:', error);
        displayErrorMessage('Authentication failed. Please try again.');
    }
}

// Handle Google Authentication
async function handleGoogleAuth(isSignUp = false) {
    const provider = new GoogleAuthProvider();
    try {
        const result = await signInWithPopup(auth, provider);
        const user = result.user;
        
        // Check if this is a new user
        const isNewUser = result._tokenResponse.isNewUser;
        
        await handleAuthSuccess(user, isNewUser);
    } catch (error) {
        displayErrorMessage(`Google sign-${isSignUp ? 'up' : 'in'} failed: ${error.message}`);
    }
}

// Document ready event listeners
document.addEventListener('DOMContentLoaded', () => {
    // Handle signup link on login page
    const signupLink = document.querySelector('a[href="/signup"]');
    if (signupLink) {
        signupLink.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/signup';
        });
    }

    // Handle login form
    const loginForm = document.getElementById("loginForm");
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById("email").value;
            const password = document.getElementById("password").value;

            try {
                const userCredential = await signInWithEmailAndPassword(auth, email, password);
                await handleAuthSuccess(userCredential.user, false);
            } catch (error) {
                displayErrorMessage("Login failed: " + error.message);
            }
        });

        // Google Login handler
        const googleLoginButton = document.getElementById("google-login");
        if (googleLoginButton) {
            googleLoginButton.addEventListener('click', () => handleGoogleAuth(false));
        }
    }

    // Handle signup form
    const signUpForm = document.getElementById("signupForm");
    if (signUpForm) {
        signUpForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const firstname = document.getElementById("firstname-input").value;
            const email = document.getElementById("email-input").value;
            const password = document.getElementById("password-input").value;
            const repeatPassword = document.getElementById("repeat-password-input").value;

            if (password !== repeatPassword) {
                displayErrorMessage("Passwords do not match");
                return;
            }

            try {
                const userCredential = await createUserWithEmailAndPassword(auth, email, password);
                const user = userCredential.user;

                // Save user info to Firestore
                await setDoc(doc(db, "users", user.uid), {
                    firstname: firstname,
                    email: email,
                    createdAt: new Date().toISOString()
                });

                await handleAuthSuccess(user, true);
            } catch (error) {
                displayErrorMessage("Sign-up failed: " + error.message);
            }
        });

        // Google Sign-up handler
        const googleSignUpButton = document.getElementById("google-signup");
        if (googleSignUpButton) {
            googleSignUpButton.addEventListener('click', () => handleGoogleAuth(true));
        }
    }
});

// Logout handler
async function handleLogout() {
    try {
        await auth.signOut();
        // Clear session on backend
        await fetch('/logout', {
            method: 'GET',
            credentials: 'include'
        });
        window.location.href = '/login';
    } catch (error) {
        console.error('Logout error:', error);
        displayErrorMessage("Logout failed: " + error.message);
    }
}

// Authentication state observer
onAuthStateChanged(auth, async (user) => {
    const signUpButton = document.getElementById("sign-up-btn");
    const profilePic = document.getElementById("profile-pic");
    const profileName = document.getElementById("profile-name");
    const profileEmail = document.getElementById("profile-email");
    const logoutButton = document.getElementById("logout");
    
    if (user) {
        // User is signed in
        try {
            const token = await user.getIdToken();
            await verifyTokenWithBackend(token);
            
            if (signUpButton) signUpButton.style.display = "none";
            if (profilePic) {
                profilePic.style.display = "block";
                profilePic.src = user.photoURL || 'a.jpeg';
                profilePic.addEventListener('click', toggleDropdown);
            }
            
            if (profileName) profileName.textContent = user.displayName || user.email.split('@')[0];
            if (profileEmail) profileEmail.textContent = user.email;
            if (logoutButton) {
                logoutButton.addEventListener('click', (e) => {
                    e.preventDefault();
                    handleLogout();
                });
            }

            // Update UI for authenticated state
            document.querySelectorAll('.auth-required').forEach(elem => {
                elem.style.display = 'block';
            });
            document.querySelectorAll('.no-auth-required').forEach(elem => {
                elem.style.display = 'none';
            });

        } catch (error) {
            console.error('Token verification error:', error);
            await handleLogout();
        }
    } else {
        // User is signed out
        if (signUpButton) signUpButton.style.display = "block";
        if (profilePic) profilePic.style.display = "none";
        
        // Update UI for non-authenticated state
        document.querySelectorAll('.auth-required').forEach(elem => {
            elem.style.display = 'none';
        });
        document.querySelectorAll('.no-auth-required').forEach(elem => {
            elem.style.display = 'block';
        });

        // Redirect to login if on protected page
        const protectedPaths = ['/', '/index.html'];
        if (protectedPaths.includes(window.location.pathname)) {
            window.location.href = '/login';
        }
    }
});

// Dropdown toggle function
function toggleDropdown() {
    const dropdown = document.getElementById('profile-dropdown');
    if (dropdown) {
        dropdown.classList.toggle('show');
    }
}

// Close dropdown when clicking outside
window.addEventListener('click', (event) => {
    if (!event.target.matches('#profile-pic')) {
        const dropdowns = document.getElementsByClassName('profile-dropdown');
        Array.from(dropdowns).forEach(dropdown => {
            if (dropdown.classList.contains('show')) {
                dropdown.classList.remove('show');
            }
        });
    }
});

export { handleLogout };