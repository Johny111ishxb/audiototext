// firebaseauth.js
import { initializeApp } from 'https://www.gstatic.com/firebasejs/9.23.0/firebase-app.js';
import { 
    getAuth, 
    createUserWithEmailAndPassword, 
    signInWithEmailAndPassword, 
    signInWithPopup, 
    GoogleAuthProvider, 
    onAuthStateChanged,
    signOut
} from 'https://www.gstatic.com/firebasejs/9.23.0/firebase-auth.js';
import { 
    getFirestore, 
    doc, 
    setDoc, 
    getDoc 
} from 'https://www.gstatic.com/firebasejs/9.23.0/firebase-firestore.js';

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
const googleProvider = new GoogleAuthProvider();

// UI Helper Functions
function displayErrorMessage(message, duration = 5000) {
    const errorMessage = document.getElementById("error-message");
    if (errorMessage) {
        errorMessage.textContent = message;
        errorMessage.style.display = 'block';
        setTimeout(() => {
            errorMessage.style.display = 'none';
        }, duration);
    } else {
        console.error('Error:', message);
    }
}

function displaySuccessMessage(message, duration = 3000) {
    const successMessage = document.getElementById("success-message");
    if (successMessage) {
        successMessage.textContent = message;
        successMessage.style.display = 'block';
        setTimeout(() => {
            successMessage.style.display = 'none';
        }, duration);
    }
}

function showLoading() {
    const loadingElement = document.getElementById('loading-spinner');
    if (loadingElement) {
        loadingElement.style.display = 'block';
    }
}

function hideLoading() {
    const loadingElement = document.getElementById('loading-spinner');
    if (loadingElement) {
        loadingElement.style.display = 'none';
    }
}

// Authentication Helper Functions
function getAuthErrorMessage(errorCode) {
    const errorMessages = {
        'auth/email-already-in-use': 'An account with this email already exists.',
        'auth/invalid-email': 'Invalid email address format.',
        'auth/operation-not-allowed': 'Email/password accounts are not enabled. Please contact support.',
        'auth/weak-password': 'Password is too weak. Please use at least 6 characters.',
        'auth/user-disabled': 'This account has been disabled.',
        'auth/user-not-found': 'No account found with this email.',
        'auth/wrong-password': 'Incorrect password.',
        'auth/network-request-failed': 'Network error. Please check your connection.',
        'auth/too-many-requests': 'Too many attempts. Please try again later.',
        'auth/popup-closed-by-user': 'Google sign-in was cancelled.',
        'auth/cancelled-popup-request': 'Only one popup request allowed at a time.',
        'auth/popup-blocked': 'The sign-in popup was blocked by your browser.',
        'auth/requires-recent-login': 'Please sign in again to continue.',
        'default': 'Authentication failed. Please try again.'
    };
    return errorMessages[errorCode] || errorMessages.default;
}

// API Functions
async function verifyTokenWithBackend(token) {
    try {
        showLoading();
        const response = await fetch('/api/auth/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ token: token }),
            credentials: 'include'
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Token verification failed');
        }
        
        return await response.json();
    } catch (error) {
        console.error('Token verification error:', error);
        throw error;
    } finally {
        hideLoading();
    }
}

// Authentication Functions
async function handleAuthSuccess(user, isNewUser = false) {
    try {
        showLoading();
        // Force refresh the token to ensure we have the most recent one
        const token = await user.getIdToken(true);
        await verifyTokenWithBackend(token);
        
        if (isNewUser) {
            // Create or update user document in Firestore
            await setDoc(doc(db, "users", user.uid), {
                firstname: user.displayName || user.email.split('@')[0],
                email: user.email,
                createdAt: new Date().toISOString(),
                lastLogin: new Date().toISOString(),
                photoURL: user.photoURL || null
            }, { merge: true });
        } else {
            // Update last login time
            await setDoc(doc(db, "users", user.uid), {
                lastLogin: new Date().toISOString()
            }, { merge: true });
        }
        
        displaySuccessMessage("Authentication successful! Redirecting...");
        // Add a small delay to ensure token is properly stored
        await new Promise(resolve => setTimeout(resolve, 1000));
        window.location.href = '/';
    } catch (error) {
        console.error('Authentication error:', error);
        displayErrorMessage('Authentication failed. Please try again.');
        // Force logout on auth failure
        await handleLogout();
    } finally {
        hideLoading();
    }
}

async function handleEmailSignIn(email, password) {
    try {
        showLoading();
        const userCredential = await signInWithEmailAndPassword(auth, email, password);
        await handleAuthSuccess(userCredential.user, false);
    } catch (error) {
        console.error('Login error:', error);
        displayErrorMessage(getAuthErrorMessage(error.code));
    } finally {
        hideLoading();
    }
}

async function handleEmailSignUp(email, password, firstname) {
    try {
        showLoading();
        const userCredential = await createUserWithEmailAndPassword(auth, email, password);
        const user = userCredential.user;
        
        // Additional user data
        await setDoc(doc(db, "users", user.uid), {
            firstname: firstname,
            email: email,
            createdAt: new Date().toISOString(),
            lastLogin: new Date().toISOString()
        });
        
        await handleAuthSuccess(user, true);
    } catch (error) {
        console.error('Signup error:', error);
        displayErrorMessage(getAuthErrorMessage(error.code));
    } finally {
        hideLoading();
    }
}

async function handleGoogleAuth(isSignUp = false) {
    try {
        showLoading();
        const result = await signInWithPopup(auth, googleProvider);
        const user = result.user;
        const isNewUser = result._tokenResponse.isNewUser;
        
        await handleAuthSuccess(user, isNewUser);
    } catch (error) {
        console.error('Google auth error:', error);
        displayErrorMessage(getAuthErrorMessage(error.code));
    } finally {
        hideLoading();
    }
}

async function handleLogout() {
    try {
        showLoading();
        await signOut(auth);
        // Clear session on backend
        await fetch('/api/auth/logout', {
            method: 'POST',
            credentials: 'include'
        });
        window.location.href = '/login';
    } catch (error) {
        console.error('Logout error:', error);
        displayErrorMessage("Logout failed: " + error.message);
    } finally {
        hideLoading();
    }
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    // Login Form Handler
    const loginForm = document.getElementById("loginForm");
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById("email").value;
            const password = document.getElementById("password").value;
            await handleEmailSignIn(email, password);
        });

        // Google Login Button
        const googleLoginButton = document.getElementById("google-login");
        if (googleLoginButton) {
            googleLoginButton.addEventListener('click', () => handleGoogleAuth(false));
        }
    }

    // Signup Form Handler
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

            await handleEmailSignUp(email, password, firstname);
        });

        // Google Sign-up Button
        const googleSignUpButton = document.getElementById("google-signup");
        if (googleSignUpButton) {
            googleSignUpButton.addEventListener('click', () => handleGoogleAuth(true));
        }
    }

    // Logout Button
    const logoutButton = document.getElementById("logout");
    if (logoutButton) {
        logoutButton.addEventListener('click', async (e) => {
            e.preventDefault();
            await handleLogout();
        });
    }
});

// Authentication State Observer
onAuthStateChanged(auth, async (user) => {
    const signUpButton = document.getElementById("sign-up-btn");
    const profilePic = document.getElementById("profile-pic");
    const profileName = document.getElementById("profile-name");
    const profileEmail = document.getElementById("profile-email");
    const authElements = document.querySelectorAll('.auth-required');
    const noAuthElements = document.querySelectorAll('.no-auth-required');
    
    if (user) {
        try {
            // User is signed in
            const token = await user.getIdToken();
            await verifyTokenWithBackend(token);
            
            // Update UI elements
            if (signUpButton) signUpButton.style.display = "none";
            if (profilePic) {
                profilePic.style.display = "block";
                profilePic.src = user.photoURL || '/static/images/default-avatar.png';
                profilePic.addEventListener('click', toggleDropdown);
            }
            if (profileName) profileName.textContent = user.displayName || user.email.split('@')[0];
            if (profileEmail) profileEmail.textContent = user.email;
            
            // Show/hide authenticated elements
            authElements.forEach(elem => elem.style.display = 'block');
            noAuthElements.forEach(elem => elem.style.display = 'none');
            
        } catch (error) {
            console.error('Token verification error:', error);
            await handleLogout();
        }
    } else {
        // User is signed out
        if (signUpButton) signUpButton.style.display = "block";
        if (profilePic) profilePic.style.display = "none";
        
        // Show/hide non-authenticated elements
        authElements.forEach(elem => elem.style.display = 'none');
        noAuthElements.forEach(elem => elem.style.display = 'block');
        
        // Redirect to login if on protected page
        const protectedPaths = ['/', '/index.html'];
        if (protectedPaths.includes(window.location.pathname)) {
            window.location.href = '/login';
        }
    }
});

// UI Utilities
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

// Export necessary functions
export {
    handleLogout,
    handleEmailSignIn,
    handleEmailSignUp,
    handleGoogleAuth,
    auth
};
