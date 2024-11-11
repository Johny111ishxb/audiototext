// firebaseauth.js
import { initializeApp } from 'https://www.gstatic.com/firebasejs/9.23.0/firebase-app.js';
import { 
    getAuth, 
    createUserWithEmailAndPassword, 
    signInWithEmailAndPassword, 
    signInWithPopup, 
    GoogleAuthProvider, 
    onAuthStateChanged,
    setPersistence,
    browserLocalPersistence
} from 'https://www.gstatic.com/firebasejs/9.23.0/firebase-auth.js';
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

// Set persistence to LOCAL
setPersistence(auth, browserLocalPersistence).catch((error) => {
    console.error("Persistence error:", error);
});

// Error message display function
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

// Success message display function
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

// Token verification with backend
async function verifyTokenWithBackend(token) {
    try {
        const response = await fetch('/verify-token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            credentials: 'include',
            body: JSON.stringify({ token })
        });
        
        if (!response.ok) {
            throw new Error(`Token verification failed: ${response.statusText}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('Token verification error:', error);
        throw error;
    }
}

// Authentication success handler
async function handleAuthSuccess(user, isNewUser = false) {
    try {
        const token = await user.getIdToken(true);
        
        // Verify token with backend
        await verifyTokenWithBackend(token);
        
        if (isNewUser) {
            // Save new user data to Firestore
            await setDoc(doc(db, "users", user.uid), {
                firstname: user.displayName || user.email.split('@')[0],
                email: user.email,
                createdAt: new Date().toISOString()
            });
        }
        
        displaySuccessMessage("Authentication successful! Redirecting...");
        
        // Set a small delay before redirect
        setTimeout(() => {
            window.location.href = '/';
        }, 1500);
    } catch (error) {
        console.error('Authentication error:', error);
        displayErrorMessage(`Authentication failed: ${error.message}`);
        await auth.signOut();
    }
}

// Google Authentication handler
async function handleGoogleAuth(isSignUp = false) {
    const provider = new GoogleAuthProvider();
    provider.setCustomParameters({
        prompt: 'select_account'
    });
    
    try {
        const result = await signInWithPopup(auth, provider);
        const isNewUser = result._tokenResponse.isNewUser;
        await handleAuthSuccess(result.user, isNewUser);
    } catch (error) {
        displayErrorMessage(`Google sign-${isSignUp ? 'up' : 'in'} failed: ${error.message}`);
    }
}

// Document ready event listeners
document.addEventListener('DOMContentLoaded', () => {
    // Login form handler
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
                let errorMessage = "Login failed: ";
                switch (error.code) {
                    case 'auth/wrong-password':
                        errorMessage += "Invalid password. Please try again.";
                        break;
                    case 'auth/user-not-found':
                        errorMessage += "No account found with this email.";
                        break;
                    case 'auth/invalid-email':
                        errorMessage += "Invalid email format.";
                        break;
                    default:
                        errorMessage += error.message;
                }
                displayErrorMessage(errorMessage);
            }
        });

        // Google Login button
        const googleLoginButton = document.getElementById("google-login");
        if (googleLoginButton) {
            googleLoginButton.addEventListener('click', () => handleGoogleAuth(false));
        }
    }

    // Signup form handler
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
                await setDoc(doc(db, "users", userCredential.user.uid), {
                    firstname,
                    email,
                    createdAt: new Date().toISOString()
                });
                await handleAuthSuccess(userCredential.user, true);
            } catch (error) {
                let errorMessage = "Sign-up failed: ";
                switch (error.code) {
                    case 'auth/email-already-in-use':
                        errorMessage += "This email is already registered.";
                        break;
                    case 'auth/weak-password':
                        errorMessage += "Password should be at least 6 characters.";
                        break;
                    default:
                        errorMessage += error.message;
                }
                displayErrorMessage(errorMessage);
            }
        });

        // Google Signup button
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
        await fetch('/logout', {
            method: 'POST',
            credentials: 'include'
        });
        window.location.href = '/login';
    } catch (error) {
        console.error('Logout error:', error);
        displayErrorMessage("Logout failed: " + error.message);
    }
}

// Auth state observer
onAuthStateChanged(auth, async (user) => {
    if (user) {
        try {
            const token = await user.getIdToken(true);
            await verifyTokenWithBackend(token);
            
            // Update UI elements for authenticated state
            document.querySelectorAll('.auth-required').forEach(elem => {
                elem.style.display = 'block';
            });
            document.querySelectorAll('.no-auth-required').forEach(elem => {
                elem.style.display = 'none';
            });
        } catch (error) {
            console.error('Auth state error:', error);
            await handleLogout();
        }
    } else {
        // Update UI elements for non-authenticated state
        document.querySelectorAll('.auth-required').forEach(elem => {
            elem.style.display = 'none';
        });
        document.querySelectorAll('.no-auth-required').forEach(elem => {
            elem.style.display = 'block';
        });

        // Redirect if on protected page
        const protectedPaths = ['/', '/index.html'];
        if (protectedPaths.includes(window.location.pathname)) {
            window.location.href = '/login';
        }
    }
});

export { handleLogout };
