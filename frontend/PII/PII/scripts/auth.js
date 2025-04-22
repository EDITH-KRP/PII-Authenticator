// User Authentication Scripts
document.addEventListener('DOMContentLoaded', () => {
    // Initialize logger
    Logger.info('Auth page loaded');
    
    // Check if user is already logged in
    const currentUser = localStorage.getItem('currentUser');
    if (currentUser && window.location.pathname.includes('login.html')) {
        Logger.info('User already logged in, redirecting to dashboard');
        window.location.href = 'dashboard.html';
        return;
    }
    
    // Login Form Handler
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            Logger.info('Login form submitted');
            
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const remember = document.getElementById('remember')?.checked || false;
            
            try {
                // Show loading state
                const submitBtn = loginForm.querySelector('button[type="submit"]');
                const originalBtnText = submitBtn.textContent;
                submitBtn.disabled = true;
                submitBtn.textContent = 'Logging in...';
                
                // API URL
                const API_URL = 'http://127.0.0.1:5000';
                
                // Make API call to login
                const response = await fetch(`${API_URL}/login`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        email,
                        password
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    Logger.info('Login successful');
                    
                    // Store user data in localStorage
                    localStorage.setItem('currentUser', JSON.stringify({
                        id: data.user_id,
                        name: data.name,
                        email: data.email,
                        token: data.token
                    }));
                    
                    if (remember) {
                        localStorage.setItem('rememberMe', 'true');
                    } else {
                        localStorage.removeItem('rememberMe');
                    }
                    
                    // Redirect to dashboard
                    window.location.href = 'dashboard.html';
                } else {
                    Logger.error(`Login failed: ${data.error}`);
                    alert(data.error || 'Login failed. Please check your credentials and try again.');
                    
                    // Reset button state
                    submitBtn.disabled = false;
                    submitBtn.textContent = originalBtnText;
                }
            } catch (error) {
                Logger.error(`Login error: ${error.message}`);
                alert('An error occurred during login. Please try again.');
                
                // Reset button state
                submitBtn.disabled = false;
                submitBtn.textContent = originalBtnText;
            }
        });
    }
    
    // Signup Form Handler
    const signupForm = document.getElementById('signupForm');
    if (signupForm) {
        signupForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            Logger.info('Signup form submitted');
            
            const fullName = document.getElementById('fullName').value;
            const email = document.getElementById('email').value;
            const phone = document.getElementById('phone').value;
            const dob = document.getElementById('dob').value;
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            const terms = document.getElementById('terms').checked;
            
            // Validate form
            if (password !== confirmPassword) {
                alert('Passwords do not match');
                return;
            }
            
            if (!terms) {
                alert('You must agree to the Terms of Service and Privacy Policy');
                return;
            }
            
            try {
                // Show loading state
                const submitBtn = signupForm.querySelector('button[type="submit"]');
                const originalBtnText = submitBtn.textContent;
                submitBtn.disabled = true;
                submitBtn.textContent = 'Creating Account...';
                
                // API URL
                const API_URL = 'http://127.0.0.1:5000';
                
                // Make API call to register
                const response = await fetch(`${API_URL}/register`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        name: fullName,
                        email,
                        phone,
                        dob,
                        password
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    Logger.info('Signup successful');
                    
                    // Store user data in localStorage
                    localStorage.setItem('currentUser', JSON.stringify({
                        id: data.user_id,
                        name: data.name,
                        email: data.email,
                        token: data.token
                    }));
                    
                    // Redirect to dashboard page
                    window.location.href = 'dashboard.html';
                } else {
                    Logger.error(`Signup failed: ${data.error}`);
                    alert(data.error || 'Registration failed. Please try again.');
                    
                    // Reset button state
                    submitBtn.disabled = false;
                    submitBtn.textContent = originalBtnText;
                }
            } catch (error) {
                Logger.error(`Signup error: ${error.message}`);
                alert('An error occurred during registration. Please try again.');
                
                // Reset button state
                submitBtn.disabled = false;
                submitBtn.textContent = originalBtnText;
            }
        });
    }
    
    // Logout Handler
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', (e) => {
            e.preventDefault();
            Logger.info('User logged out');
            
            // Clear user data from localStorage
            localStorage.removeItem('currentUser');
            
            // Redirect to login page
            window.location.href = 'login.html';
        });
    }
});