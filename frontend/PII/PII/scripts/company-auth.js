// Company Authentication Scripts
document.addEventListener('DOMContentLoaded', () => {
    // Initialize logger
    Logger.info('Company Auth page loaded');
    
    // Check if company is already logged in
    const currentCompany = localStorage.getItem('currentCompany');
    if (currentCompany && window.location.pathname.includes('login.html')) {
        Logger.info('Company already logged in, redirecting to dashboard');
        window.location.href = 'dashboard.html';
        return;
    }
    
    // Login Form Handler
    const companyLoginForm = document.getElementById('companyLoginForm');
    if (companyLoginForm) {
        companyLoginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            Logger.info('Company login form submitted');
            
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const remember = document.getElementById('remember')?.checked || false;
            
            try {
                // Show loading state
                const submitBtn = companyLoginForm.querySelector('button[type="submit"]');
                const originalBtnText = submitBtn.textContent;
                submitBtn.disabled = true;
                submitBtn.textContent = 'Logging in...';
                
                // API URL
                const API_URL = 'http://127.0.0.1:5000';
                
                // Make API call to login
                const response = await fetch(`${API_URL}/company/login`, {
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
                    Logger.info('Company login successful');
                    
                    // Store company data in localStorage
                    localStorage.setItem('currentCompany', JSON.stringify({
                        id: data.company_id,
                        name: data.company_name,
                        email: data.email,
                        token: data.token,
                        businessType: data.business_type
                    }));
                    
                    if (remember) {
                        localStorage.setItem('rememberCompany', 'true');
                    } else {
                        localStorage.removeItem('rememberCompany');
                    }
                    
                    // Redirect to dashboard
                    window.location.href = 'dashboard.html';
                } else {
                    Logger.error(`Company login failed: ${data.error}`);
                    alert(data.error || 'Login failed. Please check your credentials and try again.');
                    
                    // Reset button state
                    submitBtn.disabled = false;
                    submitBtn.textContent = originalBtnText;
                }
            } catch (error) {
                Logger.error(`Company login error: ${error.message}`);
                alert('An error occurred during login. Please try again.');
                
                // Reset button state
                submitBtn.disabled = false;
                submitBtn.textContent = originalBtnText;
            }
        });
    }
    
    // Signup Form Handler
    const companySignupForm = document.getElementById('companySignupForm');
    if (companySignupForm) {
        companySignupForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            Logger.info('Company signup form submitted');
            
            const companyName = document.getElementById('companyName').value;
            const businessType = document.getElementById('businessType').value;
            const registrationNumber = document.getElementById('registrationNumber').value;
            const email = document.getElementById('email').value;
            const phone = document.getElementById('phone').value;
            const address = document.getElementById('address').value;
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
                const submitBtn = companySignupForm.querySelector('button[type="submit"]');
                const originalBtnText = submitBtn.textContent;
                submitBtn.disabled = true;
                submitBtn.textContent = 'Registering Company...';
                
                // API URL
                const API_URL = 'http://127.0.0.1:5000';
                
                // Make API call to register company
                const response = await fetch(`${API_URL}/company/register`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        company_name: companyName,
                        business_type: businessType,
                        registration_number: registrationNumber,
                        email,
                        phone,
                        address,
                        password
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    Logger.info('Company signup successful');
                    
                    // Store company data in localStorage
                    localStorage.setItem('currentCompany', JSON.stringify({
                        id: data.company_id,
                        name: data.company_name,
                        email: data.email,
                        token: data.token,
                        businessType: data.business_type
                    }));
                    
                    // Redirect to company dashboard
                    window.location.href = 'dashboard.html';
                } else {
                    Logger.error(`Company signup failed: ${data.error}`);
                    alert(data.error || 'Registration failed. Please try again.');
                    
                    // Reset button state
                    submitBtn.disabled = false;
                    submitBtn.textContent = originalBtnText;
                }
            } catch (error) {
                Logger.error(`Company signup error: ${error.message}`);
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
            Logger.info('Company logged out');
            
            // Clear company data from localStorage
            localStorage.removeItem('currentCompany');
            
            // Redirect to login page
            window.location.href = 'login.html';
        });
    }
});