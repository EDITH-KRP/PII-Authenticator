// Token Generation Scripts
document.addEventListener('DOMContentLoaded', () => {
    // Initialize logger
    Logger.info('Token generation page loaded');
    
    // Check if user is logged in
    const currentUser = localStorage.getItem('currentUser');
    if (!currentUser) {
        Logger.info('User not logged in, redirecting to login page');
        window.location.href = 'login.html';
        return;
    }
    
    // Parse user data
    const userData = JSON.parse(currentUser);
    
    // API URL
    const API_URL = 'http://127.0.0.1:5000';
    
    // Check if user already has a token
    fetch(`${API_URL}/user/tokens`, {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${userData.token}`
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.tokens && data.tokens.length > 0) {
            // User already has a token, redirect to profile page
            Logger.info('User already has a token, redirecting to profile page');
            alert('You already have a token. Redirecting to your profile page.');
            window.location.href = 'profile.html';
        }
    })
    .catch(error => {
        Logger.error(`Error checking if user has tokens: ${error.message}`);
    });
    
    // Generate token form
    const generateForm = document.getElementById('generateForm');
    if (generateForm) {
        generateForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            Logger.info('Generate token form submitted');
            
            try {
                // Show loading state
                const submitBtn = generateForm.querySelector('button[type="submit"]');
                const originalBtnText = submitBtn.textContent;
                submitBtn.disabled = true;
                submitBtn.textContent = 'Generating...';
                
                const response = await fetch(`${API_URL}/user/tokens/generate`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${userData.token}`
                    }
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    Logger.info('Token generated successfully');
                    
                    // Show success message
                    alert('Token generated successfully');
                    
                    // Redirect to profile page
                    window.location.href = 'profile.html';
                } else {
                    Logger.error(`Failed to generate token: ${data.error}`);
                    alert(data.error || 'Failed to generate token. Please try again.');
                    
                    // Reset button state
                    submitBtn.disabled = false;
                    submitBtn.textContent = originalBtnText;
                }
            } catch (error) {
                Logger.error(`Error generating token: ${error.message}`);
                alert('An error occurred while generating token. Please try again.');
                
                // Reset button state
                const submitBtn = generateForm.querySelector('button[type="submit"]');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Generate Token';
            }
        });
    }
    
    // Logout handler
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