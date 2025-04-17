// Company Settings Scripts
document.addEventListener('DOMContentLoaded', () => {
    // Initialize logger
    Logger.info('Company settings page loaded');
    
    // Check if company is logged in
    const currentCompany = localStorage.getItem('currentCompany');
    if (!currentCompany) {
        Logger.info('Company not logged in, redirecting to login page');
        window.location.href = 'login.html';
        return;
    }
    
    // Parse company data
    const companyData = JSON.parse(currentCompany);
    
    // API URL
    const API_URL = 'http://127.0.0.1:5000';
    
    // Load company profile data
    const loadCompanyProfile = async () => {
        try {
            const response = await fetch(`${API_URL}/company/profile`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${companyData.token}`
                }
            });
            
            const data = await response.json();
            
            if (response.ok) {
                Logger.info('Loaded company profile data');
                
                // Populate form fields
                document.getElementById('companyName').value = data.company_name || '';
                document.getElementById('businessType').value = data.business_type || 'other';
                document.getElementById('registrationNumber').value = data.registration_number || '';
                document.getElementById('email').value = data.email || '';
                document.getElementById('phone').value = data.phone || '';
                document.getElementById('address').value = data.address || '';
            } else {
                Logger.error(`Failed to load company profile: ${data.error}`);
                alert(data.error || 'Failed to load company profile. Please try again.');
            }
        } catch (error) {
            Logger.error(`Error loading company profile: ${error.message}`);
            alert('An error occurred while loading company profile. Please try again.');
        }
    };
    
    // Handle profile form submission
    const profileForm = document.getElementById('profileForm');
    if (profileForm) {
        profileForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            Logger.info('Profile form submitted');
            
            const formData = {
                company_name: document.getElementById('companyName').value,
                business_type: document.getElementById('businessType').value,
                registration_number: document.getElementById('registrationNumber').value,
                email: document.getElementById('email').value,
                phone: document.getElementById('phone').value,
                address: document.getElementById('address').value
            };
            
            try {
                // Show loading state
                const submitBtn = profileForm.querySelector('button[type="submit"]');
                const originalBtnText = submitBtn.textContent;
                submitBtn.disabled = true;
                submitBtn.textContent = 'Saving...';
                
                const response = await fetch(`${API_URL}/company/profile`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${companyData.token}`
                    },
                    body: JSON.stringify(formData)
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    Logger.info('Company profile updated successfully');
                    alert('Company profile updated successfully');
                    
                    // Update company name in localStorage
                    const updatedCompanyData = JSON.parse(localStorage.getItem('currentCompany'));
                    updatedCompanyData.name = formData.company_name;
                    localStorage.setItem('currentCompany', JSON.stringify(updatedCompanyData));
                } else {
                    Logger.error(`Failed to update company profile: ${data.error}`);
                    alert(data.error || 'Failed to update company profile. Please try again.');
                }
                
                // Reset button state
                submitBtn.disabled = false;
                submitBtn.textContent = originalBtnText;
            } catch (error) {
                Logger.error(`Error updating company profile: ${error.message}`);
                alert('An error occurred while updating company profile. Please try again.');
                
                // Reset button state
                const submitBtn = profileForm.querySelector('button[type="submit"]');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Save Changes';
            }
        });
    }
    
    // Handle security form submission
    const securityForm = document.getElementById('securityForm');
    if (securityForm) {
        securityForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            Logger.info('Security form submitted');
            
            const currentPassword = document.getElementById('currentPassword').value;
            const newPassword = document.getElementById('newPassword').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            const twoFactorAuth = document.getElementById('twoFactorAuth').checked;
            
            // Validate passwords
            if (newPassword !== confirmPassword) {
                alert('New passwords do not match');
                return;
            }
            
            try {
                // Show loading state
                const submitBtn = securityForm.querySelector('button[type="submit"]');
                const originalBtnText = submitBtn.textContent;
                submitBtn.disabled = true;
                submitBtn.textContent = 'Updating...';
                
                const response = await fetch(`${API_URL}/company/security`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${companyData.token}`
                    },
                    body: JSON.stringify({
                        current_password: currentPassword,
                        new_password: newPassword,
                        two_factor_auth: twoFactorAuth
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    Logger.info('Security settings updated successfully');
                    alert('Security settings updated successfully');
                    
                    // Clear password fields
                    document.getElementById('currentPassword').value = '';
                    document.getElementById('newPassword').value = '';
                    document.getElementById('confirmPassword').value = '';
                } else {
                    Logger.error(`Failed to update security settings: ${data.error}`);
                    alert(data.error || 'Failed to update security settings. Please try again.');
                }
                
                // Reset button state
                submitBtn.disabled = false;
                submitBtn.textContent = originalBtnText;
            } catch (error) {
                Logger.error(`Error updating security settings: ${error.message}`);
                alert('An error occurred while updating security settings. Please try again.');
                
                // Reset button state
                const submitBtn = securityForm.querySelector('button[type="submit"]');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Update Security Settings';
            }
        });
    }
    
    // Handle notification form submission
    const notificationForm = document.getElementById('notificationForm');
    if (notificationForm) {
        notificationForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            Logger.info('Notification form submitted');
            
            const formData = {
                email_validations: document.getElementById('emailValidations').checked,
                email_security: document.getElementById('emailSecurity').checked,
                email_updates: document.getElementById('emailUpdates').checked,
                email_marketing: document.getElementById('emailMarketing').checked,
                notification_frequency: document.getElementById('notificationFrequency').value
            };
            
            try {
                // Show loading state
                const submitBtn = notificationForm.querySelector('button[type="submit"]');
                const originalBtnText = submitBtn.textContent;
                submitBtn.disabled = true;
                submitBtn.textContent = 'Saving...';
                
                const response = await fetch(`${API_URL}/company/notifications`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${companyData.token}`
                    },
                    body: JSON.stringify(formData)
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    Logger.info('Notification preferences updated successfully');
                    alert('Notification preferences updated successfully');
                } else {
                    Logger.error(`Failed to update notification preferences: ${data.error}`);
                    alert(data.error || 'Failed to update notification preferences. Please try again.');
                }
                
                // Reset button state
                submitBtn.disabled = false;
                submitBtn.textContent = originalBtnText;
            } catch (error) {
                Logger.error(`Error updating notification preferences: ${error.message}`);
                alert('An error occurred while updating notification preferences. Please try again.');
                
                // Reset button state
                const submitBtn = notificationForm.querySelector('button[type="submit"]');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Save Preferences';
            }
        });
    }
    
    // Handle API key actions
    document.querySelectorAll('.btn-show-key').forEach(button => {
        button.addEventListener('click', function() {
            const keyValueElement = this.closest('.api-key').querySelector('.key-value');
            
            if (keyValueElement.textContent.includes('•')) {
                // This is a dummy key for demonstration
                keyValueElement.textContent = 'sk_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
                this.textContent = 'Hide';
            } else {
                keyValueElement.textContent = '••••••••••••••••••••••••';
                this.textContent = 'Show';
            }
        });
    });
    
    document.querySelectorAll('.btn-copy-key').forEach(button => {
        button.addEventListener('click', function() {
            const keyValueElement = this.closest('.api-key').querySelector('.key-value');
            let keyText = keyValueElement.textContent;
            
            // If key is hidden, show it first
            if (keyText.includes('•')) {
                const showButton = this.closest('.api-key').querySelector('.btn-show-key');
                showButton.click();
                keyText = keyValueElement.textContent;
            }
            
            // Copy to clipboard
            navigator.clipboard.writeText(keyText)
                .then(() => {
                    const originalText = this.textContent;
                    this.textContent = 'Copied!';
                    setTimeout(() => {
                        this.textContent = originalText;
                    }, 2000);
                })
                .catch(err => {
                    Logger.error(`Copy failed: ${err}`);
                    alert('Failed to copy API key. Please try again.');
                });
        });
    });
    
    document.querySelectorAll('.btn-regenerate-key').forEach(button => {
        button.addEventListener('click', function() {
            if (confirm('Are you sure you want to regenerate this API key? This will invalidate the current key and may break existing integrations.')) {
                const keyValueElement = this.closest('.api-key').querySelector('.key-value');
                // This is a dummy key for demonstration
                keyValueElement.textContent = 'sk_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
                
                // Show success message
                alert('API key regenerated successfully. Make sure to update your integrations.');
            }
        });
    });
    
    // Settings navigation
    const settingsLinks = document.querySelectorAll('.settings-nav a');
    const settingsSections = document.querySelectorAll('.settings-section');
    
    settingsLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            
            const targetId = link.getAttribute('href').substring(1);
            
            // Update active link
            settingsLinks.forEach(l => l.classList.remove('active'));
            link.classList.add('active');
            
            // Show target section, hide others
            settingsSections.forEach(section => {
                if (section.id === targetId) {
                    section.classList.add('active');
                } else {
                    section.classList.remove('active');
                }
            });
        });
    });
    
    // Load company profile data
    loadCompanyProfile();
    
    // Logout handler
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