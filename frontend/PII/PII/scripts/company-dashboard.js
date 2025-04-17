// Company Dashboard Scripts
document.addEventListener('DOMContentLoaded', () => {
    // Initialize logger
    Logger.info('Company dashboard page loaded');
    
    // Check if company is logged in
    const currentCompany = localStorage.getItem('currentCompany');
    if (!currentCompany) {
        Logger.info('Company not logged in, redirecting to login page');
        window.location.href = 'login.html';
        return;
    }
    
    // Parse company data
    const companyData = JSON.parse(currentCompany);
    
    // Update company name in the dashboard
    const companyNameElement = document.getElementById('companyName');
    if (companyNameElement) {
        companyNameElement.textContent = companyData.name;
    }
    
    // API URL
    const API_URL = 'http://127.0.0.1:5000';
    
    // Load validation statistics
    const loadValidationStats = async () => {
        try {
            const response = await fetch(`${API_URL}/company/validations/stats`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${companyData.token}`
                }
            });
            
            const data = await response.json();
            
            if (response.ok) {
                Logger.info('Loaded validation statistics');
                
                // Update stats
                const todayCountElement = document.getElementById('todayCount');
                const totalCountElement = document.getElementById('totalCount');
                const successRateElement = document.getElementById('successRate');
                
                if (todayCountElement) {
                    todayCountElement.textContent = data.today_count;
                }
                
                if (totalCountElement) {
                    totalCountElement.textContent = data.total_count;
                }
                
                if (successRateElement) {
                    successRateElement.textContent = `${data.success_rate}%`;
                }
            } else {
                Logger.error(`Failed to load validation stats: ${data.error}`);
            }
        } catch (error) {
            Logger.error(`Error loading validation stats: ${error.message}`);
        }
    };
    
    // Load recent validations
    const loadRecentValidations = async () => {
        try {
            const response = await fetch(`${API_URL}/company/validations/recent`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${companyData.token}`
                }
            });
            
            const data = await response.json();
            
            if (response.ok) {
                Logger.info(`Loaded ${data.validations.length} recent validations`);
                
                // Display recent validations
                const recentListElement = document.getElementById('recentList');
                const emptyRecentState = document.getElementById('emptyRecentState');
                
                if (recentListElement) {
                    if (data.validations.length > 0) {
                        // Hide empty state
                        if (emptyRecentState) {
                            emptyRecentState.style.display = 'none';
                        }
                        
                        // Clear existing entries
                        recentListElement.innerHTML = '';
                        
                        // Add each validation
                        data.validations.forEach(validation => {
                            const validationEntry = document.createElement('div');
                            validationEntry.className = 'recent-validation';
                            validationEntry.innerHTML = `
                                <div class="validation-info">
                                    <div class="token-id">${validation.token}</div>
                                    <div class="validation-time">${new Date(validation.timestamp).toLocaleString()}</div>
                                </div>
                                <div class="validation-status ${validation.is_valid ? 'status-valid' : 'status-invalid'}">
                                    ${validation.is_valid ? 'Valid' : 'Invalid'}
                                </div>
                            `;
                            
                            validationEntry.addEventListener('click', () => {
                                // Redirect to validation details
                                window.location.href = `validation-details.html?id=${validation.id}`;
                            });
                            
                            recentListElement.appendChild(validationEntry);
                        });
                    } else {
                        // Show empty state
                        if (emptyRecentState) {
                            emptyRecentState.style.display = 'block';
                        }
                    }
                }
            } else {
                Logger.error(`Failed to load recent validations: ${data.error}`);
            }
        } catch (error) {
            Logger.error(`Error loading recent validations: ${error.message}`);
        }
    };
    
    // Quick validation form
    const quickValidateForm = document.getElementById('quickValidateForm');
    if (quickValidateForm) {
        quickValidateForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            Logger.info('Quick validation form submitted');
            
            const token = document.getElementById('tokenInput').value;
            
            if (!token) {
                alert('Please enter a token to validate');
                return;
            }
            
            try {
                // Show loading state
                const submitBtn = quickValidateForm.querySelector('button[type="submit"]');
                const originalBtnText = submitBtn.textContent;
                submitBtn.disabled = true;
                submitBtn.textContent = 'Validating...';
                
                // Make API call to validate token
                const response = await fetch(`${API_URL}/company/validate`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${companyData.token}`
                    },
                    body: JSON.stringify({
                        token,
                        purpose: 'quick_check'
                    })
                });
                
                const data = await response.json();
                
                // Display validation result
                const validationResultElement = document.getElementById('validationResult');
                if (validationResultElement) {
                    if (response.ok) {
                        if (data.is_valid) {
                            validationResultElement.innerHTML = `
                                <div class="validation-success">
                                    <h3>✓ Valid Token</h3>
                                    <p>This token is valid and verified on the blockchain.</p>
                                </div>
                                <div class="validation-details">
                                    <div class="detail-item">
                                        <span class="detail-label">Token:</span>
                                        <span class="detail-value">${data.token}</span>
                                    </div>
                                    <div class="detail-item">
                                        <span class="detail-label">Verified On:</span>
                                        <span class="detail-value">${new Date().toLocaleString()}</span>
                                    </div>
                                    <div class="detail-item">
                                        <span class="detail-label">Transaction Hash:</span>
                                        <span class="detail-value">${data.tx_hash}</span>
                                    </div>
                                </div>
                                <a href="validate.html?token=${token}" class="btn primary full-width" style="margin-top: 1rem;">View Full Details</a>
                            `;
                        } else {
                            validationResultElement.innerHTML = `
                                <div class="validation-error">
                                    <h3>✗ Invalid Token</h3>
                                    <p>${data.error || 'This token is not valid or could not be verified.'}</p>
                                </div>
                            `;
                        }
                    } else {
                        validationResultElement.innerHTML = `
                            <div class="validation-error">
                                <h3>✗ Validation Error</h3>
                                <p>${data.error || 'An error occurred during validation. Please try again.'}</p>
                            </div>
                        `;
                    }
                }
                
                // Reset button state
                submitBtn.disabled = false;
                submitBtn.textContent = originalBtnText;
                
                // Reload stats and recent validations
                loadValidationStats();
                loadRecentValidations();
            } catch (error) {
                Logger.error(`Error validating token: ${error.message}`);
                
                const validationResultElement = document.getElementById('validationResult');
                if (validationResultElement) {
                    validationResultElement.innerHTML = `
                        <div class="validation-error">
                            <h3>✗ System Error</h3>
                            <p>An unexpected error occurred. Please try again later.</p>
                        </div>
                    `;
                }
                
                // Reset button state
                const submitBtn = quickValidateForm.querySelector('button[type="submit"]');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Validate';
            }
        });
    }
    
    // Load company data
    loadValidationStats();
    loadRecentValidations();
    
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