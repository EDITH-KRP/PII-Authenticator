// Company Validation Scripts
document.addEventListener('DOMContentLoaded', () => {
    // Initialize logger
    Logger.info('Company validation page loaded');
    
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
    
    // Check for token in URL
    const urlParams = new URLSearchParams(window.location.search);
    const tokenFromUrl = urlParams.get('token');
    
    if (tokenFromUrl) {
        Logger.info(`Token found in URL: ${tokenFromUrl}`);
        document.getElementById('tokenInput').value = tokenFromUrl;
    }
    
    // Handle purpose selection
    const validationPurpose = document.getElementById('validationPurpose');
    const otherPurposeGroup = document.getElementById('otherPurposeGroup');
    
    if (validationPurpose && otherPurposeGroup) {
        validationPurpose.addEventListener('change', () => {
            if (validationPurpose.value === 'other') {
                otherPurposeGroup.style.display = 'block';
            } else {
                otherPurposeGroup.style.display = 'none';
            }
        });
    }
    
    // Validation form
    const validateForm = document.getElementById('validateForm');
    if (validateForm) {
        validateForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            Logger.info('Validation form submitted');
            
            const token = document.getElementById('tokenInput').value;
            const purpose = document.getElementById('validationPurpose').value;
            const otherPurpose = document.getElementById('otherPurpose')?.value || '';
            const consent = document.getElementById('consentCheck').checked;
            
            if (!token) {
                alert('Please enter a token to validate');
                return;
            }
            
            if (!purpose) {
                alert('Please select a validation purpose');
                return;
            }
            
            if (purpose === 'other' && !otherPurpose) {
                alert('Please specify the validation purpose');
                return;
            }
            
            if (!consent) {
                alert('You must confirm that you have the user\'s consent to validate this token');
                return;
            }
            
            try {
                // Show loading state
                const submitBtn = validateForm.querySelector('button[type="submit"]');
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
                        purpose: purpose === 'other' ? otherPurpose : purpose,
                        company_id: companyData.id
                    })
                });
                
                const data = await response.json();
                
                // Display validation result
                const validationResultElement = document.getElementById('validationResult');
                const blockchainDetailsElement = document.getElementById('blockchainDetails');
                
                if (validationResultElement) {
                    // Clear initial state
                    validationResultElement.innerHTML = '';
                    
                    if (response.ok) {
                        if (data.is_valid) {
                            validationResultElement.innerHTML = `
                                <div class="validation-success">
                                    <h3>✓ Valid Token</h3>
                                    <p>This token is valid and verified on the blockchain.</p>
                                </div>
                                
                                <div class="user-info">
                                    <h4>User Information</h4>
                                    <div class="user-info-grid">
                                        <div class="user-info-item">
                                            <div class="user-info-label">Name</div>
                                            <div class="user-info-value">${data.user_info.name}</div>
                                        </div>
                                        <div class="user-info-item">
                                            <div class="user-info-label">Email</div>
                                            <div class="user-info-value">${data.user_info.email}</div>
                                        </div>
                                        <div class="user-info-item">
                                            <div class="user-info-label">Date of Birth</div>
                                            <div class="user-info-value">${data.user_info.dob}</div>
                                        </div>
                                        <div class="user-info-item">
                                            <div class="user-info-label">Phone</div>
                                            <div class="user-info-value">${data.user_info.phone}</div>
                                        </div>
                                        <div class="user-info-item">
                                            <div class="user-info-label">ID Type</div>
                                            <div class="user-info-value">${data.user_info.id_type}</div>
                                        </div>
                                        <div class="user-info-item">
                                            <div class="user-info-label">ID Number</div>
                                            <div class="user-info-value">${data.user_info.id_number}</div>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="blockchain-verification">
                                    <h4>
                                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#00ff88" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                                            <polyline points="22 4 12 14.01 9 11.01"></polyline>
                                        </svg>
                                        Blockchain Verification
                                    </h4>
                                    <p>This token has been verified on the Sepolia blockchain.</p>
                                    <div class="transaction-hash">${data.tx_hash}</div>
                                    <a href="https://sepolia.etherscan.io/tx/${data.tx_hash}" target="_blank" class="etherscan-link">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                            <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
                                            <polyline points="15 3 21 3 21 9"></polyline>
                                            <line x1="10" y1="14" x2="21" y2="3"></line>
                                        </svg>
                                        View on Etherscan
                                    </a>
                                </div>
                            `;
                            
                            // Display blockchain details
                            if (blockchainDetailsElement) {
                                blockchainDetailsElement.innerHTML = `
                                    <div class="blockchain-record">
                                        <h4>Validation Record</h4>
                                        <p>This validation has been recorded on the blockchain for transparency and auditability.</p>
                                        <div class="transaction-hash">${data.validation_tx_hash}</div>
                                        <a href="https://sepolia.etherscan.io/tx/${data.validation_tx_hash}" target="_blank" class="etherscan-link">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                                <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
                                                <polyline points="15 3 21 3 21 9"></polyline>
                                                <line x1="10" y1="14" x2="21" y2="3"></line>
                                            </svg>
                                            View Validation Record on Etherscan
                                        </a>
                                    </div>
                                `;
                            }
                        } else {
                            validationResultElement.innerHTML = `
                                <div class="validation-error">
                                    <h3>✗ Invalid Token</h3>
                                    <p>${data.error || 'This token is not valid or could not be verified.'}</p>
                                </div>
                            `;
                            
                            // Clear blockchain details
                            if (blockchainDetailsElement) {
                                blockchainDetailsElement.innerHTML = '';
                            }
                        }
                    } else {
                        validationResultElement.innerHTML = `
                            <div class="validation-error">
                                <h3>✗ Validation Error</h3>
                                <p>${data.error || 'An error occurred during validation. Please try again.'}</p>
                            </div>
                        `;
                        
                        // Clear blockchain details
                        if (blockchainDetailsElement) {
                            blockchainDetailsElement.innerHTML = '';
                        }
                    }
                }
                
                // Reset button state
                submitBtn.disabled = false;
                submitBtn.textContent = originalBtnText;
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
                
                // Clear blockchain details
                const blockchainDetailsElement = document.getElementById('blockchainDetails');
                if (blockchainDetailsElement) {
                    blockchainDetailsElement.innerHTML = '';
                }
                
                // Reset button state
                const submitBtn = validateForm.querySelector('button[type="submit"]');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Validate Token';
            }
        });
    }
    
    // If token is in URL, trigger validation
    if (tokenFromUrl) {
        // Wait a bit for the form to be fully loaded
        setTimeout(() => {
            const submitBtn = validateForm.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.click();
            }
        }, 500);
    }
    
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