document.addEventListener('DOMContentLoaded', () => {
    // Initialize logger
    Logger.info('Generate Token page loaded');
    
    const generateTokenButton = document.getElementById('generate-token');
    const generateForm = document.getElementById('generateForm');
    
    // Create result container for displaying the token
    const resultContainer = document.createElement('div');
    resultContainer.classList.add('result-container');
    resultContainer.style.display = 'none';
    resultContainer.style.marginTop = '1.5rem';
    resultContainer.style.padding = '1.5rem';
    resultContainer.style.backgroundColor = 'rgba(0, 114, 255, 0.1)';
    resultContainer.style.borderRadius = '0.75rem';
    resultContainer.style.border = '1px solid rgba(0, 195, 255, 0.3)';
    resultContainer.style.boxShadow = '0 4px 20px rgba(0, 0, 0, 0.2)';
    
    // Insert result container into the DOM
    generateForm.appendChild(resultContainer);
    Logger.debug('Result container added to form');

    // Backend API URL
    const API_URL = 'http://127.0.0.1:5000';
    Logger.debug(`API URL set to: ${API_URL}`);

    // Enable the generate button when all fields are filled
    const formInputs = generateForm.querySelectorAll('input, select');
    Logger.debug(`Found ${formInputs.length} form inputs`);
    
    function checkFormValidity() {
        let isValid = true;
        let emptyFields = [];
        
        formInputs.forEach(input => {
            if (!input.value.trim()) {
                isValid = false;
                emptyFields.push(input.placeholder || input.name || 'Unknown field');
            }
        });
        
        generateTokenButton.disabled = !isValid;
        
        if (isValid) {
            generateTokenButton.classList.add('active');
            generateTokenButton.style.opacity = '1';
            Logger.debug('Form is valid, generate button enabled');
        } else {
            generateTokenButton.classList.remove('active');
            generateTokenButton.style.opacity = '0.6';
            Logger.debug(`Form is invalid, missing fields: ${emptyFields.join(', ')}`);
        }
    }

    formInputs.forEach(input => {
        input.addEventListener('input', () => {
            checkFormValidity();
        });
        
        // Also check on change event for select elements
        if (input.tagName === 'SELECT') {
            input.addEventListener('change', () => {
                checkFormValidity();
            });
        }
    });

    // Initial check for form validity
    checkFormValidity();

    // Event listener for the generate button
    generateTokenButton.addEventListener('click', async () => {
        console.log('Generate token button clicked');
        Logger.info('Generate token button clicked');
        
        // Get form values
        const formData = {};
        formInputs.forEach(input => {
            if (input.type === 'select-one') {
                formData.id_type = input.value;
            } else if (input.placeholder === 'Enter ID Number') {
                formData.id_number = input.value;
            } else if (input.placeholder === 'Name') {
                formData.name = input.value;
                formData.user_id = input.value.toLowerCase().replace(/\s+/g, '_');
            } else if (input.placeholder === 'Email ID') {
                formData.email = input.value;
            } else if (input.placeholder === 'Date of Birth') {
                formData.dob = input.value;
            } else if (input.placeholder === 'Phone Number') {
                formData.phone = input.value;
            }
        });
        
        console.log('Form data collected:', formData);
        
        // Check if any required fields are missing
        const requiredFields = ['user_id', 'name', 'email', 'dob', 'phone', 'id_type', 'id_number'];
        const missingFields = requiredFields.filter(field => !formData[field]);
        
        if (missingFields.length > 0) {
            console.error('Missing required fields:', missingFields);
            alert('Please fill in all required fields: ' + missingFields.join(', '));
            return;
        }
        
        // Create loading overlay
        const loadingOverlay = document.createElement('div');
        loadingOverlay.style.position = 'fixed';
        loadingOverlay.style.top = '0';
        loadingOverlay.style.left = '0';
        loadingOverlay.style.width = '100%';
        loadingOverlay.style.height = '100%';
        loadingOverlay.style.backgroundColor = 'rgba(0, 0, 0, 0.7)';
        loadingOverlay.style.display = 'flex';
        loadingOverlay.style.flexDirection = 'column';
        loadingOverlay.style.justifyContent = 'center';
        loadingOverlay.style.alignItems = 'center';
        loadingOverlay.style.zIndex = '1000';
        
        const spinner = document.createElement('div');
        spinner.style.border = '4px solid rgba(255, 255, 255, 0.3)';
        spinner.style.borderTop = '4px solid #ffffff';
        spinner.style.borderRadius = '50%';
        spinner.style.width = '40px';
        spinner.style.height = '40px';
        spinner.style.animation = 'spin 1s linear infinite';
        
        const loadingText = document.createElement('p');
        loadingText.textContent = 'Generating token...';
        loadingText.style.color = 'white';
        loadingText.style.marginTop = '1rem';
        
        // Add keyframes for spinner animation
        const style = document.createElement('style');
        style.textContent = `
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
        `;
        document.head.appendChild(style);
        
        loadingOverlay.appendChild(spinner);
        loadingOverlay.appendChild(loadingText);
        document.body.appendChild(loadingOverlay);
        
        try {
            console.log('Making API call to:', `${API_URL}/encrypt`);
            
            // Update loading message to show progress
            let dots = 0;
            const loadingInterval = setInterval(() => {
                dots = (dots + 1) % 4;
                loadingText.textContent = `Generating token${'.'.repeat(dots)}`;
            }, 500);
            
            // Make API call to backend with timeout
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout
            
            const response = await fetch(`${API_URL}/encrypt`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    user_id: formData.user_id,
                    name: formData.name,
                    email: formData.email,
                    dob: formData.dob,
                    phone: formData.phone,
                    id_type: formData.id_type,
                    id_number: formData.id_number
                }),
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            clearInterval(loadingInterval);
            
            console.log('API response status:', response.status);
            
            const data = await response.json();
            console.log('API response data:', data);
            
            // Debug transaction hash
            console.log('Transaction hash (txn_hash):', data.txn_hash);
            console.log('Transaction hash (tx_hash):', data.tx_hash);
            
            // Log the transaction hash for debugging
            console.log('Transaction hash from backend:', data.txn_hash || data.tx_hash);
            
            // Use txn_hash if available, otherwise use tx_hash
            if (!data.txn_hash && data.tx_hash) {
                data.txn_hash = data.tx_hash;
            }
            
            // If no transaction hash is provided, show a pending message
            if (!data.txn_hash) {
                console.warn('No transaction hash found in response');
                data.txn_hash = 'Transaction pending...';
            }
            
            if (response.ok) {
                // Store the token and JWT in localStorage for validation
                const tokens = JSON.parse(localStorage.getItem('realTokens') || '[]');
                if (!tokens.includes(data.token)) {
                    tokens.push(data.token);
                    localStorage.setItem('realTokens', JSON.stringify(tokens));
                    console.log(`Token ${data.token} stored in localStorage for convenience`);
                }
                
                // Store JWT for later use
                localStorage.setItem(`jwt_${data.token}`, data.jwt);
                
                // Check if this is an existing token message
                const isExistingToken = data.message && data.message.includes("Existing token retrieved");
                
                // Display success message with token
                resultContainer.innerHTML = `
                    <h3 style="color: #00ff88; margin-bottom: 1rem;">${isExistingToken ? 'Existing Token Retrieved' : 'Token Generated Successfully'}!</h3>
                    ${isExistingToken ? 
                        `<div style="background: rgba(255, 193, 7, 0.1); padding: 1rem; border-radius: 0.5rem; border: 1px solid rgba(255, 193, 7, 0.3); margin-bottom: 1rem;">
                            <p style="color: #ffc107;"><strong>Note:</strong> A token already exists for this user. Only one token is allowed per user.</p>
                        </div>` : ''
                    }
                    <div style="background: rgba(0, 114, 255, 0.1); padding: 1rem; border-radius: 0.5rem; border: 1px solid rgba(0, 195, 255, 0.3); margin-bottom: 1rem;">
                        <p style="margin-bottom: 0.5rem;"><strong>Your Token:</strong></p>
                        <div style="font-family: 'Courier New', monospace; font-size: 1.2rem; background: rgba(16, 24, 39, 0.8); color: #00ff88; padding: 0.8rem; border-radius: 0.5rem; text-align: center; letter-spacing: 1px; border: 1px solid rgba(0, 195, 255, 0.5);">
                            ${data.token}
                        </div>
                    </div>
                    <div style="background: rgba(0, 114, 255, 0.1); padding: 1rem; border-radius: 0.5rem; border: 1px solid rgba(0, 195, 255, 0.3); margin-bottom: 1rem;">
                        <p style="margin-bottom: 0.5rem;"><strong>Transaction Hash:</strong></p>
                        <div style="font-family: 'Courier New', monospace; font-size: 0.8rem; background: rgba(16, 24, 39, 0.8); color: #00ff88; padding: 0.8rem; border-radius: 0.5rem; text-align: center; overflow-wrap: break-word; border: 1px solid rgba(0, 195, 255, 0.5);">
                            ${data.txn_hash || data.tx_hash || 'Transaction pending...'}
                        </div>
                        <p style="margin-top: 0.5rem; font-size: 0.8rem; color: rgba(255, 255, 255, 0.6);">
                            <small>
                                This is the real blockchain transaction ID that confirms your token is stored securely on the Sepolia testnet.
                            </small>
                        </p>
                        <div style="display: flex; align-items: center; margin-top: 0.8rem;">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: #00c3ff; margin-right: 0.5rem;">
                                <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
                                <polyline points="15 3 21 3 21 9"></polyline>
                                <line x1="10" y1="14" x2="21" y2="3"></line>
                            </svg>
                            <a href="https://sepolia.etherscan.io/tx/${data.txn_hash || data.tx_hash}" target="_blank" style="color: #00c3ff; text-decoration: underline; font-weight: bold;" id="etherscan-link">
                                View on Etherscan
                            </a>
                        </div>
                        <script>
                            // Verify the transaction hash is valid
                            document.getElementById('etherscan-link').addEventListener('click', function(e) {
                                const txHash = "${data.txn_hash || data.tx_hash}";
                                console.log("Opening Etherscan with transaction hash:", txHash);
                                // No need to prevent default - let the link work normally
                            });
                        </script>
                    </div>
                    <div style="display: flex; align-items: center; margin-top: 1rem;">
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: #00c3ff; margin-right: 0.5rem;">
                            <circle cx="12" cy="12" r="10"></circle>
                            <path d="M12 8v4l2 2"></path>
                        </svg>
                        <p style="color: rgba(255, 255, 255, 0.7);"><small>Keep this token safe. You'll need it for verification. This token is securely stored on the blockchain.</small></p>
                    </div>
                    <div style="margin-top: 1rem;">
                        <button id="validate-now" class="btn secondary" style="margin-right: 0.5rem;">Validate Now</button>
                        <button id="generate-new" class="btn primary">Generate Another</button>
                    </div>
                `;
                
                // Add event listeners to the buttons
                const validateNowButton = resultContainer.querySelector('#validate-now');
                validateNowButton.addEventListener('click', () => {
                    window.location.href = `validate.html#${data.token}`;
                });
                
                const generateNewButton = resultContainer.querySelector('#generate-new');
                generateNewButton.addEventListener('click', () => {
                    resultContainer.style.display = 'none';
                    formInputs.forEach(input => {
                        input.value = '';
                    });
                    checkFormValidity();
                });
            } else {
                // Display error message
                resultContainer.innerHTML = `
                    <h3 style="color: #ff3b5c; margin-bottom: 1rem;">Error</h3>
                    <div style="background: rgba(255, 59, 92, 0.1); padding: 1rem; border-radius: 0.5rem; border: 1px solid rgba(255, 59, 92, 0.3);">
                        <p>${data.error || 'Failed to generate token. Please try again.'}</p>
                    </div>
                    <div style="display: flex; align-items: center; margin-top: 1rem;">
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: #ff3b5c; margin-right: 0.5rem;">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="12" y1="8" x2="12" y2="12"></line>
                            <line x1="12" y1="16" x2="12.01" y2="16"></line>
                        </svg>
                        <p style="color: rgba(255, 255, 255, 0.7);"><small>Please try again or contact support if the problem persists.</small></p>
                    </div>
                    <div style="margin-top: 1rem;">
                        <button id="try-again" class="btn primary">Try Again</button>
                    </div>
                `;
                
                // Add event listener to the try again button
                const tryAgainButton = resultContainer.querySelector('#try-again');
                tryAgainButton.addEventListener('click', () => {
                    resultContainer.style.display = 'none';
                });
            }
        } catch (error) {
            console.error('API call error:', error);
            
            // Display error message
            resultContainer.innerHTML = `
                <h3 style="color: #ff3b5c; margin-bottom: 1rem;">Connection Error</h3>
                <div style="background: rgba(255, 59, 92, 0.1); padding: 1rem; border-radius: 0.5rem; border: 1px solid rgba(255, 59, 92, 0.3);">
                    <p>${error.name === 'AbortError' 
                        ? 'Request timed out. The server took too long to respond.' 
                        : 'Failed to connect to the server. Please check your internet connection and try again.'}</p>
                </div>
                <div style="display: flex; align-items: center; margin-top: 1rem;">
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: #ff3b5c; margin-right: 0.5rem;">
                        <line x1="18" y1="6" x2="6" y2="18"></line>
                        <line x1="6" y1="6" x2="18" y2="18"></line>
                    </svg>
                    <p style="color: rgba(255, 255, 255, 0.7);"><small>Please check if the backend server is running at ${API_URL}.</small></p>
                </div>
                <div style="margin-top: 1rem;">
                    <button id="try-again" class="btn primary">Try Again</button>
                </div>
            `;
            
            // Add event listener to the try again button
            const tryAgainButton = resultContainer.querySelector('#try-again');
            tryAgainButton.addEventListener('click', () => {
                resultContainer.style.display = 'none';
            });
        } finally {
            // Show the result container
            resultContainer.style.display = 'block';
            console.log('Result container displayed');
            
            // Remove the loading overlay
            document.body.removeChild(loadingOverlay);
        }
    });
});