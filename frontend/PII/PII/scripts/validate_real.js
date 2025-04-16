document.addEventListener('DOMContentLoaded', () => {
    // Initialize logger
    Logger.info('Validate Token page loaded');
    
    // Check if there's a token in the URL hash
    if (window.location.hash) {
        const token = window.location.hash.substring(1);
        if (token) {
            console.log(`Found token in URL hash: ${token}`);
            const tokenInput = document.querySelector('#validateForm input[type="text"]');
            if (tokenInput) {
                tokenInput.value = token;
                console.log('Token input field populated from URL hash');
            }
        }
    }
    
    const validateForm = document.getElementById('validateForm');
    
    // Create result container for displaying validation results
    const resultContainer = document.createElement('div');
    resultContainer.classList.add('result-container');
    resultContainer.style.display = 'none';
    resultContainer.style.marginTop = '1rem';
    resultContainer.style.padding = '1rem';
    resultContainer.style.borderRadius = '8px';
    
    // Insert result container into the DOM
    validateForm.appendChild(resultContainer);
    Logger.debug('Result container added to form');

    // Backend API URL
    const API_URL = 'http://127.0.0.1:5000';
    Logger.debug(`API URL set to: ${API_URL}`);

    // Event listener for the form submission
    validateForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        Logger.info('Validate token form submitted');
        
        const tokenInput = validateForm.querySelector('input[type="text"]');
        const token = tokenInput.value.trim();
        
        if (!token) {
            Logger.warn('Token validation attempted with empty token');
            
            // Log user action
            Logger.logUserAction('validate_token_empty');
            
            resultContainer.innerHTML = `
                <h3 style="color: #ec4899; margin-bottom: 0.5rem;">Error</h3>
                <p>Please enter a token.</p>
            `;
            resultContainer.style.backgroundColor = 'rgba(236, 72, 153, 0.1)';
            resultContainer.style.border = '1px solid rgba(236, 72, 153, 0.3)';
            resultContainer.style.display = 'block';
            return;
        }
        
        Logger.debug(`Validating token: ${token}`);
        
        // Log user action
        Logger.logUserAction('validate_token_attempt', { token });
        
        // Create loading overlay with progress indicator
        Logger.debug('Creating loading overlay');
        const loadingOverlay = document.createElement('div');
        loadingOverlay.classList.add('loading-overlay');
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
        spinner.classList.add('spinner');
        spinner.style.border = '4px solid rgba(255, 255, 255, 0.3)';
        spinner.style.borderTop = '4px solid #ffffff';
        spinner.style.borderRadius = '50%';
        spinner.style.width = '40px';
        spinner.style.height = '40px';
        spinner.style.animation = 'spin 1s linear infinite';
        
        const loadingText = document.createElement('p');
        loadingText.textContent = 'Validating token...';
        loadingText.style.color = 'white';
        loadingText.style.marginTop = '1rem';
        loadingText.style.fontSize = '1.2rem';
        
        // Add a progress indicator
        const progressContainer = document.createElement('div');
        progressContainer.style.width = '250px';
        progressContainer.style.height = '8px';
        progressContainer.style.backgroundColor = 'rgba(255, 255, 255, 0.2)';
        progressContainer.style.borderRadius = '4px';
        progressContainer.style.marginTop = '1rem';
        progressContainer.style.overflow = 'hidden';
        
        const progressBar = document.createElement('div');
        progressBar.style.width = '0%';
        progressBar.style.height = '100%';
        progressBar.style.backgroundColor = '#2dd4bf';
        progressBar.style.transition = 'width 0.3s ease-in-out';
        
        progressContainer.appendChild(progressBar);
        
        // Add a status message
        const statusMessage = document.createElement('p');
        statusMessage.style.color = 'rgba(255, 255, 255, 0.7)';
        statusMessage.style.fontSize = '0.9rem';
        statusMessage.style.marginTop = '0.5rem';
        statusMessage.textContent = 'Connecting to blockchain...';
        
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
        loadingOverlay.appendChild(progressContainer);
        loadingOverlay.appendChild(statusMessage);
        document.body.appendChild(loadingOverlay);
        
        // Animate the progress bar
        let progress = 0;
        const progressInterval = setInterval(() => {
            // Validation is faster than generation, so we can move the progress bar faster
            if (progress < 90) {
                progress += (90 - progress) / 5;
                progressBar.style.width = `${progress}%`;
                
                // Update status message based on progress
                if (progress < 40) {
                    statusMessage.textContent = 'Verifying token on blockchain...';
                } else if (progress < 70) {
                    statusMessage.textContent = 'Checking digital signature...';
                } else {
                    statusMessage.textContent = 'Almost done...';
                }
            }
        }, 200);
        
        const startTime = performance.now();
        
        try {
            Logger.debug('Making API call to /validate_token endpoint');
            
            // Update loading message to show progress
            let dots = 0;
            const loadingInterval = setInterval(() => {
                dots = (dots + 1) % 4;
                loadingText.textContent = `Validating token${'.'.repeat(dots)}`;
            }, 500);
            
            // Make API call to backend with timeout
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 15000); // 15 second timeout
            
            try {
                console.log('Making API call to:', `${API_URL}/validate_token`);
                
                const response = await fetch(`${API_URL}/validate_token`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        token: token
                    }),
                    signal: controller.signal
                });
                
                clearTimeout(timeoutId);
                clearInterval(loadingInterval);
                
                console.log('API response status:', response.status);
                
                const data = await response.json();
                console.log('API response data:', data);
                
                const endTime = performance.now();
                const requestTime = (endTime - startTime) / 1000;
                
                Logger.debug(`API call completed in ${requestTime.toFixed(2)} seconds`);
            
                if (response.ok) {
                    if (data.valid) {
                        // Complete the progress animation
                        clearInterval(progressInterval);
                        progressBar.style.width = '100%';
                        statusMessage.textContent = 'Token validated successfully!';
                        
                        Logger.info(`Token validated successfully: ${token}`, {
                            response_time: requestTime.toFixed(2)
                        });
                        
                        // Log user action
                        Logger.logUserAction('token_validated', { token });
                        
                        // Short delay to show the completed progress
                        setTimeout(() => {
                            // Display success message
                            resultContainer.innerHTML = `
                                <h3 style="color: #2dd4bf; margin-bottom: 0.5rem;">Token Validated Successfully!</h3>
                                <p>This token is valid and has been verified on the blockchain.</p>
                                <div style="margin-top: 1rem;">
                                    <button id="validate-another" class="btn primary">Validate Another</button>
                                    <button id="generate-new" class="btn secondary">Generate New Token</button>
                                </div>
                            `;
                            resultContainer.style.backgroundColor = 'rgba(45, 212, 191, 0.1)';
                            resultContainer.style.border = '1px solid rgba(45, 212, 191, 0.3)';
                            resultContainer.style.display = 'block';
                            
                            // Add event listeners to the buttons
                            const validateAnotherButton = resultContainer.querySelector('#validate-another');
                            validateAnotherButton.addEventListener('click', () => {
                                resultContainer.style.display = 'none';
                                tokenInput.value = '';
                                tokenInput.focus();
                            });
                            
                            const generateNewButton = resultContainer.querySelector('#generate-new');
                            generateNewButton.addEventListener('click', () => {
                                window.location.href = 'generate.html';
                            });
                            
                            // Remove loading overlay
                            document.body.removeChild(loadingOverlay);
                            Logger.debug('Loading overlay removed after successful validation');
                        }, 500);
                        
                        // Return early to prevent the finally block from removing the overlay
                        return;
                    } else {
                        // Stop the progress animation with error state
                        clearInterval(progressInterval);
                        progressBar.style.width = '100%';
                        progressBar.style.backgroundColor = '#ec4899';
                        statusMessage.textContent = 'Token is invalid';
                        
                        Logger.warn(`Invalid token: ${token}`, {
                            response_time: requestTime.toFixed(2)
                        });
                        
                        // Log user action
                        Logger.logUserAction('token_invalid', { token });
                        
                        // Short delay to show the error state
                        setTimeout(() => {
                            // Display invalid token message
                            resultContainer.innerHTML = `
                                <h3 style="color: #ec4899; margin-bottom: 0.5rem;">Invalid Token</h3>
                                <p>This token could not be verified. Please check and try again.</p>
                                <div style="margin-top: 1rem;">
                                    <button id="try-again" class="btn primary">Try Again</button>
                                    <button id="generate-new" class="btn secondary">Generate New Token</button>
                                </div>
                            `;
                            resultContainer.style.backgroundColor = 'rgba(236, 72, 153, 0.1)';
                            resultContainer.style.border = '1px solid rgba(236, 72, 153, 0.3)';
                            resultContainer.style.display = 'block';
                            
                            // Add event listeners to the buttons
                            const tryAgainButton = resultContainer.querySelector('#try-again');
                            tryAgainButton.addEventListener('click', () => {
                                resultContainer.style.display = 'none';
                                tokenInput.focus();
                            });
                            
                            const generateNewButton = resultContainer.querySelector('#generate-new');
                            generateNewButton.addEventListener('click', () => {
                                window.location.href = 'generate.html';
                            });
                            
                            // Remove loading overlay
                            document.body.removeChild(loadingOverlay);
                            Logger.debug('Loading overlay removed after invalid token');
                        }, 500);
                        
                        // Return early to prevent the finally block from removing the overlay
                        return;
                    }
                } else {
                    // Stop the progress animation with error state
                    clearInterval(progressInterval);
                    progressBar.style.width = '100%';
                    progressBar.style.backgroundColor = '#ec4899';
                    statusMessage.textContent = 'Error occurred';
                    
                    Logger.error(`Token validation error: ${data.error || 'Unknown error'}`, {
                        token,
                        response_time: requestTime.toFixed(2)
                    });
                    
                    // Log user action
                    Logger.logUserAction('token_validation_error', { 
                        token,
                        error: data.error
                    });
                    
                    // Short delay to show the error state
                    setTimeout(() => {
                        // Display error message
                        resultContainer.innerHTML = `
                            <h3 style="color: #ec4899; margin-bottom: 0.5rem;">Error</h3>
                            <p>${data.error || 'Failed to validate token. Please try again.'}</p>
                            <div style="margin-top: 1rem;">
                                <button id="try-again" class="btn primary">Try Again</button>
                            </div>
                        `;
                        resultContainer.style.backgroundColor = 'rgba(236, 72, 153, 0.1)';
                        resultContainer.style.border = '1px solid rgba(236, 72, 153, 0.3)';
                        resultContainer.style.display = 'block';
                        
                        // Add event listener to the try again button
                        const tryAgainButton = resultContainer.querySelector('#try-again');
                        tryAgainButton.addEventListener('click', () => {
                            resultContainer.style.display = 'none';
                            tokenInput.focus();
                        });
                        
                        // Remove loading overlay
                        document.body.removeChild(loadingOverlay);
                        Logger.debug('Loading overlay removed after error');
                    }, 500);
                    
                    // Return early to prevent the finally block from removing the overlay
                    return;
                }
            } catch (error) {
                clearTimeout(timeoutId);
                clearInterval(loadingInterval);
                clearInterval(progressInterval);
                
                console.error('API call error:', error);
                
                // Show error in progress bar
                progressBar.style.width = '100%';
                progressBar.style.backgroundColor = '#ec4899';
                statusMessage.textContent = 'Error occurred';
                
                let errorMessage = 'Failed to connect to the server. Please try again later.';
                
                if (error.name === 'AbortError') {
                    errorMessage = 'The request took too long to complete. This might be due to network issues or high server load.';
                    Logger.error('Request timeout', { error: error.message });
                    
                    // Log user action
                    Logger.logUserAction('request_timeout', {
                        token
                    });
                } else {
                    Logger.error('Connection error', { 
                        token,
                        error: error.message
                    });
                    
                    // Log user action
                    Logger.logUserAction('connection_error', {
                        token,
                        error: error.message
                    });
                }
                
                // Short delay to show the error state
                setTimeout(() => {
                    resultContainer.innerHTML = `
                        <h3 style="color: #ec4899; margin-bottom: 0.5rem;">Error</h3>
                        <p>${errorMessage}</p>
                        <p><small>Please check if the backend server is running at ${API_URL}.</small></p>
                        <div style="margin-top: 1rem;">
                            <button id="try-again" class="btn primary">Try Again</button>
                        </div>
                    `;
                    resultContainer.style.backgroundColor = 'rgba(236, 72, 153, 0.1)';
                    resultContainer.style.border = '1px solid rgba(236, 72, 153, 0.3)';
                    resultContainer.style.display = 'block';
                    
                    // Add event listener to the try again button
                    const tryAgainButton = resultContainer.querySelector('#try-again');
                    tryAgainButton.addEventListener('click', () => {
                        resultContainer.style.display = 'none';
                        tokenInput.focus();
                    });
                    
                    // Remove loading overlay
                    document.body.removeChild(loadingOverlay);
                    Logger.debug('Loading overlay removed after connection error');
                }, 500);
                
                // Return early to prevent the finally block from removing the overlay
                return;
            }
        } catch (outerError) {
            // This catches any errors in the outer try block
            console.error('Unexpected error:', outerError);
            Logger.error('Unexpected error', { 
                error: outerError.message
            });
            
            if (progressInterval) clearInterval(progressInterval);
            
            resultContainer.innerHTML = `
                <h3 style="color: #ec4899; margin-bottom: 0.5rem;">Unexpected Error</h3>
                <p>An unexpected error occurred. Please try again later.</p>
                <div style="margin-top: 1rem;">
                    <button id="try-again" class="btn primary">Try Again</button>
                </div>
            `;
            resultContainer.style.backgroundColor = 'rgba(236, 72, 153, 0.1)';
            resultContainer.style.border = '1px solid rgba(236, 72, 153, 0.3)';
            resultContainer.style.display = 'block';
            
            // Add event listener to the try again button
            const tryAgainButton = resultContainer.querySelector('#try-again');
            tryAgainButton.addEventListener('click', () => {
                resultContainer.style.display = 'none';
                tokenInput.focus();
            });
            
            // Remove loading overlay
            if (document.body.contains(loadingOverlay)) {
                document.body.removeChild(loadingOverlay);
            }
        }
    });
});