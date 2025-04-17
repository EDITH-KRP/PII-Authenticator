// User Profile Scripts
document.addEventListener('DOMContentLoaded', () => {
    // Initialize logger
    Logger.info('User profile page loaded');
    
    // Check if user is logged in
    const currentUser = localStorage.getItem('currentUser');
    if (!currentUser) {
        Logger.info('User not logged in, redirecting to login page');
        window.location.href = 'login.html';
        return;
    }
    
    // Parse user data
    const userData = JSON.parse(currentUser);
    
    // Update user name in the profile
    const userNameElement = document.getElementById('userName');
    if (userNameElement) {
        userNameElement.textContent = userData.name;
    }
    
    // API URL
    const API_URL = 'http://127.0.0.1:5000';
    
    // Load user profile data
    const loadUserProfile = async () => {
        try {
            const response = await fetch(`${API_URL}/user/profile`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${userData.token}`
                }
            });
            
            const data = await response.json();
            
            if (response.ok) {
                Logger.info('Loaded user profile data');
                
                // Update profile information
                document.getElementById('profileName').textContent = data.name || 'Not provided';
                document.getElementById('profileEmail').textContent = data.email || 'Not provided';
                document.getElementById('profilePhone').textContent = data.phone || 'Not provided';
                document.getElementById('profileDob').textContent = data.dob ? new Date(data.dob).toLocaleDateString() : 'Not provided';
                document.getElementById('profileCreated').textContent = data.created_at ? new Date(data.created_at * 1000).toLocaleDateString() : 'Not provided';
                
                // Populate edit form
                document.getElementById('fullName').value = data.name || '';
                document.getElementById('email').value = data.email || '';
                document.getElementById('phone').value = data.phone || '';
                document.getElementById('dob').value = data.dob || '';
            } else {
                Logger.error(`Failed to load user profile: ${data.error}`);
                alert(data.error || 'Failed to load user profile. Please try again.');
            }
        } catch (error) {
            Logger.error(`Error loading user profile: ${error.message}`);
            alert('An error occurred while loading user profile. Please try again.');
        }
    };
    
    // Load user tokens
    const loadUserTokens = async () => {
        try {
            const response = await fetch(`${API_URL}/user/tokens`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${userData.token}`
                }
            });
            
            const data = await response.json();
            
            if (response.ok) {
                Logger.info(`Loaded ${data.tokens.length} tokens for user`);
                
                // Update token count
                const tokenCountElement = document.getElementById('tokenCount');
                if (tokenCountElement) {
                    tokenCountElement.textContent = data.tokens.length;
                }
                
                // Display tokens
                const tokenListElement = document.getElementById('tokenList');
                const emptyTokenState = document.getElementById('emptyTokenState');
                
                if (tokenListElement) {
                    if (data.tokens.length > 0) {
                        // Hide empty state
                        if (emptyTokenState) {
                            emptyTokenState.style.display = 'none';
                        }
                        
                        // Clear existing tokens
                        tokenListElement.innerHTML = '';
                        
                        // Add each token
                        data.tokens.forEach(token => {
                            const tokenCard = document.createElement('div');
                            tokenCard.className = 'token-card';
                            tokenCard.innerHTML = `
                                <h3>Identity Token</h3>
                                <p>Created: ${new Date(token.created_at).toLocaleString()}</p>
                                <div class="token-value">${token.token}</div>
                                <p>Status: <span class="token-status ${token.active ? 'active' : 'inactive'}">${token.active ? 'Active' : 'Inactive'}</span></p>
                                <div class="blockchain-info">
                                    <p>Transaction Hash:</p>
                                    <div class="transaction-hash">${token.tx_hash}</div>
                                    <a href="https://sepolia.etherscan.io/tx/${token.tx_hash}" target="_blank" class="etherscan-link">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                            <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
                                            <polyline points="15 3 21 3 21 9"></polyline>
                                            <line x1="10" y1="14" x2="21" y2="3"></line>
                                        </svg>
                                        View on Etherscan
                                    </a>
                                </div>
                                <div class="token-actions">
                                    <button class="btn secondary btn-copy" data-token="${token.token}">Copy Token</button>
                                    <button class="btn primary btn-view-details" data-token="${token.token}">View Details</button>
                                </div>
                            `;
                            
                            tokenListElement.appendChild(tokenCard);
                        });
                        
                        // Add event listeners for token actions
                        document.querySelectorAll('.btn-copy').forEach(button => {
                            button.addEventListener('click', () => {
                                const tokenValue = button.getAttribute('data-token');
                                navigator.clipboard.writeText(tokenValue)
                                    .then(() => {
                                        button.textContent = 'Copied!';
                                        setTimeout(() => {
                                            button.textContent = 'Copy Token';
                                        }, 2000);
                                    })
                                    .catch(err => {
                                        Logger.error(`Copy failed: ${err}`);
                                        alert('Failed to copy token. Please try again.');
                                    });
                            });
                        });
                        
                        document.querySelectorAll('.btn-view-details').forEach(button => {
                            button.addEventListener('click', () => {
                                const tokenValue = button.getAttribute('data-token');
                                // Redirect to token details page
                                window.location.href = `token-details.html?token=${tokenValue}`;
                            });
                        });
                    } else {
                        // Show empty state
                        if (emptyTokenState) {
                            emptyTokenState.style.display = 'block';
                        }
                    }
                }
            } else {
                Logger.error(`Failed to load tokens: ${data.error}`);
                alert(data.error || 'Failed to load tokens. Please try again.');
            }
        } catch (error) {
            Logger.error(`Error loading tokens: ${error.message}`);
            alert('An error occurred while loading tokens. Please try again.');
        }
    };
    
    // Load user documents
    const loadUserDocuments = async () => {
        try {
            const response = await fetch(`${API_URL}/user/documents`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${userData.token}`
                }
            });
            
            const data = await response.json();
            
            if (response.ok) {
                Logger.info(`Loaded ${data.documents.length} documents for user`);
                
                // Update document count
                const documentCountElement = document.getElementById('documentCount');
                if (documentCountElement) {
                    documentCountElement.textContent = data.documents.length;
                }
                
                // Display documents
                const documentListElement = document.getElementById('documentList');
                const emptyDocState = document.getElementById('emptyDocState');
                
                if (documentListElement) {
                    if (data.documents.length > 0) {
                        // Hide empty state
                        if (emptyDocState) {
                            emptyDocState.style.display = 'none';
                        }
                        
                        // Clear existing documents
                        documentListElement.innerHTML = '';
                        
                        // Add each document
                        data.documents.forEach(doc => {
                            const docCard = document.createElement('div');
                            docCard.className = 'document-card';
                            docCard.innerHTML = `
                                <h3>${doc.title}</h3>
                                <p>Type: ${doc.type}</p>
                                <p>Uploaded: ${new Date(doc.uploaded_at).toLocaleString()}</p>
                                <div class="document-actions">
                                    <button class="btn secondary btn-view-doc" data-doc-id="${doc.id}">View Document</button>
                                    <button class="btn primary btn-download-doc" data-doc-id="${doc.id}">Download</button>
                                </div>
                            `;
                            
                            documentListElement.appendChild(docCard);
                        });
                        
                        // Add event listeners for document actions
                        document.querySelectorAll('.btn-view-doc').forEach(button => {
                            button.addEventListener('click', () => {
                                const docId = button.getAttribute('data-doc-id');
                                // Open document viewer
                                window.open(`document-viewer.html?id=${docId}`, '_blank');
                            });
                        });
                        
                        document.querySelectorAll('.btn-download-doc').forEach(button => {
                            button.addEventListener('click', async () => {
                                const docId = button.getAttribute('data-doc-id');
                                try {
                                    const response = await fetch(`${API_URL}/user/documents/${docId}/download`, {
                                        method: 'GET',
                                        headers: {
                                            'Authorization': `Bearer ${userData.token}`
                                        }
                                    });
                                    
                                    if (response.ok) {
                                        const blob = await response.blob();
                                        const url = window.URL.createObjectURL(blob);
                                        const a = document.createElement('a');
                                        a.style.display = 'none';
                                        a.href = url;
                                        a.download = `document-${docId}.pdf`;
                                        document.body.appendChild(a);
                                        a.click();
                                        window.URL.revokeObjectURL(url);
                                    } else {
                                        const data = await response.json();
                                        Logger.error(`Failed to download document: ${data.error}`);
                                        alert(data.error || 'Failed to download document. Please try again.');
                                    }
                                } catch (error) {
                                    Logger.error(`Error downloading document: ${error.message}`);
                                    alert('An error occurred while downloading the document. Please try again.');
                                }
                            });
                        });
                    } else {
                        // Show empty state
                        if (emptyDocState) {
                            emptyDocState.style.display = 'block';
                        }
                    }
                }
            } else {
                Logger.error(`Failed to load documents: ${data.error}`);
                alert(data.error || 'Failed to load documents. Please try again.');
            }
        } catch (error) {
            Logger.error(`Error loading documents: ${error.message}`);
            alert('An error occurred while loading documents. Please try again.');
        }
    };
    
    // Update token status
    const updateTokenStatus = () => {
        const tokenStatusElement = document.getElementById('tokenStatus');
        if (tokenStatusElement) {
            // In a real app, this would be based on actual token status
            tokenStatusElement.textContent = 'Active';
        }
    };
    
    // Document upload modal
    const uploadModal = document.getElementById('uploadModal');
    const uploadDocBtn = document.getElementById('uploadDocBtn');
    const uploadDocBtnEmpty = document.getElementById('uploadDocBtnEmpty');
    const closeModalBtns = document.querySelectorAll('.close');
    
    if (uploadModal && uploadDocBtn) {
        uploadDocBtn.addEventListener('click', () => {
            uploadModal.style.display = 'block';
        });
        
        if (uploadDocBtnEmpty) {
            uploadDocBtnEmpty.addEventListener('click', () => {
                uploadModal.style.display = 'block';
            });
        }
    }
    
    // Edit profile modal
    const editProfileModal = document.getElementById('editProfileModal');
    const editProfileBtn = document.getElementById('editProfileBtn');
    
    if (editProfileModal && editProfileBtn) {
        editProfileBtn.addEventListener('click', () => {
            editProfileModal.style.display = 'block';
        });
    }
    
    // Close modals
    if (closeModalBtns) {
        closeModalBtns.forEach(btn => {
            btn.addEventListener('click', function() {
                const modal = this.closest('.modal');
                if (modal) {
                    modal.style.display = 'none';
                }
            });
        });
        
        window.addEventListener('click', (event) => {
            if (event.target === uploadModal) {
                uploadModal.style.display = 'none';
            }
            if (event.target === editProfileModal) {
                editProfileModal.style.display = 'none';
            }
        });
    }
    
    // Document upload form
    const documentUploadForm = document.getElementById('documentUploadForm');
    if (documentUploadForm) {
        documentUploadForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            Logger.info('Document upload form submitted');
            
            const docTitle = document.getElementById('docTitle').value;
            const docType = document.getElementById('docType').value;
            const docFile = document.getElementById('docFile').files[0];
            
            if (!docFile) {
                alert('Please select a file to upload');
                return;
            }
            
            try {
                // Show loading state
                const submitBtn = documentUploadForm.querySelector('button[type="submit"]');
                const originalBtnText = submitBtn.textContent;
                submitBtn.disabled = true;
                submitBtn.textContent = 'Uploading...';
                
                // Create form data
                const formData = new FormData();
                formData.append('title', docTitle);
                formData.append('type', docType);
                formData.append('file', docFile);
                
                const response = await fetch(`${API_URL}/user/documents/upload`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${userData.token}`
                    },
                    body: formData
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    Logger.info('Document uploaded successfully');
                    alert('Document uploaded successfully');
                    
                    // Close modal
                    uploadModal.style.display = 'none';
                    
                    // Reset form
                    documentUploadForm.reset();
                    
                    // Reload documents
                    loadUserDocuments();
                } else {
                    Logger.error(`Failed to upload document: ${data.error}`);
                    alert(data.error || 'Failed to upload document. Please try again.');
                }
                
                // Reset button state
                submitBtn.disabled = false;
                submitBtn.textContent = originalBtnText;
            } catch (error) {
                Logger.error(`Error uploading document: ${error.message}`);
                alert('An error occurred while uploading the document. Please try again.');
                
                // Reset button state
                const submitBtn = documentUploadForm.querySelector('button[type="submit"]');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Upload Document';
            }
        });
    }
    
    // Profile edit form
    const profileForm = document.getElementById('profileForm');
    if (profileForm) {
        profileForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            Logger.info('Profile form submitted');
            
            const formData = {
                name: document.getElementById('fullName').value,
                email: document.getElementById('email').value,
                phone: document.getElementById('phone').value,
                dob: document.getElementById('dob').value
            };
            
            try {
                // Show loading state
                const submitBtn = profileForm.querySelector('button[type="submit"]');
                const originalBtnText = submitBtn.textContent;
                submitBtn.disabled = true;
                submitBtn.textContent = 'Saving...';
                
                const response = await fetch(`${API_URL}/user/profile`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${userData.token}`
                    },
                    body: JSON.stringify(formData)
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    Logger.info('Profile updated successfully');
                    alert('Profile updated successfully');
                    
                    // Close modal
                    editProfileModal.style.display = 'none';
                    
                    // Update user name in localStorage
                    const updatedUserData = JSON.parse(localStorage.getItem('currentUser'));
                    updatedUserData.name = formData.name;
                    localStorage.setItem('currentUser', JSON.stringify(updatedUserData));
                    
                    // Update user name in the profile
                    if (userNameElement) {
                        userNameElement.textContent = formData.name;
                    }
                    
                    // Reload profile data
                    loadUserProfile();
                } else {
                    Logger.error(`Failed to update profile: ${data.error}`);
                    alert(data.error || 'Failed to update profile. Please try again.');
                }
                
                // Reset button state
                submitBtn.disabled = false;
                submitBtn.textContent = originalBtnText;
            } catch (error) {
                Logger.error(`Error updating profile: ${error.message}`);
                alert('An error occurred while updating profile. Please try again.');
                
                // Reset button state
                const submitBtn = profileForm.querySelector('button[type="submit"]');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Save Changes';
            }
        });
    }
    
    // Security form
    const securityForm = document.getElementById('securityForm');
    if (securityForm) {
        securityForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            Logger.info('Security form submitted');
            
            const currentPassword = document.getElementById('currentPassword').value;
            const newPassword = document.getElementById('newPassword').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            
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
                
                const response = await fetch(`${API_URL}/user/password`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${userData.token}`
                    },
                    body: JSON.stringify({
                        current_password: currentPassword,
                        new_password: newPassword
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    Logger.info('Password updated successfully');
                    alert('Password updated successfully');
                    
                    // Reset form
                    securityForm.reset();
                } else {
                    Logger.error(`Failed to update password: ${data.error}`);
                    alert(data.error || 'Failed to update password. Please try again.');
                }
                
                // Reset button state
                submitBtn.disabled = false;
                submitBtn.textContent = originalBtnText;
            } catch (error) {
                Logger.error(`Error updating password: ${error.message}`);
                alert('An error occurred while updating password. Please try again.');
                
                // Reset button state
                const submitBtn = securityForm.querySelector('button[type="submit"]');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Update Password';
            }
        });
    }
    
    // Load user data
    loadUserProfile();
    loadUserTokens();
    loadUserDocuments();
    updateTokenStatus();
    
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