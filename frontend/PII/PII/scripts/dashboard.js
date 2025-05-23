// User Dashboard Scripts
document.addEventListener('DOMContentLoaded', () => {
    // Initialize logger
    Logger.info('User dashboard page loaded');
    
    // Check if user is logged in
    const currentUser = localStorage.getItem('currentUser');
    if (!currentUser) {
        Logger.info('User not logged in, redirecting to login page');
        window.location.href = 'login.html';
        return;
    }
    
    // Parse user data
    const userData = JSON.parse(currentUser);
    
    // Update user name in the dashboard
    const userNameElement = document.getElementById('userName');
    if (userNameElement) {
        userNameElement.textContent = userData.name;
    }
    
    // API URL - Use absolute URL
    const API_URL = 'http://127.0.0.1:5000';
    
    // Load user documents
    const loadUserDocuments = async () => {
        return new Promise(async (resolve, reject) => {
            try {
                // Use the JWT token directly without modification
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
                                    // Open document viewer in the same window
                                    window.location.href = `document-viewer.html?id=${docId}`;
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
                    resolve(data.documents.length);
                } else {
                    Logger.error(`Failed to load documents: ${data.error}`);
                    alert(`Error loading documents: ${data.error}`);
                    resolve(0);
                }
            } catch (error) {
                Logger.error(`Error loading documents: ${error.message}`);
                
                // Provide more detailed error message
                let errorMessage = error.message;
                if (error.message === 'Failed to fetch') {
                    errorMessage = 'Failed to connect to the server. Please make sure the backend server is running.';
                }
                
                alert(`Error loading documents: ${errorMessage}`);
                
                // Log additional debug information
                console.error('Error details:', error);
                console.log('Current user token:', userData.token);
                
                resolve(0);
            }
        });
    };
    
    // Show empty documents state
    const showEmptyDocumentsState = () => {
        Logger.info('No documents found, showing empty state');
        
        // Update document count
        const documentCountElement = document.getElementById('documentCount');
        if (documentCountElement) {
            documentCountElement.textContent = '0';
        }
        
        // Display empty state
        const documentListElement = document.getElementById('documentList');
        const emptyDocState = document.getElementById('emptyDocState');
        
        if (documentListElement) {
            // Clear existing documents
            documentListElement.innerHTML = '';
            
            // Show empty state
            if (emptyDocState) {
                emptyDocState.style.display = 'block';
            }
        }
    };
    
    // Update account status
    const updateAccountStatus = () => {
        const accountStatusElement = document.getElementById('accountStatus');
        if (accountStatusElement) {
            accountStatusElement.textContent = 'Active';
        }
        
        // Set last login date
        const lastLoginElement = document.getElementById('lastLogin');
        if (lastLoginElement) {
            const now = new Date();
            lastLoginElement.textContent = now.toLocaleDateString();
        }
    };
    
    // Document upload modal
    const uploadModal = document.getElementById('uploadModal');
    const uploadDocBtn = document.getElementById('uploadDocBtn');
    const closeUploadModalBtn = document.querySelector('#uploadModal .close');
    
    if (uploadModal && closeUploadModalBtn) {
        // Add event listener to the upload button if it exists
        if (uploadDocBtn) {
            uploadDocBtn.addEventListener('click', (e) => {
                e.preventDefault();
                uploadModal.style.display = 'block';
                console.log('Upload modal opened');
            });
        }
        
        closeUploadModalBtn.addEventListener('click', () => {
            uploadModal.style.display = 'none';
        });
        
        // Close modal when clicking outside
        window.addEventListener('click', (event) => {
            if (event.target === uploadModal) {
                uploadModal.style.display = 'none';
            }
        });
    }
    
    // Document upload form
    const documentUploadForm = document.getElementById('documentUploadForm');
    if (documentUploadForm) {
        console.log('Document upload form found, adding submit listener');
        documentUploadForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            console.log('Document upload form submitted');
            Logger.info('Document upload form submitted');
            
            const docTitle = document.getElementById('docTitle').value;
            const docType = document.getElementById('docType').value;
            const docFile = document.getElementById('docFile').files[0];
            
            if (!docFile) {
                alert('Please select a file to upload');
                return;
            }
            
            // Check file size (max 10MB)
            const maxSize = 10 * 1024 * 1024; // 10MB in bytes
            if (docFile.size > maxSize) {
                alert('File is too large. Maximum size is 10MB.');
                return;
            }
            
            // Disable submit button and show loading state
            const submitBtn = documentUploadForm.querySelector('button[type="submit"]');
            const originalBtnText = submitBtn.textContent;
            submitBtn.disabled = true;
            submitBtn.textContent = 'Uploading...';
            
            try {
                // Show progress message
                submitBtn.textContent = 'Uploading document...';
                
                // Create form data
                const formData = new FormData();
                formData.append('title', docTitle);
                formData.append('type', docType);
                formData.append('file', docFile);
                
                // Make API call to upload document
                Logger.info(`Uploading document: ${docTitle}, type: ${docType}`);
                
                const response = await fetch(`${API_URL}/user/documents/upload`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${userData.token}`
                    },
                    body: formData
                });
                
                let data;
                try {
                    data = await response.json();
                } catch (e) {
                    Logger.error(`Error parsing response: ${e.message}`);
                    throw new Error('Server error. Could not parse response.');
                }
                
                if (response.ok) {
                    Logger.info('Document uploaded successfully');
                    Logger.info(`Transaction hash: ${data.tx_hash}`);
                    
                    // Close modal
                    uploadModal.style.display = 'none';
                    
                    // Reset form
                    documentUploadForm.reset();
                    
                    // Reload documents
                    loadUserDocuments();
                    
                    // Show success message with blockchain transaction details
                    alert(`Document uploaded successfully!\n\nBlockchain Transaction: ${data.tx_hash}\n\nYour document has been encrypted and stored securely.`);
                } else {
                    Logger.error(`Document upload failed: ${data.error}`);
                    throw new Error(data.error || 'Failed to upload document. Please try again.');
                }
            } catch (error) {
                Logger.error(`Error uploading document: ${error.message}`);
                alert(`Error: ${error.message}`);
            } finally {
                // Reset button state
                submitBtn.disabled = false;
                submitBtn.textContent = originalBtnText;
            }
        });
    }
    
    // Copy token button
    document.addEventListener('click', (e) => {
        if (e.target && e.target.id === 'copyTokenBtn') {
            const tokenValue = document.getElementById('tokenValue').textContent;
            navigator.clipboard.writeText(tokenValue)
                .then(() => {
                    e.target.textContent = 'Copied!';
                    setTimeout(() => {
                        e.target.textContent = 'Copy';
                    }, 2000);
                })
                .catch(err => {
                    Logger.error(`Copy failed: ${err}`);
                    alert('Failed to copy token. Please try again.');
                });
                // Create a modified token that includes the user ID
                const modifiedToken = `${userData.id}:${userData.token}`;
                
        }
    });
    
    // Update Etherscan link
    document.addEventListener('DOMNodeInserted', (e) => {
        const txHashValue = document.getElementById('txHashValue');
        const viewOnEtherscan = document.getElementById('viewOnEtherscan');
        
        if (txHashValue && viewOnEtherscan && txHashValue.textContent) {
            viewOnEtherscan.href = `https://sepolia.etherscan.io/tx/${txHashValue.textContent}`;
        }
    });
    
    // Document scanner functionality removed
    
    // Check if server is running before loading documents
    async function checkServerStatus() {
        try {
            const response = await fetch(`${API_URL}/health`, { method: 'GET' });
            if (response.ok) {
                Logger.info('Backend server is running');
                // Server is running, load documents
                loadUserDocuments();
                updateAccountStatus();
            } else {
                Logger.error('Backend server returned an error');
                alert('Error connecting to the server. Please make sure the backend server is running.');
            }
        } catch (error) {
            Logger.error(`Server check failed: ${error.message}`);
            alert('Cannot connect to the backend server. Please make sure the server is running.');
        }
    }
    
    // Initialize
    checkServerStatus();
});