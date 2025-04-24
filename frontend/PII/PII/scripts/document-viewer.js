// Document Viewer Scripts
document.addEventListener('DOMContentLoaded', () => {
    // Initialize logger
    Logger.info('Document viewer page loaded');
    
    // Check if user is logged in
    const currentUser = localStorage.getItem('currentUser');
    if (!currentUser) {
        Logger.info('User not logged in, redirecting to login page');
        window.location.href = 'login.html';
        return;
    }
    
    // Parse user data
    const userData = JSON.parse(currentUser);
    
    // API URL - Use absolute URL
    const API_URL = 'http://127.0.0.1:5000';
    
    // Get document ID from URL
    const urlParams = new URLSearchParams(window.location.search);
    const documentId = urlParams.get('id');
    
    if (!documentId) {
        showError('No document ID provided');
        return;
    }
    
    // Check if server is running before loading document
    async function checkServerStatus() {
        try {
            const response = await fetch(`${API_URL}/health`, { method: 'GET' });
            if (response.ok) {
                Logger.info('Backend server is running');
                // Server is running, load document
                loadDocument(documentId);
            } else {
                Logger.error('Backend server returned an error');
                showError('Error connecting to the server. Please make sure the backend server is running.');
            }
        } catch (error) {
            Logger.error(`Server check failed: ${error.message}`);
            showError('Cannot connect to the backend server. Please make sure the server is running.');
        }
    }
    
    // Initialize
    checkServerStatus();
    
    // Download button event listener
    const downloadBtn = document.getElementById('downloadBtn');
    if (downloadBtn) {
        downloadBtn.addEventListener('click', () => {
            downloadDocument(documentId);
        });
    }
    
    // Function to load document
    async function loadDocument(docId) {
        try {
            // Show loading state
            document.getElementById('loadingState').style.display = 'flex';
            document.getElementById('documentViewer').style.display = 'none';
            document.getElementById('errorState').style.display = 'none';
            
            // Fetch document details
            const response = await fetch(`${API_URL}/user/documents/${docId}`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${userData.token}`
                }
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to load document');
            }
            
            const documentData = await response.json();
            
            // Update document details
            document.getElementById('documentTitle').textContent = documentData.title || 'Untitled Document';
            document.getElementById('documentType').textContent = documentData.type || 'Unknown';
            document.getElementById('uploadDate').textContent = new Date(documentData.uploaded_at).toLocaleString();
            document.getElementById('documentId').textContent = documentData.id;
            document.getElementById('fileSize').textContent = documentData.file_size || 'Unknown';
            
            // Update blockchain info
            if (documentData.tx_hash) {
                const txHashLink = document.getElementById('txHashLink');
                txHashLink.textContent = documentData.tx_hash;
                txHashLink.href = `https://sepolia.etherscan.io/tx/${documentData.tx_hash}`;
            }
            
            // Check if document has a preview
            if (documentData.preview_url) {
                // Show preview based on file type
                const fileType = documentData.file_type?.toLowerCase() || '';
                
                if (fileType.includes('image') || fileType.includes('jpg') || fileType.includes('jpeg') || fileType.includes('png')) {
                    // Show image preview
                    const documentImage = document.getElementById('documentImage');
                    documentImage.src = documentData.preview_url;
                    documentImage.style.display = 'block';
                    document.getElementById('documentPlaceholder').style.display = 'none';
                    document.getElementById('documentFrame').style.display = 'none';
                } else if (fileType.includes('pdf')) {
                    // Show PDF preview
                    const documentFrame = document.getElementById('documentFrame');
                    documentFrame.src = documentData.preview_url;
                    documentFrame.style.display = 'block';
                    document.getElementById('documentPlaceholder').style.display = 'none';
                    document.getElementById('documentImage').style.display = 'none';
                } else {
                    // No preview available
                    document.getElementById('documentPlaceholder').style.display = 'block';
                    document.getElementById('documentImage').style.display = 'none';
                    document.getElementById('documentFrame').style.display = 'none';
                }
            } else {
                // No preview available
                document.getElementById('documentPlaceholder').style.display = 'block';
                document.getElementById('documentImage').style.display = 'none';
                document.getElementById('documentFrame').style.display = 'none';
            }
            
            // Show document viewer
            document.getElementById('loadingState').style.display = 'none';
            document.getElementById('documentViewer').style.display = 'block';
            
            Logger.info(`Document loaded: ${documentData.id}`);
        } catch (error) {
            Logger.error(`Error loading document: ${error.message}`);
            
            // Provide more detailed error message
            let errorMessage = error.message;
            if (error.message === 'Failed to fetch') {
                errorMessage = 'Failed to connect to the server. Please make sure the backend server is running.';
            }
            
            // Log additional debug information
            console.error('Error details:', error);
            console.log('Document ID:', docId);
            console.log('Current user token:', userData.token);
            
            showError(errorMessage);
        }
    }
    
    // Function to download document
    async function downloadDocument(docId) {
        try {
            Logger.info(`Downloading document: ${docId}`);
            
            // Show loading state on button
            const downloadBtn = document.getElementById('downloadBtn');
            const originalText = downloadBtn.textContent;
            downloadBtn.disabled = true;
            downloadBtn.textContent = 'Downloading...';
            
            const response = await fetch(`${API_URL}/user/documents/${docId}/download`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${userData.token}`
                }
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to download document');
            }
            
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = `document-${docId}.pdf`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            
            // Reset button state
            downloadBtn.disabled = false;
            downloadBtn.textContent = originalText;
            
            Logger.info(`Document downloaded: ${docId}`);
        } catch (error) {
            Logger.error(`Error downloading document: ${error.message}`);
            alert(`Error: ${error.message}`);
            
            // Reset button state
            const downloadBtn = document.getElementById('downloadBtn');
            downloadBtn.disabled = false;
            downloadBtn.textContent = 'Download';
        }
    }
    
    // Function to show error
    function showError(message) {
        document.getElementById('loadingState').style.display = 'none';
        document.getElementById('documentViewer').style.display = 'none';
        document.getElementById('errorState').style.display = 'block';
        document.getElementById('errorMessage').textContent = message || 'An error occurred while loading the document.';
        Logger.error(`Document viewer error: ${message}`);
    }
});