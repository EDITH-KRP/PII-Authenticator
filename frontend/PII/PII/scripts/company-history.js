// Company Validation History Scripts
document.addEventListener('DOMContentLoaded', () => {
    // Initialize logger
    Logger.info('Company validation history page loaded');
    
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
    
    // Pagination variables
    let currentPage = 1;
    const itemsPerPage = 10;
    let totalPages = 1;
    let allValidations = [];
    
    // Filter variables
    let dateFilter = 'all';
    let statusFilter = 'all';
    let searchQuery = '';
    
    // Load validation history
    const loadValidationHistory = async () => {
        try {
            const response = await fetch(`${API_URL}/company/validations/all`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${companyData.token}`
                }
            });
            
            const data = await response.json();
            
            if (response.ok) {
                Logger.info(`Loaded ${data.validations.length} validations`);
                
                // Store all validations
                allValidations = data.validations;
                
                // Apply filters and display
                applyFiltersAndDisplay();
            } else {
                Logger.error(`Failed to load validation history: ${data.error}`);
                alert(data.error || 'Failed to load validation history. Please try again.');
            }
        } catch (error) {
            Logger.error(`Error loading validation history: ${error.message}`);
            alert('An error occurred while loading validation history. Please try again.');
        }
    };
    
    // Apply filters and display validations
    const applyFiltersAndDisplay = () => {
        // Apply date filter
        let filteredValidations = allValidations;
        
        if (dateFilter !== 'all') {
            const now = new Date();
            const today = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime() / 1000;
            const weekAgo = today - (7 * 24 * 60 * 60);
            const monthAgo = today - (30 * 24 * 60 * 60);
            
            filteredValidations = filteredValidations.filter(validation => {
                const timestamp = validation.timestamp;
                
                if (dateFilter === 'today') {
                    return timestamp >= today;
                } else if (dateFilter === 'week') {
                    return timestamp >= weekAgo;
                } else if (dateFilter === 'month') {
                    return timestamp >= monthAgo;
                }
                
                return true;
            });
        }
        
        // Apply status filter
        if (statusFilter !== 'all') {
            filteredValidations = filteredValidations.filter(validation => {
                if (statusFilter === 'valid') {
                    return validation.is_valid;
                } else if (statusFilter === 'invalid') {
                    return !validation.is_valid;
                }
                
                return true;
            });
        }
        
        // Apply search query
        if (searchQuery) {
            const query = searchQuery.toLowerCase();
            filteredValidations = filteredValidations.filter(validation => {
                return validation.token.toLowerCase().includes(query) || 
                       validation.id.toLowerCase().includes(query);
            });
        }
        
        // Calculate total pages
        totalPages = Math.max(1, Math.ceil(filteredValidations.length / itemsPerPage));
        
        // Adjust current page if needed
        if (currentPage > totalPages) {
            currentPage = totalPages;
        }
        
        // Update page info
        const pageInfoElement = document.getElementById('pageInfo');
        if (pageInfoElement) {
            pageInfoElement.textContent = `Page ${currentPage} of ${totalPages}`;
        }
        
        // Get current page items
        const startIndex = (currentPage - 1) * itemsPerPage;
        const endIndex = startIndex + itemsPerPage;
        const currentItems = filteredValidations.slice(startIndex, endIndex);
        
        // Display validations
        displayValidations(currentItems, filteredValidations.length);
    };
    
    // Display validations in the table
    const displayValidations = (validations, totalCount) => {
        const tableBodyElement = document.getElementById('historyTableBody');
        const emptyStateElement = document.getElementById('emptyHistoryState');
        
        if (tableBodyElement) {
            if (validations.length > 0) {
                // Hide empty state
                if (emptyStateElement) {
                    emptyStateElement.style.display = 'none';
                }
                
                // Clear existing rows
                tableBodyElement.innerHTML = '';
                
                // Add each validation
                validations.forEach(validation => {
                    const row = document.createElement('tr');
                    
                    row.innerHTML = `
                        <td>${new Date(validation.timestamp * 1000).toLocaleString()}</td>
                        <td>${validation.token}</td>
                        <td>${validation.purpose || 'N/A'}</td>
                        <td><span class="validation-status ${validation.is_valid ? 'status-valid' : 'status-invalid'}">${validation.is_valid ? 'Valid' : 'Invalid'}</span></td>
                        <td>
                            <button class="btn secondary btn-view-details" data-id="${validation.id}">View Details</button>
                        </td>
                    `;
                    
                    tableBodyElement.appendChild(row);
                });
                
                // Add event listeners for view details buttons
                document.querySelectorAll('.btn-view-details').forEach(button => {
                    button.addEventListener('click', () => {
                        const validationId = button.getAttribute('data-id');
                        // Redirect to validation details page
                        window.location.href = `validation-details.html?id=${validationId}`;
                    });
                });
            } else {
                // Show empty state
                if (emptyStateElement) {
                    emptyStateElement.style.display = 'block';
                }
                
                // Clear table
                tableBodyElement.innerHTML = '';
            }
        }
    };
    
    // Event listeners for filters
    const dateFilterElement = document.getElementById('dateFilter');
    if (dateFilterElement) {
        dateFilterElement.addEventListener('change', () => {
            dateFilter = dateFilterElement.value;
            currentPage = 1;
            applyFiltersAndDisplay();
        });
    }
    
    const statusFilterElement = document.getElementById('statusFilter');
    if (statusFilterElement) {
        statusFilterElement.addEventListener('change', () => {
            statusFilter = statusFilterElement.value;
            currentPage = 1;
            applyFiltersAndDisplay();
        });
    }
    
    const searchInputElement = document.getElementById('searchInput');
    if (searchInputElement) {
        searchInputElement.addEventListener('input', () => {
            searchQuery = searchInputElement.value;
            currentPage = 1;
            applyFiltersAndDisplay();
        });
    }
    
    // Pagination event listeners
    const prevPageButton = document.getElementById('prevPage');
    if (prevPageButton) {
        prevPageButton.addEventListener('click', () => {
            if (currentPage > 1) {
                currentPage--;
                applyFiltersAndDisplay();
            }
        });
    }
    
    const nextPageButton = document.getElementById('nextPage');
    if (nextPageButton) {
        nextPageButton.addEventListener('click', () => {
            if (currentPage < totalPages) {
                currentPage++;
                applyFiltersAndDisplay();
            }
        });
    }
    
    // Load validation history
    loadValidationHistory();
    
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