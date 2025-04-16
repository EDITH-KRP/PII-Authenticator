// Add interactivity for buttons and animations
document.addEventListener('DOMContentLoaded', () => {
    const generateButton = document.querySelector('.btn.primary');
    const validateButton = document.querySelector('.btn.secondary');
  
    // Add loading animation on button click
    generateButton.addEventListener('click', (e) => {
      e.preventDefault();
      showLoading('Redirecting to Generate Token page...');
      setTimeout(() => {
        window.location.href = 'generate.html';
      }, 2000);
    });
  
    validateButton.addEventListener('click', (e) => {
      e.preventDefault();
      showLoading('Redirecting to Validate Token page...');
      setTimeout(() => {
        window.location.href = 'validate.html';
      }, 2000);
    });
  
    // Function to show loading animation
    function showLoading(message) {
      const loadingOverlay = document.createElement('div');
      loadingOverlay.className = 'loading-overlay';
      loadingOverlay.innerHTML = `
        <div class="spinner"></div>
        <p>${message}</p>
      `;
      document.body.appendChild(loadingOverlay);
  
      // Remove loading overlay after 3 seconds
      setTimeout(() => {
        loadingOverlay.remove();
      }, 3000);
    }
  });