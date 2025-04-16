// Animation script for blockchain and encryption animation

document.addEventListener('DOMContentLoaded', function() {
  // Create block content
  const blocks = document.querySelectorAll('.block');
  blocks.forEach((block, index) => {
    // Generate random hex for each block to simulate blockchain hashes
    const randomHex = Math.floor(Math.random() * 16777215).toString(16).padStart(6, '0');
    block.setAttribute('data-content', `#${randomHex}`);
    block.textContent = `${index + 1}`;
  });

  // Hide animation after timeout - faster now (2 seconds)
  setTimeout(() => {
    const animationContainer = document.querySelector('.animation-container');
    animationContainer.classList.add('fade-out');
    
    // Remove from DOM after fade out
    setTimeout(() => {
      animationContainer.remove();
    }, 300); // Faster fade out
  }, 2000); // Shorter display time
});

// Function to generate random encryption-like text
function generateEncryptionText() {
  const chars = '0123456789abcdefABCDEF';
  let result = '';
  for (let i = 0; i < 8; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}