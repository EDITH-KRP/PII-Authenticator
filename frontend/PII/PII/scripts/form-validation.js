// Form Validation Utilities
const FormValidator = {
    // Validate email format (must end with .com, .in, .org, .edu, .gov, .net)
    validateEmail: function(email) {
        const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(com|in|org|edu|gov|net)$/;
        return emailRegex.test(email);
    },
    
    // Validate phone number (10 digits)
    validatePhone: function(phone) {
        const phoneRegex = /^\d{10}$/;
        return phoneRegex.test(phone);
    },
    
    // Validate Aadhaar number (12 digits)
    validateAadhaar: function(aadhaar) {
        const aadhaarRegex = /^\d{12}$/;
        return aadhaarRegex.test(aadhaar);
    },
    
    // Validate PAN number (10 alphanumeric characters in specific format)
    validatePAN: function(pan) {
        const panRegex = /^[A-Z]{5}[0-9]{4}[A-Z]{1}$/;
        return panRegex.test(pan);
    },
    
    // Validate password strength
    validatePassword: function(password) {
        // At least 8 characters, 1 uppercase, 1 lowercase, 1 number, 1 special character
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        return passwordRegex.test(password);
    },
    
    // Get password strength message
    getPasswordStrength: function(password) {
        if (!password) return { strength: 0, message: "No password entered" };
        
        let strength = 0;
        let message = "";
        
        // Check length
        if (password.length >= 8) strength += 1;
        
        // Check for uppercase
        if (/[A-Z]/.test(password)) strength += 1;
        
        // Check for lowercase
        if (/[a-z]/.test(password)) strength += 1;
        
        // Check for numbers
        if (/\d/.test(password)) strength += 1;
        
        // Check for special characters
        if (/[@$!%*?&]/.test(password)) strength += 1;
        
        // Determine message based on strength
        if (strength === 0 || strength === 1) {
            message = "Very weak";
        } else if (strength === 2) {
            message = "Weak";
        } else if (strength === 3) {
            message = "Medium";
        } else if (strength === 4) {
            message = "Strong";
        } else {
            message = "Very strong";
        }
        
        return { strength, message };
    },
    
    // Show validation error
    showError: function(inputElement, message) {
        // Remove any existing error message
        this.clearError(inputElement);
        
        // Create error message element
        const errorElement = document.createElement('div');
        errorElement.className = 'validation-error';
        errorElement.textContent = message;
        
        // Insert error message after input
        inputElement.parentNode.insertBefore(errorElement, inputElement.nextSibling);
        
        // Add error class to input
        inputElement.classList.add('input-error');
    },
    
    // Clear validation error
    clearError: function(inputElement) {
        // Remove error class from input
        inputElement.classList.remove('input-error');
        
        // Remove any existing error message
        const errorElement = inputElement.nextElementSibling;
        if (errorElement && errorElement.className === 'validation-error') {
            errorElement.parentNode.removeChild(errorElement);
        }
    },
    
    // Apply input masks
    applyInputMasks: function() {
        // Phone number mask
        document.querySelectorAll('input[type="tel"]').forEach(input => {
            input.addEventListener('input', function(e) {
                // Remove non-digits
                let value = this.value.replace(/\D/g, '');
                
                // Limit to 10 digits
                if (value.length > 10) {
                    value = value.slice(0, 10);
                }
                
                // Format as XXX-XXX-XXXX
                if (value.length > 6) {
                    this.value = value.slice(0, 3) + '-' + value.slice(3, 6) + '-' + value.slice(6);
                } else if (value.length > 3) {
                    this.value = value.slice(0, 3) + '-' + value.slice(3);
                } else {
                    this.value = value;
                }
            });
        });
        
        // Aadhaar number mask
        document.querySelectorAll('input[data-type="aadhaar"]').forEach(input => {
            input.addEventListener('input', function(e) {
                // Remove non-digits
                let value = this.value.replace(/\D/g, '');
                
                // Limit to 12 digits
                if (value.length > 12) {
                    value = value.slice(0, 12);
                }
                
                // Format as XXXX-XXXX-XXXX
                if (value.length > 8) {
                    this.value = value.slice(0, 4) + '-' + value.slice(4, 8) + '-' + value.slice(8);
                } else if (value.length > 4) {
                    this.value = value.slice(0, 4) + '-' + value.slice(4);
                } else {
                    this.value = value;
                }
            });
        });
        
        // PAN number mask
        document.querySelectorAll('input[data-type="pan"]').forEach(input => {
            input.addEventListener('input', function(e) {
                // Convert to uppercase
                this.value = this.value.toUpperCase();
                
                // Limit to 10 characters
                if (this.value.length > 10) {
                    this.value = this.value.slice(0, 10);
                }
            });
        });
    },
    
    // Initialize form validation
    init: function() {
        this.applyInputMasks();
        
        // Add validation for email fields
        document.querySelectorAll('input[type="email"]').forEach(input => {
            input.addEventListener('blur', function() {
                if (this.value && !FormValidator.validateEmail(this.value)) {
                    FormValidator.showError(this, 'Please enter a valid email address ending with .com, .in, .org, .edu, .gov, or .net');
                } else {
                    FormValidator.clearError(this);
                }
            });
        });
        
        // Add validation for phone fields
        document.querySelectorAll('input[type="tel"]').forEach(input => {
            input.addEventListener('blur', function() {
                // Remove formatting for validation
                const phoneValue = this.value.replace(/\D/g, '');
                if (this.value && !FormValidator.validatePhone(phoneValue)) {
                    FormValidator.showError(this, 'Please enter a valid 10-digit phone number');
                } else {
                    FormValidator.clearError(this);
                }
            });
        });
        
        // Add validation for Aadhaar fields
        document.querySelectorAll('input[data-type="aadhaar"]').forEach(input => {
            input.addEventListener('blur', function() {
                // Remove formatting for validation
                const aadhaarValue = this.value.replace(/\D/g, '');
                if (this.value && !FormValidator.validateAadhaar(aadhaarValue)) {
                    FormValidator.showError(this, 'Please enter a valid 12-digit Aadhaar number');
                } else {
                    FormValidator.clearError(this);
                }
            });
        });
        
        // Add validation for PAN fields
        document.querySelectorAll('input[data-type="pan"]').forEach(input => {
            input.addEventListener('blur', function() {
                if (this.value && !FormValidator.validatePAN(this.value)) {
                    FormValidator.showError(this, 'Please enter a valid PAN number (e.g., ABCDE1234F)');
                } else {
                    FormValidator.clearError(this);
                }
            });
        });
        
        // Add validation for password fields
        document.querySelectorAll('input[type="password"]').forEach(input => {
            // Skip confirm password fields
            if (input.id.includes('confirm') || input.name.includes('confirm')) {
                return;
            }
            
            // Create password strength indicator
            const strengthIndicator = document.createElement('div');
            strengthIndicator.className = 'password-strength';
            input.parentNode.insertBefore(strengthIndicator, input.nextSibling);
            
            input.addEventListener('input', function() {
                const strength = FormValidator.getPasswordStrength(this.value);
                
                // Update strength indicator
                strengthIndicator.textContent = strength.message;
                strengthIndicator.className = 'password-strength';
                
                // Add strength class
                if (strength.strength === 0 || strength.strength === 1) {
                    strengthIndicator.classList.add('very-weak');
                } else if (strength.strength === 2) {
                    strengthIndicator.classList.add('weak');
                } else if (strength.strength === 3) {
                    strengthIndicator.classList.add('medium');
                } else if (strength.strength === 4) {
                    strengthIndicator.classList.add('strong');
                } else {
                    strengthIndicator.classList.add('very-strong');
                }
            });
            
            input.addEventListener('blur', function() {
                if (this.value && !FormValidator.validatePassword(this.value)) {
                    FormValidator.showError(this, 'Password must be at least 8 characters with 1 uppercase, 1 lowercase, 1 number, and 1 special character');
                } else {
                    FormValidator.clearError(this);
                }
            });
        });
        
        // Add validation for confirm password fields
        document.querySelectorAll('input[id*="confirm"], input[name*="confirm"]').forEach(input => {
            input.addEventListener('blur', function() {
                // Find the password field
                let passwordField;
                if (this.id.includes('confirm')) {
                    passwordField = document.getElementById(this.id.replace('confirm', '').replace('Confirm', ''));
                } else {
                    passwordField = document.querySelector('input[type="password"]:not([name*="confirm"])');
                }
                
                if (passwordField && this.value !== passwordField.value) {
                    FormValidator.showError(this, 'Passwords do not match');
                } else {
                    FormValidator.clearError(this);
                }
            });
        });
    }
};

// Initialize form validation when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    FormValidator.init();
});