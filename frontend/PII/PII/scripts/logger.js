/**
 * Frontend logging utility for PII Authenticator
 * Provides client-side logging with server sync capabilities
 */

// Log levels
const LOG_LEVELS = {
    DEBUG: 0,
    INFO: 1,
    WARN: 2,
    ERROR: 3
};

// Current log level (can be changed at runtime)
let currentLogLevel = LOG_LEVELS.INFO;

// Backend API URL
const API_URL = 'http://127.0.0.1:5000';

// In-memory log storage
const logHistory = [];

// Maximum number of logs to keep in memory
const MAX_LOG_HISTORY = 100;

/**
 * Format a log message with timestamp and level
 * @param {string} level - The log level
 * @param {string} message - The log message
 * @returns {string} - Formatted log message
 */
function formatLogMessage(level, message) {
    const timestamp = new Date().toISOString();
    return `${timestamp} [${level}] ${message}`;
}

/**
 * Add a log entry to the in-memory history
 * @param {string} level - The log level
 * @param {string} message - The log message
 * @param {Object} data - Additional data to log
 */
function addToHistory(level, message, data) {
    // Add to history
    logHistory.push({
        timestamp: new Date().toISOString(),
        level,
        message,
        data
    });
    
    // Trim history if needed
    if (logHistory.length > MAX_LOG_HISTORY) {
        logHistory.shift();
    }
}

/**
 * Send logs to the backend server
 * @param {Array} logs - Array of log entries to send
 * @returns {Promise} - Promise that resolves when logs are sent
 */
async function sendLogsToServer(logs) {
    try {
        // This is a placeholder - in a real app, you would implement
        // a backend endpoint to receive and store logs
        const response = await fetch(`${API_URL}/client_logs`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ logs })
        });
        
        return response.ok;
    } catch (error) {
        console.error('Failed to send logs to server:', error);
        return false;
    }
}

/**
 * Log a debug message
 * @param {string} message - The message to log
 * @param {Object} data - Additional data to log
 */
function debug(message, data = null) {
    if (currentLogLevel <= LOG_LEVELS.DEBUG) {
        const formattedMessage = formatLogMessage('DEBUG', message);
        console.debug(formattedMessage, data || '');
        addToHistory('DEBUG', message, data);
    }
}

/**
 * Log an info message
 * @param {string} message - The message to log
 * @param {Object} data - Additional data to log
 */
function info(message, data = null) {
    if (currentLogLevel <= LOG_LEVELS.INFO) {
        const formattedMessage = formatLogMessage('INFO', message);
        console.info(formattedMessage, data || '');
        addToHistory('INFO', message, data);
    }
}

/**
 * Log a warning message
 * @param {string} message - The message to log
 * @param {Object} data - Additional data to log
 */
function warn(message, data = null) {
    if (currentLogLevel <= LOG_LEVELS.WARN) {
        const formattedMessage = formatLogMessage('WARN', message);
        console.warn(formattedMessage, data || '');
        addToHistory('WARN', message, data);
    }
}

/**
 * Log an error message
 * @param {string} message - The message to log
 * @param {Object} data - Additional data to log
 */
function error(message, data = null) {
    if (currentLogLevel <= LOG_LEVELS.ERROR) {
        const formattedMessage = formatLogMessage('ERROR', message);
        console.error(formattedMessage, data || '');
        addToHistory('ERROR', message, data);
    }
}

/**
 * Log a user action
 * @param {string} action - The action performed
 * @param {Object} details - Details about the action
 */
function logUserAction(action, details = {}) {
    info(`User Action: ${action}`, details);
    
    // You could send important user actions to the server immediately
    // sendLogsToServer([{ level: 'INFO', message: `User Action: ${action}`, data: details }]);
}

/**
 * Set the current log level
 * @param {string} level - The log level to set
 */
function setLogLevel(level) {
    if (LOG_LEVELS[level] !== undefined) {
        currentLogLevel = LOG_LEVELS[level];
        info(`Log level set to ${level}`);
    } else {
        warn(`Invalid log level: ${level}`);
    }
}

/**
 * Get all logs from history
 * @returns {Array} - Array of log entries
 */
function getLogs() {
    return [...logHistory];
}

/**
 * Clear the log history
 */
function clearLogs() {
    logHistory.length = 0;
    info('Log history cleared');
}

// Export the logger functions
const Logger = {
    debug,
    info,
    warn,
    error,
    logUserAction,
    setLogLevel,
    getLogs,
    clearLogs,
    sendLogsToServer,
    LOG_LEVELS
};

// Make logger available globally
window.Logger = Logger;