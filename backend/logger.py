"""
Logger module for the PII Authenticator application.
Provides centralized logging functionality with different log levels and formats.
"""

import os
import logging
import datetime
from logging.handlers import RotatingFileHandler

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)

# Configure the main logger
logger = logging.getLogger('pii_authenticator')
logger.setLevel(logging.DEBUG)

# Create formatters
standard_formatter = logging.Formatter(
    '%(asctime)s [%(levelname)s] %(module)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

detailed_formatter = logging.Formatter(
    '%(asctime)s [%(levelname)s] %(module)s.%(funcName)s:%(lineno)d - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Create console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(standard_formatter)
logger.addHandler(console_handler)

# Create file handlers
# Main log file - contains all logs
main_log_file = os.path.join('logs', 'pii_authenticator.log')
main_file_handler = RotatingFileHandler(
    main_log_file, maxBytes=10*1024*1024, backupCount=5
)
main_file_handler.setLevel(logging.DEBUG)
main_file_handler.setFormatter(detailed_formatter)
logger.addHandler(main_file_handler)

# Error log file - contains only errors
error_log_file = os.path.join('logs', 'errors.log')
error_file_handler = RotatingFileHandler(
    error_log_file, maxBytes=10*1024*1024, backupCount=5
)
error_file_handler.setLevel(logging.ERROR)
error_file_handler.setFormatter(detailed_formatter)
logger.addHandler(error_file_handler)

# Access log file - contains only access logs
access_log_file = os.path.join('logs', 'access.log')
access_file_handler = RotatingFileHandler(
    access_log_file, maxBytes=10*1024*1024, backupCount=5
)
access_file_handler.setLevel(logging.INFO)
access_file_handler.setFormatter(standard_formatter)

# Create a filter for access logs
class AccessLogFilter(logging.Filter):
    def filter(self, record):
        return hasattr(record, 'access_log') and record.access_log

access_file_handler.addFilter(AccessLogFilter())
logger.addHandler(access_file_handler)

# Create a function to log access attempts
def log_access(endpoint, user_id=None, token=None, ip_address=None, status=None, details=None):
    """
    Log an access attempt to the system.
    
    Args:
        endpoint (str): The API endpoint that was accessed
        user_id (str, optional): The user ID if available
        token (str, optional): The token if available
        ip_address (str, optional): The IP address of the requester
        status (str, optional): The status of the request (success/failure)
        details (str, optional): Additional details about the request
    """
    log_record = logging.LogRecord(
        name='pii_authenticator',
        level=logging.INFO,
        pathname='',
        lineno=0,
        msg=f"ACCESS: {endpoint} | User: {user_id or 'N/A'} | Token: {token or 'N/A'} | IP: {ip_address or 'N/A'} | Status: {status or 'N/A'} | Details: {details or 'N/A'}",
        args=(),
        exc_info=None
    )
    log_record.access_log = True
    
    # Pass the record to all handlers
    for handler in logger.handlers:
        if handler.level <= logging.INFO:
            handler.handle(log_record)

# Export the logger
def get_logger():
    return logger