# PII Authenticator Backend Testing Guide

This document provides instructions for testing the PII Authenticator backend API.

## Prerequisites

- Python 3.6+
- Required Python packages:
  - requests
  - colorama
  - argparse
  - matplotlib (for load testing)
  - numpy (for load testing)

## Manual API Testing

The `test_api.py` script provides functions to test all backend API endpoints.

### Running the Tests

1. Make sure the backend server is running:
   ```
   python app.py
   ```

2. Run the test script:
   ```
   python test_api.py
   ```
   
   Or use the provided batch file:
   ```
   run_tests.bat
   ```

### Available Tests

- **Health Check**: Tests the `/health` endpoint
- **Token Generation**: Tests the `/encrypt` endpoint
- **Token Validation**: Tests the `/validate_token` endpoint
- **Invalid Token**: Tests validation with an invalid token
- **Missing Fields**: Tests token generation with missing fields
- **Empty Token**: Tests validation with an empty token

### Command Line Options

```
python test_api.py [--url URL] [--test {all,health,generate,validate,invalid,missing,empty}] [--user-id USER_ID] [--id-number ID_NUMBER] [--token TOKEN]
```

- `--url`: Base URL of the API (default: http://127.0.0.1:5000)
- `--test`: Specific test to run (default: all)
- `--user-id`: User ID for token generation
- `--id-number`: ID number for token generation
- `--token`: Token for validation

Examples:

```
# Run all tests
python test_api.py

# Run only the health check test
python test_api.py --test health

# Generate a token with specific user ID and ID number
python test_api.py --test generate --user-id john_doe --id-number 12345

# Validate a specific token
python test_api.py --test validate --token ABC123XYZ
```

## Load Testing

The `load_test.py` script performs load testing on the backend API endpoints.

### Running Load Tests

1. Make sure the backend server is running:
   ```
   python app.py
   ```

2. Run the load test script:
   ```
   python load_test.py
   ```
   
   Or use the provided batch file:
   ```
   run_load_tests.bat
   ```

### Command Line Options

```
python load_test.py [--url URL] [--requests REQUESTS] [--concurrency CONCURRENCY] [--no-plot]
```

- `--url`: Base URL of the API (default: http://127.0.0.1:5000)
- `--requests`: Number of requests per endpoint (default: 100)
- `--concurrency`: Number of concurrent requests (default: 10)
- `--no-plot`: Disable plotting of results

Examples:

```
# Run load test with default settings
python load_test.py

# Run load test with 500 requests and 20 concurrent connections
python load_test.py --requests 500 --concurrency 20

# Run load test without generating plots
python load_test.py --no-plot
```

### Load Test Results

The load test script will output:

1. Success and error counts for each endpoint
2. Response time statistics (average, min, max, 95th percentile)
3. A plot of the results saved as `load_test_results.png`

## Monitoring Logs

During testing, you can monitor the logs to see what's happening on the backend:

1. Open the logs directory:
   ```
   cd logs
   ```

2. View the main log file:
   ```
   type pii_authenticator.log
   ```

3. View error logs:
   ```
   type errors.log
   ```

4. View access logs:
   ```
   type access.log
   ```

## Troubleshooting

If you encounter issues during testing:

1. Make sure the backend server is running
2. Check the logs for error messages
3. Verify that all required Python packages are installed
4. Ensure the API URL is correct

## Adding Custom Tests

You can extend the test scripts to add your own custom tests:

1. In `test_api.py`, add a new function for your test
2. Update the `run_all_tests()` function to include your test
3. Add your test to the command line options in the `main()` function