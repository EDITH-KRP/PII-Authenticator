# Manual Testing Guide for PII Authenticator Backend

This guide provides instructions for manually testing the PII Authenticator backend API.

## Testing Tools

We've created several testing tools to help you test the backend:

1. **Basic API Testing**: `test_api.py` - Tests individual API endpoints
2. **Load Testing**: `load_test.py` - Tests API performance under load
3. **Log Viewer**: `view_logs.bat` - Helps view and analyze logs

## Running Basic API Tests

The `test_api.py` script provides functions to test all backend API endpoints.

```bash
# Run all tests
python test_api.py

# Test specific endpoints
python test_api.py --test health
python test_api.py --test generate --user-id test_user --id-number 12345
python test_api.py --test validate --token YOUR_TOKEN
```

## Running Load Tests

The `load_test.py` script performs load testing on the backend API endpoints.

```bash
# Run with default settings (100 requests, 10 concurrent)
python load_test.py

# Run with custom settings
python load_test.py --requests 20 --concurrency 5

# Run without generating plots
python load_test.py --no-plot
```

The load test will generate a plot (`load_test_results.png`) showing:
- Response time distributions
- Success vs error counts
- Average response times

## Viewing Logs

Use the `view_logs.bat` script to view and analyze logs:

```bash
view_logs.bat
```

This will open a menu allowing you to:
1. View main logs
2. View error logs
3. View access logs
4. View all logs combined
5. Clear logs

## Test Results

During our testing, we observed:

1. **Health Check**: The `/health` endpoint responds quickly (< 10ms)
2. **Token Generation**: The `/encrypt` endpoint takes ~1.5-2.5 seconds to generate a token
3. **Token Validation**: The `/validate_token` endpoint takes ~0.7 seconds to validate a token
4. **Error Handling**: The API correctly handles invalid inputs and returns appropriate error messages

### Performance Metrics

Based on our load testing with 10 requests and 3 concurrent users:

- **Generate Token**:
  - Average Response Time: 1.61 seconds
  - Min Response Time: 1.40 seconds
  - Max Response Time: 2.20 seconds
  - 95th Percentile: 1.92 seconds

- **Validate Token**:
  - Average Response Time: 0.79 seconds
  - Min Response Time: 0.66 seconds
  - Max Response Time: 1.53 seconds
  - 95th Percentile: 1.17 seconds

## Known Issues

1. **Blockchain Integration**: There are some issues with the blockchain integration:
   - The `rawTransaction` attribute should be `raw_transaction` in the `store_token_on_blockchain` function
   - Contract verification sometimes fails with "Could not transact with/call contract function"

2. **Token Validation**: Tokens are not being properly stored on the blockchain, causing validation to fail

## Next Steps

1. Fix the blockchain integration issues
2. Implement proper error handling for blockchain operations
3. Add more comprehensive tests for edge cases
4. Improve performance of token generation and validation

## Conclusion

The PII Authenticator backend API is functioning correctly for basic operations, but there are some issues with the blockchain integration that need to be addressed. The logging system is working well and provides good visibility into the application's behavior.