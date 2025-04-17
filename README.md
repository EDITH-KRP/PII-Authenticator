# Blockchain ID Authentication System

This project provides a secure way to authenticate personal identification information (PII) using blockchain technology. The system allows users to generate secure tokens for their PII data, which can then be validated by companies through blockchain verification.

## Features

- Generate secure tokens for PII data
- Store encrypted data on IPFS via Filebase
- Validate tokens using blockchain verification
- User-friendly web interface
- Separate user and company portals
- Blockchain-based token authentication

## Project Structure

- **Backend**: Flask-based API server for handling authentication and blockchain interactions
- **Frontend**: HTML/CSS/JavaScript web interface for users and companies
- **Blockchain**: Smart contracts for token verification using Hardhat

## Prerequisites

- Python 3.8+
- Node.js 14+ and npm
- Web browser (Chrome, Firefox, or Edge recommended)
- Ethereum wallet and Alchemy API key (for blockchain interactions)
- Filebase account (for IPFS storage)

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/blockchain-id-authentication.git
cd blockchain-id-authentication
```

### 2. Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd PII-Authenticator/backend
   ```

2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Create a `.env` file in the backend directory with the following variables:
   ```
   ALCHEMY_API_KEY=your_alchemy_api_key
   PRIVATE_KEY=your_ethereum_private_key
   CONTRACT_ADDRESS=your_deployed_contract_address
   FILEBASE_ACCESS_KEY=your_filebase_access_key
   FILEBASE_SECRET_KEY=your_filebase_secret_key
   BUCKET_NAME=your_filebase_bucket_name
   ENCRYPTED_AES_KEY=your_base64_encoded_aes_key
   ```

### 3. Blockchain Setup (Optional - Only if deploying a new contract)

1. Navigate to the blockchain directory:
   ```bash
   cd PII-Authenticator/blockchain
   ```

2. Install the required Node.js packages:
   ```bash
   npm install
   ```

3. Create a `.env` file in the blockchain directory with:
   ```
   ALCHEMY_API_KEY=your_alchemy_api_key
   PRIVATE_KEY=your_ethereum_private_key
   ```

4. Deploy the smart contract:
   ```bash
   npx hardhat run scripts/deploy_and_update.js --network sepolia
   ```
   
5. The script will automatically update the contract address in the backend configuration.

## Running the Application

### Option 1: Using the Batch File (Windows)

Simply run the `start_app.bat` file in the root directory:
```bash
start_app.bat
```

This will:
- Start the Flask backend server
- Open the frontend in your default browser
- Display server status information

### Option 2: Manual Start

1. Start the backend server:
   ```bash
   cd PII-Authenticator/backend
   python app.py
   ```

2. Open the frontend in your browser by navigating to:
   ```
   PII-Authenticator/frontend/PII/PII/index.html
   ```

## User Guide

### For Individual Users

1. **Register an Account**:
   - Navigate to the User Signup page
   - Fill in your details and create an account

2. **Login**:
   - Use your email and password to log in

3. **Generate a Token**:
   - Go to the "Generate Token" page
   - Fill in all required PII fields
   - Click "Generate Token"
   - Save the generated token for future verification

4. **View Your Profile**:
   - Access your profile to see your account details
   - View your generated tokens

### For Companies

1. **Register a Company Account**:
   - Navigate to the Company Signup page
   - Fill in your company details

2. **Login to Company Portal**:
   - Use your company email and password

3. **Validate Tokens**:
   - Go to the "Validate Token" page
   - Enter the token provided by a user
   - Click "Validate"
   - View the verification results

4. **Access Validation History**:
   - View a history of all tokens your company has validated

## Testing

### Running Backend Tests

```bash
cd PII-Authenticator/backend
python -m pytest
```

Or use the provided batch file:
```bash
run_tests.bat
```

### Load Testing

```bash
cd PII-Authenticator/backend
python load_test.py
```

Or use the provided batch file:
```bash
run_load_tests.bat
```

## Troubleshooting

- **CORS Issues**: Make sure the backend server is running on port 5000
- **Blockchain Connection Errors**: Verify your Alchemy API key and network settings
- **Token Validation Failures**: Ensure the contract address is correctly set in your .env file
- **File Storage Issues**: Check your Filebase credentials and bucket configuration

## Security Notes

- All PII data is encrypted before storage
- Tokens are verified on the blockchain for authenticity
- User passwords are securely hashed
- Environment variables should be kept confidential

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Ethereum and Hardhat for blockchain functionality
- Filebase for decentralized storage
- Flask for the backend API