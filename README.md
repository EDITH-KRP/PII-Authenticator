# Blockchain ID Authentication System

This project provides a secure way to authenticate personal identification information (PII) using blockchain technology. The system allows users to generate secure tokens for their PII data, which can then be validated by companies through blockchain verification.

![Blockchain ID Authentication](https://via.placeholder.com/800x400?text=Blockchain+ID+Authentication)

## How It Works

### System Architecture

The Blockchain ID Authentication system consists of three main components:

1. **Frontend Web Application**: User and company interfaces for interacting with the system
2. **Backend API Server**: Handles authentication, data processing, and blockchain interactions
3. **Blockchain Smart Contracts**: Provides immutable verification of token authenticity

### Data Flow

1. **User Registration & Authentication**:
   - Users register with email and password
   - Authentication is handled via JWT tokens
   - Secure sessions are maintained in localStorage

2. **Token Generation Process**:
   - User submits their personal identification information (PII)
   - Data is encrypted using AES-256 encryption
   - Encrypted data is stored on IPFS via Filebase
   - A unique token is generated and linked to the data
   - Token is registered on the Ethereum blockchain (Sepolia testnet)
   - User receives the token for future verification

3. **Token Validation Process**:
   - Companies request token from users
   - Token is submitted to the validation endpoint
   - System verifies token authenticity on the blockchain
   - If valid, company receives confirmation of data authenticity
   - All validation attempts are logged for audit purposes

4. **Security Measures**:
   - All PII data is encrypted before storage
   - Only encrypted data is stored on IPFS
   - Blockchain provides tamper-proof verification
   - No PII is exposed during the validation process

## Features

- **Secure Token Generation**: Create cryptographically secure tokens for PII data
- **Blockchain Verification**: Validate tokens using Ethereum smart contracts
- **Decentralized Storage**: Store encrypted data on IPFS via Filebase
- **User Dashboard**: Manage personal tokens and account information
- **Company Portal**: Validate tokens and view validation history
- **Audit Logging**: Track all system activities for security purposes
- **Responsive Design**: User-friendly interface that works on all devices

## Project Structure

```
blockchain-id-authentication/
├── PII-Authenticator/
│   ├── backend/                 # Flask API server
│   │   ├── app.py               # Main application entry point
│   │   ├── user_auth.py         # User authentication logic
│   │   ├── company_auth.py      # Company authentication logic
│   │   ├── token_auth.py        # Token generation and verification
│   │   ├── w3_utils.py          # Blockchain and IPFS utilities
│   │   ├── document_processor.py # Document processing utilities
│   │   └── requirements.txt     # Python dependencies
│   │
│   ├── frontend/                # Web interface
│   │   └── PII/PII/
│   │       ├── index.html       # Landing page
│   │       ├── login.html       # User login page
│   │       ├── signup.html      # User registration page
│   │       ├── generate.html    # Token generation page
│   │       ├── profile.html     # User profile page
│   │       ├── company/         # Company portal pages
│   │       ├── scripts/         # JavaScript files
│   │       └── styles/          # CSS stylesheets
│   │
│   ├── blockchain/              # Blockchain components
│   │   ├── contracts/           # Smart contract source code
│   │   ├── scripts/             # Deployment scripts
│   │   └── hardhat.config.js    # Hardhat configuration
│   │
│   └── README.md                # Project documentation
│
├── start_app.bat                # Application startup script
├── .gitignore                   # Git ignore file
└── LICENSE                      # MIT License
```

## Prerequisites

- **Python 3.8+**: For running the backend API server
- **Node.js 14+** and **npm**: For blockchain interactions and frontend development
- **Web Browser**: Chrome, Firefox, or Edge recommended
- **Ethereum Wallet**: For blockchain interactions (Metamask recommended)
- **Alchemy API Key**: For connecting to Ethereum networks
- **Filebase Account**: For IPFS storage access

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
   SECRET_KEY=your_jwt_secret_key
   ```

### 3. Blockchain Setup

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

4. Deploy the smart contract (optional - only if deploying a new contract):
   ```bash
   npx hardhat run scripts/deploy_and_update.js --network sepolia
   ```
   
   The script will automatically update the contract address in the backend configuration.

### 4. Frontend Setup

No additional setup is required for the frontend as it's built with vanilla HTML, CSS, and JavaScript.

## Running the Application

### Option 1: Using the Batch File (Windows)

Simply run the `start_app.bat` file in the root directory:
```bash
start_app.bat
```

This will:
- Start the Flask backend server on port 5000
- Open the frontend in your default browser
- Display server status information in the console

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

## API Endpoints

The backend provides the following RESTful API endpoints:

### User Authentication
- `POST /user/register`: Register a new user
- `POST /user/login`: Authenticate a user and get JWT token
- `GET /user/profile`: Get user profile information

### Token Management
- `POST /user/tokens/generate`: Generate a new token for PII data
- `GET /user/tokens`: Get all tokens for the authenticated user
- `GET /user/tokens/:id`: Get details for a specific token

### Token Validation
- `POST /validate_token`: Validate a token's authenticity
- `GET /company/validations`: Get validation history for a company

### Document Management
- `POST /user/documents/upload`: Upload and process a document
- `GET /user/documents`: Get all documents for the authenticated user

## User Guide

### For Individual Users

1. **Register an Account**:
   - Navigate to the User Signup page
   - Fill in your details and create an account

2. **Login**:
   - Use your email and password to log in
   - Your session will be maintained until you log out

3. **Generate a Token**:
   - Go to the "Generate Token" page
   - Fill in all required PII fields
   - Click "Generate Token"
   - The system will encrypt your data and store it securely
   - You'll receive a unique token linked to your data

4. **View Your Profile**:
   - Access your profile to see your account details
   - View your generated tokens and their status
   - See which companies have validated your tokens

### For Companies

1. **Register a Company Account**:
   - Navigate to the Company Signup page
   - Fill in your company details
   - Create a secure password

2. **Login to Company Portal**:
   - Use your company email and password
   - Access the company dashboard

3. **Validate Tokens**:
   - Go to the "Validate Token" page
   - Enter the token provided by a user
   - Click "Validate"
   - The system will verify the token on the blockchain
   - View the verification results showing token authenticity

4. **Access Validation History**:
   - View a history of all tokens your company has validated
   - Filter by date, status, or user
   - Export validation records if needed

## Testing

### Running Backend Tests

The project includes comprehensive unit and integration tests:

```bash
cd PII-Authenticator/backend
python -m pytest
```

Or use the provided batch file:
```bash
run_tests.bat
```

### Load Testing

To test system performance under load:

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
- **JWT Authentication Errors**: Verify that your SECRET_KEY is properly set

## Security Considerations

- **Data Encryption**: All PII data is encrypted using AES-256 before storage
- **Blockchain Verification**: Tokens are verified on the blockchain for authenticity
- **Password Security**: User passwords are securely hashed using bcrypt
- **Environment Variables**: All sensitive configuration is stored in environment variables
- **Access Control**: JWT-based authentication ensures proper access control
- **Audit Logging**: All system activities are logged for security auditing

## Future Enhancements

- **Multi-factor Authentication**: Add 2FA for additional security
- **Mobile Application**: Develop native mobile apps for iOS and Android
- **Advanced Analytics**: Implement analytics dashboard for system usage
- **Batch Processing**: Support for batch token validation
- **Integration APIs**: Develop APIs for third-party integrations
- **Document Verification**: Enhanced document verification capabilities

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## Acknowledgments

- **Ethereum** and **Hardhat** for blockchain functionality
- **Filebase** for decentralized IPFS storage
- **Flask** for the backend API framework
- **Web3.js** for blockchain interactions
- **Cryptography** library for secure encryption