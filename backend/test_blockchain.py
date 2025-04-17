#!/usr/bin/env python
# test_blockchain.py - Test blockchain connection and contract interaction

import os
import json
import time
from web3 import Web3, HTTPProvider
from dotenv import load_dotenv
import traceback

# Load environment variables
load_dotenv()

# Get environment variables
ALCHEMY_API_KEY = os.getenv('ALCHEMY_API_KEY')
PRIVATE_KEY = os.getenv('PRIVATE_KEY')
CONTRACT_ADDRESS = os.getenv('CONTRACT_ADDRESS')
SEPOLIA_RPC_URL = os.getenv('SEPOLIA_RPC_URL', f"https://eth-sepolia.g.alchemy.com/v2/{ALCHEMY_API_KEY}")

print(f"Using contract address: {CONTRACT_ADDRESS}")
print(f"Using Sepolia RPC URL: {SEPOLIA_RPC_URL}")

# Connect to Sepolia via Alchemy
try:
    print("Connecting to Ethereum network via Alchemy...")
    start_time = time.time()
    
    web3 = Web3(HTTPProvider(SEPOLIA_RPC_URL))
    
    if not web3.is_connected():
        print("Could not connect to Sepolia via Alchemy")
        exit(1)
    else:
        elapsed_time = time.time() - start_time
        print(f"Connected to Ethereum network in {elapsed_time:.4f} seconds")
        print(f"Latest block number: {web3.eth.block_number}")
except Exception as e:
    print(f"Failed to initialize Web3: {e}")
    traceback.print_exc()
    exit(1)

# Try to load contract ABI
try:
    print("Loading contract ABI...")
    abi_path = "../blockchain/artifacts/contracts/Token_Auth.sol/TokenAuth.json"
    with open(abi_path, "r") as f:
        contract_json = json.load(f)
        contract_abi = contract_json["abi"]
    print("Contract ABI loaded successfully")
except Exception as e:
    print(f"Failed to load contract ABI: {e}")
    traceback.print_exc()
    exit(1)

# Initialize contract
try:
    print("Initializing contract...")
    # Make sure CONTRACT_ADDRESS is properly formatted
    clean_address = CONTRACT_ADDRESS.strip()
    
    # Convert to checksum address
    checksum_address = web3.to_checksum_address(clean_address)
    
    contract = web3.eth.contract(address=checksum_address, abi=contract_abi)
    account = web3.eth.account.from_key(PRIVATE_KEY)
    print(f"Contract initialized at address {checksum_address}")
    
    # Verify contract exists on the blockchain
    try:
        code = web3.eth.get_code(checksum_address)
        if code == b'' or code == '0x':
            print(f"No contract code found at address {checksum_address}")
            print("This may be an invalid contract address")
            exit(1)
        else:
            print(f"Contract code verified at address {checksum_address}")
    except Exception as e:
        print(f"Could not verify contract code: {e}")
        traceback.print_exc()
        exit(1)
except Exception as e:
    print(f"Failed to initialize contract: {e}")
    traceback.print_exc()
    exit(1)

# Test storing a token
try:
    print("\nTesting token storage...")
    test_token = f"TEST_TOKEN_{int(time.time())}"
    print(f"Token to store: {test_token}")
    
    # Get the latest nonce
    nonce = web3.eth.get_transaction_count(account.address)
    print(f"Current nonce for account {account.address}: {nonce}")
    
    # Build the transaction
    tx = contract.functions.storeToken(test_token).build_transaction({
        'from': account.address,
        'nonce': nonce,
        'gas': 300000,
        'gasPrice': web3.to_wei('20', 'gwei')
    })
    
    # Sign and send the transaction
    print("Signing transaction...")
    signed_tx = web3.eth.account.sign_transaction(tx, private_key=PRIVATE_KEY)
    
    print("Sending transaction to network...")
    tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
    tx_hash_hex = tx_hash.hex()
    
    print(f"Transaction sent: {tx_hash_hex}")
    
    # Wait for the transaction receipt
    print("Waiting for transaction receipt (this may take a minute)...")
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    
    print(f"Receipt received: {receipt.transactionHash.hex()}")
    print(f"Transaction status: {'Success' if receipt.status == 1 else 'Failed'}")
    print(f"Block number: {receipt.blockNumber}")
    print(f"Gas used: {receipt.gasUsed}")
    
    # Test verifying the token
    print("\nTesting token verification...")
    try:
        result = contract.functions.verifyToken(test_token).call()
        print(f"Token verification result: {result}")
        if result:
            print("Token verification successful!")
        else:
            print("Token verification failed!")
    except Exception as e:
        print(f"Error verifying token: {e}")
        traceback.print_exc()
    
    print("\nBlockchain test completed successfully!")
except Exception as e:
    print(f"Error in blockchain test: {e}")
    traceback.print_exc()