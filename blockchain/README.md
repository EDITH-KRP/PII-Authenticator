# Blockchain Operations

This directory contains the smart contract and scripts for interacting with the Ethereum blockchain (Sepolia testnet).

## Current Contract

The TokenAuth contract is currently deployed at: `0xD23Dcb6F54352b8F801aE60d33Ff3f214a652d90`

This contract is used for storing and verifying authentication tokens on the blockchain.

## Using the Blockchain Operations Tool

The `blockchain_operations.bat` file provides a simple interface for interacting with the blockchain:

1. **Check existing contract status** - Verifies that the deployed contract is working correctly
2. **Deploy new contract** - Only use this if the existing contract is not working
3. **Exit** - Close the tool

### When to Deploy a New Contract

You should only deploy a new contract if:
- The existing contract is not working (check using option 1)
- You need to make changes to the contract functionality
- The contract has been compromised

Note that deploying a new contract:
- Requires Sepolia ETH for gas fees
- May take several minutes to complete
- Will update the contract address in the deployment_record.json file

## Files

- `contracts/Token_Auth.sol` - The smart contract for token authentication
- `scripts/check_contract.js` - Script to check if the contract is working
- `scripts/deploy.js` - Script to deploy a new contract
- `scripts/verify.js` - Script to verify the contract on Etherscan
- `hardhat.config.js` - Configuration for the Hardhat development environment
- `deployment_record.json` - Record of the deployed contract address

## Environment Setup

The contract deployment uses environment variables from `../backend/.env`:

- `SEPOLIA_RPC_URL` - RPC URL for the Sepolia testnet
- `PRIVATE_KEY` - Private key for the deployer account
- `CONTRACT_ADDRESS` - Address of the deployed contract