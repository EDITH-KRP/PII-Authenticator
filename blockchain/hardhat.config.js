require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config({ path: "../backend/.env" });

// Log network configuration for debugging
const sepoliaUrl = process.env.SEPOLIA_RPC_URL;
console.log(`Using Sepolia RPC URL: ${sepoliaUrl ? sepoliaUrl.substring(0, 20) + '...' : 'undefined'}`);
console.log(`Private key available: ${process.env.PRIVATE_KEY ? 'Yes' : 'No'}`);

module.exports = {
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200
      }
    }
  },
  networks: {
    sepolia: {
      url: process.env.SEPOLIA_RPC_URL,
      accounts: [process.env.PRIVATE_KEY],
      gas: 3000000,           // Reduced gas limit to avoid estimation issues
      gasPrice: 40000000000,  // 40 Gwei - higher to ensure faster confirmation
      timeout: 300000,        // 5 minutes timeout
      confirmations: 1,       // Wait for 1 confirmation
      networkCheckTimeout: 300000, // 5 minutes timeout for network checks
      timeoutBlocks: 200,     // Wait 200 blocks for transaction to be mined
    },
    hardhat: {
      chainId: 1337,
      mining: {
        auto: true,
        interval: 5000
      }
    }
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts"
  },
  mocha: {
    timeout: 120000 // 2 minutes timeout for tests
  }
};
