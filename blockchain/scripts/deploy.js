const hre = require("hardhat");
const fs = require("fs");
const path = require("path");
const dotenv = require("dotenv");

// Load environment variables from backend/.env
dotenv.config({ path: "../backend/.env" });

async function main() {
  console.log("🚀 Deploying TokenAuth contract...");

  // Check for required environment variables
  if (!process.env.SEPOLIA_RPC_URL || !process.env.PRIVATE_KEY) {
    console.error("❌ SEPOLIA_RPC_URL or PRIVATE_KEY missing in .env file!");
    process.exit(1);
  }

  try {
    const signers = await hre.ethers.getSigners();
    const deployer = signers[0];

    console.log(`👤 Using deployer: ${deployer.address}`);
    console.log(`💰 Deployer balance: ${hre.ethers.utils.formatEther(await deployer.getBalance())} ETH`);
    
    // Check if the deployer has enough ETH
    const balance = await deployer.getBalance();
    if (balance.lt(hre.ethers.utils.parseEther("0.01"))) {
      console.error(`❌ Deployer has insufficient funds: ${hre.ethers.utils.formatEther(balance)} ETH`);
      console.error("Please fund your account with at least 0.01 ETH to deploy the contract");
      process.exit(1);
    }

    // Deploy the contract with a timeout
    console.log("Compiling contract...");
    const TokenAuth = await hre.ethers.getContractFactory("TokenAuth");
    
    console.log("Deploying contract with higher gas price...");
    
    // Override gas settings for more reliable deployment
    const overrides = {
      gasLimit: 3000000,
      gasPrice: hre.ethers.utils.parseUnits("40", "gwei"), // Higher gas price for faster confirmation
    };
    
    console.log(`Using gas limit: ${overrides.gasLimit}, gas price: ${hre.ethers.utils.formatUnits(overrides.gasPrice, "gwei")} Gwei`);
    
    const deployPromise = TokenAuth.deploy(overrides);
    
    // Set a timeout for deployment (5 minutes)
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error("Deployment timed out after 5 minutes")), 300000);
    });
    
    // Race the deployment against the timeout
    const contract = await Promise.race([deployPromise, timeoutPromise]);
    
    console.log(`Transaction hash: ${contract.deployTransaction.hash}`);
    console.log("Waiting for deployment transaction to be mined (up to 5 minutes)...");
    
    // Set a timeout for the transaction to be mined
    const miningPromise = contract.deployed();
    const miningTimeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error("Transaction mining timed out after 5 minutes")), 300000);
    });
    
    // Wait for the transaction to be mined or timeout
    await Promise.race([miningPromise, miningTimeoutPromise]);

    console.log(`✅ TokenAuth Contract deployed at: ${contract.address}`);
    
    // Update the deployment record
    const deploymentRecord = {
      contractAddress: contract.address,
      deploymentTime: new Date().toISOString(),
      network: "sepolia",
      deployer: deployer.address,
      transactionHash: contract.deployTransaction.hash
    };

    const deploymentRecordPath = path.join(__dirname, "../deployment_record.json");
    fs.writeFileSync(deploymentRecordPath, JSON.stringify(deploymentRecord, null, 2));
    console.log(`✅ Created deployment record at: ${deploymentRecordPath}`);
    
    // Update the .env file with the new contract address
    const envFilePath = path.join(__dirname, "../../backend/.env");
    let envContent = fs.readFileSync(envFilePath, "utf8");
    
    // Replace the CONTRACT_ADDRESS line
    envContent = envContent.replace(
      /CONTRACT_ADDRESS=.*/,
      `CONTRACT_ADDRESS=${contract.address}`
    );
    
    // Set BLOCKCHAIN_DEV_MODE to false since we now have a real contract
    if (envContent.includes("BLOCKCHAIN_DEV_MODE=")) {
      envContent = envContent.replace(
        /BLOCKCHAIN_DEV_MODE=.*/,
        "BLOCKCHAIN_DEV_MODE=false"
      );
    } else {
      envContent += "\nBLOCKCHAIN_DEV_MODE=false";
    }
    
    // Write the updated .env file
    fs.writeFileSync(envFilePath, envContent);
    console.log(`✅ Updated .env file with new contract address: ${contract.address}`);
    
    console.log("\n🎉 Deployment completed successfully!");
    console.log(`📝 Contract Address: ${contract.address}`);
    console.log(`🔍 View on Etherscan: https://sepolia.etherscan.io/address/${contract.address}`);
  } catch (error) {
    console.error("❌ Deployment failed:", error);
    
    // Provide more detailed error information
    if (error.message.includes("timed out")) {
      console.error("\n⚠️ The deployment timed out. This could be due to:");
      console.error("  - Network congestion on Sepolia");
      console.error("  - Insufficient gas price");
      console.error("  - RPC endpoint issues");
      console.error("\n📋 Suggestions:");
      console.error("  1. Check your Sepolia RPC URL in the .env file");
      console.error("  2. Ensure your account has enough ETH for gas");
      console.error("  3. Try increasing the gas price in hardhat.config.js");
    } else if (error.message.includes("insufficient funds")) {
      console.error("\n⚠️ Your account has insufficient funds to deploy the contract.");
      console.error("📋 Please fund your account with Sepolia ETH from a faucet:");
      console.error("  - https://sepoliafaucet.com/");
      console.error("  - https://faucet.sepolia.dev/");
    } else if (error.message.includes("nonce")) {
      console.error("\n⚠️ Nonce error detected. This could be due to:");
      console.error("  - A pending transaction from the same account");
      console.error("  - Incorrect nonce tracking");
      console.error("\n📋 Suggestions:");
      console.error("  1. Wait for pending transactions to complete");
      console.error("  2. Reset your account nonce in MetaMask");
    }
    
    process.exit(1);
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("❌ Script execution failed:", error);
    process.exit(1);
  });
