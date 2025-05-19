const hre = require("hardhat");
const fs = require("fs");
const path = require("path");
const dotenv = require("dotenv");

// Load environment variables from backend/.env
dotenv.config({ path: "../backend/.env" });

async function main() {
  console.log("🚀 Starting TokenAuth contract deployment with strict timeout...");

  // Check for required environment variables
  if (!process.env.SEPOLIA_RPC_URL || !process.env.PRIVATE_KEY) {
    console.error("❌ SEPOLIA_RPC_URL or PRIVATE_KEY missing in .env file!");
    process.exit(1);
  }

  try {
    // Get network information
    const provider = hre.ethers.provider;
    const network = await provider.getNetwork();
    console.log(`🌐 Connected to network: ${network.name} (chainId: ${network.chainId})`);
    
    // Get gas price
    const gasPrice = await provider.getGasPrice();
    console.log(`⛽ Current gas price: ${hre.ethers.utils.formatUnits(gasPrice, "gwei")} Gwei`);

    // Get signers
    const signers = await hre.ethers.getSigners();
    const deployer = signers[0];

    console.log(`👤 Using deployer: ${deployer.address}`);
    const balance = await deployer.getBalance();
    console.log(`💰 Deployer balance: ${hre.ethers.utils.formatEther(balance)} ETH`);
    
    // Check if the deployer has enough ETH
    if (balance.lt(hre.ethers.utils.parseEther("0.01"))) {
      console.error(`❌ Deployer has insufficient funds: ${hre.ethers.utils.formatEther(balance)} ETH`);
      console.error("Please fund your account with at least 0.01 ETH to deploy the contract");
      process.exit(1);
    }

    // Compile the contract
    console.log("📝 Compiling contract...");
    await hre.run("compile");
    console.log("✅ Compilation successful");

    // Get the contract factory
    console.log("🏭 Creating contract factory...");
    const TokenAuth = await hre.ethers.getContractFactory("TokenAuth");
    
    // Deploy with a longer timeout
    console.log("🚀 Deploying contract...");
    console.log("⏱️ Setting 300-second timeout for deployment transaction...");
    
    // Create a promise that rejects after 300 seconds (5 minutes)
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error("Deployment transaction timed out after 300 seconds")), 300000);
    });
    
    // Create the deployment promise
    const deploymentPromise = async () => {
      try {
        // Override gas settings for more reliable deployment
        const overrides = {
          gasLimit: 3000000,
          gasPrice: hre.ethers.utils.parseUnits("40", "gwei"), // Increased gas price for faster confirmation
        };
        
        console.log(`🔧 Using gas limit: ${overrides.gasLimit}, gas price: ${hre.ethers.utils.formatUnits(overrides.gasPrice, "gwei")} Gwei`);
        
        // Deploy the contract with overrides
        console.log("📤 Sending deployment transaction...");
        const contract = await TokenAuth.deploy(overrides);
        console.log(`📝 Transaction hash: ${contract.deployTransaction.hash}`);
        
        // Wait for transaction to be mined (with a longer timeout)
        console.log("⏳ Waiting for transaction to be mined (240 second timeout)...");
        const receipt = await Promise.race([
          contract.deployTransaction.wait(1),
          new Promise((_, reject) => setTimeout(() => reject(new Error("Transaction mining timed out")), 240000))
        ]);
        
        // Get the contract instance
        const contractAddress = receipt.contractAddress;
        console.log(`✅ Contract deployed at address: ${contractAddress}`);
        
        return { contract, receipt };
      } catch (error) {
        console.error("❌ Deployment transaction failed:", error.message);
        throw error;
      }
    };
    
    // Race the deployment against the timeout
    const { contract, receipt } = await Promise.race([deploymentPromise(), timeoutPromise]);
    
    // Update the deployment record
    const deploymentRecord = {
      contractAddress: receipt.contractAddress,
      deploymentTime: new Date().toISOString(),
      network: "sepolia",
      deployer: deployer.address,
      transactionHash: receipt.transactionHash
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
      `CONTRACT_ADDRESS=${receipt.contractAddress}`
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
    console.log(`✅ Updated .env file with new contract address: ${receipt.contractAddress}`);
    
    console.log("\n🎉 Deployment completed successfully!");
    console.log(`📝 Contract Address: ${receipt.contractAddress}`);
    console.log(`🔍 View on Etherscan: https://sepolia.etherscan.io/address/${receipt.contractAddress}`);
  } catch (error) {
    console.error("❌ Deployment failed:", error.message);
    
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
      console.error("  4. Try using a different RPC endpoint for Sepolia");
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
    } else if (error.message.includes("estimate gas")) {
      console.error("\n⚠️ Gas estimation failed. This could be due to:");
      console.error("  - Contract compilation issues");
      console.error("  - Contract initialization errors");
      console.error("\n📋 Suggestions:");
      console.error("  1. Check your contract code for errors");
      console.error("  2. Try simplifying the contract constructor");
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