const hre = require("hardhat");
const fs = require("fs");
const path = require("path");
const dotenv = require("dotenv");

// Load environment variables from backend/.env
dotenv.config({ path: "../backend/.env" });

async function main() {
  console.log("🚀 Deploying TokenAuth contract to Sepolia testnet...");

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

    // Deploy the contract
    const TokenAuth = await hre.ethers.getContractFactory("TokenAuth");
    console.log("Deploying contract...");
    const contract = await TokenAuth.deploy();
    
    console.log("Waiting for deployment transaction to be mined...");
    await contract.deployed();

    console.log(`✅ TokenAuth Contract deployed at: ${contract.address}`);

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
    console.log(`✅ Set BLOCKCHAIN_DEV_MODE to false`);

    // Create a deployment record
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

    console.log("\n🎉 Deployment completed successfully!");
    console.log(`📝 Contract Address: ${contract.address}`);
    console.log(`🔍 View on Etherscan: https://sepolia.etherscan.io/address/${contract.address}`);
  } catch (error) {
    console.error("❌ Deployment failed:", error);
    process.exit(1);
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("❌ Script execution failed:", error);
    process.exit(1);
  });