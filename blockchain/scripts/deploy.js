const hre = require("hardhat");
const fs = require("fs");
const dotenv = require("dotenv");

dotenv.config({ path: "../backend/.env" }); // ✅ Ensure correct path

if (!process.env.SEPOLIA_RPC_URL || !process.env.PRIVATE_KEY) {
  console.error("❌ INFURA_API_KEY or PRIVATE_KEY missing in .env file!");
  process.exit(1);
}

async function main() {
  console.log("🚀 Deploying TokenAuth contract...");

  const signers = await hre.ethers.getSigners();
  const deployer = signers[0];

  console.log(`👤 Using deployer: ${deployer.address}`);

  const TokenAuth = await hre.ethers.getContractFactory("TokenAuth");
  const contract = await TokenAuth.deploy();
  await contract.deployed();

  console.log(`✅ TokenAuth Contract deployed at: ${contract.address}`);
}

main().catch((error) => {
  console.error("❌ Deployment failed:", error);
  process.exit(1);
});
