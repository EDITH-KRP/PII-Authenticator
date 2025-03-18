require("dotenv").config();
const { ethers } = require("hardhat");

async function main() {
  const contractAddress = process.env.CONTRACT_ADDRESS;

  if (!contractAddress) {
    console.error("❌ CONTRACT_ADDRESS is missing in .env file!");
    process.exit(1);
  }

  console.log(`🔍 Verifying contract at ${contractAddress}...`);

  try {
    await hre.run("verify:verify", {
      address: contractAddress,
      constructorArguments: [],
    });

    console.log("✅ Contract verified successfully!");
  } catch (error) {
    console.error("❌ Verification failed:", error);
  }
}

main();
