require("dotenv").config();
const { ethers } = require("hardhat");

async function main() {
  const provider = new ethers.providers.JsonRpcProvider("http://127.0.0.1:8545");
  const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
  const contractAddress = process.env.CONTRACT_ADDRESS;
  const contractABI = require("../contract_abi.json");

  const contract = new ethers.Contract(contractAddress, contractABI, wallet);

  // Example: Store ID hash on blockchain
  const tx = await contract.storeID("123456789", ethers.utils.formatBytes32String("hashed_value"));
  await tx.wait();
  console.log("✅ ID Hash stored on blockchain!");

  // Example: Verify ID
  const isVerified = await contract.verifyID("123456789", ethers.utils.formatBytes32String("hashed_value"));
  console.log("🔍 Verification result:", isVerified);
}

main();
