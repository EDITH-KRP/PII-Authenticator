const { ethers } = require("hardhat");
const fs = require("fs");
const dotenv = require("dotenv");

async function main() {
  const IDRegistry = await ethers.getContractFactory("IDRegistry");
  const contract = await IDRegistry.deploy();

  await contract.deployed();

  console.log(`✅ Contract deployed at: ${contract.address}`);

  // Update the .env file
  const envConfig = dotenv.parse(fs.readFileSync("../backend/.env"));
  envConfig["CONTRACT_ADDRESS"] = contract.address;

  fs.writeFileSync("../backend/.env", Object.entries(envConfig).map(([key, value]) => `${key}=${value}`).join("\n"));
  console.log("✅ CONTRACT_ADDRESS updated in .env file!");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
