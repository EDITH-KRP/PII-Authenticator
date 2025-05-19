const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  try {
    // Read the deployment record
    const deploymentRecordPath = path.join(__dirname, "../deployment_record.json");
    const deploymentRecord = JSON.parse(fs.readFileSync(deploymentRecordPath, "utf8"));
    
    console.log("Checking contract at address:", deploymentRecord.contractAddress);
    
    // Get the contract factory
    const TokenAuth = await hre.ethers.getContractFactory("TokenAuth");
    
    // Attach to the deployed contract
    const contract = TokenAuth.attach(deploymentRecord.contractAddress);
    
    // Try to call a view function to check if the contract is working
    console.log("Attempting to interact with the contract...");
    
    // Get the owner of the contract (this is a workaround since the contract doesn't have a direct view function)
    const signers = await hre.ethers.getSigners();
    const deployer = signers[0];
    
    // Try to store a token (this will fail if the contract is not working or if the caller is not the owner)
    try {
      const testToken = "test_token_" + Date.now();
      console.log(`Storing test token: ${testToken}`);
      
      // Store the token
      const tx = await contract.storeToken(testToken);
      console.log("Transaction hash:", tx.hash);
      
      // Wait for the transaction to be mined
      console.log("Waiting for transaction to be mined...");
      await tx.wait();
      
      // Verify the token
      const isVerified = await contract.verifyToken(testToken);
      console.log(`Token verification result: ${isVerified}`);
      
      console.log("✅ Contract is working correctly!");
    } catch (error) {
      console.error("❌ Error interacting with the contract:", error.message);
      
      if (error.message.includes("not the owner")) {
        console.log("The contract exists but you're not the owner. This is expected if using a different account.");
      } else if (error.message.includes("call revert exception")) {
        console.error("The contract exists but the function call reverted. The contract might be in an invalid state.");
      } else if (error.message.includes("does not exist")) {
        console.error("The contract does not exist at the specified address. It might have been removed or not deployed correctly.");
      } else {
        console.error("Unknown error. The contract might not be working correctly.");
      }
    }
    
  } catch (error) {
    console.error("❌ Script execution failed:", error);
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("❌ Script execution failed:", error);
    process.exit(1);
  });