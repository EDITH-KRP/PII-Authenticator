require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config({ path: "../backend/.env" }); // ✅ Correct Path

module.exports = {
  solidity: "0.8.20",
  networks: {
    sepolia: {
      url: process.env.SEPOLIA_RPC_URL,
      accounts: [process.env.PRIVATE_KEY],
      gas: 5000000, // Increase gas
      gasPrice: 20000000000 // 20 Gwei
    }
  },
};
