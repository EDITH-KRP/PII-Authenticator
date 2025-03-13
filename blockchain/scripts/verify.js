const hre = require("hardhat");

async function main() {
    const contractAddress = "0xYourContractAddress";
    const idNumber = "123456789";
    const idHash = "0xYourComputedHash";

    const idRegistry = await hre.ethers.getContractAt("IDRegistry", contractAddress);
    const isVerified = await idRegistry.verifyID(idNumber, idHash);

    console.log(`🔍 ID verification result: ${isVerified ? "✅ Valid" : "❌ Tampered"}`);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
