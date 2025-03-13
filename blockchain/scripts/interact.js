const { ethers } = require("hardhat");

async function main() {
    const contractAddress = "0xYourContractAddress";
    const idNumber = "123456789";

    const idRegistry = await ethers.getContractAt("IDRegistry", contractAddress);
    const storedHash = await idRegistry.idHashes(idNumber);

    console.log(`🔗 Stored Hash for ${idNumber}: ${storedHash}`);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
