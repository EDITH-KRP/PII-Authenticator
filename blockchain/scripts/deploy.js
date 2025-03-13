const hre = require("hardhat");

async function main() {
    const IDRegistry = await hre.ethers.getContractFactory("IDRegistry");
    const idRegistry = await IDRegistry.deploy();
    await idRegistry.deployed();

    console.log("✅ IDRegistry deployed to:", idRegistry.address);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});