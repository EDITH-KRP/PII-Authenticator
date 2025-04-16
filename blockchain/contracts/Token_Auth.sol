// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TokenAuth {
    mapping(bytes32 => bool) private tokenExists;

    address private owner;

    constructor() {
        owner = msg.sender; // Only deployer can store tokens
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    function storeToken(string memory token) public onlyOwner {
        bytes32 tokenHash = keccak256(abi.encodePacked(token));
        require(!tokenExists[tokenHash], "Token already exists");
        tokenExists[tokenHash] = true;
    }

    function verifyToken(string memory token) public view returns (bool) {
        bytes32 tokenHash = keccak256(abi.encodePacked(token));
        return tokenExists[tokenHash];
    }
}
