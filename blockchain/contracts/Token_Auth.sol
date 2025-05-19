// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/**
 * @title TokenAuth
 * @dev Contract for storing and verifying authentication tokens
 */
contract TokenAuth {
    // Mapping from token hash to existence
    mapping(bytes32 => bool) private tokenExists;

    // Contract owner address
    address private immutable owner;

    // Events
    event TokenStored(bytes32 indexed tokenHash);

    /**
     * @dev Constructor sets the owner of the contract
     */
    constructor() {
        owner = msg.sender; // Only deployer can store tokens
    }

    /**
     * @dev Modifier to restrict function access to contract owner
     */
    modifier onlyOwner() {
        require(msg.sender == owner, "TokenAuth: caller is not the owner");
        _;
    }

    /**
     * @dev Store a token hash in the contract
     * @param token The token string to hash and store
     */
    function storeToken(string calldata token) external onlyOwner {
        bytes32 tokenHash = keccak256(abi.encodePacked(token));
        require(!tokenExists[tokenHash], "TokenAuth: token already exists");
        
        tokenExists[tokenHash] = true;
        emit TokenStored(tokenHash);
    }

    /**
     * @dev Verify if a token exists in the contract
     * @param token The token string to verify
     * @return bool True if the token exists, false otherwise
     */
    function verifyToken(string calldata token) external view returns (bool) {
        bytes32 tokenHash = keccak256(abi.encodePacked(token));
        return tokenExists[tokenHash];
    }
}
