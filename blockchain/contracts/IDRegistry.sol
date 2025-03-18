// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IDRegistry {
    mapping(string => bytes32) private idHashes;

    function storeID(string memory idNumber, bytes32 idHash) public {
        idHashes[idNumber] = idHash;
    }

    function verifyID(string memory idNumber, bytes32 idHash) public view returns (bool) {
        return idHashes[idNumber] == idHash;
    }
}
