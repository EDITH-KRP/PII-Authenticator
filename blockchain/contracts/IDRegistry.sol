// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract IDRegistry {
    mapping(string => bytes32) public idHashes;

    event IDStored(string indexed idNumber, bytes32 idHash);

    function storeIDHash(string memory idNumber, bytes32 idHash) public {
        idHashes[idNumber] = idHash;
        emit IDStored(idNumber, idHash);
    }

    function verifyID(string memory idNumber, bytes32 hashToCheck) public view returns (bool) {
        return idHashes[idNumber] == hashToCheck;
    }
}