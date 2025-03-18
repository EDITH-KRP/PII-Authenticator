from web3 import Web3
import json
import os
from config import INFURA_URL, CONTRACT_ADDRESS

# Load the contract ABI
with open("../blockchain/contract_abi.json", "r") as f:
    contract_abi = json.load(f)["abi"]

# Connect to Ethereum network
w3 = Web3(Web3.HTTPProvider(INFURA_URL))

# Convert contract address to checksum format
contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=contract_abi)

# Verify ID on Blockchain
def verify_id_on_blockchain(id_number, id_hash):
    id_hash = Web3.to_bytes(hexstr=id_hash)
    return contract.functions.verifyID(id_number, id_hash).call()