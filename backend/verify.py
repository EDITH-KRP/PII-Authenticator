from web3 import Web3
import json
import os
from config import INFURA_URL, CONTRACT_ADDRESS

# Load contract ABI
with open("../blockchain/contract_abi.json", "r") as f:
    contract_abi = json.load(f)["abi"]

# Connect to Ethereum/Polygon
w3 = Web3(Web3.HTTPProvider(INFURA_URL))
contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=contract_abi)

def verify_id_on_blockchain(id_number, id_hash):
    return contract.functions.verifyID(id_number, id_hash).call()
