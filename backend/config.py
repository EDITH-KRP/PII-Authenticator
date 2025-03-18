import os
from dotenv import load_dotenv

load_dotenv()

INFURA_PROJECT_ID = os.getenv("INFURA_PROJECT_ID")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
ENCRYPTED_AES_KEY = os.getenv("ENCRYPTED_AES_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")

INFURA_URL = f"https://goerli.infura.io/v3/{INFURA_PROJECT_ID}"
