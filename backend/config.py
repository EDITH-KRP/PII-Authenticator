import os
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

INFURA_URL = f"https://goerli.infura.io/v3/{os.getenv('INFURA_PROJECT_ID')}"
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")