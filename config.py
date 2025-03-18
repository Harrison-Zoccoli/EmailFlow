import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.modify'
]
CREDENTIALS_FILE = 'credentials.json'
TOKEN_FILE = 'token.json'
CLIENT_ID = os.getenv('CLIENT_ID')
AZURE_OPENAI_KEY = os.getenv('AZURE_OPENAI_KEY')
AZURE_OPENAI_ENDPOINT = os.getenv('AZURE_OPENAI_ENDPOINT')
AZURE_OPENAI_DEPLOYMENT = "emailflow-openai"  # Keep hardcoded working value

# Azure deployment URL (needed for production)
AZURE_URL = "https://mailflow-webapp-hvb6a9c6hya7akdy.canadacentral-01.azurewebsites.net"
