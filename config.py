# Python Imports
import os
from dotenv import load_dotenv
from pathlib import Path

dotenv_path = Path('.env')
load_dotenv(dotenv_path=dotenv_path)

# SNOLAB Networks
SNOLAB_NETWORKS = os.environ[f"SNOLAB_NETWORKS"].split(',')

# CAs
LETS_ENCRYPT = "Let's Encrypt"
DIGI_CERT = "DigiCert Inc"

# Email Configuration
SMTP_PORT = 25
SMTP_SERVER = os.environ[f"SMTP_SERVER"]
EMAIL_USERNAME = os.environ[f"EMAIL_USERNAME"]
EMAIL_SENT_TO = os.environ["EMAIL_SENT_TO"]
