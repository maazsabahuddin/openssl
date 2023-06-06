# Python Imports
import os
from io import BytesIO
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

# Image
REPORT_HEADER_LOGO_PATH = os.path.abspath('images/SNOLAB-logo.png')


def get_logo():
    """
    This function will return the logo data in bytes format.
    :return:
    """
    with open(REPORT_HEADER_LOGO_PATH, 'rb') as f:
        return BytesIO(f.read())


REPORT_LOGO_DATA = get_logo()
