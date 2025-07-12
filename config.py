# config.py
import os
from dotenv import load_dotenv

load_dotenv()

NGROK_AUTHTOKEN = os.environ.get("NGROK_AUTHTOKEN")
NGROK_RESERVED_DOMAIN = os.environ.get("NGROK_RESERVED_DOMAIN")
WASENDER_SESSION_ID = os.environ.get("WASENDER_SESSION_ID")
WASENDER_API_TOKEN = os.environ.get("WASENDER_API_TOKEN")
WASENDER_PERSONAL_TOKEN = os.environ.get("WASENDER_PERSONAL_TOKEN")
WASENDER_WEBHOOK_SECRET = os.environ.get("WASENDER_WEBHOOK_SECRET")
GODADDY_KEY = os.environ.get("GODADDY_KEY")
GODADDY_SECRET = os.environ.get("GODADDY_SECRET")
OWNER_PHONE_NUMBER = os.environ.get("OWNER_PHONE_NUMBER")
DOWNLOAD_DIR = os.path.join(os.path.dirname(__file__), 'downloads')
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'uploads')
LOGS_DIR = os.path.join(os.path.dirname(__file__), 'logs')
PUBLIC_URL = None
# Load and parse the group IDs from a comma-separated string
raw_group_ids = os.environ.get("TARGET_GROUP_IDS", "")
TARGET_GROUP_IDS = [gid.strip() for gid in raw_group_ids.split(',') if gid.strip()]

# Basic validation
if not all([NGROK_AUTHTOKEN, WASENDER_SESSION_ID, WASENDER_PERSONAL_TOKEN, OWNER_PHONE_NUMBER]):
    raise ValueError("One or more required environment variables are missing. Check your .env file.")

if not TARGET_GROUP_IDS:
    print("⚠️ WARNING: TARGET_GROUP_IDS is not set in the .env file. The bot won't be able to send messages to any groups.")