import os
import logging
from datetime import datetime
import pytz
import config
from whatsapp_client import client as whatsapp_client
from scheduler import schedule_sync
import base64
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CONVERSATION_STATE = {}

def log_message(message):
    """A simple logging function for demonstration."""
    from datetime import datetime
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] {message}")
    # In a real app, you'd use the logging module.

def find_media_info(message_object):
    """Finds the first available media object and its type from the message."""
    media_keys = {
        'imageMessage': 'image',
        'videoMessage': 'video',
        'audioMessage': 'audio',
        'documentMessage': 'document',
        'stickerMessage': 'sticker',
    }
    if not message_object:
        return None
        
    for key, type_str in media_keys.items():
        if key in message_object:
            return message_object[key], type_str
    return None

def get_decryption_keys(media_key, media_type):
    """Derives decryption keys using HKDF."""
    info_map = {
        'image': b'WhatsApp Image Keys',
        'sticker': b'WhatsApp Image Keys',
        'video': b'WhatsApp Video Keys',
        'audio': b'WhatsApp Audio Keys',
        'document': b'WhatsApp Document Keys',
    }
    info = info_map.get(media_type)
    if not info:
        raise ValueError(f"Invalid media type: {media_type}")

    media_key_bytes = base64.b64decode(media_key)
    
    # Use HKDF to derive a 112-byte expanded key.
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=112,
        salt=b'',
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(media_key_bytes)

def handle_media_decryption(media_info, media_type):
    """Main function to decrypt and save a media file."""
    url = media_info.get('url')
    media_key = media_info.get('mediaKey')
    if not url or not media_key:
        raise ValueError("Media object is missing 'url' or 'mediaKey'.")

    # 1. Download the encrypted file
    response = requests.get(url)
    response.raise_for_status()
    encrypted_data = response.content

    # 2. Derive the IV and Cipher Key
    keys = get_decryption_keys(media_key, media_type)
    iv = keys[:16]
    cipher_key = keys[16:48]

    # 3. The actual ciphertext is the file content, minus the last 10 bytes (MAC hash).
    ciphertext = encrypted_data[:-10]

    # 4. Decrypt using AES-256-CBC
    cipher = Cipher(algorithms.AES(cipher_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_data

def handle_incoming_message(message: dict):
    """Main function to process incoming messages (now receives a standardized dict)."""
    # message is now our clean, parsed object
    if not message.get("content"):
        return

    # FIX: Use the 'from' field from our parsed object
    sender_id = message.get("from")
    
    # IMPORTANT: The bot should only be controlled by you.
    # The sender_id from the webhook includes '@s.whatsapp.net', so we compare against that.
    owner_jid = f"{config.OWNER_PHONE_NUMBER}@s.whatsapp.net"
    if sender_id != owner_jid:
        logging.info(f"Ignoring message from non-owner: {sender_id}")
        return

    current_state_info = CONVERSATION_STATE.get(owner_jid)

    match message.get("type", ""):
        case "conversation" | "text":
            user_reply = message.get("content", {}).get("body", "").strip().lower()
        case "video" | "audio":
            # Need to decrypt url
            user_reply = ""
        case _:
            user_reply = ""
    media_result = find_media_info

    if not current_state_info:
        # Check if the user is replying to the bot or sending a new message to sync
        if user_reply not in ["1", "2", "sync", "ignore", "immediately", "schedule"] and not user_reply.isnumeric():
             start_new_sync_flow(owner_jid, message)
        else:
            # It's likely a stray reply, ignore it.
            whatsapp_client.send_text_message(owner_jid, "I'm not sure what that's for. Please send me a new message to start a sync.")

    else:
        continue_sync_flow(owner_jid, user_reply, current_state_info)


def start_new_sync_flow(owner_jid, message):
    """Starts the conversation to sync a new message."""
    logging.info(f"Starting new sync flow for user {owner_jid}")
    CONVERSATION_STATE[owner_jid] = {
        "state": "AWAITING_ACTION_CHOICE",
        "original_message": message
    }
    whatsapp_client.send_text_message(
        owner_jid,
        "What do you want to do with this message?\n\n1. *Sync*\n2. *Ignore*"
    )

def continue_sync_flow(owner_jid, user_reply, state_info):
    """Handles the subsequent steps of the conversation."""
    state = state_info.get("state")
    original_message = state_info.get("original_message")

    if state == "AWAITING_ACTION_CHOICE":
        if "sync" in user_reply or user_reply == "1":
            CONVERSATION_STATE[owner_jid]["state"] = "AWAITING_SCHEDULE_CHOICE"
            whatsapp_client.send_text_message(
                owner_jid,
                "Great! When should I sync it?\n\n1. *Immediately*\n2. *Schedule*"
            )
        elif "ignore" in user_reply or user_reply == "2":
            whatsapp_client.send_text_message(owner_jid, "Okay, ignoring this message. Ready for the next one!")
            del CONVERSATION_STATE[owner_jid]
        else:
            whatsapp_client.send_text_message(owner_jid, "Sorry, I didn't understand. Please reply with 'Sync' or 'Ignore'.")

    elif state == "AWAITING_SCHEDULE_CHOICE":
        if "immediately" in user_reply or user_reply == "1":
            sync_immediately(owner_jid, original_message)
        elif "schedule" in user_reply or user_reply == "2":
            CONVERSATION_STATE[owner_jid]["state"] = "AWAITING_DATETIME"
            whatsapp_client.send_text_message(
                owner_jid,
                "Please provide a date and time for scheduling in `YYYYMMDDHHmmss` format (Israel Time).\n\n*Example*: `20241231223000` for Dec 31, 2024 at 10:30 PM."
            )
        else:
            whatsapp_client.send_text_message(owner_jid, "Sorry, I didn't understand. Please reply with 'Immediately' or 'Schedule'.")

    elif state == "AWAITING_DATETIME":
        handle_scheduling(owner_jid, user_reply, original_message)


def sync_immediately(owner_jid, original_message):
    """Sends the message to all target groups right away."""
    logging.info(f"Syncing message immediately for {owner_jid}")
    if not config.TARGET_GROUP_IDS:
        whatsapp_client.send_text_message(owner_jid, "⚠️ Cannot sync: No target group IDs are configured in your .env file.")
        del CONVERSATION_STATE[owner_jid]
        return

    for group_id in config.TARGET_GROUP_IDS:
        whatsapp_client.resend_message(group_id, original_message)
    
    whatsapp_client.send_text_message(owner_jid, f"✅ Done! Message sent to {len(config.TARGET_GROUP_IDS)} groups.")
    del CONVERSATION_STATE[owner_jid]


def handle_scheduling(owner_jid, datetime_str, original_message):
    """Parses the datetime string and schedules the message."""
    try:
        israel_tz = pytz.timezone('Asia/Jerusalem')
        naive_dt = datetime.strptime(datetime_str, "%Y%m%d%H%M%S")
        israel_dt = israel_tz.localize(naive_dt)

        if israel_dt < datetime.now(israel_tz):
            whatsapp_client.send_text_message(owner_jid, "❌ The scheduled time is in the past. Please provide a future time.")
            return

        schedule_sync(israel_dt, original_message)
        
        formatted_date = israel_dt.strftime('%A, %B %d, %Y at %I:%M %p %Z')
        whatsapp_client.send_text_message(
            owner_jid,
            f"👍 Got it! I've scheduled your message to be sent on:\n\n*{formatted_date}*"
        )
        del CONVERSATION_STATE[owner_jid]

    except ValueError:
        whatsapp_client.send_text_message(
            owner_jid,
            "❌ Invalid format. Please use `YYYYMMDDHHmmss`.\n*Example*: `20241231223000`"
        )