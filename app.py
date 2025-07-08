import os
import logging
import requests
import ngrok
from flask import Flask, request, jsonify, send_from_directory, abort


# Import our custom modules
import config
from scheduler import start_scheduler
from bot_handler import handle_incoming_message, find_media_info, handle_media_decryption


# --- Basic Setup ---
#logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
app = Flask(__name__)
# --- NEW: Payload Parser Function ---
def parse_raw_message(raw_msg: dict) -> dict or None:
    """
    Parses the raw message object from the WasenderAPI webhook
    and transforms it into a standardized format for our bot.
    """
    if not isinstance(raw_msg, dict):
        return None

    key = raw_msg.get("key", {})
    message_content = raw_msg.get("message", {})
    
    if not key or not message_content:
        return None

    # This is our new, clean, and standardized message format
    parsed_message = {
        "id": key.get("id"),
        "from": key.get("remoteJid"),
        "from_me": key.get("fromMe", False),
        "type": None,
        "content": {}
    }

    # Determine message type and content
    if "conversation" in message_content and message_content["conversation"]:
        parsed_message["type"] = "text"
        parsed_message["content"]["body"] = message_content["conversation"]
    # Add other types as you discover their payload structure
    # For example, for an image:
    # elif "imageMessage" in message_content:
    #     parsed_message["type"] = "image"
    #     parsed_message["content"]["url"] = message_content["imageMessage"].get("url")
    #     parsed_message["content"]["caption"] = message_content["imageMessage"].get("caption")
    elif "videoMessage" in message_content and message_content["videoMessage"]:
        parsed_message["type"] = "video"
        parsed_message["content"]["body"] = message_content["videoMessage"]
    elif "audioMessage" in message_content and message_content["audioMessage"]:
        parsed_message["type"] = "audio"
        parsed_message["content"]["body"] = message_content["audioMessage"]
    else:
        # Unsupported message type for now
        return None

    return parsed_message

def preprocess_incoming_message(message_content, media_result, message_id):
    updates_dict = {}
    if message_content:
        logging.info(f"Text: {message_content}")
        # TODO: Save text message to your database here.
        
    if media_result:
        media_info, media_type = media_result
        logging.info(f"Media found. Type: {media_type}. Attempting to decrypt...")

        decrypted_data = handle_media_decryption(media_info, media_type)
        logging.info(f"Successfully decrypted media. saving to file")
        os.makedirs(config.DOWNLOAD_DIR, exist_ok=True)
        extension = media_info.get('mimetype', 'application/octet-stream').split('/')[-1]
        filename = media_info.get('fileName') or f"{message_id}.{extension}"
        output_path = os.path.join(config.DOWNLOAD_DIR, os.path.basename(filename)) # Use basename to prevent path traversal
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        logging.info(f"Decrypted file saved to {output_path}")
        logging.info(f"Decrypted file available via {config.PUBLIC_URL}/download/{filename}")
        updates_dict[f"data/messages/message/{media_type}Message/url"] = f'{config.PUBLIC_URL}/download/{filename}'
    return updates_dict

def update_dict_path(data, path, value, sep="/"):
    keys = path.split(sep)
    d = data
    for key in keys[:-1]:
        d = d.setdefault(key, {})  # Create nested dicts if not present
    d[keys[-1]] = value


# --- Webhook Handler ---
@app.route('/', methods=['POST'])
def webhook():
    """Main webhook endpoint to receive events from WasenderAPI."""
    if not request.is_json:
        logging.warning("Received non-JSON request")
        return "Invalid request", 400
    
    payload = request.get_json()
    logging.info(f"📥 Received webhook: {payload}")

    match payload.get("event"):
        case "messages.upsert":
            message_data = payload.get('data', {}).get('messages', [{}])

            # Filter non messages (e.g., user deleted messages):
            if not message_data:
                logging.warning('Webhook received but no message data found.')
                return jsonify({"status": "skipped, no messages found"}), 200

            key = message_data.get('key', {})
            message_id = key.get('id', 'unknown_id')
            remote_jid = key.get('remoteJid')
            if not remote_jid:
                logging.warning('Ignoring message with no remoteJid.')
                return jsonify({"status": "Ignoring message with no remoteJid"}), 200
            
            from_me = key.get('fromMe', False)
            push_name = message_data.get('pushName', 'Unknown') if not from_me else 'Me'
            phone_number = remote_jid.split('@')[0]
            
            message = message_data.get('message', {})
            message_content = message.get('conversation') or (message.get('extendedTextMessage') or {}).get('text')
            media_result = find_media_info(message)
            
            if not message_content and not media_result:
                logging.warning(f"Ignoring event with no content (ID: {message_id})")
                return jsonify({"status": f"Ignoring event with no content (ID: {message_id})"}), 200
            
            logging.info(f"Pre-processing message from {push_name} ({phone_number}). ID: {message_id}")
            updates_dict = preprocess_incoming_message(message_content, media_result, message_id)
            for path,value in updates_dict.items():
                update_dict_path(payload, path, value)
            logging.info("Finished pre-processing message")

            data = payload.get("data", {})
        
            raw_messages = data.get("messages")
            messages_to_process = []

            # FIX: Handle both single object and list of objects
            if isinstance(raw_messages, dict):
                messages_to_process.append(raw_messages)
            elif isinstance(raw_messages, list):
                messages_to_process = raw_messages
            
            for raw_msg in messages_to_process:
                # Use our parser to standardize the message
                parsed_message = parse_raw_message(raw_msg)
                
                if parsed_message and not parsed_message.get("from_me"):
                    handle_incoming_message(parsed_message)
        case _:
            pass
    return jsonify({"status": "ok"}), 200

    if payload.get("event") == "messages.upsert":
        data = payload.get("data", {})
        
        raw_messages = data.get("messages")
        messages_to_process = []

        # FIX: Handle both single object and list of objects
        if isinstance(raw_messages, dict):
            messages_to_process.append(raw_messages)
        elif isinstance(raw_messages, list):
            messages_to_process = raw_messages
        
        for raw_msg in messages_to_process:
            # Use our parser to standardize the message
            parsed_message = parse_raw_message(raw_msg)
            
            if parsed_message and not parsed_message.get("from_me"):
                handle_incoming_message(parsed_message)
    else:
        print(payload.get('event'))

    return jsonify({"status": "ok"}), 200


@app.route('/health', methods=['GET'])
def health_check():
    """A simple health check endpoint."""
    return "OK", 200

@app.route('/download/<path:filename>', methods=['GET'])
def download_file(filename):
    try:
        return send_from_directory(
            config.DOWNLOAD_DIR,
            filename,
            as_attachment=True  # Forces download
        )
    except FileNotFoundError:
        abort(404)

# --- WasenderAPI Setup Function (No changes needed here) ---
def update_wasender_webhook(url):
    """Updates the webhook URL in your WasenderAPI session settings."""
    endpoint = f"https://www.wasenderapi.com/api/whatsapp-sessions/{config.WASENDER_SESSION_ID}"
    headers = {
        "Authorization": f"Bearer {config.WASENDER_PERSONAL_TOKEN}",
        "Content-Type": "application/json"
    }
    data = {
        "account_protection": False,
        "webhook_url": url,
        "webhook_enabled": True,
        "webhook_events": ["messages.upsert","message.sent","qrcode.updated","messages.update",
                        "message-receipt.update","chats.upsert","chats.delete","groups.update",
                        "contacts.upsert","session.status","messages.delete","messages.reaction",
                        "chats.update","groups.upsert","group-participants.update","contacts.update"]
    }
    logging.info(f"Attempting to update WasenderAPI webhook to {url}...")
    try:
        resp = requests.put(endpoint, json=data, headers=headers)
        resp.raise_for_status()
        logging.info("✅ WasenderAPI webhook updated successfully!")
        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ WasenderAPI webhook update failed: {e.response.status_code if e.response else 'N/A'}, {e.response.text if e.response else str(e)}")
        return False

# --- Main Execution Block (No changes needed here) ---
if __name__ == "__main__":
    start_scheduler()

    try:
        ngrok.set_auth_token(config.NGROK_AUTHTOKEN)
        listener = ngrok.forward("http://localhost:5000")
        config.PUBLIC_URL = listener.url()
        logging.info(f"🔗 ngrok tunnel is active: {config.PUBLIC_URL}")

        update_wasender_webhook(config.PUBLIC_URL)
        
        logging.info("🚀 Starting Flask server...")
        app.run(host="0.0.0.0", port=5000)

    except Exception as e:
        logging.critical(f"💥 An error occurred during startup: {e}")
    finally:
        if config.PUBLIC_URL:
            logging.info("Shutting down ngrok tunnel.")
            ngrok.disconnect(config.PUBLIC_URL)