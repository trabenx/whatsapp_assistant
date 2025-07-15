import os
import logging
from logging.handlers import TimedRotatingFileHandler
import requests
import secrets
import ngrok
from flask import Flask, request, jsonify, send_from_directory, abort, render_template, redirect, url_for, flash
from datetime import datetime
import config
from scheduler import start_scheduler
from bot_handler import handle_incoming_message, find_media_info, handle_media_decryption

from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user


for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)

# --- App's main logger ---
main_log_handler = TimedRotatingFileHandler(
    os.path.join(config.LOGS_DIR, 'app.log'),
    when='midnight',
    interval=1,
    backupCount=0,
    encoding='utf-8',
    utc=False
)
main_log_handler.suffix = "%Y-%m-%d"
main_log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.getLogger().setLevel(logging.INFO)
logging.getLogger().addHandler(main_log_handler)          # Log to file
logging.getLogger().addHandler(logging.StreamHandler())   # Log to console
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
#logging.basicConfig(level=logging.INFO)
logging.info("Logger initialized with daily rotation.")

# --- Initialize app directories ---
os.makedirs(config.DOWNLOAD_DIR, exist_ok=True)
os.makedirs(config.UPLOAD_DIR, exist_ok=True)
os.makedirs(config.LOGS_DIR, exist_ok=True)

# --- Initialize Flask app & requests-logger ---

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(24))
request_logger = logging.getLogger('request_logger')
request_logger.setLevel(logging.INFO)
requests_log_handlers = TimedRotatingFileHandler(
    os.path.join(config.LOGS_DIR, 'requests.log'),
    when='midnight',
    interval=1,
    backupCount=0,
    encoding='utf-8',
    utc=True
)
requests_log_handlers.suffix = "%Y-%m-%d"
requests_log_handlers.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
request_logger.addHandler(requests_log_handlers)
request_logger.propagate=False  # do NOT log to console

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

@app.before_request
def log_incoming_request():
    ts = datetime.utcnow().isoformat()
    ip = get_client_ip()
    method = request.method
    path = request.path
    logging.info(f"📥 Received webhook: [{ts}] {ip} {method} {path}]")
    try:
        if request.content_type and 'multipart/form-data' in request.content_type:
            file_info = []
            for f in request.files.values():
                file_info.append({
                    'filename': f.filename,
                    'content_type': f.content_type,
                    'content_length': request.content_length  # request-wide length, optional
                })
            request_logger.info(f"[{ts}] {ip} {method} {path} - File upload: {file_info}")

        elif request.is_json:
            data = request.get_json()
            request_logger.info(f"[{ts}] {ip} {method} {path} - JSON body: {data}")
        else:
            raw_data = request.get_data(as_text=True)
            request_logger.warning(f"[{ts}] {ip} {method} {path} - Non-JSON body: {raw_data}")
    except Exception as e:
        request_logger.error(f"[{ts}] {ip} {method} {path} - Error reading request: {e}")


# --- Flask-Login Configuration ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirect to 'login' view if user is not logged in

# --- Dummy User Model (for demonstration) ---
# In a real app, you would use a database (e.g., SQLAlchemy)
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

# Dummy user database
users = {
    '1': User(id='1', username='verified_user', password='password123')
}

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

@app.route('/')
def index():
    if current_user.is_authenticated:
        return f'Hello, {current_user.username}! <a href="/upload">Upload a File</a> or <a href="/logout">Logout</a>'
    return 'Hello, Guest! <a href="/login">Login</a>'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Find user
        user_to_login = None
        for user in users.values():
            if user.username == username and user.password == password:
                user_to_login = user
                break
        
        if user_to_login:
            login_user(user_to_login)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('upload_file'))
        else:
            flash('Invalid username or password.', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required # This decorator protects the route
def upload_file():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            return jsonify({'error': 'No file part in the request'}), 400
        
        file = request.files['file']
        
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
            
        if file:
            # Use secure_filename to prevent directory traversal attacks
            filename = secure_filename(file.filename)
            save_path = os.path.join(config.UPLOAD_DIR, filename)
            file.save(save_path)
            
            # Return a success response to the JavaScript
            return jsonify({
                'message': 'File uploaded successfully!',
                'filename': filename
            }), 200

    # If GET request, render the upload form
    return render_template('upload.html')


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
    elif "imageMessage" in message_content and message_content["imageMessage"]:
        parsed_message["type"] = "image"
        parsed_message["content"]["body"] = message_content["imageMessage"]
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
@app.route('/wasender_webhook', methods=['POST'])
def wasender_webhook():
    """Main webhook endpoint to receive events from WasenderAPI."""
    if not request.is_json:
        logging.warning("Received non-JSON request")
        return "Invalid request", 400
    
    payload = request.get_json()
    #logging.info(f"📥 Received webhook: {payload}")

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
        listener = ngrok.forward("http://localhost:5000", domain=config.NGROK_RESERVED_DOMAIN)
        config.PUBLIC_URL = listener.url()
        logging.info(f"🔗 ngrok tunnel is active: {config.PUBLIC_URL}")

        update_wasender_webhook(f'{config.PUBLIC_URL}/wasender_webhook')
        logging.info("🚀 Starting Flask server...")
        app.run(host="0.0.0.0", port=5000)

    except Exception as e:
        logging.critical(f"💥 An error occurred during startup: {e}")
    finally:
        if config.PUBLIC_URL:
            logging.info("Shutting down ngrok tunnel.")
            ngrok.disconnect(config.PUBLIC_URL)