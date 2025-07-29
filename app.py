import os
import logging
import time
from logging.handlers import TimedRotatingFileHandler
import requests
import secrets
import ngrok
import json
from flask import Flask, request, jsonify, send_from_directory, abort, render_template, redirect, url_for, flash
from datetime import datetime
import config
from scheduler import start_scheduler
from bot_handler import handle_incoming_message, find_media_info, handle_media_decryption

from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

from persistent_queue_processor import PersistentQueueProcessor

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
logging.info("Logger initialized with daily rotation.")
logging.getLogger('werkzeug').setLevel(logging.WARNING)

# --- Initialize app directories ---
os.makedirs(config.DOWNLOAD_DIR, exist_ok=True)
os.makedirs(config.UPLOAD_DIR, exist_ok=True)
os.makedirs(config.LOGS_DIR, exist_ok=True)

# --- Initialize persistent queue process ---
from whatsapp.wasenderapi_whatsapp_provider import WASenderApiWhatsAppProvider
wa_provider = WASenderApiWhatsAppProvider()

def wasender_processing_logic(payload):
    payload_json = json.loads(payload)
    # simulate processing logic
    time.sleep(2)
    
processor = PersistentQueueProcessor(r'dbs/wasender_queue.db', wa_provider.webhook_handler)

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

@app.errorhandler(Exception)
def handle_global_exception(e):
    """Global handler for unhandled exceptions."""
    logging.error(f"Unhandled Exception: {e}", exc_info=True)
    return jsonify(status='error', message='An internal server error occurred.'), 500

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


# --- Webhook Handler ---
@app.route('/wasender_webhook', methods=['POST'])
def wasender_webhook():
    """Main webhook endpoint to receive events from WasenderAPI."""

    if not request.headers.get('X-Webhook-Signature','') == config.WASENDER_WEBHOOK_SECRET:
        logging.warning("Request arrive with invalid/empty webhook secret")
        return "Invalid request", 400

    if not request.is_json:
        logging.warning("Received non-JSON request")
        return "Invalid request", 400
    
    payload = request.get_data()
    processor.append(payload)

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
        processor.stop()