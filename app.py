# app.py - V4 - Refactored for API Usage
# CRITICAL FIX 1: EVENTLET MONKEY PATCH MUST BE FIRST
import eventlet
eventlet.monkey_patch()
# ---------------------------------------------------

import os
import json
import re
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, render_template, Blueprint
from flask_socketio import SocketIO, join_room
from mailparser import MailParser
from redis import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

app = Flask(__name__)

# --- Configuration ---
REDIS_URL = os.environ.get("UPSTASH_REDIS_URL")
REDIS_TOKEN = os.environ.get("UPSTASH_REDIS_TOKEN")
SUBDOMAIN = os.environ.get("SUBDOMAIN", "codewithjames.top")
ADDRESS_TTL_DAYS = 14
## REFACTOR: Add an API Key from environment variables for security
API_KEY = os.environ.get("API_KEY") # IMPORTANT: Set this in your environment!

# --- Redis Connection (No changes) ---
redis_client = None
try:
    redis_host = REDIS_URL.split('://')[1]
    redis_client = Redis.from_url(
        url=f"rediss://default:{REDIS_TOKEN}@{redis_host}",
        decode_responses=True,
        ssl_cert_reqs=None
    )
    redis_client.ping()
    print("[INFO] Successfully connected to Upstash Redis.")
except (RedisConnectionError, Exception) as e:
    print(f"[ERROR] Could not connect to Redis: {e}")
    exit(1)

# --- SocketIO Initialization (No changes) ---
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# --- Constants & Key Definitions (No changes) ---
ADDRESSES_KEY = "addresses"
MESSAGES_PREFIX = "messages:"

# --- Helper Functions (No changes) ---
# Your OTP function is fine as a heuristic, don't worry about it being "shitty". It's a value-add!
def extract_otp(raw_email_content):
    content_to_search = raw_email_content.upper()
    patterns = [r'(?:CODE|OTP|PIN|TOKEN|IS)[:\s]*\b([A-Z0-9]{5,8})\b', r'\b([A-Z]{6})\b', r'\b(\d{4,8})\b']
    for pattern in patterns:
        match = re.search(pattern, content_to_search)
        if match:
            return match.group(1).strip()
    return None

def generate_address(alias=None):
    alias_part = alias or secrets.token_hex(4)
    addr = f"{alias_part}@{SUBDOMAIN}"
    now = datetime.utcnow()
    expires = now + timedelta(days=ADDRESS_TTL_DAYS)
    expires_iso = expires.isoformat()
    redis_client.hset(ADDRESSES_KEY, addr, expires_iso)
    return addr, expires_iso







# Place this new function above your store_message function
def extract_email_details(html_body, text_body):
    """
    Parses email content to extract OTPs (numeric and mixed-alphanumeric),
    lists of potential numeric codes, and all hyperlinks.
    """
    # Combine HTML and text for a comprehensive search space
    content_to_search = f"{html_body} {text_body}"
    
    # --- 1. Link Extraction ---
    # A robust regex to find all http/https links.
    link_pattern = r'https?://[^\s"\'<>]+'
    links = re.findall(link_pattern, content_to_search)
    # Remove duplicates while preserving order
    unique_links = sorted(list(set(links)), key=links.index) if links else []

    # --- 2. OTP and Code Extraction ---
    # We search the uppercase version to simplify regex patterns
    search_upper = content_to_search.upper()

    # Pattern for numeric codes (4 to 8 digits). \b ensures we match whole numbers.
    numeric_pattern = r'\b(\d{4,8})\b'
    all_numeric_codes = re.findall(numeric_pattern, search_upper)

    # Pattern for mixed alphanumeric codes (5-8 chars, must contain at least one letter).
    # This avoids capturing purely numeric codes again.
    # (?=.*[A-Z]) is a "positive lookahead" that asserts a letter must exist.
    mixed_pattern = r'\b(?=.*[A-Z])[A-Z0-9]{5,8}\b'
    all_mixed_codes = re.findall(mixed_pattern, search_upper)

    # --- 3. Assigning the final attributes ---
    otp_digit = all_numeric_codes[0] if all_numeric_codes else None
    otp_mix = all_mixed_codes[0] if all_mixed_codes else None
    otp_lists = all_numeric_codes if all_numeric_codes else []

    return {
        "otp_digit": otp_digit,
        "otp_mix": otp_mix,
        "otp_lists": otp_lists,
        "links": unique_links
    }


# Replace your existing store_message function with this new version
def store_message(to_address, from_addr, subject, raw):
    if not redis_client.hexists(ADDRESSES_KEY, to_address):
        print(f"[Webhook] Received mail for unknown/expired address: {to_address}")
        return # Stop processing for unknown addresses

    html_body, text_body, full_sender_identity = "No HTML content found.", "No plain text content found.", from_addr
    try:
        if raw and raw.strip():
            parser = MailParser.from_string(raw)
            html_body = parser.text_html[0] if parser.text_html else html_body
            text_body = parser.text_plain[0] if parser.text_plain else text_body
            if parser.from_ and isinstance(parser.from_, list) and parser.from_[0]:
                name, email = parser.from_[0][0], parser.from_[0][1]
                full_sender_identity = f"{name} <{email}>" if name else email
            if html_body == "No HTML content found." and text_body != "No plain text content found.":
                 html_body = f'<pre>{text_body}</pre>'
    except Exception as e:
        error_msg = f"'{e}'"
        print(f"[ERROR] Failed to parse email: {error_msg}")
        text_body = f"ERROR: Failed to parse raw content. Details: {error_msg}"
        html_body = f'<h1>Error parsing email content!</h1><pre>{error_msg}</pre>'

    # Generate a more stable message ID
    message_id = f"{datetime.utcnow().timestamp()}-{secrets.token_hex(2)}"

    # Call our new super extractor!
    extracted_data = extract_email_details(html_body, text_body)

    message_data = {
        "id": message_id,
        "from": full_sender_identity,
        "subject": subject,
        "received_at": datetime.utcnow().isoformat(),
        "html_body": html_body,
        "text_body": text_body,
    }
    # Cleanly merge the extracted data into our message object
    message_data.update(extracted_data)
    
    redis_client.lpush(f"{MESSAGES_PREFIX}{to_address}", json.dumps(message_data))
    redis_client.ltrim(f"{MESSAGES_PREFIX}{to_address}", 0, 99)

    # Emit a richer real-time event for the frontend
    mini_msg = {
        "id": message_id,
        "address": to_address,
        "from": full_sender_identity,
        "subject": subject,
        "received_at": message_data["received_at"],
        "otp_digit": extracted_data["otp_digit"], # Add new fields to socket event
        "otp_mix": extracted_data["otp_mix"]
    }
    socketio.emit('new_mail', mini_msg, room=to_address)














#####################################################################
## REFACTOR 1: API SECURITY & STRUCTURE
#####################################################################

# Create a Blueprint for our version 1 API
api_v1 = Blueprint('api_v1', __name__, url_prefix='/api/v1')

# Define our API key authentication decorator
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not API_KEY:
            # If API_KEY is not set on the server, internal error
            return jsonify({"error": "API service is not configured."}), 500
        
        provided_key = request.headers.get('X-API-Key')
        if not provided_key or provided_key != API_KEY:
            return jsonify({"error": "Unauthorized. Invalid or missing API Key."}), 401
        
        return f(*args, **kwargs)
    return decorated_function

#####################################################################
## REFACTOR 2: NEW RESTFUL API ENDPOINTS
#####################################################################

@api_v1.route("/addresses", methods=["POST"])
@require_api_key
def create_address():
    """Generates a new disposable email address."""
    data = request.get_json(silent=True) or {}
    alias = data.get("alias")
    # Optional: Add validation for alias format here
    addr, expires_at = generate_address(alias)
    return jsonify({"address": addr, "expires_at": expires_at}), 201

@api_v1.route("/addresses/<string:email>/messages", methods=["GET"])
@require_api_key
def get_messages_for_address(email):
    """Gets a list of messages (summary view) for a given address."""
    messages_json = redis_client.lrange(f"{MESSAGES_PREFIX}{email}", 0, -1)
    messages_summary = []
    for msg_json in messages_json:
        try:
            msg = json.loads(msg_json)
            messages_summary.append({
                "id": msg.get("id"),
                "from": msg.get("from"),
                "subject": msg.get("subject"),
                "received_at": msg.get("received_at"),
                # Add our new, powerful fields to the summary!
                "otp_digit": msg.get("otp_digit"),
                "otp_mix": msg.get("otp_mix"),
                "has_links": bool(msg.get("links")) # A boolean flag is useful here
            })
        except (json.JSONDecodeError, KeyError):
            continue
    return jsonify(messages_summary)

@api_v1.route("/messages/<string:email>/<string:message_id>", methods=["GET"])
@require_api_key
def get_full_message(email, message_id):
    """Gets the full body of a single message by its ID."""
    messages_json = redis_client.lrange(f"{MESSAGES_PREFIX}{email}", 0, -1)
    for msg_json in messages_json:
        try:
            msg = json.loads(msg_json)
            if msg.get("id") == message_id:
                # For security, don't expose the raw field in the API
                msg.pop("raw", None) 
                return jsonify(msg)
        except (json.JSONDecodeError, KeyError):
            continue
    return jsonify({"error": "Message not found."}), 404

# Register the blueprint with the main Flask app
app.register_blueprint(api_v1)

#####################################################################
## WEBHOOK & FRONTEND ROUTES (Largely unchanged)
#####################################################################

@app.route("/", methods=["GET"])
def home():
    """Serves the frontend application."""
    return render_template("index.html")

@app.route("/webhook", methods=["POST"])
def api_webhook():
    """Webhook endpoint for receiving new emails."""
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "No JSON received"}), 400
    to_addr, from_addr, subject, raw = data.get("to"), data.get("from", "unknown"), data.get("subject", ""), data.get("raw", data.get("text", ""))
    if not to_addr:
        return jsonify({"error": "Missing 'to' field"}), 400
    
    # Still use background task for speed
    socketio.start_background_task(store_message, to_addr, from_addr, subject, raw)
    
    return jsonify({"status": "success", "message": "processing in background"}), 200

# This endpoint is for your frontend's history panel, so it can remain.
@app.route("/addresses", methods=["GET"])
def list_all_addresses():
    """Lists all known addresses for the frontend history."""
    all_addresses = redis_client.hgetall(ADDRESSES_KEY)
    addresses_list = [{"address": addr, "expires_at": expires_at} for addr, expires_at in all_addresses.items()]
    addresses_list.sort(key=lambda x: x['expires_at'], reverse=True)
    return jsonify(addresses_list)

@socketio.on('join_mailbox')
def on_join(data):
    mailbox_address = data.get('address')
    if mailbox_address:
        join_room(mailbox_address)
        print(f"Client {request.sid} joined room: {mailbox_address}")

# Add headers after every request (No changes)
@app.after_request
def add_security_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return response

# Note: The old /generate and /get routes are now gone, replaced by the API blueprint.
# You will need to update your frontend JavaScript to call the new API endpoints.
# This is a good thing, as your frontend will now use the same API as any other client.
