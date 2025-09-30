# app.py - Rocket Speed & HTML Views UPGRADE (Fully Patched)

# CRITICAL FIX 1: EVENTLET MONKEY PATCH MUST BE FIRST
import eventlet 
eventlet.monkey_patch() 
# ---------------------------------------------------

import os
import json
import re 
from flask import Flask, request, jsonify, abort, render_template
from flask_socketio import SocketIO, emit, join_room
# Corrected library usage: MailParser is the class, mailparser is the library
from mailparser import MailParser 
from datetime import datetime, timedelta
import secrets
from redis import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

app = Flask(__name__)

# --- SOCKETIO INITIALIZATION (REQUIRED FOR ROCKET SPEED) ---
# Use eventlet as the async mode for better compatibility with Gunicorn/Render
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet') 
# -----------------------------------------------------------

# --- Configuration from Environment (SECURE) ---
REDIS_URL = os.environ.get("UPSTASH_REDIS_URL")
REDIS_TOKEN = os.environ.get("UPSTASH_REDIS_TOKEN")
SUBDOMAIN = os.environ.get("SUBDOMAIN", "codewithjames.top") 

if not REDIS_URL or not REDIS_TOKEN:
    print("FATAL: UPSTASH_REDIS_URL or UPSTASH_REDIS_TOKEN is not set in environment.")
    pass 

ADDRESS_TTL_DAYS = 14 

# Initialize Redis client 
redis_client = None 

# --- CRITICAL: REDIS CONNECTION BLOCK ---
try:
    redis_host = REDIS_URL.split('://')[1]
    
    redis_client = Redis.from_url(
        url=f"rediss://default:{REDIS_TOKEN}@{redis_host}",
        decode_responses=True,
        ssl_cert_reqs=None 
    )
    
    redis_client.ping()
    print("[INFO] Successfully connected to Upstash Redis.")
except RedisConnectionError as e:
    print(f"[ERROR] Could not connect to Redis (Connection Error): {e}")
    exit(1)
except Exception as e:
    print(f"[ERROR] Could not connect to Redis (General Error): {e}")
    exit(1)
# ------------------------------------------


# --- Constants & Key Definitions ---
ADDRESSES_KEY = "addresses"
MESSAGES_PREFIX = "messages:" 

# --- Helpers (OTP Extractor remains the same) ---
def extract_otp(raw_email_content):
    """Intelligently extracts potential OTPs/verification codes."""
    patterns = [
        r'(?:code|otp|pin|token|is)[:\s]*([A-Z0-9]{5,8})',
        r'(\b\d{4,8}\b)',
        r'([A-Z]{6}\b)'
    ]
    
    content = raw_email_content.upper()
    
    for pattern in patterns:
        match = re.search(pattern, content)
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

# --- Helpers (MODIFIED: Parsing FIX) ---
def store_message(to_address, from_addr, subject, raw):
    if not redis_client.hexists(ADDRESSES_KEY, to_address):
        print(f"[Webhook] Received mail for unknown/expired address: {to_address}")
    
    # --- FIX 3: Correct MailParser Initialization and Fallback ---
    html_body = "No HTML content found."
    text_body = "No plain text content found."
    otp_code = extract_otp(raw)
    
    try:
        if raw and raw.strip():
            # Use the safer from_string method
            parser = MailParser.from_string(raw)
            
            if parser and parser.body:
                # Extract the body parts safely
                html_body = parser.body.get('html', [html_body])[0]
                text_body = parser.body.get('plain', [text_body])[0]
                
                # Optional: Fallback to plain text if HTML is empty
                if not html_body and text_body:
                     html_body = f'<pre>{text_body}</pre>'
            
    except Exception as e:
        print(f"[ERROR] Failed to parse email: {e}")
        # Ensure error message is explicitly stored if parsing fails
        text_body = f"ERROR: Failed to parse raw content. Details: {e}"
        html_body = f'<h1>Error parsing email content!</h1><pre>{e}</pre>'
        
    message_data = {
        "from": from_addr,
        "subject": subject,
        "raw": raw,
        "received_at": datetime.utcnow().isoformat(),
        
        "html_body": html_body,
        "text_body": text_body,
        "otp": otp_code
    }
    
    # 1. Store the full message in Redis
    redis_client.lpush(f"{MESSAGES_PREFIX}{to_address}", json.dumps(message_data))
    redis_client.ltrim(f"{MESSAGES_PREFIX}{to_address}", 0, 99)
    
    # 2. Emit SocketIO event for instant update (ROCKET SPEED)
    mini_msg = {
        "address": to_address,
        "from": from_addr,
        "subject": subject,
        "otp": otp_code,
        "received_at": message_data["received_at"],
        "id": 1 # Placeholder ID; client will re-fetch list for correct ID sequence
    }
    socketio.emit('new_mail', mini_msg, room=to_address)
# ------------------------------------------------


# --- SOCKETIO EVENT HANDLERS (No changes needed) ---
@socketio.on('join_mailbox')
def on_join(data):
    """Allows client to join a specific room named after the mailbox address."""
    mailbox_address = data.get('address')
    if mailbox_address:
        join_room(mailbox_address)
        print(f"Client {request.sid} joined room: {mailbox_address}")


# --- API endpoints ---

@app.route("/", methods=["GET"])
def home():
    """Renders the main single-page application (the inbox UI)."""
    return render_template("index.html")

@app.route("/generate", methods=["GET"])
def api_generate():
    alias = request.args.get("alias")
    addr, expires_at = generate_address(alias)
    return jsonify({"address": addr, "expires_at": expires_at})

# MODIFIED api_get (No changes needed here, uses fixed data from Redis)
@app.route("/get", methods=["GET"])
def api_get():
    email = request.args.get("address")
    if not email:
        return jsonify({"error": "Missing address parameter"}), 400
    
    messages_json = redis_client.lrange(f"{MESSAGES_PREFIX}{email}", 0, -1)
    
    messages = []
    for i, msg_json in enumerate(messages_json):
        try:
            msg = json.loads(msg_json)
            
            messages.append({
                "id": len(messages_json) - i, 
                "address": email,
                "received_at": msg.get("received_at"),
                "from": msg.get("from"),
                "subject": msg.get("subject"),
                
                # Data fields rely on the fixed store_message
                "html_body": msg.get("html_body", "No HTML content found."), 
                "text_body": msg.get("text_body", "No plain text content found."),
                "otp": msg.get("otp"),
                
                "raw_json": msg 
            })
            
        except json.JSONDecodeError:
            continue
            
    return jsonify(messages)

# MODIFIED api_webhook (No changes needed, uses fixed store_message)
@app.route("/webhook", methods=["POST"])
def api_webhook():
    data = request.get_json(force=True, silent=True) 
    if not data:
        print("[Webhook] No JSON received or invalid content-type.")
        return jsonify({"error": "No JSON received"}), 400
    to_addr = data.get("to")
    from_addr = data.get("from", "unknown")
    subject = data.get("subject", "")
    raw = data.get("raw", data.get("text", "")) 
    if not to_addr:
        print(f"[Webhook] Missing 'to' field in data: {data}")
        return jsonify({"error": "Missing 'to' field"}), 400
    
    store_message(to_addr, from_addr, subject, raw)
    print(f"[Webhook] Saved email to {to_addr} from {from_addr}")
    return jsonify({"status": "success"})

@app.route("/delete", methods=["POST"])
def api_delete():
    email = request.args.get("address")
    if not email:
        return jsonify({"error": "Missing address parameter"}), 400
    redis_client.hdel(ADDRESSES_KEY, email)
    redis_client.delete(f"{MESSAGES_PREFIX}{email}")
    return jsonify({"status": "deleted", "address": email})

# MODIFIED api_list_addresses (FIX 2: Removed unnecessary decode)
@app.route("/addresses", methods=["GET"])
def api_list_addresses():
    all_addresses = redis_client.hgetall(ADDRESSES_KEY)
    addresses_list = []
    for addr, expires_at in all_addresses.items():
        # FIX: Removed .decode() because decode_responses=True is set
        addresses_list.append({"address": addr, "created_at": None, "expires_at": expires_at}) 
    addresses_list.sort(key=lambda x: x['expires_at'], reverse=True)
    return jsonify(addresses_list)

# The run block is removed. 
# Render Start Command: gunicorn --worker-class eventlet -w 1 app:app
