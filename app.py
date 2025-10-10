# app.py - V6 - Final, AI-Powered, and Architecturally Sound

# CRITICAL FIX 1: EVENTLET MONKEY PATCH MUST BE FIRST
import eventlet
eventlet.monkey_patch()
# ---------------------------------------------------

import os
import json
import re
import secrets
import requests
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
API_KEY = os.environ.get("API_KEY")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY")

# --- Redis Connection ---
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

# --- SocketIO Initialization ---
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# --- Constants & Key Definitions ---
ADDRESSES_KEY = "addresses"
MESSAGES_PREFIX = "messages:"

# --- Helper Functions ---

# --- FIX 1: THE UPGRADED AI EXTRACTOR ---
def extract_details_with_ai(text_content):
    """Uses OpenRouter to intelligently extract OTPs and returns them."""
    if not OPENROUTER_API_KEY:
        print("[AI_WARN] OPENROUTER_API_KEY not set. Skipping AI.")
        return {"otp_digit": None, "otp_mix": None}

    # A much stricter, improved prompt
    system_prompt = """You are an expert JSON-only data extraction tool. Analyze the user-provided email text.
Your task is to find two types of codes:
1. `otp_digit`: A numeric-only code, 4-8 digits long. IGNORE any dashes or spaces (e.g., "123-456" becomes "123456").
2. `otp_mix`: An alphanumeric code, 5-8 characters long.

Your response MUST be a single, valid JSON object and nothing else.
- If a code is found, populate its key.
- If a code is not found, its value MUST be null.
- DO NOT extract common English words. A code must look like a code.
- Do not add any explanation.

Example:
Input: "Your code is 123-456 and your ticket is ABC789."
Output:
{
  "otp_digit": "123456",
  "otp_mix": "ABC789"
}"""

    try:
        response = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "meta-llama/llama-3.1-8b-instruct:free", # A more capable model
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": text_content[:4000]}
                ]
            },
            timeout=15
        )
        response.raise_for_status()
        content_string = response.json()['choices'][0]['message']['content']
        extracted_codes = json.loads(content_string)
        
        # Final validation and cleaning
        otp_digit = extracted_codes.get("otp_digit")
        if otp_digit and isinstance(otp_digit, str):
            otp_digit = re.sub(r'\D', '', otp_digit) # Remove non-digits as a fallback

        return {
            "otp_digit": otp_digit or None,
            "otp_mix": extracted_codes.get("otp_mix") or None
        }
    except Exception as e:
        print(f"[AI_ERROR] Failed to extract details with AI: {e}")
        return {"otp_digit": None, "otp_mix": None}

def extract_links_with_regex(html_body, text_body):
    """A simple, fast regex-based function to ONLY extract links."""
    content = f"{html_body} {text_body}"
    links = re.findall(r'https?://[^\s"\'<>]+', content)
    return sorted(list(set(links)), key=links.index) if links else []

def generate_address(alias=None):
    # This function is unchanged
    alias_part = alias or secrets.token_hex(4)
    addr = f"{alias_part}@{SUBDOMAIN}"
    now = datetime.utcnow()
    expires = now + timedelta(days=ADDRESS_TTL_DAYS)
    expires_iso = expires.isoformat()
    redis_client.hset(ADDRESSES_KEY, addr, expires_iso)
    return addr, expires_iso

# --- FIX 2: THE "ANALYZE ONCE" WORKFLOW ---
def store_message(to_address, from_addr, subject, raw):
    """This function is now the ONLY place where AI is called."""
    if not redis_client.hexists(ADDRESSES_KEY, to_address):
        print(f"[Webhook] Ignoring mail for unknown address: {to_address}")
        return

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
        print(f"[ERROR] Failed to parse email: {e}")
        text_body, html_body = f"ERROR: {e}", f"<h1>Error parsing email: {e}</h1>"
    
    # --- HYBRID EXTRACTION ENGINE RUNS HERE, ONCE ---
    ai_otps = extract_details_with_ai(text_body)
    regex_links = extract_links_with_regex(html_body, text_body)

    message_id = f"{datetime.utcnow().timestamp()}-{secrets.token_hex(2)}"
    message_data = {
        "id": message_id,
        "from": full_sender_identity,
        "subject": subject,
        "received_at": datetime.utcnow().isoformat(),
        "html_body": html_body,
        "text_body": text_body,
        "links": regex_links,
        "otp_digit": ai_otps.get("otp_digit"),
        "otp_mix": ai_otps.get("otp_mix"),
    }
    
    redis_client.lpush(f"{MESSAGES_PREFIX}{to_address}", json.dumps(message_data))
    redis_client.ltrim(f"{MESSAGES_PREFIX}{to_address}", 0, 99)

    mini_msg = {
        "id": message_id, "address": to_address, "from": full_sender_identity,
        "subject": subject, "received_at": message_data["received_at"],
        "otp_digit": message_data["otp_digit"], "otp_mix": message_data["otp_mix"]
    }
    socketio.emit('new_mail', mini_msg, room=to_address)
    print(f"[INFO] Stored message for {to_address} with AI analysis.")

# --- API ENDPOINTS (Now much faster, they just read from Redis) ---
api_v1 = Blueprint('api_v1', __name__, url_prefix='/api/v1')
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not API_KEY: return jsonify({"error": "API service not configured."}), 500
        provided_key = request.headers.get('X-API-Key')
        if not provided_key or provided_key != API_KEY: return jsonify({"error": "Unauthorized."}), 401
        return f(*args, **kwargs)
    return decorated_function

@api_v1.route("/addresses", methods=["POST"])
@require_api_key
def create_address():
    data = request.get_json(silent=True) or {}
    addr, expires_at = generate_address(data.get("alias"))
    return jsonify({"address": addr, "expires_at": expires_at}), 201

# FIX 3: This endpoint is now simpler and faster. No fallback logic needed.
@api_v1.route("/addresses/<string:email>/messages", methods=["GET"])
@require_api_key
def get_messages_for_address(email):
    messages_json = redis_client.lrange(f"{MESSAGES_PREFIX}{email}", 0, -1)
    messages_summary = []
    for msg_json in messages_json:
        try:
            msg = json.loads(msg_json)
            messages_summary.append({
                "id": msg.get("id"), # All new messages will have a valid ID
                "from": msg.get("from"),
                "subject": msg.get("subject"),
                "received_at": msg.get("received_at"),
                "otp_digit": msg.get("otp_digit"),
                "otp_mix": msg.get("otp_mix"),
                "has_links": bool(msg.get("links"))
            })
        except (json.JSONDecodeError, KeyError): continue
    return jsonify(messages_summary)

# FIX 4: This endpoint is also simpler and faster.
@api_v1.route("/messages/<string:email>/<string:message_id>", methods=["GET"])
@require_api_key
def get_full_message(email, message_id):
    messages_json = redis_client.lrange(f"{MESSAGES_PREFIX}{email}", 0, -1)
    for msg_json in messages_json:
        try:
            msg = json.loads(msg_json)
            # Only need to check the 'id' field now.
            if msg.get("id") == message_id:
                return jsonify(msg)
        except (json.JSONDecodeError, KeyError): continue
    return jsonify({"error": "Message not found."}), 404

app.register_blueprint(api_v1)

# --- WEBHOOK & FRONTEND ROUTES ---
@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")

@app.route("/webhook", methods=["POST"])
def api_webhook():
    data = request.get_json(force=True, silent=True)
    if not data: return jsonify({"error": "No JSON received"}), 400
    to_addr = data.get("to")
    if not to_addr: return jsonify({"error": "Missing 'to' field"}), 400
    socketio.start_background_task(
        store_message, to_addr, data.get("from", "unknown"),
        data.get("subject", ""), data.get("raw", data.get("text", ""))
    )
    return jsonify({"status": "processing"}), 202

@app.route("/addresses", methods=["GET"])
def list_all_addresses():
    all_addresses = redis_client.hgetall(ADDRESSES_KEY)
    addresses_list = [{"address": addr, "expires_at": expires_at} for addr, expires_at in all_addresses.items()]
    addresses_list.sort(key=lambda x: x['expires_at'], reverse=True)
    return jsonify(addresses_list)

@socketio.on('join_mailbox')
def on_join(data):
    mailbox_address = data.get('address')
    if mailbox_address: join_room(mailbox_address)

@app.after_request
def add_security_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return response
