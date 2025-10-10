# app.py - V5 - Final, Secure, Rate-Limited Version

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
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# --- Configuration ---
REDIS_URL = os.environ.get("UPSTASH_REDIS_URL")
REDIS_TOKEN = os.environ.get("UPSTASH_REDIS_TOKEN")
SUBDOMAIN = os.environ.get("SUBDOMAIN", "codewithjames.top")
ADDRESS_TTL_DAYS = 14
API_KEY = os.environ.get("API_KEY")

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
    
# --- NEW SECURITY LAYER: RATE LIMITER ---
# Initialize the rate limiter. It uses the client's IP address as the key.
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=f"redis://default:{REDIS_TOKEN}@{redis_host}",
    storage_options={"ssl_cert_reqs": None}
)

# --- SocketIO Initialization ---
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# --- Constants & Key Definitions ---
ADDRESSES_KEY = "addresses"
MESSAGES_PREFIX = "messages:"

# --- Helper Functions (No changes) ---
def extract_email_details(html_body, text_body):
    content_to_search = f"{html_body} {text_body}"
    link_pattern = r'https?://[^\s"\'<>]+'
    links = re.findall(link_pattern, content_to_search)
    unique_links = sorted(list(set(links)), key=links.index) if links else []
    search_upper = content_to_search.upper()
    numeric_pattern = r'\b(\d{4,8})\b'
    all_numeric_codes = re.findall(numeric_pattern, search_upper)
    mixed_pattern = r'\b(?=.*[A-Z])[A-Z0-9]{5,8}\b'
    all_mixed_codes = re.findall(mixed_pattern, search_upper)
    return {
        "otp_digit": all_numeric_codes[0] if all_numeric_codes else None,
        "otp_mix": all_mixed_codes[0] if all_mixed_codes else None,
        "otp_lists": all_numeric_codes if all_numeric_codes else [],
        "links": unique_links
    }

def generate_address(alias=None):
    alias_part = alias or secrets.token_hex(4)
    addr = f"{alias_part}@{SUBDOMAIN}"
    now = datetime.utcnow()
    expires = now + timedelta(days=ADDRESS_TTL_DAYS)
    expires_iso = expires.isoformat()
    redis_client.hset(ADDRESSES_KEY, addr, expires_iso)
    return addr, expires_iso

def store_message(to_address, from_addr, subject, raw):
    if not redis_client.hexists(ADDRESSES_KEY, to_address):
        print(f"[Webhook] Received mail for unknown/expired address: {to_address}")
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
        error_msg = f"'{e}'"
        print(f"[ERROR] Failed to parse email: {error_msg}")
        text_body = f"ERROR: Failed to parse raw content. Details: {error_msg}"
        html_body = f'<h1>Error parsing email content!</h1><pre>{error_msg}</pre>'
    message_id = f"{datetime.utcnow().timestamp()}-{secrets.token_hex(2)}"
    extracted_data = extract_email_details(html_body, text_body)
    message_data = {
        "id": message_id, "from": full_sender_identity, "subject": subject,
        "received_at": datetime.utcnow().isoformat(), "html_body": html_body, "text_body": text_body,
    }
    message_data.update(extracted_data)
    redis_client.lpush(f"{MESSAGES_PREFIX}{to_address}", json.dumps(message_data))
    redis_client.ltrim(f"{MESSAGES_PREFIX}{to_address}", 0, 99)
    mini_msg = {
        "id": message_id, "address": to_address, "from": full_sender_identity, "subject": subject,
        "received_at": message_data["received_at"], "otp_digit": extracted_data["otp_digit"], "otp_mix": extracted_data["otp_mix"]
    }
    socketio.emit('new_mail', mini_msg, room=to_address)

# --- SECURE API VAULT (INTERNAL USE) ---
api_v1 = Blueprint('api_v1', __name__, url_prefix='/api/v1')
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not API_KEY: return jsonify({"error": "API service is not configured."}), 500
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

@api_v1.route("/addresses/<string:email>/messages", methods=["GET"])
@require_api_key
def get_messages_for_address(email):
    messages_json = redis_client.lrange(f"{MESSAGES_PREFIX}{email}", 0, -1)
    messages_summary = []
    for msg_json in messages_json:
        try:
            msg = json.loads(msg_json)
            messages_summary.append({
                "id": msg.get("id"), "from": msg.get("from"), "subject": msg.get("subject"),
                "received_at": msg.get("received_at"), "otp_digit": msg.get("otp_digit"),
                "otp_mix": msg.get("otp_mix"), "has_links": bool(msg.get("links"))
            })
        except (json.JSONDecodeError, KeyError): continue
    return jsonify(messages_summary)

@api_v1.route("/messages/<string:email>/<string:message_id>", methods=["GET"])
@require_api_key
def get_full_message(email, message_id):
    messages_json = redis_client.lrange(f"{MESSAGES_PREFIX}{email}", 0, -1)
    for msg_json in messages_json:
        try:
            msg = json.loads(msg_json)
            if msg.get("id") == message_id:
                return jsonify(msg)
        except (json.JSONDecodeError, KeyError): continue
    return jsonify({"error": "Message not found."}), 404

app.register_blueprint(api_v1)

# --- PUBLIC FRONTEND PROXY (RATE-LIMITED) ---
frontend_api = Blueprint('frontend_api', __name__, url_prefix='/frontend-api')
BASE_URL = "http://127.0.0.1:10000"

# Apply a stricter rate limit for address creation to prevent abuse.
@frontend_api.route("/addresses", methods=["POST"])
@limiter.limit("10 per minute")
def proxy_create_address():
    data = request.get_json(silent=True) or {}
    headers = {'X-API-Key': API_KEY, 'Content-Type': 'application/json'}
    response = requests.post(f"{BASE_URL}/api/v1/addresses", json=data, headers=headers)
    return jsonify(response.json()), response.status_code

@frontend_api.route("/addresses/<string:email>/messages", methods=["GET"])
@limiter.limit("60 per minute") # Allow more frequent message checks
def proxy_get_messages(email):
    headers = {'X-API-Key': API_KEY}
    response = requests.get(f"{BASE_URL}/api/v1/addresses/{email}/messages", headers=headers)
    return jsonify(response.json()), response.status_code

@frontend_api.route("/messages/<string:email>/<string:message_id>", methods=["GET"])
@limiter.limit("60 per minute")
def proxy_get_full_message(email, message_id):
    headers = {'X-API-Key': API_KEY}
    response = requests.get(f"{BASE_URL}/api/v1/messages/{email}/{message_id}", headers=headers)
    return jsonify(response.json()), response.status_code

app.register_blueprint(frontend_api)

# --- OTHER PUBLIC ROUTES ---
@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")

@app.route("/webhook", methods=["POST"])
@limiter.limit("500 per minute") # Allow high volume for incoming mail
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
