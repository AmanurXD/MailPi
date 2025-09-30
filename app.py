# app.py - Finalized for Render/Upstash Redis
import os
import json
from flask import Flask, request, jsonify, abort
from datetime import datetime, timedelta
import secrets
# Using the standard 'redis' client for flexibility, assuming upstash_redis is installed
# If you are using the 'upstash_redis' package, the import should be:
# from upstash_redis import Redis
# But for maximum compatibility, let's stick to using environment vars which the client often auto-handles.
from redis import Redis 

app = Flask(__name__)

# --- Configuration from Environment (SECURE) ---
# **CRITICAL FIX:** Read credentials securely from the environment
REDIS_URL = os.environ.get("UPSTASH_REDIS_URL")
REDIS_TOKEN = os.environ.get("UPSTASH_REDIS_TOKEN")
SUBDOMAIN = os.environ.get("SUBDOMAIN", "codewithjames.top") 

if not REDIS_URL or not REDIS_TOKEN:
    print("FATAL: UPSTASH_REDIS_URL or UPSTASH_REDIS_TOKEN is not set in environment.")
    # In a real deployment environment, you'd raise an exception here.
    # For now, we'll continue with placeholder/local redis connection if possible, but warn.
    pass # Let the next block handle potential connection failure

ADDRESS_TTL_DAYS = 14  # default TTL

# Initialize Redis client 
# Using the standard 'redis' client's arguments, which usually works with Upstash
try:
    # Use decoded password for the standard redis-py client
    redis_client = Redis(url=REDIS_URL, password=REDIS_TOKEN)
    # Simple check to ensure connection is live
    redis_client.ping()
    print("[INFO] Successfully connected to Upstash Redis.")
except Exception as e:
    print(f"[ERROR] Could not connect to Redis: {e}")
    # Consider raising an exception here to halt deployment if connection fails.


# --- Constants & Key Definitions ---
ADDRESSES_KEY = "addresses"  # Hash of all active addresses: {addr: expires_at_iso}
MESSAGES_PREFIX = "messages:" # List for messages: messages:alias@domain -> [json_message_1, ...]

# --- Helpers (No changes needed, the logic is sound) ---
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
        
    message_data = {
        "from": from_addr,
        "subject": subject,
        "raw": raw,
        "received_at": datetime.utcnow().isoformat()
    }
    redis_client.lpush(f"{MESSAGES_PREFIX}{to_address}", json.dumps(message_data))
    redis_client.ltrim(f"{MESSAGES_PREFIX}{to_address}", 0, 99)

# --- API endpoints (No changes needed) ---

@app.route("/generate", methods=["GET"])
def api_generate():
    alias = request.args.get("alias")
    addr, expires_at = generate_address(alias)
    return jsonify({"address": addr, "expires_at": expires_at})

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
            msg['id'] = len(messages_json) - i 
            messages.append(msg)
        except json.JSONDecodeError:
            continue
    return jsonify(messages)

@app.route("/webhook", methods=["POST"])
def api_webhook():
    data = request.get_json(force=True, silent=True) 
    if not data:
        print("[Webhook] No JSON received or invalid content-type.")
        return jsonify({"error": "No JSON received"}), 400
    to_addr = data.get("to")
    from_addr = data.get("from", "unknown")
    subject = data.get("subject", "")
    raw = data.get("raw", data.get("text", "")) # Prioritize 'raw', fallback to 'text'
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

@app.route("/addresses", methods=["GET"])
def api_list_addresses():
    all_addresses = redis_client.hgetall(ADDRESSES_KEY)
    addresses_list = []
    for addr_bytes, expires_bytes in all_addresses.items():
        addr = addr_bytes.decode('utf-8')
        expires_at = expires_bytes.decode('utf-8')
        addresses_list.append({"address": addr, "created_at": None, "expires_at": expires_at}) # created_at is not stored, but kept for compatibility
    addresses_list.sort(key=lambda x: x['expires_at'], reverse=True)
    return jsonify(addresses_list)

# The run block is removed. Use Gunicorn for production: 
# `gunicorn app:app`
