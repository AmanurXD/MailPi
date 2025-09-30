# mail_webhook_server.py
import os
import json
from flask import Flask, request, jsonify, abort
from datetime import datetime, timedelta
import secrets
# Import the Redis client library
from upstash_redis import Redis

app = Flask(__name__)

# --- Configuration from Environment ---
# Securely load credentials from environment variables
try:
    REDIS_URL = "https://just-hog-15513.upstash.io"
    REDIS_TOKEN = "ATyZAAIncDJlNWM2YjI2ZTQ0MmQ0YzNhOGE2ZTNkYTRhN2Y4ZjU4MnAyMTU1MTM"
except KeyError:
    # If variables are not set, abort or set defaults for development (not recommended)
    print("FATAL: UPSTASH_REDIS_URL or UPSTASH_REDIS_TOKEN not set!")
    exit(1)

# Ensure SUBDOMAIN is set
SUBDOMAIN = os.environ.get("SUBDOMAIN", "codewithjames.top") 
ADDRESS_TTL_DAYS = 14  # default TTL

# Initialize Redis client (using the connection URL which includes the token/auth)
redis_client = Redis(url=REDIS_URL, password=REDIS_TOKEN)

# --- Constants & Key Definitions ---
# Redis keys for address metadata and message storage
ADDRESSES_KEY = "addresses"  # Hash of all active addresses: {addr: expires_at_iso}
MESSAGES_PREFIX = "messages:" # List for messages: messages:alias@domain -> [json_message_1, ...]

# --- Helpers ---
def generate_address(alias=None):
    """Generates a new address and stores its expiration time in Redis."""
    alias_part = alias or secrets.token_hex(4)
    addr = f"{alias_part}@{SUBDOMAIN}"
    
    now = datetime.utcnow()
    expires = now + timedelta(days=ADDRESS_TTL_DAYS)
    expires_iso = expires.isoformat()
    
    # Store the address expiration time in the addresses Hash
    redis_client.hset(ADDRESSES_KEY, addr, expires_iso)
    
    return addr, expires_iso

def store_message(to_address, from_addr, subject, raw):
    """Stores an incoming message into the address's message list in Redis."""
    # Check if the address exists (optional check, but good for validation)
    if not redis_client.hexists(ADDRESSES_KEY, to_address):
        print(f"[Webhook] Received mail for unknown/expired address: {to_address}")
        # Could decide to drop the message here, but we'll store it anyway for now
    
    message_data = {
        "from": from_addr,
        "subject": subject,
        "raw": raw,
        "received_at": datetime.utcnow().isoformat()
    }
    
    # Prepend the message JSON to the list for this address
    redis_client.lpush(f"{MESSAGES_PREFIX}{to_address}", json.dumps(message_data))
    
    # Truncate the list to keep only the last 100 messages (or limit size)
    redis_client.ltrim(f"{MESSAGES_PREFIX}{to_address}", 0, 99)

# --- API endpoints (Simplified for Redis) ---

# Generate new email
@app.route("/generate", methods=["GET"])
def api_generate():
    alias = request.args.get("alias")
    addr, expires_at = generate_address(alias)
    # The TTL of the address is inherent in the HASH data, not set on the key itself for simplicity
    return jsonify({"address": addr, "expires_at": expires_at})

# Get messages for an address
@app.route("/get", methods=["GET"])
def api_get():
    email = request.args.get("address")
    if not email:
        return jsonify({"error": "Missing address parameter"}), 400
    
    # Retrieve all messages from the list (0 to -1 is all)
    messages_json = redis_client.lrange(f"{MESSAGES_PREFIX}{email}", 0, -1)
    
    # Deserialize the JSON strings and include an index/id
    messages = []
    for i, msg_json in enumerate(messages_json):
        try:
            msg = json.loads(msg_json)
            # Add a simple 1-based index/ID for the frontend
            msg['id'] = len(messages_json) - i 
            messages.append(msg)
        except json.JSONDecodeError:
            continue # Skip malformed entries
            
    return jsonify(messages)

# Webhook endpoint to receive emails
@app.route("/webhook", methods=["POST"])
def api_webhook():
    """
    Expects JSON payload from mail-forwarding provider.
    """
    # Use silent=True to avoid raising 400 if not JSON, check later
    data = request.get_json(force=True, silent=True) 
    
    if not data:
        print("[Webhook] No JSON received or invalid content-type.")
        return jsonify({"error": "No JSON received"}), 400
        
    to_addr = data.get("to")
    from_addr = data.get("from", "unknown")
    subject = data.get("subject", "")
    # Cloudflare sends the raw content in the 'text' field (or 'raw', depends on setup). 
    # Adjust this key if 'raw' is what you see in the Cloudflare payload test.
    raw = data.get("raw", data.get("text", "")) 
    
    if not to_addr:
        print(f"[Webhook] Missing 'to' field in data: {data}")
        return jsonify({"error": "Missing 'to' field"}), 400

    store_message(to_addr, from_addr, subject, raw)
    print(f"[Webhook] Saved email to {to_addr} from {from_addr}")
    return jsonify({"status": "success"})

# Delete an address (and its messages)
@app.route("/delete", methods=["POST"])
def api_delete():
    email = request.args.get("address")
    if not email:
        return jsonify({"error": "Missing address parameter"}), 400
        
    # Delete address from the main hash
    redis_client.hdel(ADDRESSES_KEY, email)
    # Delete the message list key
    redis_client.delete(f"{MESSAGES_PREFIX}{email}")
    
    return jsonify({"status": "deleted", "address": email})

# List all addresses
@app.route("/addresses", methods=["GET"])
def api_list_addresses():
    # Retrieve all addresses and their expiration times from the hash
    all_addresses = redis_client.hgetall(ADDRESSES_KEY)
    
    addresses_list = []
    for addr_bytes, expires_bytes in all_addresses.items():
        addr = addr_bytes.decode('utf-8')
        expires_at = expires_bytes.decode('utf-8')
        
        # NOTE: You'd want to add logic here to automatically clean up expired addresses
        addresses_list.append({"address": addr, "expires_at": expires_at})
        
    # Sort by expiration (e.g., freshest first)
    addresses_list.sort(key=lambda x: x['expires_at'], reverse=True)
    
    return jsonify(addresses_list)

# The run block is removed. Use Gunicorn for production: 
# `gunicorn mail_webhook_server:app`
