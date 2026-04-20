# app.py - V6 - Final, AI-Powered, and Architecturally Sound

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
from otp import extract_verification_codes

app = Flask(__name__)

# --- Configuration ---
REDIS_URL = os.environ.get("UPSTASH_REDIS_URL")
REDIS_TOKEN = os.environ.get("UPSTASH_REDIS_TOKEN")
SUBDOMAIN = os.environ.get("SUBDOMAIN", "pawclaw.top")
ADDRESS_TTL_DAYS = os.environ.get("ADDRESS_TTL_DAYS")
MAX_MESSAGES_PER_ADDRESS = int(os.environ.get("MAX_MESSAGES_PER_ADDRESS", "250"))
API_KEY = os.environ.get("API_KEY")
APP_PUBLIC_URL = os.environ.get("APP_PUBLIC_URL", f"https://{SUBDOMAIN}")
SITE_TITLE = os.environ.get("SITE_TITLE", "MailPi")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET")

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
def utcnow():
    return datetime.utcnow()

def utcnow_iso():
    return utcnow().isoformat()

def parse_optional_int(value):
    if value in (None, ""):
        return None
    return int(value)

DEFAULT_ADDRESS_TTL_DAYS = parse_optional_int(ADDRESS_TTL_DAYS)

def parse_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"1", "true", "yes", "on"}

def parse_iso_datetime(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None

def normalize_address(email):
    return (email or "").strip().lower()

def split_alias(address):
    return normalize_address(address).split("@", 1)[0]

def validate_alias(alias):
    normalized = (alias or "").strip().lower()
    if not normalized:
        return None
    if len(normalized) > 64:
        raise ValueError("Alias must be 64 characters or fewer.")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?", normalized):
        raise ValueError("Alias may only contain letters, numbers, dots, underscores, and hyphens.")
    return normalized

def messages_key(address):
    return f"{MESSAGES_PREFIX}{normalize_address(address)}"

def parse_address_record(address, raw_value):
    address = normalize_address(address)
    if raw_value is None:
        return None

    if isinstance(raw_value, str):
        stripped = raw_value.strip()
        if stripped.startswith("{"):
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError:
                record = {}
        else:
            record = {"expires_at": stripped, "never_expires": False}
    elif isinstance(raw_value, dict):
        record = raw_value
    else:
        record = {}

    parsed = {
        "address": address,
        "alias": record.get("alias") or split_alias(address),
        "created_at": record.get("created_at"),
        "updated_at": record.get("updated_at") or record.get("created_at"),
        "expires_at": record.get("expires_at"),
        "never_expires": bool(record.get("never_expires", False)),
        "tags": record.get("tags") or [],
        "notes": record.get("notes"),
    }
    if parsed["expires_at"] in ("", None):
        parsed["expires_at"] = None
    if parsed["never_expires"] or parsed["expires_at"] is None:
        parsed["never_expires"] = True
        parsed["expires_at"] = None
    return parsed

def store_address_record(record):
    payload = {
        "address": normalize_address(record["address"]),
        "alias": record.get("alias") or split_alias(record["address"]),
        "created_at": record.get("created_at"),
        "updated_at": record.get("updated_at"),
        "expires_at": record.get("expires_at"),
        "never_expires": bool(record.get("never_expires", False)),
        "tags": record.get("tags") or [],
        "notes": record.get("notes"),
    }
    redis_client.hset(ADDRESSES_KEY, payload["address"], json.dumps(payload))
    return payload

def get_address_record(address):
    normalized = normalize_address(address)
    return parse_address_record(normalized, redis_client.hget(ADDRESSES_KEY, normalized))

def address_exists(address):
    return get_address_record(address) is not None

def is_address_active(record):
    if not record:
        return False
    if record.get("never_expires"):
        return True
    expires_at = parse_iso_datetime(record.get("expires_at"))
    if not expires_at:
        return True
    return expires_at >= utcnow()

def address_status(record):
    return "active" if is_address_active(record) else "expired"

def get_message_count(address):
    return redis_client.llen(messages_key(address))

def serialize_address_response(record, include_private=True):
    response = {
        "address": record["address"],
        "alias": record.get("alias") or split_alias(record["address"]),
        "created_at": record.get("created_at"),
        "updated_at": record.get("updated_at"),
        "expires_at": record.get("expires_at"),
        "never_expires": bool(record.get("never_expires", False)),
        "status": address_status(record),
        "message_count": get_message_count(record["address"]),
    }
    if include_private:
        response["tags"] = record.get("tags") or []
        response["notes"] = record.get("notes")
    return response

def list_address_records():
    records = []
    for address, raw_value in redis_client.hgetall(ADDRESSES_KEY).items():
        record = parse_address_record(address, raw_value)
        if record:
            records.append(record)
    records.sort(
        key=lambda item: item.get("updated_at") or item.get("created_at") or item.get("expires_at") or "",
        reverse=True,
    )
    return records

def parse_address_request(data):
    alias = validate_alias(data.get("alias"))
    never_expires = parse_bool(data.get("never_expires"), default=DEFAULT_ADDRESS_TTL_DAYS is None)
    expires_in_days = parse_optional_int(data.get("expires_in_days"))
    if expires_in_days is not None and expires_in_days < 1:
        raise ValueError("expires_in_days must be at least 1.")
    if expires_in_days is not None:
        never_expires = False
    if not never_expires and expires_in_days is None:
        expires_in_days = DEFAULT_ADDRESS_TTL_DAYS
        if expires_in_days is None:
            never_expires = True
    return alias, never_expires, expires_in_days

def generate_address(alias=None, never_expires=True, expires_in_days=None, tags=None, notes=None):
    alias_part = alias or secrets.token_hex(4)
    addr = normalize_address(f"{alias_part}@{SUBDOMAIN}")
    now_iso = utcnow_iso()
    existing = get_address_record(addr)
    expires_at = None
    if not never_expires:
        expires_at = (utcnow() + timedelta(days=expires_in_days or DEFAULT_ADDRESS_TTL_DAYS or 14)).isoformat()

    record = {
        "address": addr,
        "alias": alias_part,
        "created_at": existing.get("created_at") if existing else now_iso,
        "updated_at": now_iso,
        "expires_at": expires_at,
        "never_expires": bool(never_expires),
        "tags": tags if tags is not None else (existing.get("tags") if existing else []),
        "notes": notes if notes is not None else (existing.get("notes") if existing else None),
    }
    stored = store_address_record(record)
    return stored, serialize_address_response(stored)

def summarize_message(msg):
    return {
        "id": msg.get("id"),
        "from": msg.get("from"),
        "to": msg.get("to"),
        "subject": msg.get("subject"),
        "received_at": msg.get("received_at"),
        "otp_digit": msg.get("otp_digit"),
        "otp_mix": msg.get("otp_mix"),
        "has_links": bool(msg.get("links")),
        "link_count": len(msg.get("links") or []),
        "attachment_count": len(msg.get("attachments") or []),
    }

def read_messages(email, offset=0, limit=None):
    start = max(offset, 0)
    if limit is None:
        raw_messages = redis_client.lrange(messages_key(email), start, -1)
    else:
        raw_messages = redis_client.lrange(messages_key(email), start, start + max(limit, 1) - 1)
    messages = []
    for msg_json in raw_messages:
        try:
            messages.append(json.loads(msg_json))
        except json.JSONDecodeError:
            continue
    return messages

def find_message(email, message_id):
    for message in read_messages(email):
        if message.get("id") == message_id:
            return message
    return None

def replace_messages(email, messages):
    key = messages_key(email)
    pipeline = redis_client.pipeline()
    pipeline.delete(key)
    if messages:
        pipeline.rpush(key, *messages)
    pipeline.execute()

def delete_message(email, message_id):
    kept_messages = []
    deleted_message = None
    for msg_json in redis_client.lrange(messages_key(email), 0, -1):
        try:
            msg = json.loads(msg_json)
        except json.JSONDecodeError:
            kept_messages.append(msg_json)
            continue
        if deleted_message is None and msg.get("id") == message_id:
            deleted_message = msg
            continue
        kept_messages.append(msg_json)
    if deleted_message is None:
        return None
    replace_messages(email, kept_messages)
    return deleted_message

def delete_all_messages(email):
    deleted_count = redis_client.llen(messages_key(email))
    redis_client.delete(messages_key(email))
    return deleted_count
def extract_links_with_regex(html_body, text_body):
    """A simple, fast regex-based function to ONLY extract links."""
    content = f"{html_body} {text_body}"
    links = re.findall(r'https?://[^\s"\'<>]+', content)
    return sorted(list(set(links)), key=links.index) if links else []

# --- FIX 2: THE "ANALYZE ONCE" WORKFLOW ---
def store_message(to_address, from_addr, subject, raw):
    """This function is now the ONLY place where AI is called."""
    to_address = normalize_address(to_address)
    address_record = get_address_record(to_address)
    if not is_address_active(address_record):
        print(f"[Webhook] Ignoring mail for unknown or inactive address: {to_address}")
        return

    html_body, text_body, full_sender_identity = "No HTML content found.", "No plain text content found.", from_addr
    attachments = []
    message_id_header = None
    try:
        if raw and raw.strip():
            parser = MailParser.from_string(raw)
            html_body = parser.text_html[0] if parser.text_html else html_body
            text_body = parser.text_plain[0] if parser.text_plain else text_body
            message_id_header = getattr(parser, "message_id", None)
            if parser.from_ and isinstance(parser.from_, list) and parser.from_[0]:
                name, email = parser.from_[0][0], parser.from_[0][1]
                full_sender_identity = f"{name} <{email}>" if name else email
            attachments = [
                {
                    "filename": attachment.get("filename"),
                    "content_type": attachment.get("mail_content_type"),
                    "size": len(attachment.get("payload") or ""),
                }
                for attachment in (getattr(parser, "attachments", None) or [])
            ]
            if html_body == "No HTML content found." and text_body != "No plain text content found.":
                 html_body = f'<pre>{text_body}</pre>'
    except Exception as e:
        print(f"[ERROR] Failed to parse email: {e}")
        text_body, html_body = f"ERROR: {e}", f"<h1>Error parsing email: {e}</h1>"
    
    # --- HYBRID EXTRACTION ENGINE RUNS HERE, ONCE ---
    extracted_codes = extract_verification_codes(subject=subject, text_body=text_body, html_body=html_body)
    regex_links = extract_links_with_regex(html_body, text_body)

    message_id = f"{datetime.utcnow().timestamp()}-{secrets.token_hex(2)}"
    message_data = {
        "id": message_id,
        "from": full_sender_identity,
        "to": to_address,
        "subject": subject,
        "received_at": utcnow_iso(),
        "provider_message_id": message_id_header,
        "html_body": html_body,
        "text_body": text_body,
        "links": regex_links,
        "attachments": attachments,
        "otp_digit": extracted_codes.get("otp_digit"),
        "otp_mix": extracted_codes.get("otp_mix"),
    }
    
    redis_client.lpush(messages_key(to_address), json.dumps(message_data))
    redis_client.ltrim(messages_key(to_address), 0, MAX_MESSAGES_PER_ADDRESS - 1)

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
    try:
        alias, never_expires, expires_in_days = parse_address_request(data)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    _, response = generate_address(
        alias=alias,
        never_expires=never_expires,
        expires_in_days=expires_in_days,
        tags=data.get("tags"),
        notes=data.get("notes"),
    )
    return jsonify(response), 201

@api_v1.route("/addresses", methods=["GET"])
@require_api_key
def api_list_addresses():
    include_expired = parse_bool(request.args.get("include_expired"), default=True)
    records = []
    for record in list_address_records():
        if not include_expired and not is_address_active(record):
            continue
        records.append(serialize_address_response(record))
    return jsonify(records)

@api_v1.route("/addresses/<string:email>", methods=["GET"])
@require_api_key
def get_address(email):
    record = get_address_record(email)
    if not record:
        return jsonify({"error": "Address not found."}), 404
    return jsonify(serialize_address_response(record))

@api_v1.route("/addresses/<string:email>", methods=["DELETE"])
@require_api_key
def delete_address(email):
    normalized = normalize_address(email)
    record = get_address_record(normalized)
    if not record:
        return jsonify({"error": "Address not found."}), 404
    deleted_messages = delete_all_messages(normalized)
    redis_client.hdel(ADDRESSES_KEY, normalized)
    return jsonify({
        "deleted": True,
        "address": normalized,
        "deleted_messages": deleted_messages,
    })

# FIX 3: This endpoint is now simpler and faster. No fallback logic needed.
@api_v1.route("/addresses/<string:email>/messages", methods=["GET"])
@require_api_key
def get_messages_for_address(email):
    limit = parse_optional_int(request.args.get("limit"))
    offset = parse_optional_int(request.args.get("offset")) or 0
    messages_summary = [summarize_message(msg) for msg in read_messages(email, offset=offset, limit=limit)]
    return jsonify(messages_summary)

@api_v1.route("/addresses/<string:email>/messages", methods=["DELETE"])
@require_api_key
def clear_messages_for_address(email):
    deleted_count = delete_all_messages(email)
    return jsonify({"deleted": True, "deleted_messages": deleted_count, "address": normalize_address(email)})

# FIX 4: This endpoint is also simpler and faster.
@api_v1.route("/addresses/<string:email>/messages/<string:message_id>", methods=["GET"])
@require_api_key
def get_full_message(email, message_id):
    msg = find_message(email, message_id)
    if msg:
        return jsonify(msg)
    return jsonify({"error": "Message not found."}), 404

@api_v1.route("/addresses/<string:email>/messages/<string:message_id>", methods=["DELETE"])
@require_api_key
def delete_single_message(email, message_id):
    deleted = delete_message(email, message_id)
    if not deleted:
        return jsonify({"error": "Message not found."}), 404
    return jsonify({"deleted": True, "message_id": message_id, "address": normalize_address(email)})

@api_v1.route("/messages/<string:email>/<string:message_id>", methods=["GET"])
@require_api_key
def get_full_message_legacy(email, message_id):
    return get_full_message(email, message_id)

@api_v1.route("/service", methods=["GET"])
@require_api_key
def service_info():
    return jsonify({
        "service": "MailPi",
        "version": "v1",
        "subdomain": SUBDOMAIN,
        "default_never_expires": DEFAULT_ADDRESS_TTL_DAYS is None,
        "default_ttl_days": DEFAULT_ADDRESS_TTL_DAYS,
        "max_messages_per_address": MAX_MESSAGES_PER_ADDRESS,
    })

app.register_blueprint(api_v1)

# --- WEBHOOK & FRONTEND ROUTES ---
@app.route("/", methods=["GET"])
def home():
    return render_template(
        "index.html",
        site_title=SITE_TITLE,
        current_domain=SUBDOMAIN,
        frontend_api_key=API_KEY or "",
    )

@app.route("/webhook", methods=["POST"])
def api_webhook():
    provided_secret = request.headers.get("X-Webhook-Secret")
    print(
        f"[WEBHOOK] Hit from {request.headers.get('CF-Connecting-IP', request.remote_addr)} "
        f"secret_configured={bool(WEBHOOK_SECRET)} secret_match={provided_secret == WEBHOOK_SECRET}"
    )
    if WEBHOOK_SECRET and provided_secret != WEBHOOK_SECRET:
        print("[WEBHOOK] Rejecting request due to invalid secret.")
        return jsonify({"error": "Unauthorized."}), 401
    data = request.get_json(force=True, silent=True)
    if not data: return jsonify({"error": "No JSON received"}), 400
    to_addr = normalize_address(data.get("to"))
    if not to_addr: return jsonify({"error": "Missing 'to' field"}), 400
    print(
        f"[WEBHOOK] Accepted message to={to_addr} from={data.get('from', 'unknown')} "
        f"known_address={address_exists(to_addr)}"
    )
    socketio.start_background_task(
        store_message, to_addr, data.get("from", "unknown"),
        data.get("subject", ""), data.get("raw", data.get("text", ""))
    )
    return jsonify({"status": "processing"}), 202

@app.route("/addresses", methods=["GET"])
def list_all_addresses():
    addresses_list = [
        {
            "address": record["address"],
            "expires_at": record.get("expires_at"),
            "never_expires": record.get("never_expires", False),
            "status": address_status(record),
        }
        for record in list_address_records()
    ]
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

@app.route("/healthz", methods=["GET"])
def healthcheck():
    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
