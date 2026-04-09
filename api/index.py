# api/index.py - Vercel serverless handler
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import re
import secrets
import requests
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, render_template, Blueprint

# Configure template folder to be at root level
template_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'templates')
app = Flask(__name__, template_folder=template_dir)

# --- Configuration ---
UPSTASH_REDIS_REST_URL = os.environ.get("UPSTASH_REDIS_REST_URL")
UPSTASH_REDIS_REST_TOKEN = os.environ.get("UPSTASH_REDIS_REST_TOKEN")
SUBDOMAIN = os.environ.get("SUBDOMAIN", "pawclaw.top")
ADDRESS_TTL_DAYS = 14
API_KEY = os.environ.get("API_KEY")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY")

# --- Constants ---
ADDRESSES_KEY = "addresses"
MESSAGES_PREFIX = "messages:"

# --- Upstash REST API Helper Functions ---

def upstash_lpush(key, value):
    url = f"{UPSTASH_REDIS_REST_URL}/lpush/{key}"
    response = requests.post(
        url,
        headers={"Authorization": f"Bearer {UPSTASH_REDIS_REST_TOKEN}"},
        json=[value]
    )
    return response.json()

def upstash_ltrim(key, start, stop):
    url = f"{UPSTASH_REDIS_REST_URL}/ltrim/{key}/{start}/{stop}"
    response = requests.post(
        url,
        headers={"Authorization": f"Bearer {UPSTASH_REDIS_REST_TOKEN}"}
    )
    return response.json()

def upstash_lrange(key, start, stop):
    url = f"{UPSTASH_REDIS_REST_URL}/lrange/{key}/{start}/{stop}"
    response = requests.get(
        url,
        headers={"Authorization": f"Bearer {UPSTASH_REDIS_REST_TOKEN}"}
    )
    result = response.json()
    # Upstash returns nested array [["item1", "item2"]] - flatten it
    data = result.get("result", [])
    if data and isinstance(data, list) and len(data) > 0 and isinstance(data[0], list):
        return data[0]
    return data if isinstance(data, list) else []

def upstash_hset(key, field, value):
    url = f"{UPSTASH_REDIS_REST_URL}/hset/{key}"
    response = requests.post(
        url,
        headers={"Authorization": f"Bearer {UPSTASH_REDIS_REST_TOKEN}"},
        json={field: value}
    )
    return response.json()

def upstash_hgetall(key):
    url = f"{UPSTASH_REDIS_REST_URL}/hgetall/{key}"
    response = requests.get(
        url,
        headers={"Authorization": f"Bearer {UPSTASH_REDIS_REST_TOKEN}"}
    )
    result = response.json()
    # Upstash returns [["key1", "val1", "key2", "val2"]] - get inner array
    data = result.get("result", [])
    if data and isinstance(data, list) and len(data) > 0 and isinstance(data[0], list):
        items = data[0]
    else:
        items = data if isinstance(data, list) else []
    return {items[i]: items[i+1] for i in range(0, len(items), 2)}

def upstash_hexists(key, field):
    url = f"{UPSTASH_REDIS_REST_URL}/hexists/{key}/{field}"
    response = requests.get(
        url,
        headers={"Authorization": f"Bearer {UPSTASH_REDIS_REST_TOKEN}"}
    )
    result = response.json()
    return result.get("result", 0) == 1

# --- AI OTP Extraction ---

def _parse_ai_json_response(response_text):
    try:
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if json_match:
            json_string = json_match.group(0)
            return json.loads(json_string)
        else:
            return None
    except json.JSONDecodeError:
        return None

def extract_details_with_ai(text_content):
    if not OPENROUTER_API_KEY:
        return {"otp_digit": None, "otp_mix": None}

    system_prompt = """You are an expert JSON-only data extraction tool. Analyze the user-provided email text.
Your task is to find two types of codes:
1. `otp_digit`: A numeric-only code, 4-8 digits long. IGNORE any dashes or spaces.
2. `otp_mix`: An alphanumeric code, 5-8 characters long.

Your response MUST be a single, valid JSON object and nothing else.
- If a code is not found, its value MUST be null.
- DO NOT extract common English words."""

    try:
        response = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://mail.pawclaw.top",
                "X-Title": "MailPi API"
            },
            json={
                "model": "meta-llama/llama-3.3-8b-instruct:free",
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": text_content[:4000]}
                ]
            },
            timeout=20
        )
        response.raise_for_status()
        content_string = response.json()['choices'][0]['message']['content']
        extracted_codes = _parse_ai_json_response(content_string)
        if not extracted_codes:
            return {"otp_digit": None, "otp_mix": None}
        otp_digit = extracted_codes.get("otp_digit")
        if otp_digit and isinstance(otp_digit, str):
            otp_digit = re.sub(r'\D', '', otp_digit)
        return {
            "otp_digit": otp_digit or None,
            "otp_mix": extracted_codes.get("otp_mix") or None
        }
    except Exception as e:
        return {"otp_digit": None, "otp_mix": None}

def extract_links_with_regex(html_body, text_body):
    content = f"{html_body} {text_body}"
    links = re.findall(r'https?://[^\s"\'<>]+', content)
    return sorted(list(set(links)), key=links.index) if links else []

def generate_address(alias=None):
    alias_part = alias or secrets.token_hex(4)
    addr = f"{alias_part}@{SUBDOMAIN}"
    now = datetime.utcnow()
    expires = now + timedelta(days=ADDRESS_TTL_DAYS)
    expires_iso = expires.isoformat()
    upstash_hset(ADDRESSES_KEY, addr, expires_iso)
    return addr, expires_iso

# --- API Endpoints ---

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

@api_v1.route("/addresses/<string:email>/messages", methods=["GET"])
@require_api_key
def get_messages_for_address(email):
    messages_json = upstash_lrange(f"{MESSAGES_PREFIX}{email}", 0, -1)
    messages_summary = []
    for msg_json in messages_json:
        try:
            msg = json.loads(msg_json)
            messages_summary.append({
                "id": msg.get("id"),
                "from": msg.get("from"),
                "subject": msg.get("subject"),
                "received_at": msg.get("received_at"),
                "otp_digit": msg.get("otp_digit"),
                "otp_mix": msg.get("otp_mix"),
                "has_links": bool(msg.get("links"))
            })
        except (json.JSONDecodeError, KeyError): continue
    return jsonify(messages_summary)

@api_v1.route("/messages/<string:email>/<string:message_id>", methods=["GET"])
@require_api_key
def get_full_message(email, message_id):
    messages_json = upstash_lrange(f"{MESSAGES_PREFIX}{email}", 0, -1)
    for msg_json in messages_json:
        try:
            msg = json.loads(msg_json)
            if msg.get("id") == message_id:
                return jsonify(msg)
        except (json.JSONDecodeError, KeyError): continue
    return jsonify({"error": "Message not found."}), 404

app.register_blueprint(api_v1)

# --- Frontend & Public Routes ---

@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")

@app.route("/webhook", methods=["POST"])
def api_webhook():
    data = request.get_json(force=True, silent=True)
    if not data: return jsonify({"error": "No JSON received"}), 400
    to_addr = data.get("to")
    if not to_addr: return jsonify({"error": "Missing 'to' field"}), 400
    return jsonify({"status": "received", "note": "Processing handled by Cloudflare Worker"}), 202

@app.route("/addresses", methods=["GET"])
def list_all_addresses():
    all_addresses = upstash_hgetall(ADDRESSES_KEY)
    addresses_list = [{"address": addr, "expires_at": expires_at} for addr, expires_at in all_addresses.items()]
    addresses_list.sort(key=lambda x: x['expires_at'], reverse=True)
    return jsonify(addresses_list)

@app.after_request
def add_security_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return response
