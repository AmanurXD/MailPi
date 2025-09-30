# mail_webhook_server.py
from flask import Flask, request, jsonify, abort
from pathlib import Path
from datetime import datetime, timedelta
import secrets
import sqlite3

app = Flask(__name__)

DB_PATH = "mailbox.db"
STORAGE = Path("mail_storage")
STORAGE.mkdir(exist_ok=True)
SUBDOMAIN = "codewithjames.top"
ADDRESS_TTL_DAYS = 14  # default TTL

# --- DB initialization ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # store generated addresses
    cur.execute("""
    CREATE TABLE IF NOT EXISTS addresses (
        address TEXT PRIMARY KEY,
        created_at TEXT,
        expires_at TEXT
    )
    """)
    # store incoming messages
    cur.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        address TEXT,
        from_addr TEXT,
        subject TEXT,
        raw TEXT,
        received_at TEXT
    )
    """)
    conn.commit()
    conn.close()

init_db()

# --- Helpers ---
def generate_address(alias=None):
    alias_part = alias or secrets.token_hex(4)
    addr = f"{alias_part}@{SUBDOMAIN}"
    now = datetime.utcnow()
    expires = now + timedelta(days=ADDRESS_TTL_DAYS)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO addresses(address, created_at, expires_at) VALUES (?,?,?)",
                (addr, now.isoformat(), expires.isoformat()))
    conn.commit()
    conn.close()
    return addr

def store_message(to_address, from_addr, subject, raw):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO messages(address, from_addr, subject, raw, received_at) VALUES (?,?,?,?,?)",
        (to_address, from_addr, subject, raw, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

# --- API endpoints ---

# Generate new email
@app.route("/generate", methods=["GET"])
def api_generate():
    alias = request.args.get("alias")
    addr = generate_address(alias)
    return jsonify({"address": addr, "expires_at": (datetime.utcnow()+timedelta(days=ADDRESS_TTL_DAYS)).isoformat()})

# Get messages for an address
@app.route("/get", methods=["GET"])
def api_get():
    email = request.args.get("address")
    if not email:
        return jsonify({"error": "Missing address parameter"}), 400
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, from_addr, subject, raw, received_at FROM messages WHERE address=? ORDER BY id DESC", (email,))
    rows = cur.fetchall()
    conn.close()
    return jsonify([{"id": r[0], "from": r[1], "subject": r[2], "raw": r[3], "received_at": r[4]} for r in rows])

# Webhook endpoint to receive emails
@app.route("/webhook", methods=["POST"])
def api_webhook():
    """
    Expects JSON payload from mail-forwarding provider:
    {
      "to": "alias@org.codewithjames.top",
      "from": "sender@example.com",
      "subject": "...",
      "raw": "full email raw content"
    }
    """
    data = request.get_json(force=True)
    if not data:
        return jsonify({"error": "No JSON received"}), 400
    to_addr = data.get("to")
    from_addr = data.get("from", "unknown")
    subject = data.get("subject", "")
    raw = data.get("raw", "")
    if not to_addr:
        return jsonify({"error": "Missing 'to' field"}), 400

    store_message(to_addr, from_addr, subject, raw)
    print(f"[Webhook] Saved email to {to_addr} from {from_addr}")
    return jsonify({"status": "success"})

# Delete an address (and optionally its messages)
@app.route("/delete", methods=["POST"])
def api_delete():
    email = request.args.get("address")
    if not email:
        return jsonify({"error": "Missing address parameter"}), 400
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM addresses WHERE address=?", (email,))
    cur.execute("DELETE FROM messages WHERE address=?", (email,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "address": email})

# List all addresses
@app.route("/addresses", methods=["GET"])
def api_list_addresses():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT address, created_at, expires_at FROM addresses ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return jsonify([{"address": r[0], "created_at": r[1], "expires_at": r[2]} for r in rows])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
