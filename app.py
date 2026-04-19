"""
Melon Season — Production WL Server
PostgreSQL (Railway) / SQLite (local) + Telegram + Google Sheets
"""
import os, re, time, secrets, threading
from datetime import datetime
from collections import defaultdict
from flask import (Flask, render_template, request,
                   session, jsonify, send_from_directory)
import sqlite3
import requests as http_req

# ── Try PostgreSQL, fall back to SQLite ──────────────────────
try:
    import psycopg2
    import psycopg2.extras
    HAS_PG = True
except ImportError:
    HAS_PG = False

app = Flask(__name__, template_folder='.', static_folder='static')
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Force HTTPS cookies in production
IS_PROD = bool(os.environ.get("RAILWAY_ENVIRONMENT") or os.environ.get("DATABASE_URL"))
if IS_PROD:
    app.config['SESSION_COOKIE_SECURE'] = True

# ── CONFIG ───────────────────────────────────────────────────
MAX_SUPPLY = 150
DATABASE_URL = os.environ.get("DATABASE_URL")

# Notifications — NO hardcoded defaults. Set in Railway env vars.
TG_TOKEN   = os.environ.get("TG_BOT_TOKEN", "")
TG_CHAT    = os.environ.get("TG_CHAT_ID", "")
GSHEET_URL = os.environ.get("GSHEET_URL", "")

# ── DATABASE ─────────────────────────────────────────────────
def get_db():
    if DATABASE_URL and HAS_PG:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    else:
        db_path = os.path.join(os.path.dirname(__file__), "whitelist.db")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    if DATABASE_URL and HAS_PG:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS whitelist (
                id SERIAL PRIMARY KEY,
                x_handle TEXT NOT NULL,
                wallet TEXT NOT NULL,
                registered_at TEXT NOT NULL,
                ip TEXT,
                UNIQUE(x_handle),
                UNIQUE(wallet)
            )
        """)
    else:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                x_handle TEXT NOT NULL UNIQUE,
                wallet TEXT NOT NULL UNIQUE,
                registered_at TEXT NOT NULL,
                ip TEXT
            )
        """)
    conn.commit()
    conn.close()

init_db()

def db_query(sql, params=(), fetchone=False, fetchall=False):
    conn = get_db()
    cur = conn.cursor()
    if DATABASE_URL and HAS_PG:
        sql = sql.replace("?", "%s")
    cur.execute(sql, params)
    result = None
    if fetchone:
        result = cur.fetchone()
    elif fetchall:
        result = cur.fetchall()
    conn.commit()
    conn.close()
    return result

def db_count():
    row = db_query("SELECT COUNT(*) FROM whitelist", fetchone=True)
    return row[0] if row else 0

# ── RATE LIMITER ─────────────────────────────────────────────
_rate = defaultdict(list)
_rate_last_cleanup = time.time()

def is_rate_limited(ip):
    global _rate_last_cleanup
    now = time.time()
    
    # Cleanup stale IPs every 5 minutes to prevent memory leak
    if now - _rate_last_cleanup > 300:
        stale = [k for k, v in _rate.items() if not v or now - max(v) > 600]
        for k in stale:
            del _rate[k]
        _rate_last_cleanup = now
    
    _rate[ip] = [t for t in _rate[ip] if now - t < 600]
    if len(_rate[ip]) >= 5:
        return True
    _rate[ip].append(now)
    return False

# ── VALIDATION ───────────────────────────────────────────────
HANDLE_RE = re.compile(r'^[A-Za-z0-9_]{1,30}$')
WALLET_RE = re.compile(r'^0x[a-fA-F0-9]{40}$')

def get_real_ip():
    """Get real IP behind Railway/proxy"""
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'

# ── NOTIFICATIONS (fire & forget) ────────────────────────────
def notify_telegram(handle, wallet, count):
    if not TG_TOKEN or not TG_CHAT:
        return
    try:
        msg = (
            f"New WL Registration\n\n"
            f"Handle: @{handle}\n"
            f"Wallet: {wallet}\n"
            f"Spots: {count}/{MAX_SUPPLY}\n"
            f"Time: {datetime.utcnow().strftime('%H:%M UTC')}"
        )
        http_req.post(
            f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
            json={"chat_id": TG_CHAT, "text": msg},
            timeout=5
        )
    except Exception:
        pass

def notify_gsheet(handle, wallet, ip):
    if not GSHEET_URL:
        return
    try:
        http_req.post(GSHEET_URL, json={
            "handle": handle,
            "wallet": wallet,
            "ip": ip
        }, timeout=5)
    except Exception:
        pass

def send_notifications(handle, wallet, ip, count):
    threading.Thread(target=notify_telegram, args=(handle, wallet, count), daemon=True).start()
    threading.Thread(target=notify_gsheet, args=(handle, wallet, ip), daemon=True).start()

# ── SECURITY HEADERS ─────────────────────────────────────────
@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    # CSP — allow self, Google Fonts, and inline styles/scripts (needed for single-file HTML)
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'"
    )
    if IS_PROD:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# ── PAGES ────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory('.', 'index.html')

@app.route("/whitelist")
def whitelist_page():
    return render_template("whitelist.html",
        registered=session.get("registered", False),
        x_handle=session.get("x_handle", ""),
        wl_count=db_count())

@app.route("/health")
def health():
    return jsonify({"status": "ok", "wl": db_count()})

# ── REGISTER ─────────────────────────────────────────────────
@app.route("/register", methods=["POST"])
def register():
    ip = get_real_ip()

    if is_rate_limited(ip):
        return jsonify({"ok": False, "msg": "Too many attempts. Try again later."}), 429

    handle = request.form.get("x_handle", "").strip().lstrip("@")
    wallet = request.form.get("wallet", "").strip()

    if not HANDLE_RE.match(handle):
        return jsonify({"ok": False, "msg": "Invalid X handle"}), 400
    if not WALLET_RE.match(wallet):
        return jsonify({"ok": False, "msg": "Invalid wallet (0x + 40 hex chars)"}), 400

    count = db_count()
    if count >= MAX_SUPPLY:
        return jsonify({"ok": False, "msg": "Whitelist is full"}), 400

    # Check duplicates
    existing = db_query(
        "SELECT id FROM whitelist WHERE LOWER(x_handle)=LOWER(?) OR LOWER(wallet)=LOWER(?)",
        (handle, wallet), fetchone=True)
    if existing:
        return jsonify({"ok": False, "msg": "Already registered"}), 400

    # Insert with race-condition protection via UNIQUE constraint
    try:
        db_query("INSERT INTO whitelist (x_handle,wallet,registered_at,ip) VALUES (?,?,?,?)",
            (handle, wallet, datetime.utcnow().isoformat(), ip))
    except Exception:
        return jsonify({"ok": False, "msg": "Already registered"}), 400

    new_count = count + 1
    session["registered"] = True
    session["x_handle"] = handle

    send_notifications(handle, wallet, ip, new_count)

    return jsonify({"ok": True, "msg": f"Welcome @{handle}! Now tweet to confirm."})

# ── API ──────────────────────────────────────────────────────
@app.route("/api/wl-count")
def api_wl_count():
    return jsonify({"count": db_count(), "max": MAX_SUPPLY})

# ── RUN ──────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n[MELON SEASON] Server running")
    print("  http://localhost:5000")
    print("  http://localhost:5000/whitelist")
    print(f"  DB: {'PostgreSQL' if (DATABASE_URL and HAS_PG) else 'SQLite (local)'}")
    print(f"  Telegram: {'YES' if TG_TOKEN else 'NO (set TG_BOT_TOKEN + TG_CHAT_ID)'}")
    print(f"  Sheets: {'YES' if GSHEET_URL else 'NO (set GSHEET_URL)'}")
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1", port=5000)
