"""TajCrash V53: Telegram Web App verified identity + server demo account."""
import hashlib
import hmac
import json
import os
import secrets
import urllib.request
import urllib.error
import sqlite3
import time
from contextlib import contextmanager
from typing import Annotated

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
SESSION_SECRET = os.environ.get("SESSION_SECRET", "")
ORIGIN = os.environ.get("ALLOWED_ORIGIN", "https://shahromak.github.io")
DB_PATH = os.environ.get("DATABASE_PATH", "./tajcrash.sqlite3")
if not BOT_TOKEN or len(SESSION_SECRET) < 32:
    raise RuntimeError("Set TELEGRAM_BOT_TOKEN and a random SESSION_SECRET (32+ chars) on the server")

app = FastAPI(title="TajCrash demo identity API", docs_url=None, redoc_url=None)
# Allow the exact GitHub Pages host (including an optional configured origin).
# Browser preflight can include additional request headers; do not reject them.
app.add_middleware(
    CORSMiddleware,
    allow_origins=list({ORIGIN.strip().rstrip("/"), "https://shahromak.github.io"}),
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    max_age=600,
)

@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        yield conn
        conn.commit()
    finally:
        conn.close()

with db() as conn:
    conn.execute("""CREATE TABLE IF NOT EXISTS users
        (telegram_id INTEGER PRIMARY KEY, first_name TEXT NOT NULL,
         username TEXT, updated_at INTEGER NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS wallets
        (telegram_id INTEGER NOT NULL, currency TEXT NOT NULL,
         cents INTEGER NOT NULL DEFAULT 0 CHECK(cents >= 0),
         PRIMARY KEY(telegram_id, currency),
         FOREIGN KEY(telegram_id) REFERENCES users(telegram_id))""")

with db() as conn:
    conn.execute("""CREATE TABLE IF NOT EXISTS telegram_codes (
        telegram_id INTEGER PRIMARY KEY, code_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
        sent_at INTEGER NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS telegram_confirmations (
        telegram_id INTEGER PRIMARY KEY, confirmed_at INTEGER NOT NULL)""")

# Server-authoritative DEMO ledger. No client-supplied payouts or real money.
with db() as conn:
    conn.execute("""CREATE TABLE IF NOT EXISTS demo_ledger (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        telegram_id INTEGER NOT NULL, currency TEXT NOT NULL,
        delta_cents INTEGER NOT NULL, balance_after_cents INTEGER NOT NULL,
        operation_id TEXT NOT NULL, created_at INTEGER NOT NULL,
        UNIQUE(telegram_id, operation_id))""")

class DemoBet(BaseModel):
    currency: str
    amount_cents: int
    operation_id: str

@app.get("/demo/wallet")
def demo_wallet(authorization: Annotated[str | None, Header()] = None):
    uid = session_uid(authorization)
    return {"balances": profile(uid)["demo_balances"], "mode": "server_demo"}

@app.post("/demo/bet")
def demo_bet(body: DemoBet, authorization: Annotated[str | None, Header()] = None):
    """Debit a DEMO bet once; games must NOT award payouts until server rules exist."""
    uid = session_uid(authorization)
    if body.currency not in ("TJS", "RUB", "KZT", "USD"):
        raise HTTPException(400, "Unsupported currency")
    if not isinstance(body.amount_cents, int) or isinstance(body.amount_cents, bool) or not 1 <= body.amount_cents <= 100000:
        raise HTTPException(400, "Invalid demo bet amount")
    if not 8 <= len(body.operation_id) <= 100 or not all(ch.isascii() and (ch.isalnum() or ch in "-_") for ch in body.operation_id):
        raise HTTPException(400, "Invalid operation ID")
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute("SELECT currency,delta_cents,balance_after_cents FROM demo_ledger WHERE telegram_id=? AND operation_id=?", (uid, body.operation_id)).fetchone()
        if existing:
            if existing[0] != body.currency or existing[1] != -body.amount_cents:
                raise HTTPException(409, "Operation ID already used for another bet")
            return {"status": "already_processed", "balance_cents": existing[2], "currency": existing[0]}
        updated = conn.execute("UPDATE wallets SET cents=cents-? WHERE telegram_id=? AND currency=? AND cents>=?",
            (body.amount_cents, uid, body.currency, body.amount_cents))
        if updated.rowcount != 1:
            raise HTTPException(409, "Insufficient DEMO balance")
        balance = conn.execute("SELECT cents FROM wallets WHERE telegram_id=? AND currency=?", (uid, body.currency)).fetchone()[0]
        conn.execute("INSERT INTO demo_ledger(telegram_id,currency,delta_cents,balance_after_cents,operation_id,created_at) VALUES(?,?,?,?,?,?)",
            (uid, body.currency, -body.amount_cents, balance, body.operation_id, int(time.time())))
    return {"status": "accepted", "currency": body.currency, "balance_cents": balance}

@app.get("/demo/ledger")
def demo_ledger(authorization: Annotated[str | None, Header()] = None, limit: int = 20):
    """Authenticated, read-only transaction history for the current DEMO user."""
    uid = session_uid(authorization)
    if not 1 <= limit <= 100:
        raise HTTPException(400, "Limit must be between 1 and 100")
    with db() as conn:
        rows = conn.execute(
            """SELECT currency,delta_cents,balance_after_cents,operation_id,created_at
               FROM demo_ledger WHERE telegram_id=? ORDER BY id DESC LIMIT ?""",
            (uid, limit),
        ).fetchall()
    return {"mode": "server_demo", "entries": [
        {"currency": currency, "delta_cents": delta,
         "balance_after_cents": balance, "operation_id": op, "created_at": created}
        for currency, delta, balance, op, created in rows
    ]}


class VerifyCode(BaseModel):
    code: str

class Login(BaseModel):
    init_data: str

def verify_telegram(raw: str):
    from urllib.parse import parse_qsl
    if not raw or len(raw) > 8192:
        raise HTTPException(401, "Missing Telegram initData")
    pairs = parse_qsl(raw, keep_blank_values=True, strict_parsing=True)
    data = dict(pairs)
    if len(data) != len(pairs):
        raise HTTPException(401, "Duplicate initData fields")
    provided = data.pop("hash", "")
    check = "\n".join(f"{k}={v}" for k, v in sorted(data.items()))
    key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    expected = hmac.new(key, check.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, provided):
        raise HTTPException(401, "Invalid Telegram signature")
    try:
        auth_date = int(data["auth_date"])
        user = json.loads(data["user"])
        uid = int(user["id"])
    except (KeyError, ValueError, TypeError, json.JSONDecodeError):
        raise HTTPException(401, "Invalid Telegram user")
    now = int(time.time())
    if auth_date > now + 30 or now - auth_date > 300 or uid <= 0:
        raise HTTPException(401, "Expired Telegram initData")
    return uid, str(user.get("first_name", "Игрок"))[:128], str(user.get("username", ""))[:64]

def sign_session(uid: int):
    expires = int(time.time()) + 86400
    payload = f"{uid}.{expires}"
    sig = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"

def session_uid(authorization: str | None):
    try:
        scheme, token = (authorization or "").split(" ", 1)
        uid, expiry, sig = token.split(".")
        payload = f"{uid}.{expiry}"
        expected = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if scheme.lower() != "bearer" or not hmac.compare_digest(expected, sig) or int(expiry) < time.time():
            raise ValueError()
        return int(uid)
    except (ValueError, TypeError):
        raise HTTPException(401, "Session expired or invalid")

def profile(uid):
    with db() as conn:
        user = conn.execute("SELECT telegram_id,first_name,username FROM users WHERE telegram_id=?", (uid,)).fetchone()
        if not user:
            raise HTTPException(401, "Unknown user")
        wallets = dict(conn.execute("SELECT currency,cents FROM wallets WHERE telegram_id=?", (uid,)).fetchall())
        confirmed = conn.execute("SELECT confirmed_at FROM telegram_confirmations WHERE telegram_id=?", (uid,)).fetchone()
    return {"telegram_code_confirmed": bool(confirmed), "telegram_id": user[0], "first_name": user[1], "username": user[2], "demo_balances": {k: wallets.get(k, 0) / 100 for k in ("TJS", "RUB", "KZT", "USD")}, "verified": True, "wallet_mode": "server_demo_read_only"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/auth/telegram")
def telegram_login(body: Login):
    uid, first_name, username = verify_telegram(body.init_data)
    with db() as conn:
        conn.execute("""INSERT INTO users(telegram_id,first_name,username,updated_at) VALUES(?,?,?,?)
            ON CONFLICT(telegram_id) DO UPDATE SET first_name=excluded.first_name,
            username=excluded.username,updated_at=excluded.updated_at""", (uid, first_name, username, int(time.time())))
        for currency in ("TJS", "RUB", "KZT", "USD"):
            conn.execute("INSERT OR IGNORE INTO wallets(telegram_id,currency,cents) VALUES(?,?,?)", (uid, currency, 100000))
    return {"access_token": sign_session(uid), "token_type": "bearer", "profile": profile(uid)}

@app.get("/me")
def me(authorization: Annotated[str | None, Header()] = None):
    return profile(session_uid(authorization))

def code_digest(uid: int, code: str) -> str:
    return hmac.new(SESSION_SECRET.encode(), f"{uid}:{code}".encode(), hashlib.sha256).hexdigest()

@app.post("/auth/telegram/code/send")
def send_telegram_code(authorization: Annotated[str | None, Header()] = None):
    uid = session_uid(authorization)
    now = int(time.time())
    with db() as conn:
        existing = conn.execute("SELECT sent_at FROM telegram_codes WHERE telegram_id=?", (uid,)).fetchone()
        if existing and now - existing[0] < 60:
            raise HTTPException(429, "Подожди минуту перед новым кодом")
        confirmed = conn.execute("SELECT 1 FROM telegram_confirmations WHERE telegram_id=?", (uid,)).fetchone()
        if confirmed:
            return {"status": "already_confirmed"}
    code = f"{secrets.randbelow(1000000):06d}"
    payload = json.dumps({
        "chat_id": uid,
        "text": "🔐 Код подтверждения TajCrash: " + code + "\nДействует 5 минут. Никому не сообщай код."
    }).encode()
    req = urllib.request.Request(
        "https://api.telegram.org/bot" + BOT_TOKEN + "/sendMessage",
        data=payload, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            result = json.load(response)
        if not result.get("ok"):
            raise ValueError("Telegram rejected message")
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        raise HTTPException(502, "Не удалось отправить сообщение. Нажми Start в боте и попробуй снова.")
    with db() as conn:
        conn.execute("""INSERT INTO telegram_codes(telegram_id,code_hash,expires_at,attempts,sent_at)
            VALUES(?,?,?,?,?) ON CONFLICT(telegram_id) DO UPDATE SET
            code_hash=excluded.code_hash,expires_at=excluded.expires_at,
            attempts=0,sent_at=excluded.sent_at""",
            (uid, code_digest(uid, code), now + 300, 0, now))
    return {"status": "sent", "expires_in": 300}

@app.post("/auth/telegram/code/verify")
def verify_telegram_code(body: VerifyCode, authorization: Annotated[str | None, Header()] = None):
    uid = session_uid(authorization)
    if len(body.code) != 6 or not body.code.isascii() or not body.code.isdecimal():
        raise HTTPException(400, "Введи 6 цифр")
    now = int(time.time())
    with db() as conn:
        row = conn.execute("SELECT code_hash,expires_at,attempts FROM telegram_codes WHERE telegram_id=?", (uid,)).fetchone()
        if not row:
            raise HTTPException(400, "Сначала запроси код")
        if row[1] < now or row[2] >= 5:
            conn.execute("DELETE FROM telegram_codes WHERE telegram_id=?", (uid,))
            return {"status": "expired"}
        conn.execute("UPDATE telegram_codes SET attempts=attempts+1 WHERE telegram_id=?", (uid,))
        if not hmac.compare_digest(row[0], code_digest(uid, body.code)):
            return {"status": "invalid", "attempts_left": 4 - row[2]}
        conn.execute("DELETE FROM telegram_codes WHERE telegram_id=?", (uid,))
        conn.execute("""INSERT INTO telegram_confirmations(telegram_id,confirmed_at) VALUES(?,?)
            ON CONFLICT(telegram_id) DO UPDATE SET confirmed_at=excluded.confirmed_at""", (uid, now))
    return {"status": "confirmed"}


@app.post("/telegram/webhook")
async def telegram_bot_webhook(request: Request):
    # Telegram webhook requests are authenticated by a separately configured secret.
    expected = os.environ.get("TELEGRAM_WEBHOOK_SECRET", "")
    supplied = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
    if not expected or not hmac.compare_digest(supplied, expected):
        raise HTTPException(403, "Forbidden")
    update = await request.json()
    message = update.get("message") or {}
    chat = message.get("chat") or {}
    if chat.get("type") != "private" or not str(message.get("text", "")).startswith("/start"):
        return {"ok": True}
    chat_id = chat.get("id")
    if not isinstance(chat_id, int):
        return {"ok": True}
    payload = json.dumps({
        "chat_id": chat_id,
        "text": "🚀 Добро пожаловать в TajCrash Game!\n🎮 Открой DEMO-игру кнопкой ниже. Без реальных денег.",
        "reply_markup": {"inline_keyboard": [[{"text": "🎮 Играть в TajCrash", "web_app": {"url": "https://shahromak.github.io/tajcrash-v11/"}}]]}
    }).encode()
    req = urllib.request.Request("https://api.telegram.org/bot" + BOT_TOKEN + "/sendMessage",
        data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            json.load(response)
    except (urllib.error.URLError, TimeoutError, OSError):
        raise HTTPException(502, "Telegram send failed")
    return {"ok": True}
