"""TajCrash V53: Telegram Web App verified identity + server demo account."""
import hashlib
import hmac
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Annotated

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
SESSION_SECRET = os.environ.get("SESSION_SECRET", "")
ORIGIN = os.environ.get("ALLOWED_ORIGIN", "https://shahromak.github.io")
DB_PATH = os.environ.get("DATABASE_PATH", "./tajcrash.sqlite3")
if not BOT_TOKEN or len(SESSION_SECRET) < 32:
    raise RuntimeError("Set TELEGRAM_BOT_TOKEN and a random SESSION_SECRET (32+ chars) on the server")

app = FastAPI(title="TajCrash demo identity API", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=[ORIGIN], allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"])

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
    return {"telegram_id": user[0], "first_name": user[1], "username": user[2], "demo_balances": {k: wallets.get(k, 0) / 100 for k in ("TJS", "RUB", "KZT", "USD")}, "verified": True, "wallet_mode": "server_demo_read_only"}

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
