# TajCrash V53 — Telegram login backend (DEMO)

This backend is **not deployed**. GitHub Pages cannot run it. Deploy on a Python HTTPS host, set environment variables in the host's secret manager, then configure `window.TAJCRASH_API_URL` in the frontend. Never put the bot token or SESSION_SECRET in GitHub Pages, frontend JavaScript or Git.

Run locally: `pip install -r requirements.txt && uvicorn main:app --host 127.0.0.1 --port 8000`. Required environment variables: `TELEGRAM_BOT_TOKEN`, `SESSION_SECRET`, `ALLOWED_ORIGIN`. Optional `DATABASE_PATH`. Use persistent disk for SQLite; a production deployment should use managed database, backups, monitoring and HTTPS. Use a strict CORS origin. Only demo balances; no real money.

Endpoints: `POST /auth/telegram` with `{ "init_data": "..." }` verifies Telegram Web App HMAC and 5-minute freshness, returns an expiring bearer token. `GET /me` with Authorization Bearer returns verified Telegram profile and server-side demo balances. `GET /health` is public.

**Do not** treat this as a production gambling backend. Game outcomes, stakes, wallet operations and exchanges still run on the client and are NOT secure. Server balances are initialized independently and never auto-import client localStorage. No deposits, withdrawals or real-money bets are implemented.
