"""TajCrash demo authentication and wallet regression tests.
Run from repository root: python -m unittest discover -s backend/tests -v
Requires: pip install -r backend/requirements.txt
"""
import hashlib
import hmac
import importlib
import json
import os
import tempfile
import time
import unittest
from urllib.parse import urlencode

from fastapi import HTTPException


class AuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        os.environ["TELEGRAM_BOT_TOKEN"] = "123456:FAKE_TEST_TOKEN_NOT_REAL"
        os.environ["SESSION_SECRET"] = "test-secret-" + "x" * 40
        os.environ["DATABASE_PATH"] = os.path.join(cls.tmp.name, "test.sqlite3")
        import sys
        sys.path.insert(0, os.path.abspath("backend"))
        cls.app = importlib.import_module("main")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def telegram_data(self, uid=12345, auth_date=None, tamper=False):
        if auth_date is None:
            auth_date = int(time.time())
        data = {
            "auth_date": str(auth_date),
            "query_id": "AA-test",
            "user": json.dumps({"id": uid, "first_name": "Demo", "username": "demo_user"}, separators=(",", ":")),
        }
        check = "\\n".join(f"{k}={v}" for k, v in sorted(data.items()))
        key = hmac.new(b"WebAppData", os.environ["TELEGRAM_BOT_TOKEN"].encode(), hashlib.sha256).digest()
        data["hash"] = hmac.new(key, check.encode(), hashlib.sha256).hexdigest()
        if tamper:
            data["user"] = data["user"].replace("Demo", "Attacker")
        return urlencode(data)

    def test_health(self):
        self.assertEqual(self.app.health(), {"status": "ok"})

    def test_valid_login_and_read_only_balances(self):
        result = self.app.telegram_login(self.app.Login(init_data=self.telegram_data()))
        self.assertTrue(result["profile"]["verified"])
        self.assertEqual(result["profile"]["wallet_mode"], "server_demo_read_only")
        self.assertEqual(set(result["profile"]["demo_balances"]), {"TJS", "RUB", "KZT", "USD"})
        self.assertEqual(self.app.me("Bearer " + result["access_token"])["telegram_id"], 12345)

    def test_repeated_login_does_not_reset_balance(self):
        self.app.telegram_login(self.app.Login(init_data=self.telegram_data()))
        with self.app.db() as conn:
            conn.execute("UPDATE wallets SET cents=1234 WHERE telegram_id=12345 AND currency='TJS'")
        result = self.app.telegram_login(self.app.Login(init_data=self.telegram_data()))
        self.assertEqual(result["profile"]["demo_balances"]["TJS"], 12.34)

    def test_tampered_signature_rejected(self):
        with self.assertRaises(HTTPException) as ctx:
            self.app.verify_telegram(self.telegram_data(tamper=True))
        self.assertEqual(ctx.exception.status_code, 401)

    def test_expired_telegram_data_rejected(self):
        with self.assertRaises(HTTPException) as ctx:
            self.app.verify_telegram(self.telegram_data(auth_date=int(time.time()) - 1000))
        self.assertEqual(ctx.exception.status_code, 401)

    def test_duplicate_fields_rejected(self):
        with self.assertRaises(HTTPException):
            self.app.verify_telegram(self.telegram_data() + "&auth_date=1")

    def test_missing_telegram_data_rejected(self):
        with self.assertRaises(HTTPException):
            self.app.verify_telegram("")

    def test_invalid_session_rejected(self):
        for header in (None, "Bearer fake", "Basic anything"):
            with self.subTest(header=header), self.assertRaises(HTTPException):
                self.app.session_uid(header)

    def test_expired_session_rejected(self):
        payload = f"12345.{int(time.time()) - 10}"
        sig = hmac.new(os.environ["SESSION_SECRET"].encode(), payload.encode(), hashlib.sha256).hexdigest()
        with self.assertRaises(HTTPException):
            self.app.session_uid("Bearer " + payload + "." + sig)

    def test_no_user_without_login(self):
        with self.assertRaises(HTTPException) as ctx:
            self.app.profile(99999999)
        self.assertEqual(ctx.exception.status_code, 401)


if __name__ == "__main__":
    unittest.main()
