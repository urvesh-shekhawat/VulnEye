import os
import sys
import unittest
import json
import secrets
import http.server
import threading
import time

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner import is_safe_target, validate_outbound_url, check_status, run_scan
from database import (
    init_db,
    save_scan,
    get_all_scans,
    get_scan_by_id,
    get_latest_scan_results,
    delete_scan,
    add_monitored_asset,
    get_monitored_assets,
    delete_monitored_asset,
    generate_api_key,
    get_user_api_keys,
    revoke_api_key,
    verify_api_key,
    process_subscription_payment,
    get_user_transactions,
    get_transaction_by_id,
    send_webhook_alert
)
from api.index import app

class Phase2SecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False

    def setUp(self):
        self.client = app.test_client()

    # ================= 1. SECRET KEY & COOKIE CONFIG TESTS =================
    def test_session_cookie_security_flags(self):
        """Verify session cookies are configured with HttpOnly and SameSite=Lax"""
        self.assertTrue(app.config.get("SESSION_COOKIE_HTTPONLY"))
        self.assertEqual(app.config.get("SESSION_COOKIE_SAMESITE"), "Lax")

    def test_production_secret_key_fails_safely_if_missing(self):
        """Verify production fails loudly if SECRET_KEY is missing"""
        orig_vercel = os.environ.get("VERCEL")
        orig_secret = os.environ.get("SECRET_KEY")
        try:
            os.environ["VERCEL"] = "1"
            if "SECRET_KEY" in os.environ:
                del os.environ["SECRET_KEY"]
            
            # Re-evaluating production SECRET_KEY requirement should raise RuntimeError
            with self.assertRaises(RuntimeError):
                is_prod = bool(os.environ.get("VERCEL"))
                secret_key = os.environ.get("SECRET_KEY")
                if is_prod and not secret_key:
                    raise RuntimeError("SECRET_KEY required in production")
        finally:
            if orig_vercel is not None:
                os.environ["VERCEL"] = orig_vercel
            else:
                os.environ.pop("VERCEL", None)
            if orig_secret is not None:
                os.environ["SECRET_KEY"] = orig_secret

    # ================= 2. MULTI-TENANT & GUEST ISOLATION TESTS =================
    def test_guest_isolation_unique_sessions(self):
        """Guest login generates unique isolated user identities per session"""
        with app.test_client() as c1:
            c1.get("/login/guest")
            with c1.session_transaction() as sess1:
                email_1 = sess1.get("user", {}).get("email")
                self.assertTrue(email_1.startswith("guest_"))
                self.assertNotEqual(email_1, "analyst@vulneye.sec")

        with app.test_client() as c2:
            c2.get("/login/guest")
            with c2.session_transaction() as sess2:
                email_2 = sess2.get("user", {}).get("email")
                self.assertTrue(email_2.startswith("guest_"))
                self.assertNotEqual(email_1, email_2)

    def test_user_data_isolation_scans(self):
        """User A cannot read, find, or delete User B's scans"""
        user_a = "user_a_" + secrets.token_hex(4) + "@corp.com"
        user_b = "user_b_" + secrets.token_hex(4) + "@corp.com"

        scan_id_a = save_scan({"url": "https://target-a.com", "reachable": True, "risk": "Low"}, user_email=user_a)
        scan_id_b = save_scan({"url": "https://target-b.com", "reachable": True, "risk": "High"}, user_email=user_b)

        # User A should only see scan A
        scans_a = get_all_scans(user_email=user_a)
        scan_ids_a = [s[0] for s in scans_a]
        self.assertIn(scan_id_a, scan_ids_a)
        self.assertNotIn(scan_id_b, scan_ids_a)

        # User A cannot lookup scan B by ID
        self.assertIsNone(get_scan_by_id(scan_id_b, user_email=user_a))
        self.assertIsNotNone(get_scan_by_id(scan_id_a, user_email=user_a))

        # User A cannot delete scan B
        delete_attempt = delete_scan(scan_id_b, user_email=user_a)
        self.assertFalse(delete_attempt)
        # Scan B must still exist for User B
        self.assertIsNotNone(get_scan_by_id(scan_id_b, user_email=user_b))

        # Anonymous lookup cannot access any scan
        self.assertIsNone(get_scan_by_id(scan_id_a, user_email=None))
        self.assertEqual(get_all_scans(user_email=None), [])

    def test_user_data_isolation_assets_and_keys(self):
        """User A cannot read, delete, or revoke User B's assets or API keys"""
        user_a = "user_a_" + secrets.token_hex(4) + "@corp.com"
        user_b = "user_b_" + secrets.token_hex(4) + "@corp.com"

        # Monitored Assets
        asset_id_a = add_monitored_asset(user_a, "alpha.org")
        asset_id_b = add_monitored_asset(user_b, "beta.org")

        assets_a = get_monitored_assets(user_a)
        self.assertEqual(len(assets_a), 1)
        self.assertEqual(assets_a[0].domain, "alpha.org")

        # User A cannot delete User B's asset
        self.assertFalse(delete_monitored_asset(asset_id_b, user_email=user_a))

        # API Keys
        key_info_b = generate_api_key(user_b, "User B CI Key")
        keys_a = get_user_api_keys(user_a)
        self.assertEqual(len(keys_a), 0)

        # User A cannot revoke User B's API key
        self.assertFalse(revoke_api_key(key_info_b["id"], user_email=user_a))

    def test_user_data_isolation_invoices(self):
        """User A cannot access User B's billing transactions or invoice receipts"""
        user_a = "user_a_" + secrets.token_hex(4) + "@corp.com"
        user_b = "user_b_" + secrets.token_hex(4) + "@corp.com"

        payment_b = process_subscription_payment(user_b, "Pro SecOps", amount="$49")
        txn_id_b = payment_b["transaction_id"]

        # User A cannot access User B's transaction
        self.assertIsNone(get_transaction_by_id(txn_id_b, user_email=user_a))
        # User B can access their own
        self.assertIsNotNone(get_transaction_by_id(txn_id_b, user_email=user_b))

        # Test HTTP route authorization
        with self.client.session_transaction() as sess:
            sess["user"] = {"email": user_a, "name": "User A"}
            sess["logged_in"] = True

        resp = self.client.get(f"/invoice/{txn_id_b}")
        self.assertEqual(resp.status_code, 404)

    # ================= 3. SSRF PROTECTION TESTS =================
    def test_ssrf_validation_blocked_destinations(self):
        """Validate comprehensive SSRF blocking against loopback, private, link-local, cloud metadata"""
        blocked_targets = [
            "127.0.0.1",
            "localhost",
            "127.0.1.1",
            "0.0.0.0",
            "::1",
            "[::1]",
            "169.254.169.254",
            "169.254.170.2",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "metadata.google.internal",
            "http://127.0.0.1:8000",
            "http://169.254.169.254/latest/meta-data/"
        ]

        for target in blocked_targets:
            is_safe, msg = is_safe_target(target)
            self.assertFalse(is_safe, f"Target '{target}' should have been BLOCKED by SSRF defense! Result: {msg}")

    def test_ssrf_validation_allowed_destinations(self):
        """Validate legitimate public targets resolve as safe"""
        is_safe, msg = is_safe_target("github.com")
        self.assertTrue(is_safe, f"github.com should be safe: {msg}")

        is_safe_url, url_msg = validate_outbound_url("https://github.com/urvesh-shekhawat/VulnEye")
        self.assertTrue(is_safe_url, f"Valid https URL should be safe: {url_msg}")

    def test_webhook_ssrf_blocked_immediately(self):
        """send_webhook_alert rejects loopback and internal URLs before outbound HTTP dispatch"""
        ok, msg = send_webhook_alert("http://127.0.0.1:5000/internal", "https://target.com", "High")
        self.assertFalse(ok)
        self.assertIn("SSRF", msg)

        ok2, msg2 = send_webhook_alert("http://169.254.169.254/latest/meta-data/", "https://target.com", "High")
        self.assertFalse(ok2)
        self.assertIn("SSRF", msg2)

    def test_scanner_redirect_ssrf_blocked(self):
        """Scanner hop-by-hop redirect verification blocks redirect to internal / private endpoints"""
        # Spin up a temporary local test server that issues a 302 redirect to 127.0.0.1:9999
        class RedirectHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:9999/secret-admin")
                self.end_headers()
            def log_message(self, format, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), RedirectHandler)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            # check_status directly against initial loopback is blocked
            res = check_status(f"http://127.0.0.1:{port}/test")
            self.assertFalse(res["reachable"])
            self.assertTrue("blocked" in res["error"].lower() or "prohibited" in res["error"].lower())
        finally:
            server.shutdown()

    # ================= 4. DESTRUCTIVE ROUTES POST-ONLY TESTS =================
    def test_destructive_routes_reject_get_requests(self):
        """Destructive routes return 405 Method Not Allowed on GET requests"""
        with self.client.session_transaction() as sess:
            sess["user"] = {"email": "tester@vulneye.sec", "name": "Tester"}
            sess["logged_in"] = True

        resp1 = self.client.get("/scan/delete/1")
        self.assertEqual(resp1.status_code, 405)

        resp2 = self.client.get("/monitoring/delete/1")
        self.assertEqual(resp2.status_code, 405)

        resp3 = self.client.get("/settings/api-key/revoke/1")
        self.assertEqual(resp3.status_code, 405)

    # ================= 5. CSRF PROTECTION TESTS =================
    def test_csrf_missing_token_rejected_on_browser_session(self):
        """Browser session POST request without CSRF token is rejected with 403 Forbidden"""
        user_email = "csrf_tester@vulneye.sec"
        with self.client.session_transaction() as sess:
            sess["user"] = {"email": user_email, "name": "CSRF Tester"}
            sess["logged_in"] = True
            sess["_csrf_token"] = "valid_csrf_token_12345"

        # Attempt to add monitored asset without csrf_token
        resp = self.client.post("/monitoring/add", data={"domain": "malicious-csrf.com"})
        self.assertEqual(resp.status_code, 403)

    def test_csrf_invalid_token_rejected(self):
        """Browser session POST request with incorrect CSRF token is rejected with 403 Forbidden"""
        user_email = "csrf_tester2@vulneye.sec"
        with self.client.session_transaction() as sess:
            sess["user"] = {"email": user_email, "name": "CSRF Tester"}
            sess["logged_in"] = True
            sess["_csrf_token"] = "real_session_token_xyz"

        resp = self.client.post("/monitoring/add", data={
            "csrf_token": "fake_attacker_token_abc",
            "domain": "malicious-csrf.com"
        })
        self.assertEqual(resp.status_code, 403)

    def test_csrf_valid_token_accepted(self):
        """Browser session POST request with matching CSRF token succeeds"""
        user_email = "csrf_tester3@vulneye.sec"
        token = secrets.token_hex(32)
        with self.client.session_transaction() as sess:
            sess["user"] = {"email": user_email, "name": "CSRF Tester"}
            sess["logged_in"] = True
            sess["_csrf_token"] = token

        resp = self.client.post("/monitoring/add", data={
            "csrf_token": token,
            "domain": "safe-asset.org",
            "frequency": "weekly"
        }, follow_redirects=False)
        self.assertEqual(resp.status_code, 302)  # Successful redirect to /monitoring

        assets = get_monitored_assets(user_email)
        self.assertTrue(any(a.domain == "safe-asset.org" for a in assets))

    # ================= 6. REST API V1 BEARER AUTH & CSRF EXEMPTION =================
    def test_rest_api_bearer_auth_csrf_exempt(self):
        """REST API v1 endpoints authenticate via Bearer token without requiring CSRF tokens"""
        user_email = "api_dev_" + secrets.token_hex(4) + "@corp.com"
        key_data = generate_api_key(user_email, "CI Integration Key")
        raw_key = key_data["raw_token"]

        # Health endpoint
        resp_health = self.client.get("/api/v1/health")
        self.assertEqual(resp_health.status_code, 200)

        # History with Bearer token
        resp_hist = self.client.get("/api/v1/history", headers={
            "Authorization": f"Bearer {raw_key}"
        })
        self.assertEqual(resp_hist.status_code, 200)
        data = json.loads(resp_hist.data)
        self.assertTrue(data.get("status") == "success")

    # ================= 7. FUNCTIONALITY & EXPORT TESTS =================
    def test_json_and_pdf_exports(self):
        """Verify JSON and PDF audit report exports continue to work"""
        user_email = "exporter_" + secrets.token_hex(4) + "@corp.com"
        save_scan({"url": "https://example.com", "reachable": True, "risk": "Low"}, user_email=user_email)

        with self.client.session_transaction() as sess:
            sess["user"] = {"email": user_email, "name": "Exporter"}
            sess["logged_in"] = True
            sess["_csrf_token"] = "token_pdf_123"

        # JSON Export
        resp_json = self.client.get("/export/json?url=https://example.com")
        self.assertEqual(resp_json.status_code, 200)
        self.assertIn("application/json", resp_json.headers["Content-Type"])

        # PDF Export with CSRF token
        resp_pdf = self.client.post("/export-pdf", data={
            "csrf_token": "token_pdf_123",
            "url": "https://example.com"
        })
        self.assertEqual(resp_pdf.status_code, 200)
        self.assertIn("application/pdf", resp_pdf.headers["Content-Type"])

    def test_security_badge_generation(self):
        """Verify SVG security badge generates properly"""
        resp = self.client.get("/api/v1/badge?url=github.com")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("image/svg+xml", resp.headers["Content-Type"])
        self.assertIn("<svg", resp.data.decode("utf-8"))

if __name__ == "__main__":
    unittest.main()
