import os
import sys
import unittest
import json
import secrets
from unittest.mock import patch, MagicMock

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database import (
    init_db,
    save_webhook_config,
    get_webhook_config,
    dispatch_scan_alerts,
    send_webhook_alert,
    generate_api_key,
    save_scan
)
from api.index import app

class Phase4WebhookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        app.config["TESTING"] = True

    def setUp(self):
        self.client = app.test_client()
        self.user_a = f"analyst_{secrets.token_hex(4)}@testcorp.com"
        self.user_b = f"victim_{secrets.token_hex(4)}@testcorp.com"
        self.valid_webhook_url = "https://discord.com/api/webhooks/123456789/mocktoken"

    # ================= 1. ALERT LEVEL FILTERING =================
    @patch("database.send_webhook_alert")
    def test_high_risk_scan_triggers_webhook_under_high_and_critical(self, mock_send):
        """High-risk scan triggers webhook alert under 'High & Critical' setting"""
        mock_send.return_value = (True, "Alert delivered successfully")
        save_webhook_config(self.user_a, self.valid_webhook_url, channel_type="discord", alert_level="High & Critical", is_enabled=True)

        scan_results = {
            "url": "https://vulnerable-target.com",
            "risk": "High",
            "sensitive_files": [{"file": ".env", "severity": "High"}],
            "open_ports": [{"port": 5432, "service": "PostgreSQL"}],
            "missing_headers": ["Content-Security-Policy"]
        }

        res = dispatch_scan_alerts(scan_results, self.user_a)
        self.assertTrue(res["sent"])
        self.assertEqual(res["status"], "sent")
        mock_send.assert_called_once()
        self.assertEqual(mock_send.call_args[1]["risk_level"], "High")

    @patch("database.send_webhook_alert")
    def test_high_risk_scan_triggers_webhook_under_all(self, mock_send):
        """High-risk scan triggers webhook alert under 'All' setting"""
        mock_send.return_value = (True, "Alert delivered successfully")
        save_webhook_config(self.user_a, self.valid_webhook_url, channel_type="discord", alert_level="All", is_enabled=True)

        scan_results = {
            "url": "https://vulnerable-target.com",
            "risk": "High",
            "sensitive_files": [],
            "open_ports": [],
            "missing_headers": []
        }

        res = dispatch_scan_alerts(scan_results, self.user_a)
        self.assertTrue(res["sent"])
        self.assertEqual(res["status"], "sent")
        mock_send.assert_called_once()

    @patch("database.send_webhook_alert")
    def test_low_risk_scan_does_not_trigger_under_high_and_critical(self, mock_send):
        """Low-risk scan with no critical exposures skips webhook under 'High & Critical'"""
        save_webhook_config(self.user_a, self.valid_webhook_url, channel_type="discord", alert_level="High & Critical", is_enabled=True)

        scan_results = {
            "url": "https://secure-target.com",
            "risk": "Low",
            "sensitive_files": [],
            "open_ports": [],
            "missing_headers": ["X-Content-Type-Options"]
        }

        res = dispatch_scan_alerts(scan_results, self.user_a)
        self.assertFalse(res["sent"])
        self.assertEqual(res["status"], "skipped")
        self.assertIn("does not meet threshold", res["reason"])
        mock_send.assert_not_called()

    @patch("database.send_webhook_alert")
    def test_low_risk_scan_triggers_webhook_under_all(self, mock_send):
        """Low-risk scan DOES trigger webhook under 'All' setting"""
        mock_send.return_value = (True, "Alert delivered successfully")
        save_webhook_config(self.user_a, self.valid_webhook_url, channel_type="discord", alert_level="All", is_enabled=True)

        scan_results = {
            "url": "https://secure-target.com",
            "risk": "Low",
            "sensitive_files": [],
            "open_ports": [],
            "missing_headers": []
        }

        res = dispatch_scan_alerts(scan_results, self.user_a)
        self.assertTrue(res["sent"])
        self.assertEqual(res["status"], "sent")
        mock_send.assert_called_once()

    @patch("database.send_webhook_alert")
    def test_critical_only_filtering_triggers_on_critical_exposure(self, mock_send):
        """Critical Only setting triggers when critical exposure (.env or open DB port) exists"""
        mock_send.return_value = (True, "Alert delivered successfully")
        save_webhook_config(self.user_a, self.valid_webhook_url, channel_type="discord", alert_level="Critical Only", is_enabled=True)

        # Case A: Critical exposure present -> triggers
        scan_critical = {
            "url": "https://target-with-leak.com",
            "risk": "Medium",
            "sensitive_files": [{"file": ".env", "severity": "High"}],
            "open_ports": [],
            "missing_headers": []
        }
        res_a = dispatch_scan_alerts(scan_critical, self.user_a)
        self.assertTrue(res_a["sent"])
        self.assertEqual(res_a["status"], "sent")

        # Case B: No critical exposure -> skipped
        mock_send.reset_mock()
        scan_non_critical = {
            "url": "https://target-missing-csp.com",
            "risk": "Medium",
            "sensitive_files": [],
            "open_ports": [],
            "missing_headers": ["Content-Security-Policy"]
        }
        res_b = dispatch_scan_alerts(scan_non_critical, self.user_a)
        self.assertFalse(res_b["sent"])
        self.assertEqual(res_b["status"], "skipped")
        mock_send.assert_not_called()

    # ================= 2. CONFIGURATION & ENABLED STATE =================
    @patch("database.send_webhook_alert")
    def test_disabled_webhook_does_not_send(self, mock_send):
        """Disabled webhook (is_enabled=False) does not send alerts"""
        save_webhook_config(self.user_a, self.valid_webhook_url, channel_type="discord", alert_level="All", is_enabled=False)

        scan_results = {"url": "https://target.com", "risk": "High", "sensitive_files": [], "open_ports": []}
        res = dispatch_scan_alerts(scan_results, self.user_a)

        self.assertFalse(res["sent"])
        self.assertEqual(res["status"], "skipped")
        mock_send.assert_not_called()

    @patch("database.send_webhook_alert")
    def test_missing_webhook_config_safely_no_ops(self, mock_send):
        """User without configured webhook safely no-ops"""
        unconfigured_user = f"unconfigured_{secrets.token_hex(4)}@testcorp.com"
        scan_results = {"url": "https://target.com", "risk": "High", "sensitive_files": [], "open_ports": []}

        res = dispatch_scan_alerts(scan_results, unconfigured_user)
        self.assertFalse(res["sent"])
        self.assertEqual(res["status"], "skipped")
        mock_send.assert_not_called()

    # ================= 3. RELIABILITY & TIMEOUT SAFETY =================
    @patch("requests.post", side_effect=Exception("Connection timed out after 3000ms"))
    def test_webhook_delivery_timeout_does_not_raise_into_caller(self, mock_post):
        """Network timeout or connection drop in webhook delivery is caught safely without raising exception"""
        save_webhook_config(self.user_a, self.valid_webhook_url, channel_type="discord", alert_level="All", is_enabled=True)

        scan_results = {"url": "https://target.com", "risk": "High", "sensitive_files": [], "open_ports": []}
        res = dispatch_scan_alerts(scan_results, self.user_a)

        self.assertFalse(res["sent"])
        self.assertEqual(res["status"], "failed")
        self.assertIn("error", res["reason"].lower())

    # ================= 4. SECURITY & SSRF PROTECTION =================
    def test_private_and_loopback_webhook_url_blocked_by_ssrf(self):
        """Internal, private, and cloud metadata webhook destinations are rejected immediately"""
        blocked_urls = [
            "http://127.0.0.1:8080/webhook",
            "http://localhost:5000/webhook",
            "http://169.254.169.254/latest/meta-data",
            "http://10.0.0.1/notify",
            "http://192.168.1.1/hook"
        ]
        for url in blocked_urls:
            with self.subTest(url=url):
                save_webhook_config(self.user_a, url, channel_type="custom", alert_level="All", is_enabled=True)
                scan_results = {"url": "https://target.com", "risk": "High"}
                res = dispatch_scan_alerts(scan_results, self.user_a)
                self.assertFalse(res["sent"])
                self.assertEqual(res["status"], "failed")
                self.assertIn("SSRF Security Violation", res["reason"])

    # ================= 5. MULTI-TENANT ISOLATION =================
    @patch("database.send_webhook_alert")
    def test_user_tenant_isolation_webhook_dispatch(self, mock_send):
        """User A cannot trigger alerts to User B's configured webhook"""
        mock_send.return_value = (True, "Alert delivered successfully")
        user_b_webhook = "https://discord.com/api/webhooks/999999/victimhook"
        save_webhook_config(self.user_b, user_b_webhook, channel_type="discord", alert_level="All", is_enabled=True)

        # User A has no webhook configured
        scan_results = {"url": "https://target.com", "risk": "High"}
        res_a = dispatch_scan_alerts(scan_results, self.user_a)
        self.assertFalse(res_a["sent"])
        self.assertEqual(res_a["status"], "skipped")
        mock_send.assert_not_called()

    # ================= 6. PAYLOAD HYGIENE & SECRET PROTECTION =================
    @patch("requests.post")
    def test_payload_contains_no_raw_secrets_or_response_bodies(self, mock_post):
        """Dispatched payload contains safe descriptive summary and never dumps raw secrets or passwords"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        save_webhook_config(self.user_a, self.valid_webhook_url, channel_type="discord", alert_level="High & Critical", is_enabled=True)

        scan_results = {
            "url": "https://target-with-secrets.com",
            "risk": "High",
            "sensitive_files": [
                {
                    "file": ".env",
                    "severity": "High",
                    "raw_leak_data": "DATABASE_URL=postgres://root:supersecret123@db:5432/prod"
                }
            ],
            "open_ports": [{"port": 5432, "service": "PostgreSQL"}],
            "cookies": [{"name": "session_id", "value": "secret_session_token_xyz"}]
        }

        res = dispatch_scan_alerts(scan_results, self.user_a)
        self.assertTrue(res["sent"])
        mock_post.assert_called_once()

        # Inspect post payload
        called_json = mock_post.call_args[1]["json"]
        payload_str = json.dumps(called_json).lower()

        # Confirm no leaked raw credentials in the payload
        self.assertNotIn("supersecret123", payload_str)
        self.assertNotIn("secret_session_token_xyz", payload_str)
        self.assertIn("exposed .env configuration/source file", payload_str)
        self.assertIn("postgresql database (port 5432)", payload_str)

    # ================= 7. SCAN FLOW INTEGRATION TESTS (STEP 3) =================
    @patch("api.index.dispatch_scan_alerts")
    def test_sse_scan_flow_invokes_dispatch_and_completes_safely(self, mock_dispatch):
        """SSE scan stream invokes dispatch_scan_alerts and continues to 'done' even if webhook fails"""
        mock_dispatch.side_effect = Exception("Webhook service unavailable")

        with self.client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["user"] = {"email": self.user_a, "name": "Analyst A"}

        resp = self.client.get("/scan/stream?url=https://example.com")
        self.assertEqual(resp.status_code, 200)
        content = resp.data.decode("utf-8")

        # Verify stream completed with done event
        self.assertIn('"status": "done"', content)
        # Verify dispatch_scan_alerts was called once with user_a
        mock_dispatch.assert_called_once()
        self.assertEqual(mock_dispatch.call_args[1]["user_email"], self.user_a)

    @patch("api.index.dispatch_scan_alerts")
    def test_rest_scan_flow_invokes_dispatch_and_avoids_500_on_failure(self, mock_dispatch):
        """REST API /api/v1/scan invokes dispatch_scan_alerts and succeeds 200 even if webhook fails"""
        mock_dispatch.side_effect = Exception("Webhook connection drop")

        key_info = generate_api_key(self.user_a, name="Test CI Key")
        raw_token = key_info["raw_token"]

        resp = self.client.post(
            "/api/v1/scan",
            json={"url": "https://api-target.com"},
            headers={"Authorization": f"Bearer {raw_token}"}
        )

        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data.get("status"), "success")
        self.assertEqual(data.get("target"), "https://api-target.com")

        mock_dispatch.assert_called_once()
        self.assertEqual(mock_dispatch.call_args[1]["user_email"], self.user_a)

    @patch("api.index.dispatch_scan_alerts")
    def test_result_fallback_cache_miss_vs_cache_hit(self, mock_dispatch):
        """Result endpoint dispatches alert on new scan (cache miss), but avoids duplicates on cache hit"""
        with self.client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["user"] = {"email": self.user_a, "name": "Analyst A"}

        target_url = f"https://target-{secrets.token_hex(4)}.com"

        # 1. First request -> Cache miss (performs new scan and dispatches once)
        resp1 = self.client.get(f"/result?url={target_url}")
        self.assertEqual(resp1.status_code, 200)
        self.assertEqual(mock_dispatch.call_count, 1)

        # 2. Second request (page refresh) -> Cache hit (reads existing result, does NOT dispatch duplicate)
        resp2 = self.client.get(f"/result?url={target_url}")
        self.assertEqual(resp2.status_code, 200)
        self.assertEqual(mock_dispatch.call_count, 1)  # Count remains 1, no second call

    @patch("api.index.dispatch_scan_alerts")
    def test_tenant_identity_passed_correctly_to_dispatch(self, mock_dispatch):
        """Ensure dispatch_scan_alerts always receives the exact user_email of the active session"""
        with self.client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["user"] = {"email": self.user_b, "name": "User B"}

        self.client.get(f"/result?url=https://unique-target-{secrets.token_hex(4)}.com")
        mock_dispatch.assert_called_once()
        self.assertEqual(mock_dispatch.call_args[1]["user_email"], self.user_b)
        self.assertNotEqual(mock_dispatch.call_args[1]["user_email"], self.user_a)

if __name__ == "__main__":
    unittest.main()
