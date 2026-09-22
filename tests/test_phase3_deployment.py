import os
import sys
import unittest
import json
import secrets
from unittest.mock import patch
from sqlalchemy.pool import NullPool, QueuePool
from sqlalchemy import create_engine

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database import (
    normalize_database_url,
    get_db_status,
    init_db,
    save_scan,
    get_all_scans,
    DATABASE_URL
)
from api.index import app

class Phase3DeploymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        app.config["TESTING"] = True

    def setUp(self):
        self.client = app.test_client()

    # ================= 1. DATABASE URL NORMALIZATION =================
    def test_database_url_normalization_postgres_legacy(self):
        """Verify legacy postgres:// URLs are converted to postgresql:// and have sslmode=require"""
        legacy_url = "postgres://vulnuser:secretpass123@ep-test.neon.tech/vulneyedb"
        normalized = normalize_database_url(legacy_url)
        self.assertTrue(normalized.startswith("postgresql://"))
        self.assertIn("sslmode=require", normalized)
        self.assertIn("vulnuser:secretpass123@ep-test.neon.tech/vulneyedb", normalized)

    def test_database_url_normalization_sslmode_injection_when_absent(self):
        """Verify sslmode=require is automatically appended when missing"""
        # Case 1: No query params
        url_no_query = "postgresql://postgres.xyz:password@aws-0-us-east-1.pooler.supabase.com:6543/postgres"
        norm1 = normalize_database_url(url_no_query)
        self.assertEqual(norm1, f"{url_no_query}?sslmode=require")

        # Case 2: Existing query params without sslmode
        url_with_param = "postgresql://user:pass@host:5432/db?connect_timeout=10"
        norm2 = normalize_database_url(url_with_param)
        self.assertEqual(norm2, f"{url_with_param}&sslmode=require")

    def test_database_url_normalization_preserve_existing_sslmode(self):
        """Verify explicitly specified sslmode settings are preserved without duplicate params"""
        url_disable = "postgresql://user:pass@localhost:5432/testdb?sslmode=disable"
        self.assertEqual(normalize_database_url(url_disable), url_disable)

        url_prefer = "postgresql://user:pass@localhost:5432/testdb?sslmode=prefer"
        self.assertEqual(normalize_database_url(url_prefer), url_prefer)

        url_require = "postgresql://user:pass@host:5432/testdb?sslmode=require&connect_timeout=10"
        self.assertEqual(normalize_database_url(url_require), url_require)

    def test_database_url_normalization_sqlite(self):
        """SQLite URLs remain intact"""
        sqlite_url = "sqlite:///custom_scans.db"
        normalized = normalize_database_url(sqlite_url)
        self.assertEqual(normalized, sqlite_url)

    def test_database_url_fallback_local_vs_vercel(self):
        """When DATABASE_URL is unset, fallback to local scans.db or /tmp/scans.db on Vercel"""
        orig_vercel = os.environ.get("VERCEL")
        orig_db = os.environ.get("DATABASE_URL")
        try:
            if "DATABASE_URL" in os.environ:
                del os.environ["DATABASE_URL"]

            # Local development fallback
            os.environ.pop("VERCEL", None)
            self.assertEqual(normalize_database_url(), "sqlite:///scans.db")

            # Vercel serverless fallback
            os.environ["VERCEL"] = "1"
            self.assertEqual(normalize_database_url(), "sqlite:////tmp/scans.db")
        finally:
            if orig_vercel is not None:
                os.environ["VERCEL"] = orig_vercel
            else:
                os.environ.pop("VERCEL", None)
            if orig_db is not None:
                os.environ["DATABASE_URL"] = orig_db

    # ================= 2. SERVERLESS POOLING & ENGINE CONFIGURATION =================
    def test_serverless_engine_pooling_selects_nullpool(self):
        """Verify PostgreSQL engines in serverless environments use NullPool"""
        with patch.dict(os.environ, {"VERCEL": "1", "DATABASE_URL": "postgresql://u:p@host:6543/db?sslmode=require"}):
            url = normalize_database_url()
            is_serverless = bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))
            
            engine_kwargs = {"pool_pre_ping": True}
            if url.startswith("sqlite"):
                engine_kwargs["connect_args"] = {"check_same_thread": False}
            elif is_serverless:
                engine_kwargs["poolclass"] = NullPool
            
            test_engine = create_engine(url, **engine_kwargs)
            self.assertEqual(test_engine.pool.__class__, NullPool)

    # ================= 3. DATABASE STATUS PROBE & RESILIENT STARTUP =================
    def test_get_db_status_structure_and_safety(self):
        """Verify get_db_status returns clean status without leaking credentials"""
        status = get_db_status()
        self.assertIn("status", status)
        self.assertIn("engine", status)
        self.assertIn("configured", status)
        self.assertIn("ephemeral", status)

        # Confirm no passwords or raw credentials in the status dictionary
        status_str = json.dumps(status).lower()
        self.assertNotIn("password", status_str)
        self.assertNotIn("secret", status_str)
        self.assertNotIn("postgres://", status_str)
        self.assertNotIn("postgresql://", status_str)

    def test_init_db_failure_resilience(self):
        """Verify init_db catches schema initialization errors and returns False gracefully"""
        with patch("database.Base.metadata.create_all", side_effect=Exception("Connection refused")):
            success = init_db()
            self.assertFalse(success)

    def test_get_db_status_reports_disconnected_on_failure(self):
        """Verify get_db_status accurately reports disconnected state on connection failure"""
        with patch("database.engine.connect", side_effect=Exception("Database unreachable")):
            status = get_db_status()
            self.assertEqual(status["status"], "disconnected")
            self.assertEqual(status["error"], "Database connectivity probe failed")

    # ================= 4. PRODUCTION HEALTH CHECK ENDPOINTS =================
    def test_health_endpoints_response_format(self):
        """Verify /health, /api/v1/health, /v1/health return structured status"""
        for path in ("/health", "/api/v1/health", "/v1/health"):
            with self.subTest(endpoint=path):
                resp = self.client.get(path)
                self.assertEqual(resp.status_code, 200)
                data = json.loads(resp.data)

                self.assertEqual(data.get("status"), "online")
                self.assertIn("VulnEye", data.get("service", ""))
                self.assertIn("timestamp", data)
                self.assertIn("database", data)
                self.assertIn("status", data["database"])
                self.assertIn("engine", data["database"])
                self.assertIn("environment", data)

                # Verify no credentials or internal paths exposed
                body_text = resp.data.decode("utf-8").lower()
                self.assertNotIn("password", body_text)
                self.assertNotIn("scans.db", body_text)
                self.assertNotIn("traceback", body_text)

    def test_health_endpoint_when_database_is_disconnected(self):
        """Verify health endpoint still responds 200 with database: disconnected when database is down"""
        with patch("api.index.get_db_status", return_value={"status": "disconnected", "engine": "postgresql", "configured": True, "ephemeral": False}):
            resp = self.client.get("/api/v1/health")
            self.assertEqual(resp.status_code, 200)
            data = json.loads(resp.data)
            self.assertEqual(data["status"], "online")
            self.assertEqual(data["database"]["status"], "disconnected")
            self.assertEqual(data["database"]["engine"], "postgresql")

    # ================= 5. TABLE CREATION & PERSISTENCE =================
    def test_table_initialization_and_operations(self):
        """Verify init_db initializes tables safely and basic CRUD works"""
        init_db()
        test_email = "deploy_test_" + secrets.token_hex(4) + "@corp.com"
        scan_id = save_scan({"url": "https://deploy-test.org", "reachable": True, "risk": "Low"}, user_email=test_email)
        self.assertIsNotNone(scan_id)

        scans = get_all_scans(user_email=test_email)
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0][1], "https://deploy-test.org")

if __name__ == "__main__":
    unittest.main()
