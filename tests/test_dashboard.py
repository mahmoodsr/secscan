"""Dashboard HTTP contract with the engine subprocess boundary replayed."""

from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from time import monotonic, sleep
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from secscan.ui import create_app

ROOT = Path(__file__).resolve().parents[1]
HOST = "127.0.0.1:42424"
OPENING = "test-opening-token"


class DashboardTests(unittest.TestCase):
    label = "automated"

    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.app = create_app(HOST, OPENING, self.root / "data",
                              [sys.executable, str(ROOT / "tests/fixtures/dashboard_engine.py")])
        self.client = TestClient(self.app, base_url="http://" + HOST)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    def authenticate(self):
        self.assertEqual(self.client.get("/?session=" + OPENING).status_code, 200)

    def start(self, mode):
        (self.project / "scenario").write_text(mode)
        response = self.client.post("/api/runs", json={"project": str(self.project)})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["id"]

    def wait(self, predicate):
        cutoff = monotonic() + 15
        while monotonic() < cutoff:
            response = self.client.get("/api/state").json()
            if predicate(response):
                return response
            sleep(0.1)
        self.fail("Timed out waiting for the dashboard run")

    def test_session_origin_host_and_replayed_bootstrap(self):
        self.assertEqual(self.client.get("/api/state").status_code, 401)
        self.assertEqual(self.client.get("/assets/no-such-file").status_code, 401)
        self.authenticate()
        self.assertEqual(self.client.get("/api/state").status_code, 200)
        self.assertEqual(self.client.get("/api/state", headers={"Origin": "http://evil.test"}).status_code, 403)
        self.assertEqual(self.client.get("/api/state", headers={"Host": "evil.test"}).status_code, 403)
        self.client.cookies.clear()
        self.assertEqual(self.client.get("/?session=" + OPENING).status_code, 401)

    def test_events_reports_and_retention(self):
        self.authenticate()
        self.assertEqual(self.client.put("/api/settings", json={"retention": 2}).status_code, 200)
        before = self.start("findings")
        first = self.wait(lambda result: not result["current"]["active"])
        self.assertEqual(first["current"]["status"], "FAIL")
        self.assertEqual(first["current"]["events"][-1]["type"], "scan_finished")
        self.assertIn("semgrep: scanning", first["current"]["log"])
        report = self.client.get("/api/report/" + before).json()
        secret = next(item for item in report["findings"] if item["category"] == "secret")
        self.assertIn("file", secret)
        self.assertNotIn("description", secret)
        self.assertNotIn("fingerprint", secret)
        after = self.start("fixed")
        self.wait(lambda result: not result["current"]["active"])
        self.assertEqual(self.client.get("/api/report/" + after).json()["findings"], [])
        self.assertEqual(self.client.get("/api/export/" + before + "/md").status_code, 200)
        self.start("fixed")
        history = self.wait(lambda result: not result["current"]["active"])["history"]
        self.assertEqual(len(history), 2)
        self.assertEqual(self.client.get("/api/report/" + before).status_code, 404)

    @unittest.skipIf(sys.platform == "win32", "process-tree cancellation still requires Windows verification")
    def test_cancel_stops_process_tree_and_records_cancelled(self):
        self.authenticate()
        identifier = self.start("cancel")
        self.wait(lambda result: any(row["type"] == "tool_started" for row in result["current"]["events"]))
        self.assertEqual(self.client.post("/api/cancel").status_code, 200)
        result = self.wait(lambda result: not result["current"]["active"])
        self.assertEqual(result["history"][0]["status"], "CANCELLED")
        self.assertIsNone(result["history"][0]["report"])
        self.assertEqual(result["history"][0]["id"], identifier)
        sleep(6)
        self.assertFalse((self.project / "orphan").exists())
        self.assertFalse((self.project / "scan-reports" / ".active").exists())

    def test_settings_write_only_token_and_validate_allowlist(self):
        self.authenticate()
        token = "dashboard-fake-private-token"
        profile = {"sonar_url": "http://127.0.0.1:9000", "token": token}
        with patch("secscan.ui.save_token") as save:
            response = self.client.put("/api/settings", json=profile)
            self.assertEqual(response.status_code, 200)
            save.assert_called_once_with(profile["sonar_url"], token)
        response = self.client.get("/api/settings")
        self.assertNotIn(token, response.text)
        self.assertNotIn(token.encode(), (self.root / "data/dashboard.sqlite3").read_bytes())
        self.assertEqual(response.json()["thresholds"]["blocking"]["sonar"]["gate"], "ERROR")
        config = {"project": str(self.project), "exclusions": ["generated/**"], "allowlist": [{
            "tool": "trivy", "rule": "CVE-demo", "file": "*", "reason": "Demo", "approver": "Owner", "expiry": "2020-01-01"}]}
        self.assertEqual(self.client.put("/api/project", json=config).status_code, 200)
        view = self.client.get("/api/settings", params={"project": str(self.project)}).json()
        self.assertTrue(view["expiry"][0]["expired"])
        config["allowlist"][0]["reason"] = ""
        self.assertEqual(self.client.put("/api/project", json=config).status_code, 400)
        self.assertIn("Demo", (self.project / ".scan-config.yml").read_text())
