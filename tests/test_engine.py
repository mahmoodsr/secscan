"""Deterministic behavior tests at the engine boundary."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
import unittest
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
SONAR = json.loads((FIXTURES / "sonar.json").read_text())
SCHEMA = ROOT / "secscan" / "data" / "summary.schema.json"
TOKEN = "replay-sonar-token-do-not-write"
TOOLS = ("semgrep", "gitleaks", "trivy", "sonar-scanner")


class ReplayHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        request = urlsplit(self.path)
        endpoint = request.path.removeprefix("/api/")
        query = parse_qs(request.query)
        code = 200
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            code = 401
            response = {"valid": False}
        elif self.server.forbidden:
            code = 403
            response = {}
        elif endpoint == "ce/task":
            response = SONAR["task_success"]
        elif endpoint == "qualitygates/project_status":
            code = 404 if self.server.missing_gate else 200
            response = SONAR["gate_error" if self.server.failed_gate else "gate_ok"]
        elif endpoint == "issues/search":
            if self.server.scenario == "severity":
                response = {"paging": {"total": 5}, "issues": [
                    {"key": value, "rule": "sonar-" + value, "severity": value, "type": "BUG"}
                    for value in ("BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO")
                ]}
            else:
                response = SONAR["issues_" + self.server.scenario]
            if response["issues"]:
                key = query["componentKeys"][0]
                response = {**response, "issues": [{**row, "component": key + ":app.js"}
                                                  for row in response["issues"]]}
        elif endpoint == "hotspots/search" and "project" not in query:
            code = 400
            response = {"errors": [{"msg": "'project' is required"}]}
        else:
            response = SONAR[endpoint]
        result = json.dumps(response).encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(result)))
        self.end_headers()
        self.wfile.write(result)


@unittest.skipIf(os.name == "nt", "replay executables use POSIX shebangs; use the Windows self-test")
class EngineTests(unittest.TestCase):
    label = "automated"

    def setUp(self):
        temporary = TemporaryDirectory(prefix="secscan-tests-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.project = self.directory / "example"
        shutil.copytree(ROOT / "secscan" / "demo" / "findings", self.project,
                        ignore=shutil.ignore_patterns("scan-reports", "__pycache__"))
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        for tool in TOOLS:
            path = self.bin / tool
            body = (FIXTURES / "scanner.py").read_text()
            path.write_text(f"#!{sys.executable}\n" + body.partition("\n")[2])
            path.chmod(0o700)
        bundled = self.directory / "jre" / "bin"
        bundled.mkdir(parents=True)
        (bundled / "java").touch()
        server = ThreadingHTTPServer(("127.0.0.1", 0), ReplayHandler)
        server.failed_gate = server.missing_gate = server.forbidden = False
        server.scenario = "findings"
        self.server = server
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.env = os.environ.copy()
        self.env.update(PYTHONPATH=str(ROOT), PATH=str(self.bin), SONAR_TOKEN=TOKEN,
                        SONAR_HOST_URL=f"http://127.0.0.1:{server.server_port}",
                        XDG_CACHE_HOME=str(self.directory / "cache"), NO_PROXY="127.0.0.1,localhost",
                        https_proxy="http://127.0.0.1:1", HTTP_PROXY="http://127.0.0.1:1")
        self.report = self.project / "scan-reports"

    def run_scan(self, *options, positional=True, expected=None):
        command = [sys.executable, "-m", "secscan", "scan", "--config", str(self.project / "scan.yml"), *options]
        if positional:
            command.append(str(self.project))
        result = subprocess.run(command, cwd=self.directory if positional else self.project,
                                env=self.env, text=True, capture_output=True, timeout=20)
        if expected is not None:
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        report = self.report / "summary.json"
        return result, json.loads(report.read_bytes()) if report.exists() else None

    def test_report_contract_and_entry_points(self):
        result, first = self.run_scan(expected=1)
        _, second = self.run_scan(positional=False, expected=1)
        for key in ("findings", "severity_counts", "project_name", "quality_gate", "overall_status"):
            self.assertEqual(first[key], second[key])
        for tool, row in first["tools"].items():
            for key in ("status", "reason", "counts"):
                self.assertEqual(row[key], second["tools"][tool][key])
        import jsonschema
        jsonschema.validate(second, json.loads(SCHEMA.read_bytes()))
        self.assertIn("dashboard?id=example", second["sonar_dashboard_url"])
        self.assertIn("Issues requiring fixes", (self.report / "summary.html").read_text())
        self.assertIn("Issues requiring fixes", (self.report / "summary.md").read_text())
        events = [json.loads(line) for line in (self.report / "events.jsonl").read_text().splitlines()]
        self.assertEqual(events[0]["type"], "scan_started")
        self.assertEqual(events[-1]["exit_code"], 1)
        self.assertTrue(all(event["scan_id"] == second["scan_id"] for event in events))
        for tool in ("semgrep", "gitleaks", "trivy", "sonar"):
            self.assertTrue((self.report / (tool + ".log")).is_file())
            self.assertTrue((self.report / (tool + ".json")).is_file())
        combined = "".join(path.read_text() for path in self.report.iterdir()) + result.stdout + result.stderr
        for secret in (TOKEN, "plain-text-secret-value", "SecscanFakeDemoTokenForTestsOnly00001", "secret1234",
                       "do not serialize source"):
            self.assertNotIn(secret, combined)
        self.assertIn("--metrics=off", (self.report / "semgrep.log").read_text())
        self.assertEqual(first["tools"]["semgrep"]["status"], "FAIL")  # findings with nonzero exit
        unfixed = next(item for item in first["findings"] if item["rule"] == "CVE-DEMO-UNFIXED")
        self.assertFalse(unfixed["blocking"])

    def test_missing_crashing_malformed_and_timing_out_tools_do_not_stop_scan(self):
        for name in TOOLS[:-1]:
            with self.subTest(tool=name):
                tool = self.bin / name
                hidden = tool.with_suffix(".hidden")
                tool.rename(hidden)
                try:
                    _, report = self.run_scan(expected=1)
                    self.assertIn("not installed", report["tools"][name]["reason"])
                    self.assertEqual(report["tools"]["sonar"]["status"], "PASS")
                    self.assertEqual([key for key, result in report["tools"].items() if result["status"] == "ERROR"],
                                     [name], report["tools"])
                finally:
                    hidden.rename(tool)
        for state, reason in (("timeout", "timeout"), ("crash", "crashed"), ("invalid", "unreadable")):
            self.env["REPLAY_SEMGREP"] = state
            _, report = self.run_scan("--timeout", "0.02", expected=1)
            self.assertEqual(report["tools"]["semgrep"]["status"], "ERROR")
            self.assertIn(reason, report["tools"]["semgrep"]["reason"])
            self.assertEqual(report["tools"]["gitleaks"]["status"], "FAIL")

    def test_sonar_gate_connection_and_authentication(self):
        self.env["REPLAY_SCENARIO"] = self.server.scenario = "fixed"
        self.server.failed_gate = True
        _, report = self.run_scan(expected=1)
        self.assertEqual(report["quality_gate"]["status"], "ERROR")
        self.assertEqual(report["tools"]["sonar"]["status"], "FAIL")
        self.server.missing_gate = True
        _, report = self.run_scan(expected=2)
        self.assertEqual(report["quality_gate"]["status"], "UNAVAILABLE")
        self.assertIn("404", report["tools"]["sonar"]["reason"])
        self.server.forbidden = True
        _, report = self.run_scan(expected=2)
        self.assertIn("403", report["tools"]["sonar"]["reason"])
        self.env["SONAR_TOKEN"] = "bad-replay-token"
        _, report = self.run_scan(expected=2)
        self.assertIn("401", report["tools"]["sonar"]["reason"])
        self.env["SONAR_HOST_URL"] = "http://127.0.0.1:1"
        _, report = self.run_scan(expected=2)
        self.assertIn("unreachable", report["tools"]["sonar"]["reason"])
        self.assertEqual(report["tools"]["semgrep"]["status"], "PASS")

    def test_exit_codes_and_fixed_rescan(self):
        self.run_scan(expected=1)
        _, informational = self.run_scan("--no-fail", expected=0)
        self.assertEqual(informational["overall_status"], "FAIL")
        self.assertEqual(informational["policy_exit_code"], 1)
        self.env["REPLAY_SCENARIO"] = self.server.scenario = "fixed"
        _, fixed = self.run_scan(expected=0)
        self.assertEqual(fixed["overall_status"], "PASS")
        self.assertEqual(fixed["findings"], [])
        self.run_scan("--skip", "trivy", expected=2)
        self.run_scan("--skip", "semgrep,gitleaks,trivy,sonar", expected=3)

    def test_all_source_severity_values(self):
        self.env["REPLAY_SCENARIO"] = self.server.scenario = "severity"
        _, report = self.run_scan(expected=1)
        actual = {row["rule"]: row["severity"] for row in report["findings"]}
        self.assertEqual(actual, {
            "semgrep-ERROR": "High", "semgrep-WARNING": "Medium", "semgrep-INFO": "Low",
            "trivy-CRITICAL": "Critical", "trivy-HIGH": "High", "trivy-MEDIUM": "Medium",
            "trivy-LOW": "Low", "trivy-UNKNOWN": "Info",
            "sonar-BLOCKER": "Critical", "sonar-CRITICAL": "High", "sonar-MAJOR": "Medium",
            "sonar-MINOR": "Low", "sonar-INFO": "Info",
        })

    def test_installed_threshold_policy_changes_verdict(self):
        isolated = self.directory / "isolated-package"
        shutil.copytree(ROOT / "secscan", isolated / "secscan",
                        ignore=shutil.ignore_patterns("scan-reports", "__pycache__"))
        policy = isolated / "secscan" / "data" / "THRESHOLDS.yml"
        self.run_scan("--only", "semgrep", expected=1)
        policy.write_text(policy.read_text().replace("'code issue': [High]", "'code issue': []"))
        self.env["PYTHONPATH"] = str(isolated)
        _, report = self.run_scan("--only", "semgrep", expected=2)
        self.assertEqual(report["tools"]["semgrep"]["status"], "PASS")

    def test_trivy_cache_and_manifest_override(self):
        deps = self.project / "node_modules"
        deps.mkdir()
        (deps / "package-lock.json").write_text("{}")
        (deps / "dist.js").write_text("x")
        self.env["REPLAY_EXPECT_TRIVY_MANIFEST"] = "1"
        self.run_scan(expected=1)
        self.env["REPLAY_TRIVY"] = "db-failed"
        _, cached = self.run_scan(expected=1)
        self.assertEqual(cached["tools"]["trivy"]["database_status"], "WARN")
        metadata = self.directory / "cache" / "secscan" / "trivy" / "db" / "metadata.json"
        metadata.write_text('{"UpdatedAt":"2000-01-01T00:00:00Z","DownloadedAt":"2000-01-01T00:00:00Z"}')
        _, stale = self.run_scan(expected=1)
        self.assertEqual(stale["tools"]["trivy"]["status"], "ERROR")

    def test_allowlist_validation_and_expiration(self):
        path = self.project / "scan.yml"
        with path.open("a") as stream:
            stream.write("""allowlist:
  - {tool: semgrep, rule: demo-python-eval, file: app.py, reason: Temporary approval, approver: Lead, expiry: '2099-01-01'}
  - {tool: trivy, rule: DS-0002, file: Dockerfile, reason: Temporary approval, approver: Lead, expiry: '2000-01-01'}
""")
        _, report = self.run_scan(expected=1)
        self.assertEqual(len(report["allowlist_used"]), 1)
        self.assertEqual(len(report["allowlist_expired"]), 1)
        self.assertEqual(report["tools"]["semgrep"]["status"], "PASS")
        self.assertIn("exclusions", report["configuration_changes"])
        path.write_text("allowlist: [{tool: semgrep, rule: demo-python-eval, file: app.py}]")
        result, _ = self.run_scan(expected=3)
        self.assertIn("invalid allowlist", result.stderr)

    def test_generic_and_reduced_coverage(self):
        (self.project / "dummy.csproj").touch()
        _, known = self.run_scan(expected=1)
        self.assertTrue(any("Reduced Java" in item for item in known["coverage_notes"]))
        self.assertTrue(any("Reduced .NET" in item for item in known["coverage_notes"]))
        for path in self.project.iterdir():
            if path.name not in ("rules", "scan.yml", "scan-reports"):
                shutil.rmtree(path) if path.is_dir() else path.unlink()
        self.env["REPLAY_SCENARIO"] = self.server.scenario = "fixed"
        _, generic = self.run_scan(expected=0)
        self.assertFalse(generic["languages"])
        self.assertTrue(any("Generic mode" in item for item in generic["coverage_notes"]))

    def test_git_history_and_gitignore(self):
        git = shutil.which("git")
        if not git or subprocess.run([git, "--version"], capture_output=True).returncode:
            self.skipTest("Git is unavailable")
        (self.bin / "git").symlink_to(git)
        subprocess.run([git, "init", "--quiet", str(self.project)], check=True)
        subprocess.run([git, "-C", str(self.project), "add", "."], check=True)
        subprocess.run([git, "-C", str(self.project), "-c", "user.email=demo@example.org", "-c",
                        "user.name=Demo", "commit", "-qm", "Demo fixture"], check=True)
        _, report = self.run_scan(expected=1)
        self.assertEqual(report["tools"]["gitleaks"]["mode"], "history")
        self.assertEqual((self.project / ".gitignore").read_text(), "scan-reports/\n")
        self.run_scan(expected=1)
        self.assertEqual((self.project / ".gitignore").read_text(), "scan-reports/\n")


if __name__ == "__main__":
    unittest.main()
