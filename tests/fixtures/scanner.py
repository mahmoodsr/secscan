#!/usr/bin/env python3
"""Replay the scanner process contract for deterministic engine tests."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time

tool = Path(sys.argv[0]).stem
args = sys.argv[1:]
versions = {"semgrep": "1.146.0", "gitleaks": "8.24.2", "trivy": "0.76.1",
            "sonar-scanner": "7.2.0.5079"}
if args in (["version"], ["--version"]):
    print(("SonarScanner CLI " if tool == "sonar-scanner" else "") + versions[tool])
    sys.exit(0)

mode = os.environ.get("REPLAY_" + tool.replace("-", "_").upper(), "")
if mode == "timeout":
    time.sleep(10)
if mode == "crash":
    sys.exit(6)
if mode == "invalid":
    print("this is not JSON")
    sys.exit(0)

scenario = os.environ.get("REPLAY_SCENARIO", "findings")
finding_state = scenario == "findings"
if scenario == "severity":
    if tool == "semgrep":
        print(json.dumps({"results": [
            {"check_id": "semgrep-" + severity, "path": "app.py", "start": {"line": 1},
             "extra": {"severity": severity}} for severity in ("ERROR", "WARNING", "INFO")
        ], "errors": []}))
        sys.exit(0)
    if tool == "trivy" and "--download-db-only" not in args:
        print(json.dumps({"SchemaVersion": 2, "Results": [{"Target": "requirements.txt",
            "Vulnerabilities": [{"VulnerabilityID": "trivy-" + severity, "Severity": severity}
                for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")]}]}))
        sys.exit(0)
if tool == "semgrep":
    assert "--metrics=off" in args and "auto" not in args
    assert (Path.cwd() / "secscan-rules.yml").is_file()
    assert "secret-fixture" not in (Path.cwd() / "secscan-rules.yml").read_text()
    assert not (Path.cwd() / "node_modules").exists()
    rows = []
    if finding_state:
        rows = [{"check_id": "demo-python-eval", "path": "app.py", "start": {"line": 2},
                 "extra": {"severity": "ERROR", "message": "Dynamic evaluation",
                           "metadata": {"title": "Dynamic evaluation"}, "lines": "do not serialize source"}}]
    print(json.dumps({"results": rows, "errors": []}))
    sys.exit(bool(rows))
if tool == "gitleaks":
    assert "--redact=100" in args and "--report-path" in args
    if finding_state:
        print(json.dumps([{"RuleID": "github-pat", "File": "app.js", "Description": "GitHub PAT",
                           "StartLine": 1, "Match": "plain-text-secret-value",
                           "Secret": "plain-text-secret-value", "Fingerprint": "stored-as-hash"}]))
        print("Sensitive ghp_SecscanFakeDemoTokenForTestsOnly00001; password=secret1234", file=sys.stderr)
        sys.exit(17)
    print("[]")
if tool == "trivy":
    assert args[args.index("--scanners") + 1] == "vuln,misconfig"
    target = Path(args[-1])
    if os.environ.get("REPLAY_EXPECT_TRIVY_MANIFEST"):
        assert (target / "node_modules" / "package-lock.json").is_file()
        assert not (target / "node_modules" / "dist.js").exists()
    if "--download-db-only" in args:
        if mode == "db-failed":
            sys.exit(2)
        cache = Path(args[args.index("--cache-dir") + 1]) / "db"
        cache.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc).isoformat()
        (cache / "metadata.json").write_text(json.dumps({"UpdatedAt": now, "DownloadedAt": now}))
    else:
        assert "--skip-db-update" in args
        rows = []
        if finding_state:
            rows = [
                {"Target": "requirements.txt", "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2023-43804", "PkgName": "urllib3", "Severity": "HIGH",
                     "InstalledVersion": "1.26.4", "FixedVersion": "1.26.17"},
                    {"VulnerabilityID": "CVE-DEMO-UNFIXED", "PkgName": "urllib3", "Severity": "HIGH"}]},
                {"Target": "Dockerfile", "Misconfigurations": [
                    {"ID": "DS-0002", "Severity": "HIGH", "Status": "FAIL",
                     "Title": "Avoid running as root", "CauseMetadata": {"StartLine": 3}}]},
            ]
        print(json.dumps({"SchemaVersion": 2, "Results": rows}))
if tool == "sonar-scanner":
    assert os.environ["SONAR_TOKEN"] == "replay-sonar-token-do-not-write"
    assert not any(os.environ["SONAR_TOKEN"] in arg for arg in args)
    key = next(arg.split("=", 1)[1] for arg in args if arg.startswith("-Dsonar.projectKey="))
    path = next(arg.split("=", 1)[1] for arg in args if arg.startswith("-Dsonar.scanner.metadataFilePath="))
    Path(path).write_text(f"ceTaskId={key}\n")
    print("Sonar scanner submitted; SONAR_TOKEN=" + os.environ["SONAR_TOKEN"])
