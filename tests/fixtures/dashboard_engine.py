"""Replay the engine's subprocess, progress, and report contract."""

import json
import os
from pathlib import Path
import subprocess
import sys
from time import sleep

from secscan.reports import Reports, utc_now

ROOT = Path(__file__).resolve().parents[2]
project = Path(sys.argv[-1])
identifier = os.environ["SECSCAN_RUN_ID"]
mode = (project / "scenario").read_text().strip() if (project / "scenario").exists() else "findings"
reports = Reports(project / "scan-reports", identifier)

with reports.session():
    reports.event("scan_started", project_name=project.name)
    if mode == "cancel":
        with subprocess.Popen([sys.executable, "-c",
                               "import time; from pathlib import Path; time.sleep(6); Path('orphan').touch()"],
                              cwd=project) as process:
            reports.event("tool_started", tool="semgrep")
            process.wait()
        sys.exit(0)
    summary = json.loads((ROOT / "docs/samples" / mode / "summary.json").read_bytes())
    summary.update(scan_id=identifier, project_name=project.name, started_at=utc_now(), ended_at=utc_now())
    for tool, result in summary["tools"].items():
        reports.event("tool_started", tool=tool)
        sleep(0.16)
        reports.event("tool_finished", tool=tool, status=result["status"], counts=result["counts"])
    reports.summaries(summary)
    reports.event("report_written", files=["summary.json", "summary.md", "summary.html"])
    reports.event("scan_finished", status=summary["overall_status"], exit_code=summary["exit_code"])
sys.exit(summary["exit_code"])
