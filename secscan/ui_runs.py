"""Manage engine subprocesses and read their redacted event and report contracts."""

from collections import deque
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
from threading import RLock, Thread
from uuid import uuid4

from .config import ScanError, TOOLS
from .reports import Redactor, utc_now


def events(path):
    try:
        with path.open(encoding="utf-8") as stream:
            rows = []
            for line in stream:
                if line.endswith("\n"):
                    rows.append(json.loads(line))
            return rows
    except (OSError, ValueError):
        return []


def snapshot(root, identifier):
    base = root / "scan-reports"
    parent = base / "history"
    if base.is_symlink() or parent.is_symlink():
        raise ScanError("The report directory must be a regular directory.")
    summary = json.loads((base / "summary.json").read_text(encoding="utf-8"))
    if summary.get("scan_id") != identifier:
        raise ScanError("The engine did not produce a matching report.")
    target = parent / identifier
    target.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name in ("summary.json", "summary.html", "summary.md", "events.jsonl",
                 *(f"{tool}.{suffix}" for tool in TOOLS for suffix in ("json", "log"))):
        source = base / name
        if source.is_file() and not source.is_symlink():
            shutil.copyfile(source, target / name)
    return target, summary


class Runs:
    def __init__(self, store, command=None):
        self.store = store
        self.command = command or [sys.executable, "-m", "secscan", "scan"]
        self.lock = RLock()
        self.current = None

    def start(self, root, build, env):
        with self.lock:
            if self.current and self.current["active"]:
                raise ScanError("A scan is already running.")
            if (root / "scan-reports" / ".active").exists():
                raise ScanError("This project already has an active scan.")
            identifier = str(uuid4())
            env = {**env, "SECSCAN_RUN_ID": identifier}
            process = subprocess.Popen([*self.command, *(["--build"] if build else []), "--", str(root)],
                                       cwd=root, env=env, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       start_new_session=os.name != "nt",
                                       creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0)
            self.current = job = {
                "id": identifier, "project": str(root), "name": root.name, "started": utc_now(),
                "active": True, "status": "RUNNING", "cancelled": False, "process": process,
                "log": deque(maxlen=120), "events": [], "scan_id": identifier,
                "redactor": Redactor(extra_secrets=(env.get("SONAR_TOKEN"),)),
            }
            Thread(target=self.finish, args=(job, root), daemon=True).start()
            return self.state()

    def finish(self, job, root):
        process = job["process"]
        redactor = job["redactor"]
        with process.stdout as stream:
            for line in stream:
                with self.lock:
                    job["log"].append(redactor.text(line.decode("utf-8", "replace").rstrip())[:2000])
        process.wait()
        with self.lock:
            report_path, counts, blocking = None, {}, 0
            if job["cancelled"]:
                result = "CANCELLED"
                lockfile = root / "scan-reports" / ".active"
                try:
                    if lockfile.read_text().strip() == str(process.pid):
                        lockfile.unlink()
                except OSError:
                    pass
            else:
                try:
                    folder, report = snapshot(root, job["scan_id"])
                    report_path, counts = str(folder), report["severity_counts"]
                    blocking = len(report["blocking_findings"])
                    result = report["overall_status"]
                except (ScanError, OSError, ValueError, KeyError):
                    result = "ERROR"
                    job["log"].append("No matching scan report was available.")
            try:
                self.store.record({**job, "status": result, "counts": counts, "blocking": blocking,
                                   "report": report_path})
            finally:
                job.update(status=result, active=False, exit_code=process.returncode)

    def state(self):
        with self.lock:
            job = self.current
            if job is None:
                return None
            rows = events(Path(job["project"]) / "scan-reports" / "events.jsonl")
            job["events"] = [row for row in rows if row.get("scan_id") == job["scan_id"]]
            return {key: list(value) if key == "log" else value for key, value in job.items()
                    if key not in ("process", "cancelled", "redactor")}

    def cancel(self):
        with self.lock:
            job = self.current
            if not job or not job["active"]:
                raise ScanError("There is no active scan.")
            process = job["process"]
            if process.poll() is not None:
                raise ScanError("The scan is finishing.")
            job["cancelled"] = True
            job["status"] = "CANCELLING"
            if os.name == "nt":
                result = subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                                        capture_output=True, timeout=10)
                if result.returncode and process.poll() is None:
                    job.update(cancelled=False, status="RUNNING")
                    raise ScanError("Windows could not stop the scan process tree.")
            else:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            return self.state()
