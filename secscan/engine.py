"""Run a scan and write its public report and event contracts."""

from datetime import datetime, timezone
from getpass import getuser
from hashlib import sha256
import os
from pathlib import Path
import platform
import time
from uuid import UUID, uuid4

from . import __version__, findings
from .config import TOOLS, ScanError, settings
from .process import Run, executable, version_tuple
from .project import Project, git_ignore_reports, git_info
from .reports import Reports, utc_now
from .sonar import run_sonar, server_for
from .tools import prerequisite, network, run_gitleaks, run_semgrep, run_trivy

RUNNERS = {"semgrep": run_semgrep, "gitleaks": run_gitleaks, "trivy": run_trivy}


def outcome(results, usable):
    states = {item["status"] for item in results.values()}
    if "FAIL" in states:
        return "FAIL", 1
    if not usable:
        return "INCOMPLETE", 3
    if states != {"PASS"}:
        return "INCOMPLETE", 2
    return "PASS", 0


def prereqs(project, reports, selected, build):
    config, root = project.config, project.root
    python = platform.python_version()
    records, commands = {}, {}

    def record(name, **item):
        records[name] = item
        reports.event("prerequisite_result", name=name, **item)

    python_lock = config.lock["python"]
    actual = version_tuple(python)
    pinned = version_tuple(python_lock["pinned"])
    python_status = "MISSING" if actual < version_tuple(python_lock["minimum"]) else "WARN" if actual < pinned else "OK"
    platform_name = "windows" if os.name == "nt" else "macos"
    record("python", status=python_status, version=python, install=python_lock[platform_name],
           reason="newer than pinned" if actual > pinned else "older than pinned" if actual < pinned else "")
    for tool in (*TOOLS, "git"):
        if tool != "git" and tool not in selected:
            continue
        if tool == "sonar" and build and "dotnet" in project.languages:
            dotnet = executable("dotnet")
            commands[tool] = [dotnet] if dotnet else None
            platform_name = "windows" if os.name == "nt" else "macos"
            record(tool, status="OK" if dotnet else "MISSING", version=None, mode="dotnet",
                   reason="" if dotnet else "dotnet not installed",
                   install=config.lock["sonar_dotnet"][platform_name])
        else:
            commands[tool], detail = prerequisite(tool, config, root)
            record(tool, **detail)

    if commands.get("sonar") and records["sonar"]["mode"] != "dotnet":
        launcher_root = Path(commands["sonar"][0]).resolve().parent.parent
        if not any((launcher_root / "jre" / suffix).is_file() for suffix in
                   ("bin/java", "bin/java.exe", "Contents/Home/bin/java")):
            _, java = prerequisite("java", config, root)
            if java["version"] is not None and version_tuple(java["version"])[0] < 17:
                java.update(status="MISSING", reason="Java 17+ required for unbundled SonarScanner")
            record("java", **java)
            if java["status"] == "MISSING":
                records["sonar"]["reason"] = "Java 17+ is required by the unbundled SonarScanner"
                commands["sonar"] = None

    server = None
    sonar_error = ""
    if "sonar" in selected:
        try:
            server = server_for(config)
            server.validate(min(8, config.seconds))
            record("sonar_connection", status="OK", reason="")
        except ScanError as error:
            sonar_error = str(error)
            record("sonar_connection", status="MISSING", reason=sonar_error)
            server = None
    if commands.get("semgrep") and (not config.rules or config.changes.get("semgrep_rule_mode") == "extend"):
        record("semgrep_network", **network("Semgrep registry", "https://semgrep.dev/c/p/default"))
    if commands.get("trivy"):
        record("trivy_network", **network("Trivy database registry", "https://mirror.gcr.io/v2/"))
    return commands, records, server, sonar_error


def tool_result(status, reason="", items=(), **details):
    return {"status": status, "reason": reason, "counts": findings.counts(items), **details}


def scan(root, options):
    root = root.resolve()
    if not root.is_dir():
        raise ScanError("project directory not found")
    config = settings(root, options.config, options.timeout)
    now = utc_now()
    start = time.monotonic()
    scan_id = str(UUID(os.environ["SECSCAN_RUN_ID"])) if os.environ.get("SECSCAN_RUN_ID") else str(uuid4())
    reports = Reports(root / "scan-reports", scan_id)
    git = git_info(root)
    selected = set(options.only or TOOLS) - set(options.skip or ())
    with reports.session():
        changes = dict(config.changes)
        if git and git_ignore_reports(root):
            changes["gitignore"] = "Added scan-reports/ to .gitignore"
            print(changes["gitignore"], flush=True)
        if options.config:
            changes["config_file"] = options.config.name
        for key in ("only", "skip", "timeout", "build", "no_fail"):
            value = getattr(options, key)
            if value is not None and value is not False and value != []:
                changes[key] = value
        project = Project(root, config, git)
        if "java" in project.languages and not project.java_binaries() and not options.build:
            project.notes.append("Reduced Java analysis: compiled classes are missing; run with --build for compiler-backed analysis.")
        if "dotnet" in project.languages and not options.build:
            project.notes.append("Reduced .NET analysis: the generic scanner lacks compiler-backed analysis; run with --build.")
        reports.event("scan_started", project_name=root.name, languages=sorted(project.languages))
        commands, checks, server, sonar_error = prereqs(project, reports, selected, options.build)
        results, items = {}, []
        usable = any(commands.get(tool) and (tool != "sonar" or server) for tool in selected)

        for tool in TOOLS:
            run = Run(config.seconds)
            run.details = {}
            tool_items = []
            if tool not in selected:
                result = tool_result("SKIPPED", "excluded by --only or --skip")
            else:
                reports.event("tool_started", tool=tool)
                try:
                    command = commands[tool]
                    if not command:
                        raise ScanError(checks[tool]["reason"])
                    if tool == "sonar":
                        if not server:
                            raise ScanError(sonar_error)
                        tool_items, details = run_sonar(project, command, run, server, options.build)
                    else:
                        tool_items, details = RUNNERS[tool](project, command, checks[tool]["mode"], run)
                    findings.apply(config, tool_items)
                    gate_failed = details.get("gate", {}).get("status") == config.thresholds["blocking"]["sonar"]["gate"]
                    blocked = any(item["blocking"] for item in tool_items)
                    result = tool_result("FAIL" if gate_failed or blocked else "PASS",
                                         "Quality Gate failed" if gate_failed else "blocking findings" if blocked else "",
                                         tool_items, **details)
                except ScanError as error:
                    result = tool_result("ERROR", str(error), **run.details)
                    if run.details.get("gate", {}).get("status") == config.thresholds["blocking"]["sonar"]["gate"]:
                        result["blocking_gate"] = True
                except (OSError, UnicodeError, ValueError, KeyError, TypeError, IndexError, AttributeError) as error:
                    result = tool_result("ERROR", f"unreadable output or scanner I/O failure ({type(error).__name__})", **run.details)
            try:
                reports.json(tool + ".json", run.raw if run.raw is not None else {"status": result["status"], "reason": result["reason"]}, raw=True)
                reports.write(tool + ".log", "\n\n".join(run.logs) + "\n" if run.logs else str(result["reason"]) + "\n")
                if reports.guard((tool + ".json", tool + ".log")):
                    raise ScanError("redaction failure")
            except ScanError:
                for suffix in (".json", ".log"):
                    name = tool + suffix
                    (reports.folder / name).unlink(missing_ok=True)
                    reports.names.discard(name)
                result, tool_items = tool_result("ERROR", "redaction failure"), []
            results[tool] = result
            items.extend(tool_items)
            project.notes.extend(result.get("warnings", []))
            if result.get("gate"):
                reports.event("gate_result", **result["gate"])
            reports.event("tool_finished", tool=tool, status=result["status"],
                          reason=result["reason"], counts=result["counts"])

        used, expired = findings.apply(config, items)
        status, policy_exit = outcome(results, usable)
        if results["sonar"].get("blocking_gate") and status != "FAIL":
            status, policy_exit = "FAIL", 1
        exit_code = 0 if options.no_fail else policy_exit
        sonar = results["sonar"]
        summary = {
            "schema_version": 1, "scan_id": scan_id, "project_name": root.name,
            "project_path": sha256(os.fsencode(root)).hexdigest() if config.changes.get("project_path") == "hash" else ".",
            "started_at": now, "ended_at": utc_now(),
            "duration_seconds": round(time.monotonic() - start, 3), "engine_version": __version__,
            "developer": (getuser() if config.changes.get("record_developer", True) else None),
            "git": {"status": "git repository" if git else "not a git repository", "commit": git.commit if git else "",
                    "branch": git.branch if git else "", "content_timestamp": None if git and git.commit else
                    datetime.fromtimestamp(max(((root / path).stat().st_mtime for path in project.source_files
                                                if (root / path).is_file()), default=root.stat().st_mtime),
                                           timezone.utc).isoformat()},
            "tool_versions": {name: detail.get("version") for name, detail in checks.items() if "version" in detail},
            "pinned_versions": {name: detail["pinned"] for name, detail in config.lock.items() if "pinned" in detail},
            "dependency_versions": {"PyYAML": config.lock["dependencies"]["PyYAML"]},
            "tools": results, "prerequisites": checks, "languages": sorted(project.languages),
            "quality_gate": sonar.get("gate", {"status": "UNAVAILABLE", "conditions": []}),
            "sonar_dashboard_url": sonar.get("dashboard_url"),
            "overall_status": status, "exit_code": exit_code, "policy_exit_code": policy_exit,
            "severity_counts": findings.counts(items), "findings": items,
            "blocking_findings": [item for item in items if item["blocking"]],
            "allowlist_used": used, "allowlist_expired": expired, "configuration_changes": changes,
            "coverage_notes": list(dict.fromkeys(project.notes)), "thresholds_version": config.thresholds["version"],
        }
        if sonar.get("dotnet_version"):
            summary["tool_versions"]["sonar_dotnet"] = sonar["dotnet_version"]
        if os.environ.get("SECSCAN_RUN_ID"):
            summary["dashboard_versions"] = config.lock["dashboard"]
        reports.summaries(summary)
        if reports.guard():
            reports.write("redaction-error.log", "redaction failure\n")
            status, exit_code = "INCOMPLETE", 0 if options.no_fail else 2
            summary.update(overall_status=status, exit_code=exit_code, policy_exit_code=2,
                           findings=[], blocking_findings=[], severity_counts=findings.counts([]),
                           coverage_notes=["redaction failure"])
            reports.summaries(summary)
        reports.event("report_written", files=["summary.html", "summary.md", "summary.json"])
        reports.event("scan_finished", status=status, exit_code=exit_code)
        return exit_code
