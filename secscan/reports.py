"""Redaction, progress events, and report serialization."""

from contextlib import contextmanager
from datetime import datetime, timezone
from html import escape
import json
import os
from pathlib import Path
import re
from tempfile import NamedTemporaryFile
from urllib.parse import quote, quote_plus, urlsplit

from .config import LEVELS, ScanError

PATTERNS = [
    re.compile(r"(?i)\b(?:(?:https?|ssh|git|ftp)://)[^\s/@\"<>]+:[^\s/@\"<>]+@"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{15,}|github_pat_[A-Za-z0-9_]{20,}|(?:AKIA|ASIA)[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|s[qpu]_[A-Fa-f0-9]{32,})\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)"),
    re.compile(r"(?i)\b(?:authorization\s*[:=]\s*(?:Bearer|Basic)\s+)[\w.+/=-]+"),
    re.compile(r"(?i)\b(?:password|passwd|api[-_ ]?key|token|secret)\s*[=:]\s*[\"']?[A-Za-z0-9+/_.=-]{8,}"),
]
DEMO_SECRET = "ghp_" + "SecscanFakeDemoTokenForTestsOnly00001"
DROP_KEYS = {"match", "secret", "matchedtext", "lines", "snippet", "sourcecode",
             "metavars", "fixregex", "matched", "context", "dataflowtrace", "code", "content", "blame", "commitmessage", "messageevidence",
             "author", "email", "link", "fingerprint"}


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Redactor:
    def __init__(self, extra_secrets=()):
        secrets = {DEMO_SECRET, os.environ.get("SONAR_TOKEN", ""), *extra_secrets}
        for name, value in os.environ.items():
            if (re.search(r"(?:^|_)(?:TOKEN|SECRET|PASSWORD|API_KEY|ACCESS_KEY|KEY)(?:$|_)", name, re.I)
                    and len(value) >= 8):
                secrets.add(value)
            try:
                url = urlsplit(value) if "://" in value else None
                if url and url.password:
                    secrets.add(url.password)
            except ValueError:
                pass
        variants = {encoded for value in secrets if value for encoded in
                    (value, quote(value, safe=""), quote_plus(value), escape(value), json.dumps(value)[1:-1])}
        self.patterns = [re.compile(re.escape(value)) for value in sorted(variants, key=len, reverse=True)]
        self.patterns.extend(PATTERNS)

    def text(self, text):
        for pattern in self.patterns:
            text = pattern.sub("[REDACTED]", text)
        return text

    def data(self, data, raw=False):
        if isinstance(data, str):
            return self.text(data)
        if isinstance(data, dict):
            return {self.text(str(key)): self.data(value, raw) for key, value in data.items()
                    if not raw or re.sub(r"[^a-z]", "", str(key).lower()) not in DROP_KEYS}
        if isinstance(data, (list, tuple)):
            return [self.data(value, raw) for value in data]
        return data

    def verify(self, text):
        if any(pattern.search(text) for pattern in self.patterns):
            raise ScanError("redaction failure")


class Reports:
    def __init__(self, folder, scan_id):
        self.folder = folder
        self.scan_id = scan_id
        self.redactor = Redactor()
        self.names = set()

    @contextmanager
    def session(self):
        if self.folder.is_symlink():
            raise ScanError("scan-reports must be a regular directory")
        self.folder.mkdir(mode=0o700, exist_ok=True)
        lock = self.folder / ".active"
        try:
            with lock.open("x") as stream:
                stream.write(str(os.getpid()))
        except FileExistsError as error:
            raise ScanError("a scan is already writing reports in this project; see README for interrupted scans") from error
        try:
            self.write("events.jsonl", "")
            yield
        finally:
            lock.unlink(missing_ok=True)

    def write(self, name, value):
        value = self.redactor.text(value)
        self.redactor.verify(value)
        path = self.folder / name
        temporary = None
        try:
            with NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.folder, delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(value)
            temporary.replace(path)
            self.names.add(name)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def json(self, name, value, raw=False):
        value = self.redactor.data(value, raw=raw)
        self.write(name, json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + "\n")

    def event(self, event_name, **fields):
        event = self.redactor.data({"timestamp": utc_now(), "scan_id": self.scan_id, "type": event_name, **fields})
        line = self.redactor.text(json.dumps(event, ensure_ascii=True, allow_nan=False))
        self.redactor.verify(line)
        with (self.folder / "events.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")
        if event_name == "prerequisite_result":
            note = " · ".join(str(event[key]) for key in ("version", "reason") if event.get(key))
            install = " · " + event["install"] if event["status"] == "MISSING" and event.get("install") else ""
            print(f"{event['name']}: {event['status']}" + (f" · {note}" if note else "") + install, flush=True)
        elif event_name == "tool_started":
            print(f"{event['tool']}: scanning", flush=True)
        elif event_name == "tool_finished":
            reason = f" · {event['reason']}" if event.get("reason") else ""
            print(f"{event['tool']}: {event['status']}{reason}", flush=True)
        elif event_name == "scan_finished":
            print(f"Scan {event['status']} · exit {event['exit_code']}", flush=True)

    def guard(self, names=None):
        bad = []
        for name in sorted(self.names if names is None else names):
            path = self.folder / name
            try:
                self.redactor.verify(path.read_text(encoding="utf-8"))
            except ScanError:
                path.unlink(missing_ok=True)
                bad.append(name)
        return bad

    def summaries(self, summary):
        safe = self.redactor.data(summary)
        self.json("summary.json", safe)
        self.write("summary.md", markdown(safe))
        self.write("summary.html", html(safe))


def md(value):
    safe = escape(str(value), quote=False).replace("\n", " ").replace("\r", " ")
    return re.sub(r"([\\|`*_[\]#!])", r"\\\1", safe)


def location(row):
    return row["file"] + (f":{row['line']}" if row["line"] else "")


def ref(url):
    try:
        parsed = urlsplit(url or "")
        return url if parsed.scheme in ("http", "https") and parsed.hostname and not parsed.username else ""
    except ValueError:
        return ""


def sections(summary):
    gate = summary["quality_gate"]
    tools = [[tool, row["status"], row["reason"],
              *(row["counts"][level] for level in LEVELS)] for tool, row in summary["tools"].items()]
    blocking = [[item["tool"], item["severity"], item["rule"], location(item), item["fix"]]
                for item in summary["blocking_findings"]]
    conditions = [[row.get("metricKey", ""), row.get("status", ""), row.get("actualValue", ""),
                   row.get("errorThreshold", "")] for row in gate["conditions"]]
    overview = [[level, summary["severity_counts"][level]] for level in LEVELS]
    return [
        ("Tool results", ["Tool", "Status", "Reason", *LEVELS], tools),
        ("Severity counts", ["Severity", "Count"], overview),
        ("Issues requiring fixes", ["Tool", "Severity", "Rule", "File and line", "Fix"], blocking),
        ("Quality Gate conditions", ["Metric", "Status", "Actual", "Threshold"], conditions),
    ]


def extra(summary):
    changes = summary["configuration_changes"]
    return [
        ("Coverage notes", "\n".join(summary["coverage_notes"]) or "None"),
        ("Configuration changes", json.dumps(changes, indent=2, ensure_ascii=True) if changes else "None"),
        ("Exceptions used", json.dumps(summary["allowlist_used"], indent=2, ensure_ascii=True)),
        ("Expired exceptions", json.dumps(summary["allowlist_expired"], indent=2, ensure_ascii=True)),
        ("Tool versions", json.dumps(summary["tool_versions"], indent=2, ensure_ascii=True)),
    ]


def markdown(summary):
    lines = [f"# {md(summary['project_name'])}", "",
             f"**{summary['overall_status']}** · {summary['started_at']} · {md(summary['git']['commit'] or summary['git']['status'])}",
             "", f"Engine {summary['engine_version']} · thresholds {md(summary['thresholds_version'])} · exit {summary['exit_code']}",
             "", f"Quality Gate **{md(summary['quality_gate']['status'])}**"]
    url = ref(summary["sonar_dashboard_url"])
    if url:
        lines.append(f"\n[Open project in SonarQube](<{quote(url, safe=':/?&=%#')}>)")
    for title, columns, rows in sections(summary):
        lines += ["", f"## {title}", ""]
        if rows:
            lines.extend(["| " + " | ".join(columns) + " |", "| " + " | ".join("---" for _ in columns) + " |"])
            lines.extend("| " + " | ".join(md(value) for value in row) + " |" for row in rows)
        else:
            lines.append("None")
    for title, value in extra(summary):
        lines += ["", f"## {title}", "", "\n".join("    " + line for line in value.splitlines())]
    return "\n".join(lines) + "\n"


def html(summary):
    def esc(value):
        return escape(str(value), quote=True)

    def table(columns, rows):
        if not rows:
            return "<p>None</p>"
        header = "".join(f"<th>{esc(item)}</th>" for item in columns)
        body = "".join("<tr>" + "".join(f"<td>{esc(value)}</td>" for value in row) + "</tr>" for row in rows)
        return f"<div class=scroll><table><thead><tr>{header}</tr></thead><tbody>{body}</tbody></table></div>"

    tables = "".join(f"<section><h2>{title}</h2>{table(cols, rows)}</section>"
                     for title, cols, rows in sections(summary))
    details = "".join(f"<section><h2>{title}</h2><pre>{esc(value)}</pre></section>" for title, value in extra(summary))
    url = ref(summary["sonar_dashboard_url"])
    link = f' <a href="{esc(url)}">Open project in SonarQube</a>' if url else ""
    project = esc(summary["project_name"])
    status = esc(summary["overall_status"])
    version = esc(summary["git"]["commit"] or summary["git"]["status"])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{project} — Security scan</title>
<style>
:root{{color-scheme:light dark;font:16px/1.55 system-ui,sans-serif}}
body{{margin:0 auto;padding:2rem;max-width:68rem}}
h1{{font-size:2.5rem;margin:.5rem 0}}
section{{margin:2rem 0}}
.banner{{border:1px solid;border-radius:.75rem;padding:.75rem 1rem;font-weight:700}}
.PASS{{background:#133b2c;color:#b9f3cf}}.FAIL{{background:#63272d;color:#fff0ee}}
.INCOMPLETE{{background:#4b3916;color:#fff1bb}}
.scroll{{overflow:auto}}table{{width:100%;border-collapse:collapse;text-align:left}}
th,td{{padding:.6rem;border-bottom:1px solid GrayText;vertical-align:top}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere}}
</style></head><body>
<header><h1>{project}</h1><p>{esc(summary['started_at'])} · {version}</p>
<p class="banner {status}">{status} · exit {summary['exit_code']}</p>
<p>Engine {esc(summary['engine_version'])} · thresholds {esc(summary['thresholds_version'])}</p>
<p>Quality Gate <strong>{esc(summary['quality_gate']['status'])}</strong>{link}</p></header>
<main>{tables}{details}</main></body></html>
"""
