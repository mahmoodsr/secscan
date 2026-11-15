"""Normalize scanner output and apply the installed policy."""

from datetime import date
from hashlib import sha256
import json
from pathlib import PurePosixPath

from .config import LEVELS, ScanError, matches


def counts(findings):
    return {level: sum(item["severity"] == level for item in findings) for level in LEVELS}


def path_name(value, root=None):
    text = str(value or "").replace("\\", "/")
    if root:
        base = root.as_posix()
        if text.startswith(base + "/"):
            text = text[len(base) + 1:]
    path = PurePosixPath(text)
    if not path.is_absolute() and not any(":" in part for part in path.parts[:1]) and ".." not in path.parts:
        return "" if str(path) == "." else path.as_posix()
    return ""


def finding(config, tool, rule, title, original, category, file, line=None,
            description="", fix="", reference="", identity="", **extra):
    if not isinstance(rule, str) or not rule:
        raise ScanError("unreadable output: finding has no rule")
    original = str(original or "UNKNOWN").upper()
    severity = config.severity[tool].get(original, config.severity[tool].get("*", "Info"))
    try:
        line = int(line)
        line = line if line > 0 else None
    except (TypeError, ValueError):
        line = None
    identifier = sha256(json.dumps([tool, rule, file, identity or line], ensure_ascii=False).encode()).hexdigest()[:24]
    return {"id": identifier, "tool": tool, "rule": rule, "title": str(title or rule),
            "severity": severity, "original_severity": original, "category": category,
            "file": file, "line": line, "description": str(description or ""), "fix": str(fix or ""),
            "reference": str(reference or ""), "allowlisted": False, "blocking": False, **extra}


def semgrep(config, raw, root):
    for row in raw["results"]:
        detail = row["extra"]
        meta = detail.get("metadata") or {}
        rule = row["check_id"]
        message = detail.get("message", "")
        yield finding(config, "semgrep", rule, meta.get("title", rule),
                      detail["severity"], "code issue", path_name(row["path"], root),
                      row["start"]["line"], message, detail.get("fix") or
                      "Follow the remediation in the rule documentation.",
                      meta.get("source") or meta.get("shortlink") or "",
                      identity=detail.get("fingerprint") if detail.get("fingerprint") != "requires login" else "")


def gitleaks(config, raw, project, root):
    prefix = project.root.relative_to(project.git.root).as_posix() if project.git else "."
    for row in raw:
        file = path_name(row["File"], root)
        if prefix != "." and row.get("Commit"):
            if not file.startswith(prefix + "/"):
                continue
            file = file[len(prefix) + 1:]
        if not file or any(matches(file, rule) for rule in config.exclusions):
            continue
        rule = row["RuleID"]
        original = row.get("Fingerprint") or f"{file}:{rule}:{row.get('StartLine')}"
        fingerprint = sha256(original.encode()).hexdigest()[:24]
        yield finding(config, "gitleaks", rule, row.get("Description"), "Critical", "secret",
                      file, row.get("StartLine"), "Possible credential exposure.",
                      "Revoke or rotate the credential, then remove it from code and history.",
                      identity=fingerprint, fingerprint=fingerprint, commit=row.get("Commit") or None)


def trivy(config, raw, root):
    for target in raw.get("Results") or []:
        file = path_name(target.get("Target"), root)
        for row in target.get("Vulnerabilities") or []:
            fixed = row.get("FixedVersion") or ""
            package = row.get("PkgName", "")
            yield finding(config, "trivy", row["VulnerabilityID"], row.get("Title"),
                          row["Severity"], "vulnerability", file, description=row.get("Description", ""),
                          fix=f"Upgrade {package} to {fixed}" if fixed else "Review mitigations or replace the dependency.",
                          reference=row.get("PrimaryURL") or "", identity=package,
                          fix_available=bool(fixed), package=package, fixed_version=fixed)
        for row in target.get("Misconfigurations") or []:
            if row.get("Status", "FAIL") != "FAIL":
                continue
            metadata = row.get("CauseMetadata") or {}
            yield finding(config, "trivy", row["ID"], row.get("Title"), row["Severity"],
                          "misconfiguration", file, metadata.get("StartLine"), row.get("Description", ""),
                          row.get("Resolution") or "Review the check documentation.",
                          row.get("PrimaryURL") or "")


def sonar(config, issues, hotspots, reference):
    for row in issues:
        issue_type = row.get("type", "CODE_SMELL")
        category = "vulnerability" if issue_type == "VULNERABILITY" else "code issue"
        yield finding(config, "sonar", row["rule"], row.get("message"), row.get("severity"),
                      category, path_name(row.get("component", "").partition(":")[2]), row.get("line"),
                      row.get("message", ""), "Review the rule and suggested remediation in SonarQube.",
                      reference, identity=row.get("key"), issue_type=issue_type)
    for row in hotspots:
        yield finding(config, "sonar", row["ruleKey"], row.get("message"), row.get("severity", "INFO"),
                      "hotspot", path_name(row.get("component", "").partition(":")[2]), row.get("line"),
                      row.get("message", ""), "Review this security hotspot in SonarQube.",
                      reference, identity=row.get("key"), issue_type="SECURITY_HOTSPOT",
                      review_priority=row.get("vulnerabilityProbability"))


def apply(config, items):
    used = []
    expired = []
    valid = []
    today = date.today().isoformat()
    for entry in config.changes.get("allowlist", []):
        (expired if entry["expiry"] < today else valid).append(entry)
    for item in items:
        for entry in valid:
            if (entry["tool"] == item["tool"] and matches(item["file"], entry["file"])
                    and ("rule" not in entry or entry["rule"] == item["rule"])
                    and ("fingerprint" not in entry or entry["fingerprint"] in
                         (item.get("fingerprint"), item["id"]))):
                item["allowlisted"] = True
                if entry not in used:
                    used.append(entry)
        rule = config.thresholds["blocking"][item["tool"]].get(item["category"], [])
        if isinstance(rule, dict):
            blocking = item["severity"] in rule["severities"] and (
                item["severity"] not in rule.get("requires_fix", []) or item.get("fix_available", False))
        else:
            blocking = item["severity"] in rule
        item["blocking"] = bool(blocking and not item["allowlisted"])
    items.sort(key=lambda item: (LEVELS.index(item["severity"]), item["tool"], item["file"],
                                 item["line"] or 0, item["rule"]))
    return used, expired
