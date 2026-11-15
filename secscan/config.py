"""Load and validate the installed policy and project overrides."""

from dataclasses import dataclass
from datetime import date
from fnmatch import fnmatchcase
import math
from pathlib import Path

import yaml

DATA = Path(__file__).resolve().parent / "data"
TOOLS = ("semgrep", "gitleaks", "trivy", "sonar")
LEVELS = ("Critical", "High", "Medium", "Low", "Info")


class ScanError(Exception):
    """An error that can be reported as a scan or tool result."""


def mapping(path):
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ScanError(f"cannot read configuration {path.name}") from error
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ScanError(f"{path.name} must contain a mapping")
    return value


def load(name):
    return mapping(DATA / name)


def minutes(value):
    try:
        number = float(value)
    except (ValueError, TypeError, OverflowError):
        number = 0
    if isinstance(value, bool) or not math.isfinite(number) or number <= 0:
        raise ScanError("timeout must be a positive finite number of minutes")
    return number


def matches(path, pattern):
    parts = path.split("/")
    pattern = pattern.removeprefix("./").rstrip("/")
    if "/" not in pattern and any(fnmatchcase(part, pattern) for part in parts):
        return True
    if pattern.endswith("/**") and path == pattern[:-3]:
        return True
    return fnmatchcase(path, pattern) or fnmatchcase(path, pattern.removeprefix("**/"))


def nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def allowlist_entries(value):
    if not isinstance(value, list):
        raise ScanError("allowlist must be a list")
    result = []
    for index, entry in enumerate(value, 1):
        required = ("tool", "file", "reason", "approver")
        if (not isinstance(entry, dict)
                or set(entry) - {*required, "rule", "fingerprint", "expiry"}
                or not all(nonempty(entry.get(key)) for key in required)
                or entry["tool"] not in TOOLS
                or not (nonempty(entry.get("rule")) or nonempty(entry.get("fingerprint")))
                or any(key in entry and not nonempty(entry[key]) for key in ("rule", "fingerprint"))
                or (entry["tool"] == "gitleaks" and not nonempty(entry.get("fingerprint")))):
            raise ScanError(f"invalid allowlist entry {index}: tool, rule or fingerprint, file, reason, approver and expiry required; Gitleaks requires a fingerprint")
        try:
            expiry = date.fromisoformat(str(entry.get("expiry")))
        except ValueError as error:
            raise ScanError(f"allowlist entry {index} requires an expiry in YYYY-MM-DD format") from error
        result.append({**entry, "expiry": expiry.isoformat()})
    return result


@dataclass
class Settings:
    defaults: dict
    lock: dict
    thresholds: dict
    severity: dict
    changes: dict
    exclusions: list
    rules: object
    seconds: float


def settings(root, config_path, timeout):
    defaults = load("defaults.yml")
    path = config_path or root / ".scan-config.yml"
    changes = mapping(path) if config_path or path.exists() else {}
    allowed = {"exclusions", "allowlist", "sonar_url", "timeout_minutes",
               "semgrep_rules", "semgrep_rule_mode", "record_developer", "project_path"}
    if set(changes) - allowed:
        raise ScanError("project config contains unknown keys")
    extra = changes.get("exclusions", [])
    if not isinstance(extra, list) or not all(nonempty(item) for item in extra):
        raise ScanError("exclusions must be a list of path patterns")
    if "allowlist" in changes:
        changes["allowlist"] = allowlist_entries(changes["allowlist"])
    if changes.get("project_path", "relative") not in ("hash", "relative"):
        raise ScanError("project_path must be relative or hash")
    if not isinstance(changes.get("record_developer", True), bool):
        raise ScanError("record_developer must be true or false")
    if "sonar_url" in changes and not nonempty(changes["sonar_url"]):
        raise ScanError("sonar_url must be a nonempty URL")
    if changes.get("semgrep_rule_mode", "replace") not in ("replace", "extend"):
        raise ScanError("semgrep_rule_mode must be replace or extend")
    rules = None
    if "semgrep_rules" in changes:
        if not nonempty(changes["semgrep_rules"]):
            raise ScanError("semgrep_rules must name a project file or folder")
        rules = (root / changes["semgrep_rules"]).resolve()
        if not rules.is_relative_to(root) or not rules.exists():
            raise ScanError("semgrep_rules must exist inside the project")
    elif "semgrep_rule_mode" in changes:
        raise ScanError("semgrep_rule_mode requires semgrep_rules")
    return Settings(defaults, load("tools.lock"), load("THRESHOLDS.yml"), load("severity.yml"),
                    changes, list(dict.fromkeys(defaults["exclusions"] + extra)), rules,
                    60 * minutes(timeout if timeout is not None else changes.get("timeout_minutes", defaults["timeout_minutes"])))
