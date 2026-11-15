"""Scanner discovery, execution, and network prerequisite checks."""

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
from tempfile import TemporaryDirectory
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import yaml

from . import findings
from .config import ScanError
from .process import capture, environment, executable, version_tuple


def prerequisite(tool, config, root):
    locked = config.lock[tool]
    platform = "windows" if os.name == "nt" else "macos"
    name = locked.get("executable", tool)
    path = executable(name)
    candidates = [([path], "native")] if path else []
    if tool == "semgrep" and os.name == "nt":
        if executable("docker"):
            candidates.append(([executable("docker"), "run", "--rm", "--pull=never",
                                f"semgrep/semgrep:{locked['pinned']}", "semgrep"], "docker"))
        if executable("wsl"):
            candidates.append(([executable("wsl"), "--exec", "semgrep"], "wsl"))
    failures = []
    for cmd, mode in candidates:
        try:
            env = None
            if tool == "semgrep":
                env = environment()
                env.update(SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")
            code, stdout, stderr = capture(cmd + locked["version"], root, 15 if tool == "semgrep" else 8, env)
        except ScanError as error:
            failures.append(f"{mode}: {error}")
            continue
        output = (stdout + stderr).decode("utf-8", "replace")
        if tool == "sonar":
            version = re.search(r"SonarScanner(?: CLI)?\s+(\d[\d.]+)", output, re.I)
        elif tool == "java":
            version = re.search(r'version\s+"?(\d[\d.]*)', output)
        else:
            version = re.search(r"\b\d+\.\d+(?:\.\d+)*\b", output)
        if code or not version:
            failures.append(f"{mode}: version check failed")
            continue
        actual = version.group(1 if tool in ("sonar", "java") else 0)
        baseline = version_tuple(locked["pinned"])
        current = version_tuple(actual)
        comparison = current[:len(baseline)] if tool == "java" else current
        result = {"status": "WARN" if comparison < baseline else "OK", "version": actual,
                  "reason": ("older than pinned" if comparison < baseline else
                             "newer than pinned" if comparison > baseline else ""),
                  "install": locked[platform], "mode": mode}
        return cmd, result
    label = "not installed" if not candidates else "cannot run (" + "; ".join(failures) + ")"
    if tool == "semgrep" and os.name == "nt":
        label += "; tried native, a locally available Docker image, then WSL; install Semgrep in WSL or pull the pinned Docker image"
    return None, {"status": "MISSING", "version": None, "reason": label, "install": locked[platform]}


def network(name, url):
    try:
        with urlopen(Request(url, method="HEAD"), timeout=4):
            pass
    except HTTPError as error:
        # Registry endpoints can require authorization or reject HEAD.
        if error.code not in (401, 403, 405):
            return {"status": "WARN", "reason": f"{name} returned HTTP {error.code}"}
    except (OSError, ValueError):
        return {"status": "WARN", "reason": f"{name} is unreachable"}
    return {"status": "OK", "reason": ""}


def json_report(raw, expected):
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeError) as error:
        raise ScanError("unreadable output: expected JSON report") from error
    if not isinstance(result, expected):
        raise ScanError("unreadable output: unexpected report structure")
    return result


def inspect_exit(code, exceptions=()):
    if code not in (0, *exceptions):
        raise ScanError(f"scanner crashed or returned incomplete output (exit {code})")


def semgrep_sources(project):
    config = project.config
    local = config.rules
    if local and config.changes.get("semgrep_rule_mode", "replace") == "replace":
        packs = []
    else:
        defaults = config.defaults["semgrep"]
        packs = [*defaults["packs"]]
        packs.extend(defaults["language_packs"][name] for name in sorted(project.languages)
                     if name in defaults["language_packs"])
    # Filter the rule packs before the engine runs, so secret rules cannot expose matches.
    paths = []
    for pack in dict.fromkeys(packs):
        paths.append((pack, f"https://semgrep.dev/c/{pack}"))
    if local:
        files = [local] if local.is_file() else sorted(local.rglob("*.y*ml"))
        paths.extend((file.name, file) for file in files if file.suffix in (".yaml", ".yml") and
                     file.resolve().is_relative_to(project.root) and not file.is_symlink())
    return paths


def secret_rule(rule):
    meta = rule.get("metadata") or {}
    identifier = str(rule.get("id", "")).lower()
    words = re.split(r"[^a-z0-9]+", identifier)
    return (bool(set(words) & {"secret", "secrets", "credential", "credentials", "hardcoded"})
            or bool(re.search(r"(?:^|\W)secrets?(?:$|\W)", str(meta.get("category", "")).lower()))
            or str(rule.get("product", meta.get("product", ""))).lower() in ("secrets", "secret")
            or bool(rule.get("validators")))


def run_semgrep(project, command, mode, run):
    with project.stage("semgrep", run) as (_, target):
        rules = {}
        sources = semgrep_sources(project)
        for name, source in sources:
            try:
                run.remaining()
                if isinstance(source, str):
                    with urlopen(source, timeout=min(run.remaining(), 20)) as response:
                        document = yaml.safe_load(response.read(25_000_000))
                else:
                    document = yaml.safe_load(source.read_text(encoding="utf-8"))
                for rule in document["rules"]:
                    if not secret_rule(rule):
                        rules[rule["id"]] = rule
            except (OSError, ValueError, yaml.YAMLError, TypeError, KeyError, AttributeError) as error:
                raise ScanError(f"could not load Semgrep rule pack {name}") from error
        if not rules:
            raise ScanError("no eligible Semgrep rules")
        rule_name = "secscan-rules.yml"
        while (target / rule_name).exists():
            rule_name = "_" + rule_name
        (target / rule_name).write_text(yaml.safe_dump({"rules": list(rules.values())}), encoding="utf-8")
        args = ["scan", "--metrics=off", "--disable-version-check", "--no-git-ignore",
                "--disable-nosem", "--no-rewrite-rule-ids", "--config", rule_name,
                "--exclude", rule_name, "--json", "."]
        if mode == "docker":
            command = command[:4] + ["-v", f"{target}:/src:ro", "-w", "/src",
                                     "--network", "none"] + command[4:]
        elif mode == "wsl":
            command = command[:1] + ["--cd", str(target)] + command[1:]
        code, output, _ = run.command(command + args, target, json_stdout=True)
        inspect_exit(code, (1,))
        report = json_report(output, dict)
        if not isinstance(report.get("results"), list) or not isinstance(report.get("errors"), list):
            raise ScanError("unreadable Semgrep report")
        run.raw = report
        if any(str(item.get("level", "")).lower() == "error" for item in report["errors"]):
            raise ScanError("Semgrep reported analysis errors; see log and raw report")
        if code == 1 and not report["results"]:
            raise ScanError("Semgrep reported a failure without findings")
        return list(findings.semgrep(project.config, report, target)), {"rule_packs": [name for name, _ in sources]}


def run_gitleaks(project, command, mode, run):
    from .config import matches

    config = project.config
    with TemporaryDirectory(prefix="secscan-gitleaks-") as temporary:
        work = Path(temporary)
        # Explicit settings override repository configuration and inline suppressions.
        history = bool(project.git)
        gitleaks_config = work / "gitleaks.toml"
        gitleaks_config.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
        args = ["--redact=100", "--ignore-gitleaks-allow", "--exit-code", "17",
                "--config", str(gitleaks_config), "--gitleaks-ignore-path", str(work),
                "--report-format", "json", "--report-path", "-", "--no-banner"]
        if history and not project.git.commit:
            code, output = 0, b"[]"
        elif history:
            # Gitleaks consults the source's .gitleaksignore even with --ignore-path.
            # Run from a separate bare repository with the original object store and refs.
            repository = work / "history"
            git = executable("git")
            code, _, _ = run.command([git, "clone", "--local", "--mirror", "--quiet",
                                      str(project.git.root), str(repository)], work)
            if code != 0:
                raise ScanError("could not read Git history")
            code, output, _ = run.command(command + ["git", *args, str(repository)], work, json_stdout=True)
        else:
            with project.stage("gitleaks", run) as (_, target):
                code, output, _ = run.command(command + ["dir", *args, str(target)], work, json_stdout=True)
        inspect_exit(code, (17,))
        report = json_report(output, (type(None), list)) or []
        if code == 17 and not report:
            raise ScanError("Gitleaks reported a failure without findings")
        base = None if history else target
        items = list(findings.gitleaks(config, report, project, base))
        prefix = project.root.relative_to(project.git.root).as_posix() if history else "."
        retained = []
        for row in report:
            file = findings.path_name(row.get("File"), base)
            if prefix != ".":
                if not file.startswith(prefix + "/"):
                    continue
                file = file[len(prefix) + 1:]
            if file and not any(matches(file, rule) for rule in config.exclusions):
                retained.append({key: row[key] for key in (
                    "RuleID", "Description", "StartLine", "EndLine", "StartColumn", "EndColumn",
                    "Commit", "Entropy", "Date", "Tags") if key in row} | {"File": file})
        run.raw = retained
        return items, {"mode": "history" if history else "files"}


def cache_metadata(path):
    try:
        data = json.loads(path.read_bytes())
        updated = datetime.fromisoformat(data["UpdatedAt"].replace("Z", "+00:00"))
        downloaded = datetime.fromisoformat(data["DownloadedAt"].replace("Z", "+00:00"))
        return updated, downloaded
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return None, None


def run_trivy(project, command, mode, run):
    if os.name == "nt":
        cache_home = Path(os.environ.get("LOCALAPPDATA") or Path.home())
    else:
        cache_home = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    cache = (cache_home / "secscan" / "trivy").resolve()
    metadata = cache / "db" / "metadata.json"
    _, previous = cache_metadata(metadata)
    with project.stage("trivy", run) as (work, target):
        empty = work / "ignore"
        empty.touch()
        base = command + ["fs", "--cache-dir", str(cache), "--config", str(work / "trivy.yaml"),
                          "--ignorefile", str(empty), "--scanners", "vuln,misconfig", "--no-progress",
                          "--file-patterns", r"pip:requirements.*\.txt"]
        (work / "trivy.yaml").write_text("{}\n", encoding="utf-8")
        try:
            update_seconds = max(0.1, run.remaining() * 0.7)
            db_code, _, _ = run.command(
                base + ["--timeout", f"{update_seconds:.3f}s", "--download-db-only", str(target)],
                work, limit=update_seconds)
        except ScanError:
            db_code = 1
        updated, downloaded = cache_metadata(metadata)
        now = datetime.now(timezone.utc)
        max_age = timedelta(hours=project.config.defaults["trivy_cache_max_hours"])
        if updated is None or updated.tzinfo is None or now - updated > max_age:
            raise ScanError("Trivy vulnerability database is unavailable or stale")
        warning = db_code != 0
        state = "cached after update failure" if warning else "updated" if downloaded != previous else "current cache"
        code, output, _ = run.command(
            base + ["--timeout", f"{run.remaining():.3f}s", "--skip-db-update", "--format", "json", str(target)],
            work, json_stdout=True)
        inspect_exit(code)
        report = json_report(output, dict)
        if (not isinstance(report.get("SchemaVersion"), int)
                or (report.get("Results") is not None and not isinstance(report["Results"], list))):
            raise ScanError("unreadable Trivy report")
        run.raw = report
        return list(findings.trivy(project.config, report, target)), {
            "database": state, "database_status": "WARN" if warning else "OK",
            "database_updated_at": updated.isoformat(),
            "warnings": ["Trivy database update failed; used recent cached data."] if warning else []}
