"""Run the built-in installation test on the current host."""

from argparse import Namespace
from contextlib import contextmanager, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory

from .config import ScanError, TOOLS, mapping
from .engine import scan
from .reports import DEMO_SECRET, Redactor
from .process import executable

DEMO = Path(__file__).resolve().parent / "demo"


@contextmanager
def override_env(**values):
    old = {name: os.environ.get(name) for name in values}
    try:
        os.environ.update(values)
        yield
    finally:
        for name, value in old.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def self_test():
    checks = []
    expected = mapping(DEMO / "expected.yml")
    configured = bool(os.environ.get("SONAR_HOST_URL") and os.environ.get("SONAR_TOKEN"))

    def check(label, result):
        checks.append((label, "PASS" if result else "FAIL"))

    with TemporaryDirectory(prefix="secscan-self-test-") as temporary:
        work = Path(temporary)

        def execute(state, **overrides):
            project = work / state
            if not project.exists():
                shutil.copytree(DEMO / state, project, ignore=shutil.ignore_patterns("scan-reports", "__pycache__"))
            options = dict(config=project / "scan.yml", timeout=None, only=None, skip=None,
                           build=False, no_fail=False)
            options.update(overrides)
            with redirect_stdout(StringIO()):
                code = scan(project, Namespace(**options))
            report_dir = project / "scan-reports"
            return code, json.loads((report_dir / "summary.json").read_text(encoding="utf-8")), report_dir

        try:
            code, planted, reports = execute("findings")
            for tool in TOOLS:
                entry = planted["prerequisites"][tool]
                available = entry["status"] in ("OK", "WARN")
                detail = "" if available else f" ({entry['reason']}). Install with: {entry['install']}"
                check(f"{tool} executable{detail}", available)
            for requirement in expected["findings"]:
                if requirement["tool"] == "sonar" and not configured:
                    continue
                check(f"demo {requirement['tool']} {requirement['rule']}", any(
                    all(item.get(key) == value for key, value in requirement.items())
                    for item in planted["findings"]))
            check("blocking findings exit 1", code == 1 and planted["overall_status"] == "FAIL")
            check("redacted reports", all(DEMO_SECRET.encode() not in path.read_bytes()
                                          for path in reports.rglob("*") if path.is_file()))
            if configured:
                verdict = planted["quality_gate"]["status"]
                received = verdict in ("OK", "ERROR")
                detail = "" if received else f" ({planted['tools']['sonar']['reason']})"
                check(f"live Sonar Quality Gate{detail}", received)
            else:
                checks.append(("Sonar Quality Gate (set SONAR_HOST_URL and SONAR_TOKEN)", "SKIPPED"))
            code, fixed, _ = execute("fixed")
            check("fixed demo has no findings", fixed["findings"] == expected["fixed"])
            if configured:
                check("all four tools pass on fixed demo", code == 0 and fixed["overall_status"] == "PASS")
            else:
                check("fixed demo is incomplete without SonarQube", code == 2 and all(
                    fixed["tools"][tool]["status"] == "PASS" for tool in TOOLS if tool != "sonar"))

            for tool in ("semgrep", "gitleaks", "trivy"):
                # Discovery honors PATH. Use a private copy of PATH entries with this
                # one executable omitted, leaving the host installation untouched.
                with masked_tool(work, tool):
                    _, result, _ = execute("findings")
                check(f"{tool} hidden from PATH, other tools continue",
                      result["tools"][tool]["status"] == "ERROR" and
                      "not installed" in result["tools"][tool]["reason"] and
                      all(result["tools"][other]["status"] in ("PASS", "FAIL")
                          for other in TOOLS if other != tool and (other != "sonar" or configured)))
            with override_env(SONAR_HOST_URL="http://127.0.0.1:1", SONAR_TOKEN="demo-invalid-token"):
                code, result, _ = execute("findings")
            check("bad Sonar URL, other tools continue", code == 1 and
                  "unreachable" in result["tools"]["sonar"]["reason"] and
                  all(result["tools"][tool]["status"] in ("PASS", "FAIL") for tool in TOOLS[:-1]))
            if configured:
                with override_env(SONAR_TOKEN="demo-invalid-token"):
                    _, result, _ = execute("findings")
                check("bad Sonar token, other tools continue", "401" in result["tools"]["sonar"]["reason"] and
                      all(result["tools"][tool]["status"] in ("PASS", "FAIL") for tool in TOOLS[:-1]))
            else:
                checks.append(("invalid token against live SonarQube", "SKIPPED"))

            code, result, _ = execute("fixed", only=["gitleaks"])
            check("clean tool with skips exits 2", code == 2 and result["tools"]["gitleaks"]["status"] == "PASS")
            code, result, _ = execute("findings", only=["gitleaks"], no_fail=True)
            check("--no-fail preserves status", code == 0 and result["overall_status"] == "FAIL")
            code, result, _ = execute("fixed", skip=list(TOOLS))
            check("zero usable tools exits 3", code == 3 and result["overall_status"] == "INCOMPLETE")
        except (ScanError, OSError, ValueError, KeyError) as error:
            checks.append((Redactor().text(f"self-test interrupted: {error}"), "FAIL"))
    for name, status in checks:
        print(f"{status} {name}")
    if any(status == "FAIL" for _, status in checks):
        return 1
    if any(status == "SKIPPED" for _, status in checks):
        print("Self-test incomplete; configure SonarQube to verify the full installation.")
        return 2
    return 0


@contextmanager
def masked_tool(root, tool):
    # Keep original dependency directories and shadow scanner executables from
    # directories that would otherwise also expose the selected tool.
    scratch = root / ("path-without-" + tool)
    scratch.mkdir()
    extensions = ("", ".exe", ".bat", ".cmd") if os.name == "nt" else ("",)
    paths = os.get_exec_path()
    excluded = {Path(path).resolve() for path in paths if any(
        (Path(path) / (tool + extension)).is_file() for extension in extensions)}
    if os.name == "nt" and tool == "semgrep":
        excluded.update(Path(path).resolve() for path in paths if any(
            (Path(path) / executable_name).is_file() for executable_name in ("docker.exe", "wsl.exe")))
    remaining = [path for path in paths if Path(path).resolve() not in excluded]
    for name in ("semgrep", "gitleaks", "trivy", "sonar-scanner", "git", "java", "python3"):
        if name == tool:
            continue
        source = executable(name)
        if not source or Path(source).absolute().parent.resolve() not in excluded:
            continue
        path = Path(source).absolute()
        destination = scratch / (path.name if os.name == "nt" else name)
        if os.name == "nt":
            shutil.copy2(path, destination)
        else:
            destination.symlink_to(path)
    with override_env(PATH=os.pathsep.join([str(scratch), *remaining])):
        yield
