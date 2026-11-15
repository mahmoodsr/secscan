"""SonarScanner and the SonarQube Compute Engine/Quality Gate contract."""

import json
import os
import re
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from . import findings
from .config import ScanError
from .process import environment, executable
from .tools import inspect_exit, json_report


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Server:
    def __init__(self, url, token):
        if not url:
            raise ScanError("SonarQube URL not configured; set SONAR_HOST_URL")
        try:
            parsed = urlsplit(url)
            _ = parsed.port
            if (parsed.scheme not in ("http", "https") or not parsed.hostname
                    or parsed.username is not None or parsed.query or parsed.fragment
                    or "\\" in url or any(character.isspace() for character in url)):
                raise ValueError
        except ValueError as error:
            raise ScanError("invalid SonarQube URL") from error
        if not token:
            raise ScanError("SonarQube token missing; set SONAR_TOKEN")
        self.url = url.rstrip("/")
        self.token = token
        self.opener = build_opener(NoRedirect())

    def get(self, endpoint, seconds, **query):
        url = f"{self.url}/api/{endpoint}"
        if query:
            url += "?" + urlencode(query)
        request = Request(url, headers={"Authorization": f"Bearer {self.token}",
                                        "Accept": "application/json"})
        try:
            with self.opener.open(request, timeout=min(10, seconds)) as response:
                return json_report(response.read(), dict)
        except HTTPError as error:
            messages = {
                401: "SonarQube 401: invalid or expired token",
                403: "SonarQube 403: missing Execute Analysis or project access permission",
                404: f"SonarQube 404: {endpoint} unavailable or project missing/inaccessible",
            }
            raise ScanError(messages.get(error.code, f"SonarQube HTTP {error.code} at {endpoint}")) from error
        except URLError as error:
            if isinstance(error.reason, ssl.SSLError):
                message = "SonarQube TLS verification failed"
            elif isinstance(error.reason, TimeoutError):
                message = "SonarQube connection timeout"
            else:
                message = "SonarQube server unreachable"
            raise ScanError(message) from error
        except TimeoutError as error:
            raise ScanError("SonarQube connection timeout") from error

    def validate(self, seconds):
        if self.get("authentication/validate", seconds).get("valid") is not True:
            raise ScanError("SonarQube 401: invalid or expired token")

    def all(self, endpoint, rows, remaining, **query):
        result = []
        page = 1
        while True:
            data = self.get(endpoint, remaining(), p=page, ps=100, **query)
            batch = data.get(rows)
            if not isinstance(batch, list):
                raise ScanError(f"unreadable SonarQube {rows} response")
            paging = data.get("paging") or data
            total = paging.get("total")
            result.extend(batch)
            if total is None or len(result) >= total:
                return result
            if not batch or len(result) >= 10000:
                raise ScanError(f"SonarQube returned incomplete {rows} pagination")
            page += 1


def server_for(config):
    return Server(os.environ.get("SONAR_HOST_URL") or config.changes.get("sonar_url"),
                  os.environ.get("SONAR_TOKEN"))


def java_build(project, run):
    nested = sorted(project.java_builds, key=lambda value: (value.count("/"), value))
    roots = {}
    for relative in nested:
        manifest = project.root / relative
        if any(manifest.parent.is_relative_to(base) for base in roots):
            continue
        roots[manifest.parent] = manifest.name
    for directory, manifest in roots.items():
        maven = manifest == "pom.xml"
        name = "mvn" if maven else "gradle"
        wrapper = directory / (("mvnw.cmd" if os.name == "nt" else "mvnw") if maven else
                               ("gradlew.bat" if os.name == "nt" else "gradlew"))
        launcher = str(wrapper) if wrapper.is_file() and not wrapper.is_symlink() else executable(name)
        if not launcher:
            raise ScanError(f"Java build requested, but {name} or its project wrapper is missing")
        args = ["-B", "-DskipTests", "compile"] if maven else ["--no-daemon", "classes"]
        command = [launcher]
        if os.name != "nt" and launcher == str(wrapper) and not os.access(wrapper, os.X_OK):
            command = ["/bin/sh", launcher]
        code, _, _ = run.command(command + args, directory)
        if code:
            raise ScanError(f"Java build failed (exit {code}); see Sonar log")


def scanner_failure(code, stdout, stderr):
    if code == 0:
        return
    text = (stdout + stderr).decode("utf-8", "replace")
    categories = [
        (r"\b401\b|invalid.*token", "SonarQube 401: invalid or expired token"),
        (r"\b403\b|not authorized|not permitted", "SonarQube 403: missing Execute Analysis or Create Projects permission"),
        (r"\b404\b", "SonarQube 404: project or server endpoint not found"),
        (r"PKIX|SSLHandshake|certificate", "SonarQube TLS verification failed"),
        (r"timed?\s*out|timeout", "SonarScanner timeout"),
        (r"connectexception|connection refused|unreachable", "SonarQube server unreachable"),
    ]
    for pattern, message in categories:
        if re.search(pattern, text, re.I):
            raise ScanError(message)
    inspect_exit(code)


def dotnet_scan(project, run, target, metadata, key, server):
    dotnet = executable("dotnet")
    if not dotnet:
        raise ScanError(".NET build requested, but dotnet is not installed")
    cmd = [dotnet, "sonarscanner"]
    _, output, error = run.command(cmd + ["--version"], target)
    scanner_version = re.search(rb"SonarScanner for .NET\s+(\d[\d.]*)", output + error, re.I)
    if not scanner_version:
        platform = "windows" if os.name == "nt" else "macos"
        raise ScanError(".NET scanner unavailable; " + project.config.lock["sonar_dotnet"][platform])
    selected = sorted(project.dotnet_builds, key=lambda item: (
        not item.endswith((".sln", ".slnx")), item.count("/"), item))
    if not selected:
        raise ScanError(".NET build requested, but no solution or project file was found")
    # The .NET preprocessor supports JSON environment properties. Keep the credential
    # outside MSBuild and force the CLI path, which supports SONAR_TOKEN at analysis time.
    env = environment()
    env["SONAR_TOKEN"] = server.token
    env["SONAR_HOST_URL"] = server.url
    env["SONARQUBE_SCANNER_PARAMS"] = json.dumps({"sonar.token": server.token})
    begin = ["begin", f"/k:{key}", f"/d:sonar.host.url={server.url}",
             f"/d:sonar.scanner.metadataFilePath={metadata}",
             "/d:sonar.scanner.useSonarScannerCLI=true", "/d:sonar.scm.disabled=true"]
    scanner_failure(*run.command(cmd + begin, target, env=env))
    code, _, _ = run.command([dotnet, "build", selected[0], "--no-incremental"], target)
    if code:
        raise ScanError(f".NET build failed (exit {code}); see Sonar log")
    scanner_failure(*run.command(cmd + ["end"], target, env=env))
    return scanner_version.group(1).decode()


def run_sonar(project, command, run, server, build):
    key = re.sub(r"[^A-Za-z0-9_.-]", "-", project.root.name)[:380]
    if not re.search(r"\D", key):
        key = "project-" + key
    dashboard = f"{server.url}/dashboard?" + urlencode({"id": key})
    run.details = {"dashboard_url": dashboard, "project_key": key, "warnings": []}
    warnings = run.details["warnings"]
    use_dotnet = build and "dotnet" in project.languages
    if "dotnet" in project.languages and not use_dotnet:
        warnings.append("Reduced .NET analysis: run with --build for compiler-backed analysis.")
    if "java" in project.languages and build:
        java_build(project, run)
    binaries = project.java_binaries() if "java" in project.languages else []
    if "java" in project.languages and not binaries:
        warnings.append("Reduced Java analysis: compiled classes are missing; Java files are excluded from SonarQube.")
    with project.stage("sonar", run) as (work, target):
        metadata = work / "report-task.txt"
        if use_dotnet:
            run.details["dotnet_version"] = dotnet_scan(project, run, target, metadata, key, server)
            if not metadata.exists():
                candidates = list((target / ".sonarqube").rglob("report-task.txt"))
                if len(candidates) == 1:
                    metadata = candidates[0]
        else:
            env = environment()
            env["SONAR_HOST_URL"] = server.url
            env["SONAR_TOKEN"] = server.token
            args = [f"-Dsonar.projectKey={key}", "-Dsonar.sources=.",
                    "-Dsonar.scm.disabled=true", "-Dsonar.sourceEncoding=UTF-8",
                    f"-Dsonar.scanner.metadataFilePath={metadata}"]
            if binaries:
                args.append("-Dsonar.java.binaries=" + ",".join(map(str, binaries)))
            elif "java" in project.languages:
                args.append("-Dsonar.exclusions=**/*.java")
            scanner_failure(*run.command(command + args, target, env=env))
        if not metadata.is_file():
            raise ScanError("SonarScanner did not write analysis task metadata")
        fields = dict(line.split("=", 1) for line in metadata.read_text(encoding="utf-8").splitlines() if "=" in line)
        task_id = fields.get("ceTaskId")
        if not task_id:
            raise ScanError("SonarScanner did not provide a compute-engine task id")
        while True:
            task = server.get("ce/task", run.remaining(), id=task_id).get("task") or {}
            status = task.get("status")
            if status == "SUCCESS" and task.get("analysisId"):
                break
            if status not in ("IN_PROGRESS", "PENDING"):
                raise ScanError(f"SonarQube analysis task {status or 'returned no status'}")
            time.sleep(min(1, run.remaining()))
        gate = server.get("qualitygates/project_status", run.remaining(),
                          analysisId=task["analysisId"]).get("projectStatus") or {}
        verdict = gate.get("status")
        if verdict not in ("OK", project.config.thresholds["blocking"]["sonar"]["gate"]):
            raise ScanError("SonarQube returned no definitive Quality Gate verdict")
        run.details["gate"] = {"status": verdict, "conditions": gate.get("conditions", [])}
        run.raw = {"task": task, "quality_gate": gate}
        issues = server.all("issues/search", "issues", run.remaining, componentKeys=key, resolved="false")
        run.raw["issues"] = issues
        hotspots = server.all("hotspots/search", "hotspots", run.remaining, project=key)
        run.raw["hotspots"] = hotspots
    return list(findings.sonar(project.config, issues, hotspots, dashboard)), run.details
