"""Authenticated loopback API and launcher for the local dashboard."""

from contextlib import asynccontextmanager
from datetime import date, timedelta
from getpass import getuser
import os
from pathlib import Path
from secrets import compare_digest, token_urlsafe
import socket
import subprocess
import sys
from threading import Lock
import webbrowser

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, SecretStr

from .config import TOOLS, ScanError, allowlist_entries, load, mapping, settings
from .reports import Redactor
from .sonar import Server
from .tools import prerequisite
from .ui_runs import Runs
from .ui_store import Store, app_directory, atomic_config, clean_url, save_token, token_for

ASSETS = Path(__file__).with_name("ui_static")


class ProjectBody(BaseModel):
    project: str = Field(min_length=1, max_length=4096)


class ScanBody(ProjectBody):
    build: bool = False


class StarBody(ProjectBody):
    starred: bool


class Profile(BaseModel):
    sonar_url: str = ""
    retention: int = Field(default=50, ge=2, le=500)
    token: SecretStr = None


class AllowlistEntry(BaseModel):
    tool: str
    rule: str = ""
    fingerprint: str = ""
    file: str
    reason: str
    approver: str
    expiry: date


class ProjectProfile(ProjectBody):
    exclusions: list[str] = Field(default_factory=list)
    allowlist: list[AllowlistEntry] = Field(default_factory=list)


def project_path(value):
    root = Path(value).expanduser()
    if not root.is_absolute() or not root.is_dir():
        raise ScanError("Choose an existing project folder using its full path.")
    return root.resolve()


def native_picker():
    if sys.platform == "darwin":
        command = ["/usr/bin/osascript", "-e",
                   'POSIX path of (choose folder with prompt "Choose a project to scan")']
    elif os.name == "nt":
        command = ["powershell.exe", "-NoProfile", "-STA", "-Command",
                   "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
                   "Add-Type -AssemblyName System.Windows.Forms; "
                   "$dialog=New-Object System.Windows.Forms.FolderBrowserDialog; "
                   "if ($dialog.ShowDialog() -eq 'OK') { [Console]::Write($dialog.SelectedPath) }"]
    else:
        raise ScanError("Enter the full folder path on this platform.")
    result = subprocess.run(command, capture_output=True, encoding="utf-8", timeout=180)
    return result.stdout.strip() if result.returncode == 0 else ""


def create_app(host, opening_token, directory=None, command=None):
    store = Store(directory or app_directory())
    runs = Runs(store, command)
    session = token_urlsafe(32)
    cookie = "secscan_" + host.rsplit(":", 1)[-1]
    origin = "http://" + host
    claim = Lock()
    claimed = False

    @asynccontextmanager
    async def lifespan(app):
        yield
        current = runs.state()
        if current and current["active"]:
            try:
                process = runs.current["process"]
                runs.cancel()
                process.wait(timeout=12)
            except (OSError, ScanError, subprocess.TimeoutExpired):
                pass

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

    @app.middleware("http")
    async def authenticate(request: Request, call_next):
        nonlocal claimed
        foreign = (request.headers.get("host") != host
                   or request.headers.get("origin", origin) != origin
                   or request.headers.get("sec-fetch-site") == "cross-site")
        if foreign:
            return JSONResponse({"detail": "Foreign host or origin."}, status_code=403)
        if compare_digest(request.cookies.get(cookie, "").encode(), session.encode()):
            response = await call_next(request)
        else:
            supplied = request.query_params.get("session", "")
            with claim:
                valid = (not claimed and request.method == "GET" and request.url.path == "/"
                         and compare_digest(supplied.encode(), opening_token.encode()))
                if valid:
                    claimed = True
            if not valid:
                return JSONResponse({"detail": "Open the dashboard from secscan ui."}, status_code=401)
            response = RedirectResponse("/", status_code=303)
            response.set_cookie(cookie, session, httponly=True, samesite="strict")
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; object-src 'none'; frame-ancestors 'none'; "
            "style-src 'self' 'unsafe-inline'; base-uri 'none'; form-action 'self'")
        return response

    @app.exception_handler(ScanError)
    async def scan_error(request, error):
        return JSONResponse({"detail": Redactor().text(str(error))}, status_code=400)

    @app.exception_handler(OSError)
    async def io_error(request, error):
        return JSONResponse({"detail": "The local operation could not finish."}, status_code=400)

    from fastapi.exceptions import RequestValidationError

    @app.exception_handler(RequestValidationError)
    async def invalid_payload(request, error):
        # Validation payloads can include the raw credential supplied by the user.
        return JSONResponse({"detail": "Check the values in the form and try again."}, status_code=422)

    def effective_url(root=None):
        project_url = settings(root, None, None).changes.get("sonar_url") if root else None
        return clean_url(os.environ.get("SONAR_HOST_URL") or project_url or store.preferences()["sonar_url"])

    def saved_scan(identifier):
        row = next((item for item in store.scans() if item["id"] == identifier), None)
        if not row:
            raise HTTPException(404, "Scan not found.")
        if not row["report"]:
            raise HTTPException(404, "This scan has no completed report.")
        folder = Path(row["report"])
        if folder.is_symlink() or not folder.is_dir():
            raise HTTPException(404, "The report folder is unavailable.")
        return folder

    @app.get("/")
    def index():
        return FileResponse(ASSETS / "index.html")

    @app.get("/api/state")
    def state():
        with runs.lock:
            return {"history": store.scans(), "current": runs.state(), "developer": getuser()}

    @app.post("/api/picker")
    def picker():
        try:
            return {"project": native_picker()}
        except subprocess.TimeoutExpired as error:
            raise ScanError("The folder picker timed out.") from error

    @app.post("/api/runs")
    def start(body: ScanBody):
        root = project_path(body.project)
        url = effective_url(root)
        env = os.environ.copy()
        if url:
            env["SONAR_HOST_URL"] = url
        token = token_for(url)
        if token:
            env["SONAR_TOKEN"] = token
        return runs.start(root, body.build, env)

    @app.post("/api/cancel")
    def cancel():
        return runs.cancel()

    @app.post("/api/star")
    def star(body: StarBody):
        store.star(str(project_path(body.project)), body.starred)
        return {"ok": True}

    @app.get("/api/report/{identifier}")
    def report(identifier: str):
        import json
        path = saved_scan(identifier) / "summary.json"
        if path.is_symlink() or not path.is_file():
            raise HTTPException(404, "The summary is unavailable.")
        result = json.loads(path.read_text(encoding="utf-8"))
        secret_fields = {"id", "tool", "rule", "severity", "category", "file", "line", "allowlisted", "blocking"}
        for key in ("findings", "blocking_findings"):
            result[key] = [{field: value for field, value in item.items() if field in secret_fields}
                           if item["category"] == "secret" else item for item in result[key]]
        return result

    @app.get("/api/export/{identifier}/{format}")
    def export(identifier: str, format: str):
        if format not in ("html", "md", "json"):
            raise HTTPException(404, "Unknown export format.")
        path = saved_scan(identifier) / ("summary." + format)
        if path.is_symlink() or not path.is_file():
            raise HTTPException(404, "The export is unavailable.")
        return FileResponse(path, filename=path.name, media_type="application/octet-stream")

    @app.get("/api/setup")
    def setup():
        config = settings(Path.cwd(), None, None)
        checks = {tool: prerequisite(tool, config, Path.cwd())[1] for tool in TOOLS}
        return {"checks": checks, "token_set": bool(token_for(effective_url()))}

    @app.post("/api/connection")
    def connection():
        url = effective_url()
        if not url:
            raise ScanError("Set a SonarQube URL in Settings.")
        Server(url, token_for(url)).validate(8)
        return {"ok": True}

    @app.get("/api/settings")
    def profile(project: str = ""):
        result = store.preferences()
        root = project_path(project) if project else None
        effective = effective_url(root)
        result.update(effective_url=effective, token_set=bool(token_for(effective)),
                      thresholds=load("THRESHOLDS.yml"), severity=load("severity.yml"))
        if root:
            changes = settings(root, None, None).changes
            result.update(exclusions=changes.get("exclusions", []), allowlist=changes.get("allowlist", []))
            today = date.today()
            soon = today + timedelta(days=14)
            result["expiry"] = [
                {**item, "expired": item["expiry"] < today.isoformat()} for item in result["allowlist"]
                if item["expiry"] <= soon.isoformat()
            ]
        return result

    @app.put("/api/settings")
    def save_profile(body: Profile):
        url = clean_url(body.sonar_url)
        if body.token is not None:
            save_token(clean_url(os.environ.get("SONAR_HOST_URL") or url), body.token.get_secret_value())
        store.configure(url, body.retention)
        return {"ok": True}

    @app.put("/api/project")
    def save_project(body: ProjectProfile):
        root = project_path(body.project)
        path = root / ".scan-config.yml"
        current = mapping(path) if path.exists() else {}
        entries = [{key: value for key, value in item.model_dump().items() if value}
                   for item in body.allowlist]
        values = {**current, "exclusions": body.exclusions, "allowlist": allowlist_entries(entries)}
        with runs.lock:
            job = runs.state()
            if job and job["active"] and job["project"] == str(root):
                raise ScanError("Wait for the active scan to finish before changing its configuration.")
            atomic_config(path, values, lambda temp: settings(root, temp, None))
        return {"ok": True}

    app.mount("/assets", StaticFiles(directory=ASSETS / "assets"), name="assets")
    return app


def launch(no_browser=False):
    import uvicorn

    if not (ASSETS / "index.html").is_file():
        print("Build the dashboard with npm --prefix dashboard ci and npm --prefix dashboard run build.", file=sys.stderr)
        return 3
    opening_token = token_urlsafe(32)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        host = f"127.0.0.1:{listener.getsockname()[1]}"
        app = create_app(host, opening_token)
        url = "http://" + host + "/?session=" + opening_token
        print("Dashboard running at http://" + host, flush=True)
        if no_browser or not webbrowser.open(url):
            print("Opening URL: " + url, flush=True)
        uvicorn.Server(uvicorn.Config(app, access_log=False, log_level="warning",
                                      proxy_headers=False)).run(sockets=[listener])
    return 0
