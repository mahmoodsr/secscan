"""Local dashboard preferences, credentials, and scan history."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import sys
from tempfile import NamedTemporaryFile

import keyring
import yaml

from .config import ScanError
from .sonar import Server

SERVICE = "secscan"


def app_directory():
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", Path.home())) / SERVICE
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / SERVICE
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / SERVICE


def credential_backend():
    if sys.platform == "darwin":
        from keyring.backends.macOS import Keyring
        return Keyring()
    if os.name == "nt":
        from keyring.backends.Windows import WinVaultKeyring
        return WinVaultKeyring()
    raise ScanError("Secure storage is available on macOS and Windows.")


def token_for(url):
    if os.environ.get("SONAR_TOKEN"):
        return os.environ["SONAR_TOKEN"]
    if not url:
        return None
    try:
        return credential_backend().get_password(SERVICE, url)
    except (ScanError, keyring.errors.KeyringError):
        return None


def clean_url(value):
    value = value.strip().rstrip("/")
    if value:
        Server(value, "validation")
    return value


def save_token(url, token):
    if not url:
        raise ScanError("Set a SonarQube URL before saving a token.")
    if not token.strip() or any(ch.isspace() for ch in token) or len(token) > 512:
        raise ScanError("Enter a valid SonarQube token.")
    try:
        credential_backend().set_password(SERVICE, url, token)
    except keyring.errors.KeyringError as error:
        raise ScanError("The OS secure store could not save the token.") from error


def atomic_config(path, values, validate):
    if path.is_symlink():
        raise ScanError("Choose a project with a regular configuration file.")
    temporary = None
    try:
        with NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            yaml.safe_dump(values, stream, sort_keys=False)
        validate(temporary)
        temporary.replace(path)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


class Store:
    def __init__(self, directory):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = directory / "dashboard.sqlite3"
        with self.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS preferences (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY, project TEXT NOT NULL, name TEXT NOT NULL,
                    status TEXT NOT NULL, started TEXT NOT NULL, counts TEXT NOT NULL,
                    blocking INTEGER NOT NULL, report TEXT
                );
                CREATE INDEX IF NOT EXISTS scans_by_project ON scans(project, started DESC);
                CREATE TABLE IF NOT EXISTS starred (project TEXT PRIMARY KEY);
            """)

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def preferences(self):
        with self.db() as db:
            values = {row["key"]: json.loads(row["value"]) for row in db.execute("SELECT * FROM preferences")}
        return {"sonar_url": "", "retention": 50, **values}

    def configure(self, url, retention):
        with self.db() as db:
            db.executemany("INSERT OR REPLACE INTO preferences VALUES (?, ?)",
                           [("sonar_url", json.dumps(url)), ("retention", json.dumps(retention))])
        for project in {row["project"] for row in self.scans()}:
            self.prune(project, retention)

    def scans(self):
        with self.db() as db:
            rows = db.execute("""SELECT scans.*, starred.project IS NOT NULL AS starred
                FROM scans LEFT JOIN starred USING (project) ORDER BY started DESC, id DESC""").fetchall()
        return [{**dict(row), "counts": json.loads(row["counts"])} for row in rows]

    def record(self, row):
        with self.db() as db:
            db.execute("INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                       (row["id"], row["project"], row["name"], row["status"], row["started"],
                        json.dumps(row["counts"]), row["blocking"], row["report"]))
        self.prune(row["project"], self.preferences()["retention"])

    def prune(self, project, keep):
        # Reports belong to the project and can be kept independently of dashboard history.
        with self.db() as db:
            db.execute("""DELETE FROM scans WHERE id IN (SELECT id FROM scans
                        WHERE project = ? ORDER BY started DESC, id DESC LIMIT -1 OFFSET ?)""", (project, keep))

    def star(self, project, enabled):
        with self.db() as db:
            if enabled:
                db.execute("INSERT OR IGNORE INTO starred VALUES (?)", (project,))
            else:
                db.execute("DELETE FROM starred WHERE project = ?", (project,))
