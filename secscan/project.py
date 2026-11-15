"""Project inventory and isolated, filtered scanner inputs."""

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import os
import shutil
from tempfile import TemporaryDirectory

from .config import ScanError, matches
from .process import capture, executable


@dataclass
class Git:
    root: Path
    commit: str
    branch: str


def git_info(root):
    git = executable("git")
    if not git:
        return None
    try:
        code, output, _ = capture([git, "rev-parse", "--show-toplevel"], root, 4)
        if code:
            return None
        top = Path(os.fsdecode(output).strip()).resolve()
        _, commit, _ = capture([git, "rev-parse", "--verify", "HEAD"], root, 4)
        _, branch, _ = capture([git, "rev-parse", "--abbrev-ref", "HEAD"], root, 4)
    except (ScanError, OSError):
        return None
    return Git(top, commit.decode().strip(), branch.decode("utf-8", "replace").strip())


def git_ignore_reports(root):
    path = root / ".gitignore"
    if path.is_symlink():
        raise ScanError(".gitignore is a symlink; add scan-reports/ manually")
    old = path.read_bytes() if path.exists() else b""
    ignored = False
    for line in old.splitlines():
        entry = line.strip().lstrip(b"/")
        if entry in (b"scan-reports/", b"scan-reports"):
            ignored = True
        elif entry.startswith(b"!"):
            ignored = ignored and not matches("scan-reports", os.fsdecode(entry[1:]))
    if ignored:
        return False
    with path.open("ab") as stream:
        stream.write((b"\n" if old and not old.endswith(b"\n") else b"") + b"scan-reports/\n")
    return True


def visible_in_git(root):
    git = executable("git")
    code, output, _ = capture([git, "ls-files", "-z", "--cached", "--others", "--exclude-standard"], root, 15)
    if code:
        raise ScanError("could not enumerate Git file selection")
    return set(os.fsdecode(output).rstrip("\0").split("\0"))


class Project:
    def __init__(self, root, config, git):
        self.root = root
        self.config = config
        self.git = git
        self.languages = set()
        self.java_builds = []
        self.dotnet_builds = []
        self.source_files = []
        self.trivy_files = []
        self.notes = []
        self.inventory()

    def inventory(self):
        visible = visible_in_git(self.root) if self.git else None
        skip = {".git", ".hg", ".svn", "scan-reports", ".scannerwork", ".sonarqube", ".scan-tools"}
        max_size = self.config.defaults["max_file_bytes"]
        for directory, dirs, files in os.walk(self.root, followlinks=False, onerror=self.inventory_error):
            base = Path(directory)
            dirs[:] = sorted(name for name in dirs if name not in skip and not (base / name).is_symlink())
            for name in sorted(files):
                path = base / name
                if path.is_symlink() or not path.is_file():
                    continue
                relative = path.relative_to(self.root).as_posix()
                manifest = any(matches(name, rule) for rule in self.config.defaults["manifests"])
                if visible is not None and relative not in visible and not manifest:
                    continue
                if manifest:
                    self.trivy_files.append(relative)
                if any(matches(relative, rule) for rule in self.config.exclusions):
                    continue
                if path.stat().st_size > max_size:
                    continue
                self.source_files.append(relative)
                if not manifest:
                    self.trivy_files.append(relative)
                self.detect(relative)
        if not self.languages:
            self.notes.extend([
                "Generic mode: Semgrep uses general rules without language-specific packs.",
                "Generic mode: Trivy dependency checks require supported manifests or lockfiles.",
                "Generic mode: SonarQube only analyzes files recognized by installed analyzers.",
            ])
        if self.git:
            self.notes.append("Gitleaks Git history includes committed paths across refs; historical ignores may differ from current .gitignore.")
        self.notes.append("Symlinks are excluded from current-file scans.")

    @staticmethod
    def inventory_error(error):
        raise error

    def detect(self, relative):
        path = PurePosixPath(relative)
        name, suffix = path.name, path.suffix.lower()
        languages = {
            ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
            ".ts": "typescript", ".tsx": "typescript", ".java": "java", ".cs": "dotnet",
            ".vb": "dotnet", ".fs": "dotnet", ".php": "php", ".go": "go",
            ".tf": "infrastructure", ".tfvars": "infrastructure",
        }
        if suffix in languages:
            self.languages.add(languages[suffix])
        if name == "package.json":
            self.languages.add("javascript")
        if name in ("tsconfig.json", "tsconfig.base.json"):
            self.languages.add("typescript")
        if name.startswith("requirements") or name in ("pyproject.toml", "Pipfile"):
            self.languages.add("python")
        if name in ("pom.xml", "build.gradle", "build.gradle.kts"):
            self.languages.add("java")
            self.java_builds.append(relative)
        if suffix in (".sln", ".slnx", ".csproj", ".vbproj", ".fsproj"):
            self.languages.add("dotnet")
            self.dotnet_builds.append(relative)
        if name.startswith("composer."):
            self.languages.add("php")
        if name in ("go.mod", "go.sum"):
            self.languages.add("go")
        if name == "Dockerfile" or name.startswith("Dockerfile."):
            self.languages.add("infrastructure")

    @contextmanager
    def stage(self, tool, run):
        selection = self.trivy_files if tool == "trivy" else self.source_files
        with TemporaryDirectory(prefix="secscan-") as temporary:
            work = Path(temporary)
            target = work / "project"
            target.mkdir()
            for relative in selection:
                run.remaining()
                source = self.root / relative
                if not source.resolve().is_relative_to(self.root) or source.is_symlink():
                    continue
                destination = target / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination, follow_symlinks=False)
            yield work, target

    def java_binaries(self):
        paths = []
        for relative in sorted(self.java_builds, key=lambda path: (path.count("/"), path)):
            base = (self.root / relative).parent
            for name in ("target/classes", "build/classes"):
                directory = base / name
                if (directory.is_dir() and directory.resolve() == directory
                        and any(directory.rglob("*.class"))):
                    paths.append(directory)
        return list(dict.fromkeys(paths))
