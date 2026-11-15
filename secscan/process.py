"""Child-process lifetime and executable discovery."""

import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time

from .config import ScanError


def environment():
    # Scanner-specific environment config can suppress findings or replace tool settings.
    ignored = ("GITLEAKS_", "TRIVY_", "SEMGREP_", "SONAR_")
    return {key: value for key, value in os.environ.items()
            if not key.upper().startswith(ignored) and key.upper() != "SONARQUBE_SCANNER_PARAMS"}


def executable(name):
    if os.name == "nt":
        return shutil.which(name + ".exe") or shutil.which(name + ".bat") or shutil.which(name)
    return shutil.which(name)


def terminate(process):
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           capture_output=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
        if process.poll() is None:
            process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def argv(command):
    # cmd.exe reinterprets batch arguments; reject metacharacters before running batch launchers.
    if os.name == "nt" and Path(command[0]).suffix.lower() in (".bat", ".cmd"):
        unsafe = '%!^&|<>"\r\n'
        if any(any(character in str(part) for character in unsafe) for part in command):
            raise ScanError("Windows batch launcher cannot safely handle this project path or option")
        return [os.environ.get("ComSpec", "cmd.exe"), "/d", "/v:off", "/c", "call", *command]
    return command


def capture(command, cwd, seconds, env=None, input_data=None):
    if seconds <= 0:
        raise ScanError("timeout")
    options = ({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt"
               else {"start_new_session": True})
    try:
        with subprocess.Popen(argv(command), cwd=cwd, env=environment() if env is None else env,
                              stdin=subprocess.DEVNULL if input_data is None else subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options) as process:
            try:
                stdout, stderr = process.communicate(input_data, timeout=seconds)
            except subprocess.TimeoutExpired:
                terminate(process)
                raise ScanError("timeout") from None
            except KeyboardInterrupt:
                terminate(process)
                raise
    except OSError as error:
        raise ScanError(f"could not start executable ({type(error).__name__})") from error
    return process.returncode, stdout, stderr


class Run:
    def __init__(self, seconds):
        self.deadline = time.monotonic() + seconds
        self.logs = []
        self.raw = None

    def remaining(self):
        seconds = self.deadline - time.monotonic()
        if seconds <= 0:
            raise ScanError("timeout")
        return seconds

    def command(self, command, cwd, *, env=None, json_stdout=False, limit=None):
        self.logs.append("$ " + " ".join(map(str, command)))
        try:
            remaining = self.remaining()
            code, stdout, stderr = capture(command, cwd, min(remaining, limit) if limit else remaining, env)
        except ScanError as error:
            self.logs.append(str(error))
            raise
        # Each tool's stdout and stderr pass through the reporting boundary.
        self.logs.append(f"exit {code}")
        if stdout and not json_stdout:
            self.logs.append("stdout:\n" + stdout.decode("utf-8", "replace"))
        if stderr:
            self.logs.append("stderr:\n" + stderr.decode("utf-8", "replace"))
        return code, stdout, stderr


def version_tuple(value):
    match = re.search(r"\d+(?:\.\d+)*", value)
    return tuple(int(part) for part in match.group().split(".")) if match else ()
