"""Copy and scan both bundled demo states without changing their source files."""

from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import mkdtemp

ROOT = Path(__file__).resolve().parents[1]
demo = ROOT / "secscan" / "demo"
workspace = Path(mkdtemp(prefix="secscan-demo-"))

for state in ("findings", "fixed"):
    project = workspace / state
    shutil.copytree(demo / state, project, ignore=shutil.ignore_patterns("scan-reports", "__pycache__"))
    run = subprocess.run([sys.executable, "-m", "secscan", "scan", str(project),
                          "--config", str(project / "scan.yml")], cwd=ROOT)
    print(f"{state}: exit {run.returncode} · {project / 'scan-reports' / 'summary.html'}", flush=True)
