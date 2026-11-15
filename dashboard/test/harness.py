"""Start the actual dashboard with a disposable data directory and replayed engine."""

from pathlib import Path
import socket
import sys

import uvicorn

from secscan.ui import create_app

root = Path(__file__).resolve().parents[2]
with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    host = f"127.0.0.1:{listener.getsockname()[1]}"
    app = create_app(host, "browser-replay", Path(sys.argv[1]),
                     [sys.executable, str(root / "tests/fixtures/dashboard_engine.py")])
    print(f"http://{host}/?session=browser-replay", flush=True)
    uvicorn.Server(uvicorn.Config(app, access_log=False, log_level="warning")).run(sockets=[listener])
