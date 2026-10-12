"""
Start NetGuard (backend API + built React UI).

    py run.py                         # http://127.0.0.1:8600 (this PC only)
    py run.py --port 9000
    py run.py --host 0.0.0.0          # expose the dashboard to the LAN (no login! not recommended)
"""

import argparse
import os
import sys
import webbrowser
from pathlib import Path

import uvicorn

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def main() -> None:
    p = argparse.ArgumentParser(description="NetGuard network monitor")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8600)
    p.add_argument("--db", default=str(ROOT / "data" / "netguard.db"))
    p.add_argument("--no-browser", action="store_true")
    p.add_argument("--reload", action="store_true", help="auto-reload on code changes (development)")
    args = p.parse_args()

    os.environ["NETGUARD_DB"] = args.db
    os.chdir(ROOT)
    if not (ROOT / "frontend" / "dist" / "index.html").exists():
        print("NOTE: frontend not built yet - only the API is available.\n"
              "      Build it with:  cd frontend && npm install && npm run build\n")
    url = f"http://{'127.0.0.1' if args.host == '0.0.0.0' else args.host}:{args.port}"
    print(f"NetGuard starting on {url}  (Ctrl+C to stop)")
    if not args.no_browser:
        import threading
        threading.Timer(2.5, lambda: webbrowser.open(url)).start()
    uvicorn.run("backend.app.main:app", host=args.host, port=args.port, reload=args.reload, log_level="info")


if __name__ == "__main__":
    main()
