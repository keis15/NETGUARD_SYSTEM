"""
NetGuard FastAPI application.

Run from the wifimon folder:
    py run.py                    # http://127.0.0.1:8600
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .api import router
from .state import AppState

ROOT = Path(__file__).resolve().parents[2]          # wifimon/
FRONTEND_DIST = ROOT / "frontend" / "dist"
DEFAULT_DB = ROOT / "data" / "netguard.db"


def create_app(db_path: str | None = None, background: bool = True) -> FastAPI:
    db_path = db_path or os.environ.get("NETGUARD_DB") or str(DEFAULT_DB)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        state = AppState(db_path)
        app.state.wm = state
        if background:
            state.start()
        try:
            yield
        finally:
            state.stop()

    app = FastAPI(title="NetGuard", version="1.0.0", lifespan=lifespan)
    app.include_router(router, prefix="/api")

    if FRONTEND_DIST.exists():
        app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str):
            if path.startswith("api/"):
                raise HTTPException(404)
            file = (FRONTEND_DIST / path).resolve()
            if path and file.is_file() and FRONTEND_DIST.resolve() in file.parents:
                return FileResponse(file)
            return FileResponse(FRONTEND_DIST / "index.html")

    return app


logging.basicConfig(level=os.environ.get("NETGUARD_LOG", "INFO"),
                    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
logging.getLogger("scapy").setLevel(logging.ERROR)

app = create_app(background=os.environ.get("NETGUARD_NO_BACKGROUND") != "1")
