"""Static file server for the built dashboard - Tailscale-only, bound to 0.0.0.0:8011.

Emolga's CLI/API calls never touch this port; it exists purely so the owner can
open the dashboard from any device on the tailnet. Run after `npm run build`:
    python server.py
"""
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from starlette.responses import FileResponse

DIST_DIR = Path(__file__).resolve().parent / "dist"

app = FastAPI()

if (DIST_DIR / "assets").exists():
    app.mount("/assets", StaticFiles(directory=DIST_DIR / "assets"), name="assets")


@app.get("/{full_path:path}")
def spa(full_path: str):
    if not DIST_DIR.exists():
        raise HTTPException(503, "dashboard/dist not built yet - run `npm run build` in dashboard/")
    candidate = (DIST_DIR / full_path).resolve()
    if full_path and candidate.is_file() and DIST_DIR.resolve() in candidate.parents:
        return FileResponse(candidate)
    return FileResponse(DIST_DIR / "index.html")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8011)
