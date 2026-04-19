import asyncio
import json
import logging
import os
import re
import sqlite3
import sys
import tempfile
from html import escape
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from weasyprint import HTML as WeasyprintHTML

from notifier import discord, telegram

# ========================
# LOGGING
# ========================
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(name)s — %(message)s"
)
log = logging.getLogger(__name__)

# ========================
# PATHS
# ========================
BASE_DIR  = Path(__file__).resolve().parent
DATA_DIR  = BASE_DIR.parent / "data"
SCANNER   = BASE_DIR.parent / "main.py"
TEMPLATES = BASE_DIR / "templates"
STATIC    = BASE_DIR / "static"

DATA_DIR.mkdir(parents=True, exist_ok=True)

# ========================
# APP SETUP
# ========================
app = FastAPI(title="Vuln-Forge", version="1.0.0")

app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES))

# ========================
# ACTIVE SCANS TRACKER
# { domain: { "process": ..., "logs": [...], "status": ... } }
# ========================
active_scans: dict = {}


# ========================
# HELPERS
# ========================
def safe_domain(domain: str) -> str:
    """Sanitize domain to prevent path traversal."""
    return re.sub(r"[^a-z0-9.\-]", "_", domain.strip().lower())


def get_db_path(domain: str) -> Path:
    return DATA_DIR / f"{safe_domain(domain)}.db"


def db_connect(domain: str) -> sqlite3.Connection:
    """Open and return a SQLite connection for a domain."""
    db_path = get_db_path(domain)
    if not db_path.exists():
        raise HTTPException(status_code=404, detail=f"No scan data found for {domain}")
    return sqlite3.connect(str(db_path))


def is_scan_alive(domain: str) -> bool:
    """Check if a scan process is actually still running."""
    if domain not in active_scans:
        return False
    scan    = active_scans[domain]
    process = scan.get("process")
    # returncode is None only while process is still running
    return process is not None and process.returncode is None


# ========================
# ROUTES
# ========================
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html"
    )


@app.get("/api/scans")
async def list_scans():
    """List all scan databases available."""
    dbs = []
    for db_file in DATA_DIR.glob("*.db"):
        stat = db_file.stat()
        dbs.append({
            "domain":   db_file.stem,
            "size":     stat.st_size,
            "modified": stat.st_mtime,
        })
    dbs.sort(key=lambda x: x["modified"], reverse=True)
    return JSONResponse(dbs)

@app.delete("/api/scans/{domain}")
async def delete_scan(domain: str):
    """Delete a scan database to clear history."""
    domain = safe_domain(domain)
    
    if is_scan_alive(domain):
        raise HTTPException(status_code=400, detail="Cannot delete history while a scan is actively running on this target.")
        
    db_path = get_db_path(domain)
    if not db_path.exists():
        return JSONResponse({"status": "not_found", "domain": domain}, status_code=404)
        
    try:
        db_path.unlink()
        log.info(f"Scan history deleted for: {domain}")
        return JSONResponse({"status": "deleted", "domain": domain})
    except Exception as e:
        log.error(f"Failed to delete {db_path}: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete database file.")

@app.get("/api/active")
async def list_active():
    """List all currently active (running) scans."""
    running = []
    for domain, scan in active_scans.items():
        if is_scan_alive(domain):
            running.append({
                "domain": domain,
                "status": scan["status"],
                "log_count": len(scan["logs"])
            })
    return JSONResponse(running)


@app.post("/api/scan/start")
async def start_scan(request: Request):
    """Start a new vulnerability scan."""
    body      = await request.json()
    domain    = safe_domain(body.get("domain", ""))
    fresh     = body.get("fresh",     False)
    test      = body.get("test",      False)
    active    = body.get("active",    False)
    no_notify = body.get("no_notify", False)
    debug     = body.get("debug",     False)

    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    # Only block if process is ACTUALLY alive
    if is_scan_alive(domain):
        raise HTTPException(status_code=409, detail=f"Scan already running for {domain}")

    # Clean up stale entry if exists
    if domain in active_scans:
        log.info(f"Cleaning up stale scan entry for: {domain}")
        active_scans.pop(domain, None)

    # Build scanner command
    cmd = [sys.executable, "-u", str(SCANNER), "-d", domain]
    if fresh:     cmd += ["--fresh", "--yes"]
    if test:      cmd.append("--test")
    if active:    cmd.append("--active")
    if no_notify: cmd.append("--no-notify")
    if debug:     cmd.append("--debug")

    log.info(f"Starting scan: {' '.join(cmd)}")

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        cwd=str(BASE_DIR.parent)
    )

    active_scans[domain] = {
        "process": process,
        "logs":    [],
        "status":  "running"
    }

    asyncio.create_task(read_logs(domain, process))

    return JSONResponse({"status": "started", "domain": domain})


@app.post("/api/scan/stop")
async def stop_scan(request: Request):
    """Stop a running scan."""
    body   = await request.json()
    domain = safe_domain(body.get("domain", ""))

    if not is_scan_alive(domain):
        # Clean up stale entry
        active_scans.pop(domain, None)
        raise HTTPException(status_code=404, detail=f"No active scan for {domain}")

    active_scans[domain]["process"].terminate()
    active_scans[domain]["status"] = "stopped"
    log.info(f"Scan stopped: {domain}")

    return JSONResponse({"status": "stopped", "domain": domain})


@app.get("/api/scan/status/{domain}")
async def scan_status(domain: str):
    """Get current scan status and recent logs."""
    domain = safe_domain(domain)

    if domain not in active_scans:
        return JSONResponse({"status": "idle", "domain": domain})

    scan  = active_scans[domain]
    alive = is_scan_alive(domain)

    # Auto-fix stale running status
    if scan["status"] == "running" and not alive:
        scan["status"] = "failed"

    return JSONResponse({
        "status":    scan["status"],
        "domain":    domain,
        "alive":     alive,
        "logs":      scan["logs"][-50:]
    })


@app.post("/api/scan/clear/{domain}")
async def clear_scan(domain: str):
    """Force clear a stuck scan entry."""
    domain = safe_domain(domain)
    if domain in active_scans:
        # Kill process if somehow still alive
        process = active_scans[domain].get("process")
        if process and process.returncode is None:
            process.kill()
        active_scans.pop(domain, None)
        log.info(f"Cleared scan entry for: {domain}")
        return JSONResponse({"status": "cleared", "domain": domain})
    return JSONResponse({"status": "not_found", "domain": domain})


@app.get("/api/results/{domain}")
async def get_results(domain: str):
    """Get vulnerability results for a domain."""
    conn = db_connect(domain)
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, type, target, severity, tool, details
            FROM vulnerabilities
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high'     THEN 2
                    WHEN 'medium'   THEN 3
                    WHEN 'low'      THEN 4
                    ELSE            5
                END, id DESC
        """)
        rows = cursor.fetchall()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

    results = []
    for id_, type_, target, severity, tool, details_json in rows:
        try:
            details = json.loads(details_json) if details_json else {}
        except Exception:
            details = {}
        results.append({
            "id": id_, "type": type_, "target": target,
            "severity": severity, "tool": tool, "details": details
        })

    return JSONResponse(results)


@app.post("/api/notify/{domain}")
async def notify_results(domain: str):
    """Send Discord and Telegram notifications for a completed scan."""
    conn = db_connect(domain)
    try:
        discord.send_discord_alert(conn)
        telegram.send_telegram_alert(conn)
        log.info(f"Notifications sent for: {domain}")
        return JSONResponse({"status": "notifications_sent", "domain": domain})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@app.get("/api/report/{domain}")
async def download_report(domain: str):
    """Generate and download PDF report for a domain."""
    conn = db_connect(domain)
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, type, target, severity, tool, details
            FROM vulnerabilities
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high'     THEN 2
                    WHEN 'medium'   THEN 3
                    WHEN 'low'      THEN 4
                    ELSE 5
                END
        """)
        rows = cursor.fetchall()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

    severity_counts = {}
    for row in rows:
        sev = str(row[3]).lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    html_content = build_pdf_report(domain, rows, severity_counts)

    tmp      = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False, prefix="vf_report_")
    tmp_path = tmp.name
    tmp.close()

    try:
        WeasyprintHTML(string=html_content).write_pdf(tmp_path)
        log.info(f"PDF report generated for: {domain}")
    except Exception as e:
        Path(tmp_path).unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

    return FileResponse(
        path=tmp_path,
        filename=f"{domain}_vuln_report.pdf",
        media_type="application/pdf",
        background=None
    )


# ========================
# WEBSOCKET — LIVE LOGS
# ========================
@app.websocket("/ws/logs/{domain}")
async def websocket_logs(websocket: WebSocket, domain: str):
    """Stream live scan logs to browser via WebSocket."""
    domain = safe_domain(domain)
    await websocket.accept()
    log.info(f"WebSocket connected for: {domain}")

    try:
        last_index = 0
        while True:
            if domain in active_scans:
                scan = active_scans[domain]
                logs = scan["logs"]

                # Send new log lines
                if len(logs) > last_index:
                    for line in logs[last_index:]:
                        await websocket.send_text(json.dumps({
                            "type": "log",
                            "data": line
                        }))
                    last_index = len(logs)

                # Send status when done
                if scan["status"] in ("completed", "stopped", "failed"):
                    await websocket.send_text(json.dumps({
                        "type":   "status",
                        "status": scan["status"]
                    }))
                    break

            await asyncio.sleep(0.3)

    except WebSocketDisconnect:
        log.info(f"WebSocket disconnected for: {domain}")


# ========================
# BACKGROUND LOG READER
# ========================
async def read_logs(domain: str, process):
    """Read subprocess stdout and store logs. Cleans up after 5 minutes."""
    try:
        async for line in process.stdout:
            decoded = line.decode("utf-8", errors="replace").rstrip()
            if domain in active_scans:
                active_scans[domain]["logs"].append(decoded)

        await process.wait()

        if domain in active_scans:
            active_scans[domain]["status"] = (
                "completed" if process.returncode == 0 else "failed"
            )   
            log.info(f"Scan {active_scans[domain]['status']}: {domain} (exit {process.returncode})")

    except Exception as e:
        if domain in active_scans:
            active_scans[domain]["logs"].append(f"[ERROR] Log reader failed: {e}")
            active_scans[domain]["status"] = "failed"

    finally:
        await asyncio.sleep(300)
        active_scans.pop(domain, None)
        log.debug(f"Cleaned up active_scans entry for: {domain}")


# ========================
# PDF REPORT BUILDER
# ========================
def build_pdf_report(domain: str, rows: list, severity_counts: dict) -> str:
    severity_colors = {
        "critical": "#ff2d2d", "high": "#ff6b00",
        "medium":   "#ffd700", "low":  "#00ff88", "info": "#888888",
    }

    rows_html = ""
    for row in rows:
        id_, type_, target, severity, tool, details_json = row
        try:
            details = json.loads(details_json) if details_json else {}
        except Exception:
            details = {}

        info  = details.get("msg","") or details.get("parameter","") or details.get("payload","") or "—"
        color = severity_colors.get(str(severity).lower(), "#888")

        rows_html += f"""
        <tr>
            <td>{escape(str(id_))}</td>
            <td><span style="color:{color};font-weight:bold">{escape(str(severity)).upper()}</span></td>
            <td>{escape(str(type_))}</td>
            <td>{escape(str(tool))}</td>
            <td style="word-break:break-all">{escape(str(target))}</td>
            <td style="word-break:break-all">{escape(str(info))}</td>
        </tr>"""

    summary_html = " &nbsp;|&nbsp; ".join(
        f'<span style="color:{severity_colors.get(s,"#888")}">{escape(s.upper())}: {c}</span>'
        for s, c in severity_counts.items()
    )

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
body{{font-family:monospace;background:#0a0a0a;color:#00ff88;padding:40px}}
h1{{color:#00ff88;border-bottom:2px solid #00ff88;padding-bottom:10px}}
h2{{color:#00cc66;margin-top:8px}}
table{{width:100%;border-collapse:collapse;margin-top:20px}}
th{{background:#111;color:#00ff88;padding:10px;text-align:left;border:1px solid #333;font-size:11px;letter-spacing:1px}}
td{{padding:8px 10px;border:1px solid #222;font-size:11px;color:#ccc}}
tr:nth-child(even){{background:#0d0d0d}}
.summary{{margin:20px 0;font-size:13px}}
.footer{{margin-top:40px;color:#444;font-size:10px;border-top:1px solid #222;padding-top:10px}}
</style></head><body>
<h1>⬡ VULN-FORGE // VULNERABILITY REPORT</h1>
<h2>TARGET: {escape(domain.upper())}</h2>
<div class="summary"><strong>TOTAL FINDINGS: {len(rows)}</strong> &nbsp;&nbsp; {summary_html}</div>
<table><thead><tr>
<th>#</th><th>SEVERITY</th><th>TYPE</th><th>TOOL</th><th>TARGET</th><th>DETAILS</th>
</tr></thead><tbody>{rows_html}</tbody></table>
<div class="footer">Generated by Vuln-Forge — {escape(domain)} — RED TEAM SCANNER</div>
</body></html>"""


# ========================
# ENTRY POINT
# ========================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)