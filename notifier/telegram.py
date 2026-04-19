import json
import logging
import os
import time
from pathlib import Path

import requests

log = logging.getLogger(__name__)

# ========================
# CONSTANTS
# ========================
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID", "")
TELEGRAM_API_URL   = "https://api.telegram.org/bot{token}/sendMessage"
MAX_MSG_LEN        = 4000   # Telegram limit is 4096, keep buffer
MSG_RATE_LIMIT     = 1.0    # seconds between messages
DEFAULT_LIMIT      = 50     # max vulnerabilities to report


# ========================
# HELPERS
# ========================
def escape_html(text: object) -> str:
    """Escape text for Telegram HTML parse_mode (&, <, >)."""
    if text is None:
        return ""
    s = str(text)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def format_finding(row: tuple) -> str:
    """Format a single vulnerability row into a Telegram message block."""
    vuln_type, target, severity, tool, details_json = row

    try:
        d = json.loads(details_json) if details_json else {}
    except json.JSONDecodeError:
        d = {}

    parameter = d.get("parameter", "N/A")
    payload   = d.get("payload",   "N/A")
    msg       = d.get("msg",       "")

    # Severity emoji
    severity_emoji = {
        "critical": "🔴",
        "high":     "🟠",
        "medium":   "🟡",
        "low":      "🟢",
        "info":     "⚪",
    }.get(str(severity).lower(), "⚪")

    info_line = f"<b>Info:</b> {escape_html(msg)}\n" if msg else ""

    return (
        f"{severity_emoji} <b>{escape_html(vuln_type)}</b> | <code>{escape_html(tool)}</code>\n"
        f"<b>Target:</b> <code>{escape_html(target)}</code>\n"
        f"<b>Parameter:</b> <code>{escape_html(parameter)}</code>\n"
        f"<b>Payload:</b> <code>{escape_html(payload)}</code>\n"
        f"<b>Severity:</b> {escape_html(severity)}\n"
        f"{info_line}"
        f"{'─' * 30}\n"
    )


def send_message(token: str, chat_id: str, text: str) -> bool:
    """Send a single message to Telegram. Returns True on success."""
    url = TELEGRAM_API_URL.format(token=token)
    try:
        response = requests.post(
            url,
            json={
                "chat_id":    chat_id,
                "text":       text,
                "parse_mode": "HTML",
            },
            timeout=10
        )
        data = response.json()
        if data.get("ok"):
            return True
        else:
            log.warning(f"Telegram error: {data.get('description', 'Unknown error')}")
            return False

    except requests.exceptions.Timeout:
        log.error("Telegram request timed out.")
        return False

    except requests.exceptions.ConnectionError as e:
        log.error(f"Telegram connection error: {e}")
        return False

    except Exception as e:
        log.error(f"Telegram unexpected error: {e}")
        return False


# ========================
# MAIN ENTRY POINT
# ========================
def send_telegram_alert(conn, limit: int = DEFAULT_LIMIT) -> None:
    """
    Fetch latest vulnerabilities from the database and send them to Telegram.
    Messages are split to respect Telegram's 4096 character limit.
    """
    # Validate credentials
    token   = TELEGRAM_BOT_TOKEN
    chat_id = TELEGRAM_CHAT_ID

    if not token:
        log.warning("TELEGRAM_BOT_TOKEN not set — skipping Telegram notification.")
        return

    if not chat_id:
        log.warning("TELEGRAM_CHAT_ID not set — skipping Telegram notification.")
        return

    cursor = conn.cursor()

    # Fetch all columns sorted by severity
    cursor.execute("""
        SELECT type, target, severity, tool, details
        FROM vulnerabilities
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high'     THEN 2
                WHEN 'medium'   THEN 3
                WHEN 'low'      THEN 4
                ELSE            5
            END,
            id DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()

    if not rows:
        log.warning("No vulnerabilities to report — skipping Telegram alert.")
        return

    log.info(f"Sending {len(rows)} finding(s) to Telegram...")

    # ========================
    # BUILD MESSAGES
    # ========================
    # Severity summary
    severity_counts = {}
    for _, _, severity, _, _ in rows:
        key = str(severity).lower()
        severity_counts[key] = severity_counts.get(key, 0) + 1

    summary = " | ".join(
        f"{escape_html(str(s).upper())}: {c}"
        for s, c in severity_counts.items()
    )

    header = (
        f"🔍 <b>Vuln-Forge Scan Results</b>\n"
        f"<b>Total findings:</b> {len(rows)}\n"
        f"{summary}\n"
        f"{'─' * 30}\n\n"
    )

    lines = [header]
    for row in rows:
        try:
            lines.append(format_finding(row))
        except Exception as e:
            log.debug(f"Skipping malformed finding: {e}")
            continue

    # ========================
    # SPLIT + SEND
    # ========================
    msg          = ""
    sent_count   = 0
    failed_count = 0

    for line in lines:
        if len(msg) + len(line) > MAX_MSG_LEN:
            if send_message(token, chat_id, msg):
                sent_count += 1
            else:
                failed_count += 1
            msg = ""
            time.sleep(MSG_RATE_LIMIT)

        msg += line

    # Send remainder
    if msg.strip():
        if send_message(token, chat_id, msg):
            sent_count += 1
        else:
            failed_count += 1

    log.info(f"Telegram alert complete — {sent_count} message(s) sent, {failed_count} failed.")


# ========================
# STANDALONE
# ========================
if __name__ == "__main__":
    import argparse
    from database import get_connection, init_db

    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s"
    )

    parser = argparse.ArgumentParser(description="Send Telegram vulnerability alert standalone")
    parser.add_argument("-db",  "--database", required=True, help="Path to existing .db file")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="Max findings to send")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    DB_PATH = Path(args.database)
    if not DB_PATH.exists():
        log.error(f"Database not found: {DB_PATH}")
        exit(1)

    conn = get_connection(DB_PATH)
    init_db(conn)

    try:
        send_telegram_alert(conn, limit=args.limit)
    finally:
        conn.close()