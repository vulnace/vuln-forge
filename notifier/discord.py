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
DISCORD_WEBHOOK  = os.environ.get("DISCORD_WEBHOOK", "")  # set via environment variable
MAX_MSG_LEN      = 1900    # Discord message limit is 2000, keep buffer
MSG_RATE_LIMIT   = 1.0     # seconds between messages to avoid Discord rate limiting
DEFAULT_LIMIT    = 50      # max vulnerabilities to report


# ========================
# HELPERS
# ========================
def escape_discord_markdown(text: object) -> str:
    """Escape characters that Discord treats as Markdown (webhook content)."""
    if text is None:
        return ""
    s = str(text)
    s = s.replace("\\", "\\\\")
    s = s.replace("*", "\\*")
    s = s.replace("_", "\\_")
    s = s.replace("~", "\\~")
    s = s.replace("`", "\\`")
    s = s.replace("|", "\\|")
    return s


def format_finding(row: tuple) -> str:
    """Format a single vulnerability row into a Discord message block."""
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

    e = escape_discord_markdown
    info_line = f"**Info:** {e(msg)}\n" if msg else ""

    return (
        f"{severity_emoji} **{e(vuln_type)}** | **Tool:** {e(tool)}\n"
        f"**Target:** {e(target)}\n"
        f"**Parameter:** {e(parameter)}\n"
        f"**Payload:** {e(payload)}\n"
        f"**Severity:** {e(severity)}\n"
        f"{info_line}"
        f"---\n"
    )


def send_message(webhook: str, content: str) -> bool:
    """Send a single message to Discord. Returns True on success."""
    try:
        response = requests.post(
            webhook,
            json={"content": content},
            timeout=10
        )
        if response.status_code == 204:
            return True
        else:
            log.warning(f"Discord returned status {response.status_code}: {response.text[:100]}")
            return False
    except requests.exceptions.Timeout:
        log.error("Discord request timed out.")
        return False
    except requests.exceptions.ConnectionError as e:
        log.error(f"Discord connection error: {e}")
        return False
    except Exception as e:
        log.error(f"Discord unexpected error: {e}")
        return False


# ========================
# MAIN ENTRY POINT
# ========================
def send_discord_alert(conn, limit: int = DEFAULT_LIMIT) -> None:
    """
    Fetch latest vulnerabilities from the database and send them to Discord.
    Messages are split to respect Discord's 2000 character limit.
    """
    # Validate webhook
    webhook = DISCORD_WEBHOOK
    if not webhook:
        log.warning("DISCORD_WEBHOOK environment variable not set — skipping notification.")
        return

    cursor = conn.cursor()

    # Fetch all columns — not just details
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
        log.warning("No vulnerabilities to report — skipping Discord alert.")
        return

    log.info(f"Sending {len(rows)} vulnerability finding(s) to Discord...")

    # ========================
    # BUILD MESSAGES
    # ========================
    header = f"🔍 **Vuln-Forge Scan Results** — {len(rows)} finding(s)\n\n"
    lines  = [header]

    for row in rows:
        try:
            lines.append(format_finding(row))
        except Exception as e:
            log.debug(f"Skipping malformed finding: {e}")
            continue

    # ========================
    # SPLIT + SEND
    # ========================
    msg           = ""
    sent_count    = 0
    failed_count  = 0

    for line in lines:
        if len(msg) + len(line) > MAX_MSG_LEN:
            if send_message(webhook, msg):
                sent_count += 1
            else:
                failed_count += 1
            msg = ""
            time.sleep(MSG_RATE_LIMIT)  # respect Discord rate limit

        msg += line

    # Send remainder
    if msg.strip():
        if send_message(webhook, msg):
            sent_count += 1
        else:
            failed_count += 1

    log.info(f"Discord alert complete — {sent_count} message(s) sent, {failed_count} failed.")


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

    parser = argparse.ArgumentParser(description="Send Discord vulnerability alert standalone")
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
        send_discord_alert(conn, limit=args.limit)
    finally:
        conn.close()