import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)

# ========================
# ANSI COLORS
# ========================
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
ORANGE = "\033[93m"
YELLOW = "\033[33m"
GREEN  = "\033[92m"
GREY   = "\033[90m"
CYAN   = "\033[96m"

SEVERITY_COLOR = {
    "critical": RED,
    "high":     ORANGE,
    "medium":   YELLOW,
    "low":      GREEN,
    "info":     GREY,
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def colorize(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"


def get_severity_color(severity: str) -> str:
    return SEVERITY_COLOR.get(str(severity).lower(), GREY)


def format_details(details_json: str) -> str:
    """Extract the most useful fields from details JSON for display."""
    try:
        d = json.loads(details_json) if details_json else {}
        parts = []
        if d.get("parameter"):
            parts.append(f"param={d['parameter']}")
        if d.get("payload"):
            payload = d["payload"][:40] + ".." if len(d.get("payload", "")) > 40 else d["payload"]
            parts.append(f"payload={payload}")
        if d.get("name"):
            parts.append(f"name={d['name']}")
        if d.get("msg"):                          # ← add this
            msg = d["msg"][:60] + ".." if len(d.get("msg", "")) > 60 else d["msg"]
            parts.append(f"msg={msg}")
        return " | ".join(parts) if parts else details_json[:60]
    except Exception:
        return str(details_json)[:60]


# ========================
# MAIN ENTRY POINT
# ========================
def run(conn) -> None:
    """
    Display all vulnerabilities from the database in a formatted table,
    sorted by severity with color coding.
    """
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
            END,
            id DESC
    """)
    rows = cursor.fetchall()

    if not rows:
        log.warning("No vulnerabilities found in database.")
        print("\n[!] No vulnerabilities found.\n")
        return

    # ========================
    # SUMMARY
    # ========================
    severity_counts = {}
    for _, _, _, severity, _, _ in rows:
        key = str(severity).lower()
        severity_counts[key] = severity_counts.get(key, 0) + 1

    print(f"\n{BOLD}{CYAN}{'=' * 160}{RESET}")
    print(f"{BOLD}{CYAN}  VULNERABILITY REPORT — {len(rows)} finding(s){RESET}")
    print(f"{BOLD}{CYAN}{'=' * 160}{RESET}")

    # Summary line
    summary_parts = []
    for sev in SEVERITY_ORDER:
        if sev in severity_counts:
            color = get_severity_color(sev)
            summary_parts.append(colorize(f"{sev.upper()}: {severity_counts[sev]}", color))
    print("  " + "  |  ".join(summary_parts))
    print(f"{BOLD}{CYAN}{'=' * 160}{RESET}\n")

    # ========================
    # TABLE HEADER
    # ========================
    print(f"{BOLD}"
          f"{'ID':<5} "
          f"{'SEVERITY':<10} "
          f"{'TYPE':<25} "
          f"{'TOOL':<10} "
          f"{'TARGET':<55} "
          f"DETAILS"
          f"{RESET}")
    print("-" * 160)

    # ========================
    # ROWS
    # ========================
    for id_, type_, target, severity, tool, details in rows:
        color   = get_severity_color(severity)
        target  = target[:53] + ".." if len(target) > 55 else target
        type_   = type_[:23]  + ".." if len(type_) > 25  else type_
        details = format_details(details)

        print(
            f"{colorize(str(id_), color):<5} "
            f"{colorize(str(severity).upper()[:10], color):<10} "
            f"{type_:<25} "
            f"{tool:<10} "
            f"{target:<55} "
            f"{details}"
        )

    print(f"\n{BOLD}{CYAN}{'=' * 160}{RESET}\n")


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

    parser = argparse.ArgumentParser(description="View vulnerabilities from database")
    parser.add_argument("-db", "--database", required=True, help="Path to existing .db file")
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
        run(conn)
    finally:
        conn.close()