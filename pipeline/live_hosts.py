import logging
from pathlib import Path

from tools import httpx
from database import insert_live_hosts

log = logging.getLogger(__name__)


def run_live_host_scan(conn) -> None:
    """
    Probe all subdomains in the database for live hosts using httpx.
    Results are stored in the live_hosts table.
    """
    cursor = conn.cursor()

    # ========================
    # LOAD SUBDOMAINS
    # ========================
    cursor.execute("SELECT subdomain FROM subdomains")
    rows = cursor.fetchall()
    subdomains = [r[0] for r in rows if r[0]]

    if not subdomains:
        log.warning("No subdomains found in database — skipping live host scan.")
        return

    log.info(f"Probing {len(subdomains)} subdomain(s) for live hosts...")

    # ========================
    # RUN HTTPX
    # ========================
    live = httpx.run(subdomains)

    log.info(f"httpx found {len(live)} live host(s)")

    if not live:
        log.warning("No live hosts found.")
        return

    # ========================
    # STORE
    # ========================
    inserted = insert_live_hosts(conn, live)
    conn.commit()
    log.info(f"Live hosts stored in database: {inserted} new")


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

    parser = argparse.ArgumentParser(description="Run live host scan standalone")
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
        run_live_host_scan(conn)
    finally:
        conn.close()