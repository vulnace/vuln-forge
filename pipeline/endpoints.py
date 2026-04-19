import logging
from pathlib import Path
from urllib.parse import urlparse

from tools import katana, gau
from database import insert_endpoints

log = logging.getLogger(__name__)


def hostname_for_gau(host_or_url: str) -> str | None:
    """
    gau expects a domain/hostname; live_hosts rows are often full URLs from httpx.
    Returns lowercase hostname without port, or None if parsing fails.
    """
    s = (host_or_url or "").strip()
    if not s:
        return None
    if s.startswith(("http://", "https://")):
        parsed = urlparse(s)
        netloc = parsed.netloc
        if not netloc:
            return None
        if "@" in netloc:
            netloc = netloc.rsplit("@", 1)[-1]
        host = netloc.split(":")[0].strip()
        return host.lower() if host else None
    return s.lower().rstrip("/")


def run_endpoint_discovery(conn) -> None:
    """
    Discover endpoints from live hosts using Katana (crawler)
    and gau (historical URLs). Results are stored in the endpoints table.
    """
    cursor = conn.cursor()

    # ========================
    # LOAD LIVE HOSTS
    # ========================
    cursor.execute("SELECT host FROM live_hosts")
    rows = cursor.fetchall()
    hosts = [r[0] for r in rows if r[0]]

    if not hosts:
        log.warning("No live hosts found in database — skipping endpoint discovery.")
        return

    log.info(f"Discovering endpoints from {len(hosts)} live host(s)...")

    endpoints = set()

    # ========================
    # KATANA — active crawler
    # ========================
    try:
        log.info("Running Katana...")
        katana_results = katana.run(hosts)
        log.info(f"Katana found {len(katana_results)} endpoint(s)")
        endpoints |= katana_results
    except Exception as e:
        log.error(f"Katana failed: {e}")

    # ========================
    # GAU — historical URLs (needs hostname, not https:// URL)
    # ========================
    gau_by_hostname: dict[str, str] = {}
    for host in hosts:
        domain = hostname_for_gau(host)
        if not domain:
            log.warning(f"gau skipped — could not parse hostname from: {host!r}")
            continue
        gau_by_hostname.setdefault(domain, host)

    log.info(f"Running gau on {len(gau_by_hostname)} hostname(s)...")
    gau_total = 0
    for domain, source_url in gau_by_hostname.items():
        try:
            gau_results = gau.run(domain)
            log.debug(f"gau [{domain}] (from {source_url}) — {len(gau_results)} URL(s)")
            gau_total += len(gau_results)
            endpoints |= gau_results
        except Exception as e:
            log.error(f"gau failed for {domain}: {e}")

    log.info(f"gau found {gau_total} endpoint(s) total")

    # ========================
    # STORE
    # ========================
    log.info(f"Total unique endpoints discovered: {len(endpoints)}")

    if not endpoints:
        log.warning("No endpoints discovered.")
        return

    inserted = insert_endpoints(conn, endpoints)
    conn.commit()
    log.info(f"Endpoints stored in database: {inserted} new")


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

    parser = argparse.ArgumentParser(description="Run endpoint discovery standalone")
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
        run_endpoint_discovery(conn)
    finally:
        conn.close()