import logging
from pathlib import Path

from tools import crtsh, amass, subfinder
from database import insert_subdomains

log = logging.getLogger(__name__)


def run_subdomain_enum(domain: str, conn, active: bool = False) -> None:
    """
    Run subdomain enumeration using crt.sh, Amass, and Subfinder.
    Results are deduplicated and stored in the database.
    """
    if not domain:
        log.warning("Subdomain enumeration called with empty domain — skipping.")
        return

    log.info(f"Starting subdomain enumeration for: {domain}")

    all_subdomains = set()

    # ========================
    # CRT.SH
    # ========================
    try:
        log.info("Running crt.sh...")
        crt_results = crtsh.run(domain)
        log.info(f"crt.sh found {len(crt_results)} subdomains")
        all_subdomains |= crt_results
    except Exception as e:
        log.error(f"crt.sh failed: {e}")

    # ========================
    # AMASS
    # ========================
    try:
        log.info("Running Amass...")
        amass_results = amass.run(domain, active=active)
        log.info(f"Amass found {len(amass_results)} subdomains")
        all_subdomains |= amass_results
    except Exception as e:
        log.error(f"Amass failed: {e}")

    # ========================
    # SUBFINDER
    # ========================
    try:
        log.info("Running Subfinder...")
        subfinder_results = subfinder.run(domain)
        log.info(f"Subfinder found {len(subfinder_results)} subdomains")
        all_subdomains |= subfinder_results
    except Exception as e:
        log.error(f"Subfinder failed: {e}")

    # ========================
    # STORE
    # ========================
    log.info(f"Total unique subdomains discovered: {len(all_subdomains)}")

    inserted = insert_subdomains(conn, all_subdomains)
    conn.commit()
    log.info(f"Subdomains stored in database: {inserted} new")


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

    parser = argparse.ArgumentParser(description="Run subdomain enumeration standalone")
    parser.add_argument("-d", "--domain",   required=True, help="Target domain")
    parser.add_argument("-db", "--database", required=True, help="Path to existing .db file")
    parser.add_argument("--active", action="store_true", help="Enable active Amass scanning")
    parser.add_argument("--debug",  action="store_true", help="Enable debug output")
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
        run_subdomain_enum(args.domain, conn, active=args.active)
    finally:
        conn.close()