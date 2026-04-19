import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from tools import arjun
from database import insert_parameter

log = logging.getLogger(__name__)

# ========================
# CONSTANTS
# ========================
MAX_URLS       = 100   # max endpoints to run Arjun on
MAX_WORKERS    = 3     # parallel Arjun scans — keep low to avoid hammering target

IGNORE_EXT = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg",
    ".css", ".js", ".woff", ".woff2", ".ttf", ".ico"
}

HIGH_VALUE_KEYWORDS = {
    "api", "user", "login", "auth", "search",
    "account", "admin", "token", "password", "reset",
    "register", "profile", "upload", "download", "config"
}


# ========================
# HELPERS
# ========================
def is_valid_endpoint(url: str) -> bool:
    """Return True if the URL is worth scanning for parameters."""
    return bool(url) and not any(url.lower().endswith(ext) for ext in IGNORE_EXT)


def is_high_value(url: str) -> bool:
    """Return True if the URL contains high-value keywords."""
    url_lower = url.lower()
    return any(k in url_lower for k in HIGH_VALUE_KEYWORDS)


# ========================
# MAIN ENTRY POINT
# ========================
def run_parameter_discovery(conn) -> None:
    """
    Run Arjun parameter discovery on endpoints stored in the database.
    Discovered parameters are stored in the parameters table.
    """
    cursor = conn.cursor()

    # ========================
    # LOAD ENDPOINTS
    # ========================
    cursor.execute("SELECT url FROM endpoints")
    rows = cursor.fetchall()
    all_urls = [r[0] for r in rows if r[0]]

    if not all_urls:
        log.warning("No endpoints found in database — skipping parameter discovery.")
        return

    # ========================
    # FILTER
    # ========================
    valid_urls = [u for u in all_urls if is_valid_endpoint(u)]
    log.info(f"Valid endpoints for Arjun: {len(valid_urls)} / {len(all_urls)}")

    if not valid_urls:
        log.warning("No valid endpoints after filtering — skipping.")
        return

    # ========================
    # PRIORITIZE
    # ========================
    high_value = [u for u in valid_urls if is_high_value(u)]
    high_set = set(high_value)
    others = [u for u in valid_urls if u not in high_set]

    log.info(f"High-value endpoints: {len(high_value)} | Others: {len(others)}")

    # High-value first, then others, capped at MAX_URLS
    final_urls = (high_value + others)[:MAX_URLS]
    log.info(f"Running Arjun on {len(final_urls)} endpoints (max_workers={MAX_WORKERS})")

    # ========================
    # PARALLEL EXECUTION
    # ========================
    total_inserted = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {
            executor.submit(arjun.run, url): url
            for url in final_urls
        }

        for future in as_completed(future_to_url):
            url = future_to_url[future]

            try:
                params = future.result()

                if not params:
                    log.debug(f"Arjun found no params for: {url}")
                    continue

                # Deduplicate using set
                unique_params = set(params)
                inserted = 0

                for param in unique_params:
                    param = param.strip()
                    if not param:
                        continue
                    if insert_parameter(conn, url, param):
                        inserted += 1

                if inserted:
                    log.info(f"Arjun [{url}] — {inserted} new parameter(s) stored")
                    total_inserted += inserted

            except Exception as e:
                log.error(f"Arjun failed for {url}: {e}")

    # ========================
    # COMMIT + SUMMARY
    # ========================
    conn.commit()
    log.info(f"Parameter discovery complete — total parameters stored: {total_inserted}")


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

    parser = argparse.ArgumentParser(description="Run parameter discovery standalone")
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
        run_parameter_discovery(conn)
    finally:
        conn.close()