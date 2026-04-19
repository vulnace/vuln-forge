#!/usr/bin/env python3
import argparse
import logging
import re
import sys
import time
from pathlib import Path

from database import get_connection, init_db
from pipeline import subdomains, live_hosts, endpoints, parameters, vulnerabilities
from notifier import discord, telegram
from utils import view_vulnerabilities


# ========================
# LOGGING SETUP
# ========================
def setup_logging(debug: bool = False):
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
        ]
    )


log = logging.getLogger(__name__)


# ========================
# DOMAIN VALIDATION
# ========================
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)

def validate_domain(domain: str) -> None:
    if not domain or not DOMAIN_REGEX.match(domain):
        log.error(f"Invalid domain: '{domain}'")
        sys.exit(1)


# ========================
# SAFE PATH
# ========================
def safe_db_path(domain: str) -> Path:
    """Sanitize domain to prevent path traversal when building DB path."""
    safe_name = re.sub(r"[^a-z0-9.\-]", "_", domain)
    path = Path("data") / f"{safe_name}.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


# ========================
# PIPELINE STAGE RUNNER
# ========================
def run_stage(name: str, fn, *args) -> bool:
    """Run a pipeline stage with timing and error handling. Returns False on failure."""
    log.info(f"Starting stage: {name}")
    start = time.time()
    try:
        fn(*args)
        elapsed = time.time() - start
        log.info(f"Stage '{name}' completed in {elapsed:.1f}s")
        return True
    except Exception as e:
        elapsed = time.time() - start
        log.error(f"Stage '{name}' failed after {elapsed:.1f}s: {e}")
        return False


# ========================
# MAIN
# ========================
def main():
    parser = argparse.ArgumentParser(description="Full Recon Scanner")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("--fresh", action="store_true", help="Delete existing database before scan")
    parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompts")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--active", action="store_true", help="Enable active scanning modes") #for amass
    parser.add_argument("--test", action="store_true", help="Quick test mode — limit all inputs to 1")
    parser.add_argument("--no-notify", action="store_true", help="Skip Discord and Telegram notifications")
    args = parser.parse_args()

    setup_logging(debug=args.debug)

    domain = args.domain.strip().lower()
    validate_domain(domain)

    DB_PATH = safe_db_path(domain)

    log.info(f"Target: {domain}")
    log.debug(f"DB path: {DB_PATH.resolve()}")

    # ========================
    # FRESH FLAG
    # ========================
    if args.fresh and DB_PATH.exists():
        if not args.yes:
            confirm = input(f"[?] Delete existing database '{DB_PATH}'? [y/N]: ").strip().lower()
            if confirm != "y":
                log.info("Aborted.")
                sys.exit(0)
        DB_PATH.unlink()
        # Also delete WAL and SHM files
        Path(str(DB_PATH) + "-wal").unlink(missing_ok=True)
        Path(str(DB_PATH) + "-shm").unlink(missing_ok=True)
        log.info("Existing database deleted.")
    elif args.fresh:
        log.info("No existing database found, starting fresh.")

    # ========================
    # DB INIT
    # ========================
    conn = get_connection(DB_PATH)
    init_db(conn)
    log.debug("Database initialized.")

    # ========================
    # PIPELINE
    # ========================
    scan_start = time.time()

    try:
        stages = [
            ("Subdomain Enumeration",   subdomains.run_subdomain_enum,      domain, conn, args.active),   # Crt.sh + Amass + Subfinder
            ("Live Host Scan",          live_hosts.run_live_host_scan,       conn),          # Httpx
            ("Endpoint Discovery",      endpoints.run_endpoint_discovery,    conn),          # Katana + Gau
            ("Parameter Discovery",     parameters.run_parameter_discovery,  conn),          # Arjun
            ("Vulnerability Scan",      vulnerabilities.run_vulnerability_scan, conn, args.test),       # Nuclei + SQLMap + Dalfox
        ]

        for name, fn, *fn_args in stages:
            success = run_stage(name, fn, *fn_args)
            if not success:
                log.warning(f"Stage '{name}' failed — continuing to next stage.")

        # ========================
        # NOTIFICATIONS + REPORT
        # ========================
        if not args.no_notify:
            try:
                discord.send_discord_alert(conn)
            except Exception as e:
                log.warning(f"Discord notification failed: {e}")

            try:
                telegram.send_telegram_alert(conn)
            except Exception as e:
                log.warning(f"Telegram notification failed: {e}")
        else:
            log.info("Notifications skipped due to --no-notify flag.")

        view_vulnerabilities.run(conn)

    finally:
        conn.close()
        total = time.time() - scan_start
        log.info(f"Scan completed in {total:.1f}s")


if __name__ == "__main__":
    main()