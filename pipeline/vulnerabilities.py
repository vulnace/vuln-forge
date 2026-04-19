import json
import tempfile
from pathlib import Path

import logging
import subprocess
import time

from database import insert_vulnerability
from tools import nuclei, sqlmap, dalfox, nikto

log = logging.getLogger(__name__)

# ========================
# CONSTANTS
# ========================
IGNORE_EXT = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg",
    ".css", ".js", ".woff", ".woff2", ".ttf", ".ico"
}

MAX_ENDPOINTS   = 500
MAX_PARAM_URLS  = 100
MAX_TOOL_INPUTS = 20  # SQLMap + Dalfox input cap
MAX_NIKTO_HOSTS = 10  # Nikto runs per host, can be slow


# ========================
# HELPERS
# ========================
def is_valid_url(url: str) -> bool:
    """Return True if the URL should be included in scans (not a static asset)."""
    return bool(url) and not any(url.lower().endswith(ext) for ext in IGNORE_EXT)


def sanitize_url(url: str) -> str | None:
    """
    Basic URL sanitization — reject clearly malformed or dangerous URLs.
    Returns None if the URL should be skipped.
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        log.debug(f"Skipping non-HTTP URL: {url}")
        return None
    if len(url) > 2048:
        log.debug(f"Skipping oversized URL ({len(url)} chars)")
        return None
    return url


# ========================
# DATA LOADING
# ========================
def load_targets(cursor) -> tuple[list, list, list]:
    """Load and return (hosts, endpoints, param_urls) from the database."""

    # Live hosts
    cursor.execute("SELECT host FROM live_hosts")
    hosts = list({r[0] for r in cursor.fetchall()})
    log.info(f"Live hosts: {len(hosts)}")

    # Endpoints
    cursor.execute("SELECT url FROM endpoints")
    raw_endpoints = [u[0] for u in cursor.fetchall()]
    endpoints = []
    for url in raw_endpoints:
        clean = sanitize_url(url)
        if clean and is_valid_url(clean):
            endpoints.append(clean)
    endpoints = list(set(endpoints))
    log.info(f"Valid endpoints: {len(endpoints)}")

    # Parameters from Arjun
    cursor.execute("SELECT url, parameter FROM parameters")
    rows = cursor.fetchall()
    param_urls = []
    for url, param in rows:
        if not param:
            log.debug(f"Skipping empty param for URL: {url}")
            continue
        if "=" in param:
            log.debug(f"Skipping param with '=' (already contains value): {param}")
            continue
        if "http" in param:
            log.debug(f"Skipping suspicious param value: {param}")
            continue
        test_url = f"{url}?{param}=1"
        clean = sanitize_url(test_url)
        if clean and is_valid_url(clean):
            param_urls.append(clean)

    # Parameters from Katana/Gau (endpoints with inline params)
    for url in raw_endpoints:
        if "?" in url and "=" in url:
            clean = sanitize_url(url)
            if clean and is_valid_url(clean):
                param_urls.append(clean)
    log.info(f"Inline param URLs from endpoints: {len([u for u in raw_endpoints if '?' in u and '=' in u])}")

    # Final dedup
    param_urls = list(set(param_urls))
    log.info(f"Total parameter URLs: {len(param_urls)}")

    return hosts, endpoints, param_urls


# ========================
# SQL TECHNOLOGY DETECTION
# ========================
def detect_sql_technology(conn, nuclei_targets: list) -> bool:
    """
    Check if target uses SQL database by:
    1. Checking existing Nuclei results in DB
    2. Running Nuclei tech detection
    """
    SQL_TECHNOLOGIES = {
        "mysql", "postgresql", "mssql", "sqlite",
        "oracle", "mariadb", "phpmyadmin", "adminer",
        "wordpress", "wp-", "joomla", "drupal",
        "laravel", "django", "rails", "symfony"
    }

    # ========================
    # CHECK EXISTING DB RESULTS FIRST
    # ========================
    cursor = conn.cursor()
    cursor.execute("SELECT type, details FROM vulnerabilities WHERE tool = 'nuclei'")
    rows = cursor.fetchall()

    for vuln_type, details_json in rows:
        try:
            details     = json.loads(details_json) if details_json else {}
            template_id = vuln_type.lower()
            name        = details.get("name", "").lower()
            if any(sql in template_id or sql in name for sql in SQL_TECHNOLOGIES):
                log.info(f"SQL technology detected from existing results: {name or vuln_type}")
                return True
        except Exception:
            continue

    # ========================
    # RUN NUCLEI TECH DETECTION
    # ========================
    targets_file = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            delete=False,
            prefix="nuclei_tech_"
        ) as f:
            f.write("\n".join(nuclei_targets))
            targets_file = f.name

        cmd = [
            "nuclei",
            "-l",     targets_file,
            "-tags",  "tech",
            "-j",
            "-silent",
            "-no-color",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        for line in result.stdout.splitlines():
            try:
                data        = json.loads(line)
                template_id = data.get("template-id", "").lower()
                name        = data.get("info", {}).get("name", "").lower()
                if any(sql in template_id or sql in name for sql in SQL_TECHNOLOGIES):
                    log.info(f"SQL technology detected from tech scan: {name}")
                    return True
            except json.JSONDecodeError:
                continue

    except Exception as e:
        log.warning(f"Tech detection failed: {e} — running SQLMap anyway")
        return True

    finally:
        if targets_file:
            Path(targets_file).unlink(missing_ok=True)

    log.info("No SQL technology detected — skipping SQLMap")
    return False


# ========================
# NUCLEI
# ========================
def run_nuclei_scan(conn, targets: list) -> int:
    if not targets:
        log.warning("No Nuclei targets — skipping.")
        return 0

    log.info(f"Total Nuclei targets: {len(targets)}")

    try:
        log.info("Updating Nuclei templates...")
        subprocess.run(
            ["nuclei", "-update-templates"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60
        )
        log.info("Nuclei templates updated.")
    except subprocess.TimeoutExpired:
        log.warning("Nuclei template update timed out — continuing with existing templates.")
    except FileNotFoundError:
        log.error("nuclei binary not found — skipping Nuclei scan.")
        return 0

    count = 0
    try:
        log.info("Running Nuclei...")
        results = nuclei.run(targets)
        for res in results:
            template_id = res.get("template-id", "nuclei")
            matched_url = res.get("matched-at", "")
            severity    = res.get("info", {}).get("severity", "info")
            details = {
                "severity":     severity,
                "name":         res.get("info", {}).get("name", ""),
                "url":          res.get("url", ""),
                "path":         res.get("path", ""),
                "template-id":  template_id,
                "template":     res.get("template", ""),
                "template-url": res.get("template-url", ""),
            }
            if insert_vulnerability(conn, template_id, matched_url, severity, "nuclei", details):
                count += 1
    except Exception as e:
        log.error(f"Nuclei scan failed: {e}")

    log.info(f"Nuclei findings: {count}")
    return count


# ========================
# NIKTO
# ========================
def run_nikto_scan(conn, hosts: list) -> int:
    if not hosts:
        log.warning("No Nikto targets — skipping.")
        return 0

    count = 0
    log.info("Running Nikto...")
    for i, host in enumerate(hosts, 1):
        log.info(f"Nikto [{i}/{len(hosts)}]: {host}")
        try:
            results = nikto.run(host)
            for r in results:
                if insert_vulnerability(conn, r["type"], r["target"], r["severity"], "nikto", r["details"]):
                    count += 1
        except Exception as e:
            log.error(f"Nikto failed for {host}: {e}")

    log.info(f"Nikto findings: {count}")
    return count


# ========================
# SQLMAP
# ========================
def run_sqlmap_scan(conn, urls: list) -> int:
    if not urls:
        log.warning("No SQLMap targets — skipping.")
        return 0

    count = 0
    log.info("Running SQLMap...")
    for i, url in enumerate(urls, 1):
        log.info(f"SQLMap [{i}/{len(urls)}]: {url}")
        try:
            results = sqlmap.run(url)
            for r in results:
                severity  = r.get("severity", "High")
                details   = r.get("details", {})
                vuln_type = r.get("type", "SQLi")
                if insert_vulnerability(conn, vuln_type, url, severity, "sqlmap", details):
                    count += 1
        except Exception as e:
            log.error(f"SQLMap failed for {url}: {e}")
        time.sleep(0.5)

    log.info(f"SQLMap findings: {count}")
    return count


# ========================
# DALFOX
# ========================
def run_dalfox_scan(conn, urls: list) -> int:
    if not urls:
        log.warning("No Dalfox targets — skipping.")
        return 0

    count = 0
    log.info("Running Dalfox...")
    for i, url in enumerate(urls, 1):
        log.info(f"Dalfox [{i}/{len(urls)}]: {url}")
        try:
            results = dalfox.run([url])
            for r in results:
                xss_url  = r.get("url", url)
                xss_type = r.get("details", {}).get("type", "XSS")
                severity = r.get("severity", "High")
                details  = r.get("details", {})
                if insert_vulnerability(conn, xss_type, xss_url, severity, "dalfox", details):
                    count += 1
        except Exception as e:
            log.error(f"Dalfox failed for {url}: {e}")
        time.sleep(0.5)

    log.info(f"Dalfox findings: {count}")
    return count


# ========================
# MAIN ENTRY POINT
# ========================
def run_vulnerability_scan(conn, test_mode: bool = False):
    cursor = conn.cursor()

    # Empty table warnings
    cursor.execute("SELECT COUNT(*) FROM live_hosts")
    if cursor.fetchone()[0] == 0:
        log.warning("live_hosts table is empty — did you run the full pipeline first?")

    cursor.execute("SELECT COUNT(*) FROM endpoints")
    if cursor.fetchone()[0] == 0:
        log.warning("endpoints table is empty — did you run the full pipeline first?")

    cursor.execute("SELECT COUNT(*) FROM parameters")
    if cursor.fetchone()[0] == 0:
        log.warning("parameters table is empty — did you run the full pipeline first?")

    # ========================
    # TEST MODE
    # ========================
    if test_mode:
        log.warning("TEST MODE — all inputs capped to 1")
        max_endpoints   = 1
        max_param_urls  = 1
        max_tool_inputs = 1
        max_nikto_hosts = 1
    else:
        max_endpoints   = MAX_ENDPOINTS
        max_param_urls  = MAX_PARAM_URLS
        max_tool_inputs = MAX_TOOL_INPUTS
        max_nikto_hosts = MAX_NIKTO_HOSTS

    # ========================
    # LOAD TARGETS
    # ========================
    hosts, endpoints, param_urls = load_targets(cursor)

    # Apply limits with warnings
    if len(endpoints) > max_endpoints:
        log.warning(f"Capping endpoints from {len(endpoints)} to {max_endpoints}")
        endpoints = endpoints[:max_endpoints]

    if len(param_urls) > max_param_urls:
        log.warning(f"Capping param_urls from {len(param_urls)} to {max_param_urls}")
        param_urls = param_urls[:max_param_urls]

    tool_urls = [
        u for u in param_urls
        if "=" in u and "?http" not in u
    ][:max_tool_inputs]

    nikto_hosts = hosts[:max_nikto_hosts]
    if len(hosts) > max_nikto_hosts:
        log.warning(f"Capping Nikto hosts from {len(hosts)} to {max_nikto_hosts}")

    # Nuclei gets all targets — deduplicate BEFORE combining
    nuclei_targets = list(set(hosts + endpoints + param_urls))

    # ========================
    # RUN SCANS
    # ========================
    run_nuclei_scan(conn, nuclei_targets)
    conn.commit()
    log.debug("Nuclei results committed.")

    run_nikto_scan(conn, nikto_hosts)
    conn.commit()
    log.debug("Nikto results committed.")

    if detect_sql_technology(conn, nuclei_targets):
        run_sqlmap_scan(conn, tool_urls)
        conn.commit()
        log.debug("SQLMap results committed.")
    else:
        log.info("SQLMap skipped — no SQL database detected on target.")

    run_dalfox_scan(conn, tool_urls)
    conn.commit()
    log.debug("Dalfox results committed.")

    log.info("All vulnerability results stored in database.")


# ========================
# STANDALONE
# ========================
if __name__ == "__main__":
    import argparse
    from database import get_connection, init_db
    from notifier import discord, telegram
    from utils import view_vulnerabilities

    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s"
    )

    parser = argparse.ArgumentParser(description="Run vulnerability scan standalone")
    parser.add_argument("-db",       "--database",  required=True,        help="Path to existing .db file")
    parser.add_argument("--debug",   action="store_true",                 help="Enable debug output")
    parser.add_argument("--no-notify", action="store_true",               help="Skip Discord and Telegram notifications")
    parser.add_argument("--test",    action="store_true",                 help="Quick test mode — limit all inputs to 1")
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
        run_vulnerability_scan(conn, test_mode=args.test)

        if not args.no_notify:
            try:
                discord.send_discord_alert(conn)
            except Exception as e:
                log.warning(f"Discord notification failed: {e}")

            try:
                telegram.send_telegram_alert(conn)
            except Exception as e:
                log.warning(f"Telegram notification failed: {e}")

        # Always show results in terminal
        view_vulnerabilities.run(conn)

    finally:
        conn.close()