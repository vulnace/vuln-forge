import logging
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

# ========================
# CONSTANTS
# ========================
KATANA_TIMEOUT     = 300   # seconds for entire scan (5 minutes)
KATANA_DEPTH       = 3     # crawl depth
KATANA_CONCURRENCY = 10    # concurrent requests
KATANA_RATE_LIMIT  = 50    # requests per second


def run(hosts: list) -> set:
    """
    Run Katana crawler against a list of hosts.
    Returns a set of discovered endpoint URLs.
    """
    if not hosts:
        log.warning("Katana called with empty hosts list — skipping.")
        return set()

    # Filter empty entries
    hosts = [h for h in hosts if h and h.strip()]
    if not hosts:
        log.warning("All Katana hosts were empty after filtering — skipping.")
        return set()

    log.info(f"Running Katana on {len(hosts)} host(s)...")

    cmd = [
        "katana",
        "-silent",
        "-no-color",
        "-depth",       str(KATANA_DEPTH),
        "-concurrency", str(KATANA_CONCURRENCY),
        "-rate-limit",  str(KATANA_RATE_LIMIT),
    ]

    endpoints = set()

    try:
        try:
            process = subprocess.Popen(
                ["stdbuf", "-oL", *cmd],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError:
            log.debug("stdbuf not found — running katana without line buffering wrapper")
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

        # Send hosts via stdin
        input_data = "\n".join(hosts) + "\n"
        process.stdin.write(input_data)
        process.stdin.close()

        # Stream stdout line by line
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue

            log.debug(f"[katana] {line}")

            if line.startswith(("http://", "https://")):
                endpoints.add(line)
            else:
                log.debug(f"Skipping non-HTTP Katana output: {line}")

        # Wait with timeout — use wait() instead of communicate() since stdout already read
        try:
            process.wait(timeout=KATANA_TIMEOUT)
            stderr = process.stderr.read() if process.stderr else ""
            if stderr:
                log.debug(f"Katana stderr: {stderr.strip()}")
        except subprocess.TimeoutExpired:
            process.kill()
            log.error(f"Katana timed out after {KATANA_TIMEOUT}s")

        if process.returncode not in (0, None, 1):
            log.warning(f"Katana exited with code {process.returncode}")

        log.info(f"Katana found {len(endpoints)} endpoint(s)")
        return endpoints

    except FileNotFoundError:
        log.error("Katana binary not found — is it installed and on PATH?")
        return set()

    except Exception as e:
        log.error(f"Katana unexpected error: {e}")
        return set()


# ========================
# STANDALONE
# ========================
if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s"
    )

    parser = argparse.ArgumentParser(description="Run Katana standalone")
    parser.add_argument("-u", "--url",  help="Single target URL")
    parser.add_argument("-l", "--list", help="File containing list of hosts")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    if not args.url and not args.list:
        parser.error("Provide either -u URL or -l hosts-file")

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.url:
        scan_hosts = [args.url]
    else:
        scan_hosts = Path(args.list).read_text().splitlines()
        scan_hosts = [h.strip() for h in scan_hosts if h.strip()]

    endpoints = run(scan_hosts)

    print(f"\n[+] Total endpoints found: {len(endpoints)}")
    for ep in sorted(endpoints):
        print(f"  → {ep}")