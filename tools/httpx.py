import logging
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

# ========================
# CONSTANTS
# ========================
HTTPX_TIMEOUT     = 300   # seconds for entire scan (5 minutes)
HTTPX_CONCURRENCY = 50    # concurrent probes
HTTPX_REQ_TIMEOUT = 10    # seconds per HTTP request


def run(subdomains: list) -> set:
    """
    Run httpx to probe a list of subdomains for live hosts.
    Returns a set of live URLs (with protocol), or empty set on failure.
    """
    if not subdomains:
        log.warning("httpx called with empty subdomains list — skipping.")
        return set()

    # Filter empty entries
    subdomains = [s for s in subdomains if s and s.strip()]
    if not subdomains:
        log.warning("All httpx subdomains were empty after filtering — skipping.")
        return set()

    log.info(f"Running httpx on {len(subdomains)} subdomain(s)...")

    cmd = [
        "httpx",
        "-silent",
        "-no-color",
        "-threads",  str(HTTPX_CONCURRENCY),
        "-timeout",  str(HTTPX_REQ_TIMEOUT),
    ]

    live_hosts = set()

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
            log.debug("stdbuf not found — running httpx without line buffering wrapper")
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

        # Send subdomains via stdin
        input_data = "\n".join(subdomains) + "\n"
        process.stdin.write(input_data)
        process.stdin.close()

        # Stream stdout line by line
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue

            log.debug(f"[httpx] {line}")

            if line.startswith(("http://", "https://")):
                live_hosts.add(line)
                log.info(f"Live host: {line}")
            else:
                log.debug(f"Skipping non-HTTP httpx output: {line}")

        # Wait with timeout — use wait() instead of communicate() since stdout already read
        try:
            process.wait(timeout=HTTPX_TIMEOUT)
            stderr = process.stderr.read() if process.stderr else ""
            if stderr:
                log.debug(f"httpx stderr: {stderr.strip()}")
        except subprocess.TimeoutExpired:
            process.kill()
            log.error(f"httpx timed out after {HTTPX_TIMEOUT}s")

        if process.returncode not in (0, None, 1):
            log.warning(f"httpx exited with code {process.returncode}")

        log.info(f"httpx found {len(live_hosts)} live host(s)")
        return live_hosts

    except FileNotFoundError:
        log.error("httpx binary not found — is it installed and on PATH?")
        return set()

    except Exception as e:
        log.error(f"httpx unexpected error: {e}")
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

    parser = argparse.ArgumentParser(description="Run httpx standalone")
    parser.add_argument("-u", "--url",  help="Single target subdomain or URL")
    parser.add_argument("-l", "--list", help="File containing list of subdomains")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    if not args.url and not args.list:
        parser.error("Provide either -u URL or -l subdomains-file")

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.url:
        targets = [args.url]
    else:
        targets = Path(args.list).read_text().splitlines()
        targets = [t.strip() for t in targets if t.strip()]

    hosts = run(targets)

    print(f"\n[+] Total live hosts found: {len(hosts)}")
    for host in sorted(hosts):
        print(f"  → {host}")