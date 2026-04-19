import logging
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

# ========================
# CONSTANTS
# ========================
GAU_TIMEOUT    = 300   # seconds for entire scan (5 minutes)
GAU_THREADS    = 5     # concurrent requests
GAU_RETRIES    = 2     # retries per request


def run(domain: str) -> set:
    """
    Run gau (GetAllURLs) to fetch known URLs for a domain
    from AlienVault OTX, Wayback Machine, and Common Crawl.
    Returns a set of discovered URLs, or empty set on failure.
    """
    if not domain:
        log.warning("gau called with empty domain — skipping.")
        return set()

    cmd = [
        "gau",
        domain,
        "--threads",  str(GAU_THREADS),
        "--retries",  str(GAU_RETRIES),
    ]

    log.info(f"Running gau for: {domain}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=GAU_TIMEOUT
        )

        if result.returncode != 0:
            log.error(f"gau exited with code {result.returncode}")
            if result.stderr:
                log.debug(f"gau stderr: {result.stderr.strip()}")
            return set()

        if result.stderr:
            log.debug(f"gau stderr: {result.stderr.strip()}")

        urls = set()
        for line in result.stdout.splitlines():
            url = line.strip()
            if not url:
                continue
            # Only store valid HTTP URLs
            if url.startswith(("http://", "https://")):
                urls.add(url)
            else:
                log.debug(f"Skipping non-HTTP gau output: {url}")

        log.info(f"gau found {len(urls)} URL(s) for {domain}")
        return urls

    except FileNotFoundError:
        log.error("gau binary not found — is it installed and on PATH?")
        return set()

    except subprocess.TimeoutExpired:
        log.error(f"gau timed out after {GAU_TIMEOUT}s for {domain}")
        return set()

    except Exception as e:
        log.error(f"gau unexpected error: {e}")
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

    parser = argparse.ArgumentParser(description="Run gau standalone")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    urls = run(args.domain)

    print(f"\n[+] Total URLs found: {len(urls)}")
    for url in sorted(urls):
        print(f"  → {url}")