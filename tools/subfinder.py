import logging
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

SUBFINDER_TIMEOUT = 300  # 5 minutes


def run(domain: str) -> set:
    """
    Run Subfinder passive subdomain enumeration for the given domain.
    Returns a set of discovered subdomains, or an empty set on failure.
    """
    if not domain:
        log.warning("Subfinder called with empty domain — skipping.")
        return set()

    cmd = [
        "subfinder",
        "-d",      domain,
        "-silent",
    ]

    log.info(f"Running Subfinder for: {domain}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SUBFINDER_TIMEOUT
        )

        if result.returncode != 0:
            log.error(f"Subfinder exited with code {result.returncode}")
            if result.stderr:
                log.debug(f"Subfinder stderr: {result.stderr.strip()}")
            return set()

        if result.stderr:
            log.debug(f"Subfinder stderr: {result.stderr.strip()}")

        subdomains = set()
        for line in result.stdout.splitlines():
            sub = line.strip().lower()
            if sub == domain or sub.endswith(f".{domain}"):
                subdomains.add(sub)

        log.info(f"Subfinder found {len(subdomains)} subdomains for {domain}")
        return subdomains

    except FileNotFoundError:
        log.error("Subfinder binary not found — is it installed and on PATH?")
        return set()

    except subprocess.TimeoutExpired:
        log.error(f"Subfinder timed out after {SUBFINDER_TIMEOUT}s for {domain}")
        return set()

    except Exception as e:
        log.error(f"Subfinder unexpected error: {e}")
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

    parser = argparse.ArgumentParser(description="Run Subfinder standalone")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    subdomains = run(args.domain)

    print(f"\n[+] Total subdomains found: {len(subdomains)}")
    for sub in sorted(subdomains):
        print(f"  → {sub}")