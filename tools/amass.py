import logging
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

AMASS_PASSIVE_TIMEOUT = 300   # 5 minutes
AMASS_ACTIVE_TIMEOUT  = 900   # 15 minutes


def run(domain: str, active: bool = False) -> set:
    """
    Run Amass subdomain enumeration for the given domain.
    Returns a set of discovered subdomains, or an empty set on failure.
    """
    if not domain:
        log.warning("Amass called with empty domain — skipping.")
        return set()

    mode    = "active" if active else "passive"
    timeout = AMASS_ACTIVE_TIMEOUT if active else AMASS_PASSIVE_TIMEOUT

    cmd = ["amass", "enum", "-d", domain]
    if not active:
        cmd.append("-passive")

    log.info(f"Running Amass ({mode}) for: {domain}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if result.returncode != 0:
            log.error(f"Amass exited with code {result.returncode}")
            if result.stderr:
                log.debug(f"Amass stderr: {result.stderr.strip()}")
            return set()

        if result.stderr:
            log.debug(f"Amass stderr: {result.stderr.strip()}")

        subdomains = set()
        for line in result.stdout.splitlines():
            sub = line.strip().lower()
            if sub == domain or sub.endswith(f".{domain}"):
                subdomains.add(sub)

        log.info(f"Amass found {len(subdomains)} subdomains for {domain}")
        return subdomains

    except FileNotFoundError:
        log.error("Amass binary not found — is it installed and on PATH?")
        return set()

    except subprocess.TimeoutExpired:
        log.error(f"Amass timed out after {timeout}s for {domain}")
        return set()

    except Exception as e:
        log.error(f"Amass unexpected error: {e}")
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

    parser = argparse.ArgumentParser(description="Run Amass standalone")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("--active", action="store_true", help="Enable active scanning mode")
    parser.add_argument("--debug",  action="store_true", help="Enable debug output")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    subdomains = run(args.domain, active=args.active)

    print(f"\n[+] Total subdomains found: {len(subdomains)}")
    for sub in sorted(subdomains):
        print(f"  → {sub}")