import logging
import time
from pathlib import Path

import requests

log = logging.getLogger(__name__)

# ========================
# CONSTANTS
# ========================
CRTSH_URL     = "https://crt.sh/?q=%.{domain}&output=json"  # % is wildcard, not %25
CRTSH_TIMEOUT = 30      # seconds per request
CRTSH_RETRIES = 3       # number of retries on failure
CRTSH_BACKOFF = 5       # seconds between retries


def run(domain: str) -> set:
    """
    Fetch subdomains from crt.sh certificate transparency logs.
    Returns a set of discovered subdomains, or empty set on failure.
    """
    if not domain:
        log.warning("crt.sh called with empty domain — skipping.")
        return set()

    url = CRTSH_URL.format(domain=domain)
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept":     "application/json"
    }

    log.info(f"Fetching subdomains from crt.sh for: {domain}")

    # Retry loop
    data = None
    for attempt in range(1, CRTSH_RETRIES + 1):
        try:
            response = requests.get(url, headers=headers, timeout=CRTSH_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            break   # success — exit retry loop

        except requests.exceptions.Timeout:
            log.warning(f"crt.sh timed out (attempt {attempt}/{CRTSH_RETRIES})")
            if attempt < CRTSH_RETRIES:
                time.sleep(CRTSH_BACKOFF)
            else:
                log.error("crt.sh timed out — all retries exhausted.")
                return set()

        except requests.exceptions.HTTPError as e:
            log.error(f"crt.sh HTTP error: {e}")
            return set()

        except requests.exceptions.ConnectionError as e:
            log.warning(f"crt.sh connection error (attempt {attempt}/{CRTSH_RETRIES}): {e}")
            if attempt < CRTSH_RETRIES:
                time.sleep(CRTSH_BACKOFF)
            else:
                log.error("crt.sh connection failed — all retries exhausted.")
                return set()

        except ValueError:
            log.error("crt.sh returned invalid JSON.")
            return set()

        except Exception as e:
            log.error(f"crt.sh unexpected error: {e}")
            return set()

    if not data:
        return set()

    subdomains = set()

    for entry in data:
        name_value = entry.get("name_value", "")
        for sub in name_value.split("\n"):
            sub = sub.strip().lower()

            # Strip wildcard prefix
            if sub.startswith("*."):
                sub = sub[2:]

            # Strict domain match
            if sub == domain or sub.endswith(f".{domain}"):
                subdomains.add(sub)
            else:
                log.debug(f"Skipping out-of-scope subdomain: {sub}")

    log.info(f"crt.sh found {len(subdomains)} subdomains for {domain}")
    return subdomains


# ========================
# STANDALONE
# ========================
if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s"
    )

    parser = argparse.ArgumentParser(description="Run crt.sh lookup standalone")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    subdomains = run(args.domain)

    print(f"\n[+] Total subdomains found: {len(subdomains)}")
    for sub in sorted(subdomains):
        print(f"  → {sub}")