import json
import logging
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

# ========================
# CONSTANTS
# ========================
DALFOX_TIMEOUT = 300    # seconds per URL (3 minutes)
DALFOX_WORKERS = 3      # concurrent workers per URL
DALFOX_REQ_TIMEOUT = 10 # seconds per HTTP request


# ========================
# UPDATE
# ========================
def update():
    """Update Dalfox binary via Go."""
    try:
        log.info("Updating Dalfox...")
        result = subprocess.run(
            ["go", "install", "github.com/hahwul/dalfox/v2@latest"],
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode == 0:
            log.info("Dalfox updated successfully.")
        else:
            log.warning(f"Dalfox update returned code {result.returncode}: {result.stderr.strip()}")
    except subprocess.TimeoutExpired:
        log.warning("Dalfox update timed out — continuing with existing version.")
    except FileNotFoundError:
        log.warning("go not found — skipping Dalfox update.")
    except Exception as e:
        log.warning(f"Dalfox update failed: {e} — continuing with existing version.")


# ========================
# PARSE OUTPUT
# ========================
def parse_output(stdout: str, url: str) -> list:
    """
    Parse Dalfox JSON output lines.
    Returns a deduplicated list of finding dicts.
    """
    results = []
    seen = set()  # dedup key: (parameter, payload)

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)

            parameter = data.get("parameter", "")
            payload   = data.get("payload", "")

            # Deduplicate on (parameter, payload)
            dedup_key = (parameter, payload)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            results.append({
                "url": url,
                "severity": "High",
                "details": {
                    "type":      "XSS",
                    "parameter": parameter,
                    "payload":   payload,
                    "evidence":  data.get("evidence", ""),
                    "vector":    data.get("vector", ""),
                    "cwe":       data.get("cwe", ""),
                }
            })

            log.info(f"XSS found — param: {parameter} | payload: {payload[:60]}")

        except json.JSONDecodeError:
            log.debug(f"Skipping non-JSON Dalfox line: {line[:80]}")
            continue

    return results


# ========================
# RUN
# ========================
def run(urls: list) -> list:
    """
    Run Dalfox XSS scan against a list of URLs.
    Returns a list of vulnerability dicts.
    """
    if not urls:
        log.warning("Dalfox called with empty URL list — skipping.")
        return []

    all_results = []

    for url in urls:
        if not url:
            log.debug("Skipping empty URL in Dalfox input.")
            continue

        log.info(f"Dalfox scanning: {url}")

        cmd = [
            "dalfox",
            "url", url,
            "--format",   "json",
            "--silence",
            "--no-color",
            "--worker",   str(DALFOX_WORKERS),
            "--timeout",  str(DALFOX_REQ_TIMEOUT),
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=DALFOX_TIMEOUT
            )

            # Log stderr at debug level regardless of exit code
            if proc.stderr:
                log.debug(f"Dalfox stderr for {url}: {proc.stderr.strip()}")

            # Non-zero exit doesn't always mean failure in Dalfox
            if proc.returncode not in (0, 1):
                log.warning(f"Dalfox exited with code {proc.returncode} for {url}")

            findings = parse_output(proc.stdout, url)
            log.info(f"Dalfox found {len(findings)} finding(s) for {url}")
            all_results.extend(findings)

        except subprocess.TimeoutExpired:
            log.error(f"Dalfox timed out after {DALFOX_TIMEOUT}s for {url}")

        except FileNotFoundError:
            log.error("Dalfox binary not found — is it installed and on PATH?")
            return []

        except Exception as e:
            log.error(f"Dalfox unexpected error for {url}: {e}")

    return all_results


# ========================
# STANDALONE
# ========================
if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s"
    )

    parser = argparse.ArgumentParser(description="Run Dalfox standalone")
    parser.add_argument("-u", "--url", required=True, help="Target URL with parameter")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--update", action="store_true", help="Update Dalfox before scanning")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.update:
        update()

    findings = run([args.url])

    print(f"\n[+] Total findings: {len(findings)}")
    for f in findings:
        print(f"  → {f['details'].get('parameter')} | {f['details'].get('payload')}")