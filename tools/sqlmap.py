import logging
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

# ========================
# CONSTANTS
# ========================
SQLMAP_PATH    = "/opt/sqlmap/sqlmap.py"
SQLMAP_TIMEOUT = 300        # seconds per URL
SQLMAP_THREADS = 3
SQLMAP_LEVEL   = 3          # 1-5 — higher = more tests
SQLMAP_RISK    = 2          # 1-3 — higher = more risky payloads
SQLMAP_OUTPUT  = "/tmp/sqlmap"


# ========================
# UPDATE
# ========================
def update():
    """Pull latest SQLMap from GitHub."""
    try:
        log.info("Updating SQLMap...")
        result = subprocess.run(
            ["git", "-C", "/opt/sqlmap", "pull"],
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode == 0:
            log.info("SQLMap updated successfully.")
        else:
            log.warning(f"SQLMap update returned code {result.returncode}: {result.stderr.strip()}")
    except subprocess.TimeoutExpired:
        log.warning("SQLMap update timed out — continuing with existing version.")
    except FileNotFoundError:
        log.warning("git not found — skipping SQLMap update.")
    except Exception as e:
        log.warning(f"SQLMap update failed: {e} — continuing with existing version.")


# ========================
# PARSE OUTPUT
# ========================
def parse_output(process) -> list:
    """
    Stream and parse SQLMap stdout line by line.
    Returns a list of finding dicts.
    """
    results  = []
    finding  = {}
    seen     = set()  # dedup key: (parameter, type, payload)

    current_param = ""
    dbms          = ""

    for line in process.stdout:
        log.debug(f"[sqlmap] {line.rstrip()}")

        l = line.strip().lstrip("-").strip()

        # ------------------------
        # PARAMETER (start block)
        # ------------------------
        if l.startswith("Parameter:"):
            # Example: "Parameter: id (GET)"
            current_param = l.split("Parameter:")[1].strip().split(" ")[0]
            finding = {}

        # ------------------------
        # TYPE
        # ------------------------
        elif l.startswith("Type:"):
            finding["type"] = l.split("Type:", 1)[1].strip()

        # ------------------------
        # TITLE
        # ------------------------
        elif l.startswith("Title:"):
            finding["title"] = l.split("Title:", 1)[1].strip()

        # ------------------------
        # PAYLOAD → complete finding
        # ------------------------
        elif l.startswith("Payload:") and finding.get("type") and finding.get("title"):
            payload = l.split("Payload:", 1)[1].strip()

            # Deduplicate on (parameter, type, payload)
            dedup_key = (current_param, finding.get("type", ""), payload)
            if dedup_key in seen:
                finding = {}
                continue
            seen.add(dedup_key)

            finding["payload"]   = payload
            finding["parameter"] = current_param
            if dbms:
                finding["dbms"] = dbms

            results.append({
                "type":     "SQL Injection",
                "severity": "High",
                "tool":     "sqlmap",
                "details":  finding.copy()
            })

            log.info(f"SQLi found — param: {current_param} | type: {finding.get('type')}")
            finding = {}

        # ------------------------
        # DBMS — match specific patterns only
        # ------------------------
        elif l.startswith("back-end DBMS:") or l.startswith("web server operating system:"):
            dbms = l.strip()

    return results


# ========================
# RUN
# ========================
def run(url: str) -> list:
    """
    Run SQLMap against a single URL.
    Returns a list of vulnerability dicts.
    """
    if not url:
        log.warning("SQLMap called with empty URL — skipping.")
        return []

    cmd = [
        "python3", SQLMAP_PATH,
        "-u", url,
        "--batch",
        "--random-agent",
        f"--threads={SQLMAP_THREADS}",
        f"--level={SQLMAP_LEVEL}",
        f"--risk={SQLMAP_RISK}",
        f"--output-dir={SQLMAP_OUTPUT}",
        "--no-logging",
    ]

    log.info(f"SQLMap scanning: {url}")

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,   # separate stderr
            text=True
        )

        results = parse_output(process)

        # Wait for process with timeout
        try:
            _, stderr = process.communicate(timeout=SQLMAP_TIMEOUT)
            if stderr:
                log.debug(f"SQLMap stderr: {stderr.strip()}")
        except subprocess.TimeoutExpired:
            process.kill()
            log.error(f"SQLMap timed out after {SQLMAP_TIMEOUT}s for {url}")

        if process.returncode not in (0, None) and process.returncode != 1:
            log.warning(f"SQLMap exited with code {process.returncode} for {url}")

        log.info(f"SQLMap found {len(results)} finding(s) for {url}")
        return results

    except FileNotFoundError:
        log.error(f"SQLMap not found at {SQLMAP_PATH} — is it installed?")
        return []

    except Exception as e:
        log.error(f"SQLMap unexpected error for {url}: {e}")
        return []


# ========================
# STANDALONE
# ========================
if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s"
    )

    parser = argparse.ArgumentParser(description="Run SQLMap standalone")
    parser.add_argument("-u", "--url", required=True, help="Target URL with parameter")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    update()
    findings = run(args.url)

    print(f"\n[+] Total findings: {len(findings)}")
    for f in findings:
        print(f"  → {f['details'].get('parameter')} | {f['details'].get('type')} | {f['details'].get('payload')}")