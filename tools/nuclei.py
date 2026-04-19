import json
import logging
import subprocess
import tempfile
from pathlib import Path

log = logging.getLogger(__name__)

# ========================
# CONSTANTS
# ========================
NUCLEI_TIMEOUT      = 600   # seconds for entire scan (10 minutes)
NUCLEI_RATE_LIMIT   = 50    # requests per second
NUCLEI_CONCURRENCY  = 10    # concurrent template executions
NUCLEI_MIN_SEVERITY = "low" # minimum severity: info, low, medium, high, critical


# ========================
# UPDATE
# ========================
def update():
    """Update Nuclei templates."""
    try:
        log.info("Updating Nuclei templates...")
        result = subprocess.run(
            ["nuclei", "-update-templates"],
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode == 0:
            log.info("Nuclei templates updated successfully.")
        else:
            log.warning(f"Nuclei template update returned code {result.returncode}: {result.stderr.strip()}")
    except subprocess.TimeoutExpired:
        log.warning("Nuclei template update timed out — continuing with existing templates.")
    except FileNotFoundError:
        log.error("Nuclei binary not found — is it installed and on PATH?")
    except Exception as e:
        log.warning(f"Nuclei template update failed: {e} — continuing with existing templates.")


# ========================
# RUN
# ========================
def run(targets: list) -> list:
    """
    Run Nuclei scan against a list of targets.
    Returns a list of raw Nuclei result dicts.
    """
    if not targets:
        log.warning("Nuclei called with empty targets list — skipping.")
        return []

    # Filter out empty targets
    targets = [t for t in targets if t and t.strip()]
    if not targets:
        log.warning("All Nuclei targets were empty after filtering — skipping.")
        return []

    log.info(f"Nuclei scanning {len(targets)} targets...")

    targets_file = None
    results      = []

    try:
        # Write targets to temp file
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            delete=False,
            prefix="nuclei_targets_"
        ) as f:
            f.write("\n".join(targets))
            targets_file = f.name

        log.debug(f"Nuclei targets written to: {targets_file}")

        cmd = [
            "nuclei",
            "-l",            targets_file,
            "-j",                               # JSON output
            "-silent",                          # no banner
            "-no-color",
            "-rate-limit",   str(NUCLEI_RATE_LIMIT),
            "-concurrency",  str(NUCLEI_CONCURRENCY),
            "-severity",     NUCLEI_MIN_SEVERITY,
        ]

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,     # separate stderr
            text=True
        )

        # Stream stdout line by line
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue

            log.debug(f"[nuclei] {line}")

            try:
                data = json.loads(line)
                results.append(data)
                template_id = data.get("template-id", "unknown")
                severity    = data.get("info", {}).get("severity", "info")
                matched_at  = data.get("matched-at", "")
                log.info(f"Nuclei hit — [{severity}] {template_id} @ {matched_at}")
            except json.JSONDecodeError:
                log.debug(f"Skipping non-JSON Nuclei line: {line[:80]}")
                continue

        # Wait for process with timeout
        try:
            _, stderr = process.communicate(timeout=NUCLEI_TIMEOUT)
            if stderr:
                log.debug(f"Nuclei stderr: {stderr.strip()}")
        except subprocess.TimeoutExpired:
            process.kill()
            log.error(f"Nuclei timed out after {NUCLEI_TIMEOUT}s")

        if process.returncode not in (0, None) and process.returncode != 1:
            log.warning(f"Nuclei exited with code {process.returncode}")

        log.info(f"Nuclei found {len(results)} result(s)")
        return results

    except FileNotFoundError:
        log.error("Nuclei binary not found — is it installed and on PATH?")
        return []

    except Exception as e:
        log.error(f"Nuclei unexpected error: {e}")
        return []

    finally:
        # Always clean up temp file
        if targets_file:
            Path(targets_file).unlink(missing_ok=True)
            log.debug(f"Nuclei targets temp file deleted: {targets_file}")


# ========================
# STANDALONE
# ========================
if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s"
    )

    parser = argparse.ArgumentParser(description="Run Nuclei standalone")
    parser.add_argument("-u", "--url",     help="Single target URL")
    parser.add_argument("-l", "--list",    help="File containing list of targets")
    parser.add_argument("--update",        action="store_true", help="Update templates before scanning")
    parser.add_argument("--debug",         action="store_true", help="Enable debug output")
    args = parser.parse_args()

    if not args.url and not args.list:
        parser.error("Provide either -u URL or -l target-list-file")

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.update:
        update()

    if args.url:
        scan_targets = [args.url]
    else:
        scan_targets = Path(args.list).read_text().splitlines()
        scan_targets = [t.strip() for t in scan_targets if t.strip()]

    findings = run(scan_targets)

    print(f"\n[+] Total findings: {len(findings)}")
    for f in findings:
        severity   = f.get("info", {}).get("severity", "info")
        template   = f.get("template-id", "unknown")
        matched_at = f.get("matched-at", "")
        print(f"  → [{severity}] {template} @ {matched_at}")