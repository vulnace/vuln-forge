import logging
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

# ========================
# CONSTANTS
# ========================
NIKTO_TIMEOUT = 300     # 5 minutes per host
NIKTO_TUNING  = "123b"  # 1=interesting, 2=misconfigured, 3=info disclosure, b=software identification

# Lines to skip — Nikto header/info lines
SKIP_PATTERNS = [
    "Target IP", "Target Hostname", "Target Port",
    "Start Time", "End Time", "SSL Info", "Platform",
    "Server:", "Nikto v", "---", "CGI Directories",
    "requests made", "host(s) tested"
]


# ========================
# SEVERITY MAPPING
# ========================
def map_severity(vuln_id: str, msg: str) -> str:
    """Map Nikto finding to severity level based on message content."""
    msg_lower = msg.lower()

    if any(k in msg_lower for k in [
        "remote code execution", "rce", "command injection",
        "sql injection", "sqli", "file inclusion", "rfi", "lfi"
    ]):
        return "critical"

    if any(k in msg_lower for k in [
        "xss", "cross-site scripting", "csrf",
        "authentication bypass", "default password",
        "admin", "backup", "config", "exposed"
    ]):
        return "high"

    if any(k in msg_lower for k in [
        "outdated", "deprecated", "insecure",
        "misconfigured", "weak", "directory listing",
        "sensitive", "disclosure"
    ]):
        return "medium"

    if any(k in msg_lower for k in [
        "information", "header", "banner",
        "version", "server", "fingerprint",
        "missing", "retrieved"
    ]):
        return "low"

    return "info"


# ========================
# RUN
# ========================
def run(host: str) -> list:
    """
    Run Nikto web server scanner against a single host.
    Parses text output directly since Nikto 2.6.0 JSON format is unreliable.
    Returns a list of vulnerability dicts, or empty list on failure.
    """
    if not host:
        log.warning("Nikto called with empty host — skipping.")
        return []

    log.info(f"Running Nikto for: {host}")

    cmd = [
        "nikto",
        "-h",      host,
        "-Tuning", NIKTO_TUNING,
        "-nointeractive",
        "-maxtime", f"{NIKTO_TIMEOUT}s",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=NIKTO_TIMEOUT + 30  # extra buffer beyond Nikto's own timeout
        )

        if result.stderr:
            log.debug(f"Nikto stderr: {result.stderr.strip()}")

        if not result.stdout:
            log.info(f"Nikto produced no output for: {host}")
            return []

        # ========================
        # PARSE TEXT OUTPUT
        # ========================
        results = []
        seen    = set()  # dedup on (vuln_id, url)

        for line in result.stdout.splitlines():
            line = line.strip()

            # Only process finding lines
            if not line.startswith("+"):
                continue

            # Skip header/info lines
            if any(skip in line for skip in SKIP_PATTERNS):
                continue

            # Extract ID if present
            # Format: "+ [999986] /path: message"
            vuln_id = "nikto"
            msg     = line.lstrip("+ ").strip()

            if line.startswith("+ ["):
                try:
                    vuln_id = line.split("[")[1].split("]")[0].strip()
                    msg     = line.split("]", 1)[1].strip().lstrip(": ").strip()
                except Exception:
                    pass

            # Extract URL from message if path present
            # Format: "/path: message text"
            url = host
            if ": " in msg:
                parts = msg.split(": ", 1)
                if parts[0].startswith("/"):
                    url = host.rstrip("/") + parts[0]
                    msg = parts[1].strip() if len(parts) > 1 else msg

            msg = msg.strip()
            if not msg:
                continue

            # Deduplicate on (vuln_id, url)
            dedup_key = (vuln_id, url)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            severity = map_severity(vuln_id, msg)

            details = {
                "id":  vuln_id,
                "url": url,
                "msg": msg,
            }

            results.append({
                "type":     f"nikto-{vuln_id}",
                "target":   url,
                "severity": severity,
                "tool":     "nikto",
                "details":  details,
            })

            log.info(f"Nikto hit — [{severity}] {msg[:80]}")

        log.info(f"Nikto found {len(results)} finding(s) for {host}")
        return results

    except subprocess.TimeoutExpired:
        log.error(f"Nikto timed out after {NIKTO_TIMEOUT}s for {host}")
        return []

    except FileNotFoundError:
        log.error("Nikto binary not found — is it installed and on PATH?")
        return []

    except Exception as e:
        log.error(f"Nikto unexpected error for {host}: {e}")
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

    parser = argparse.ArgumentParser(description="Run Nikto standalone")
    parser.add_argument("-u", "--url",   required=True, help="Target host URL")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    findings = run(args.url)

    print(f"\n[+] Total findings: {len(findings)}")
    for f in findings:
        print(f"  → [{f['severity']}] {f['details'].get('msg', '')[:80]}")