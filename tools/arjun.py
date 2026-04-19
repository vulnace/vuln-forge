import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path

log = logging.getLogger(__name__)

# ========================
# CONSTANTS
# ========================
ARJUN_TIMEOUT    = 300   # seconds per URL (5 minutes)
ARJUN_THREADS    = 5     # concurrent requests
ARJUN_DELAY      = 0     # delay between requests in seconds


def run(url: str) -> list:
    """
    Run Arjun parameter discovery against a single URL.
    Returns a list of discovered parameter names, or empty list on failure.
    """
    if not url:
        log.warning("Arjun called with empty URL — skipping.")
        return []

    output_path: Path | None = None
    try:
        fd, tmp_name = tempfile.mkstemp(suffix=".json", prefix="arjun_")
        os.close(fd)
        output_path = Path(tmp_name)

        cmd = [
            "arjun",
            "-u",        url,
            "--threads", str(ARJUN_THREADS),
            "--delay",   str(ARJUN_DELAY),
            "-oJ",       str(output_path),
            "-q",
        ]

        log.info(f"Running Arjun for: {url}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=ARJUN_TIMEOUT
        )

        if result.returncode != 0:
            log.error(f"Arjun exited with code {result.returncode}")
            if result.stderr:
                log.debug(f"Arjun stderr: {result.stderr.strip()}")
            return []

        if result.stderr:
            log.debug(f"Arjun stderr: {result.stderr.strip()}")

        params = []
        if output_path.exists():
            try:
                data = json.loads(output_path.read_text())
                for target_url, found_params in data.items():
                    if isinstance(found_params, list):
                        for param in found_params:
                            param = param.strip()
                            if param:
                                params.append(param)
                                log.debug(f"Arjun found param: {param}")
            except (json.JSONDecodeError, Exception) as e:
                log.error(f"Arjun failed to parse output JSON: {e}")
                return []
        else:
            log.debug(f"Arjun produced no output file for: {url}")

        log.info(f"Arjun found {len(params)} parameter(s) for {url}")
        return params

    except FileNotFoundError:
        log.error("Arjun binary not found — is it installed and on PATH?")
        return []

    except subprocess.TimeoutExpired:
        log.error(f"Arjun timed out after {ARJUN_TIMEOUT}s for {url}")
        return []

    except Exception as e:
        log.error(f"Arjun unexpected error for {url}: {e}")
        return []

    finally:
        if output_path is not None:
            output_path.unlink(missing_ok=True)


# ========================
# STANDALONE
# ========================
if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s"
    )

    parser = argparse.ArgumentParser(description="Run Arjun standalone")
    parser.add_argument("-u", "--url",   required=True, help="Target URL")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    params = run(args.url)

    print(f"\n[+] Total parameters found: {len(params)}")
    for p in sorted(params):
        print(f"  → {p}")