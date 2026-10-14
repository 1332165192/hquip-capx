"""Fetch pinned Go modules before testing; keep application HTTP/2 unchanged."""
from pathlib import Path
import argparse
import importlib.util
import os
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
TRANSIENT = ("stream error", "INTERNAL_ERROR", "connection reset", "unexpected EOF", "TLS handshake timeout", "i/o timeout", "temporary failure", "502 Bad Gateway", "503 Service Unavailable")


def download_module(module):
    environment = os.environ.copy()
    debug = [part for part in environment.get("GODEBUG", "").split(",") if part and not part.startswith("http2client=")]
    environment["GODEBUG"] = ",".join(debug + ["http2client=0"])
    for attempt in range(1, 4):
        print(f"Fetch pinned {module} modules, attempt {attempt}/3", flush=True)
        result = subprocess.run(["go", "mod", "download"], cwd=ROOT / module, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = result.stdout.decode("utf-8", errors="replace")
        print(output, end="", flush=True)
        if result.returncode == 0:
            return
        if "SECURITY ERROR" in output or "checksum mismatch" in output.lower():
            raise SystemExit(result.returncode)
        if attempt == 3 or not any(marker.lower() in output.lower() for marker in TRANSIENT):
            raise SystemExit(result.returncode)
        time.sleep(attempt * 5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--module", choices=["capx", "capx-desktop", "capx-web-manager"], action="append")
    args = parser.parse_args()
    for module in args.module or ["capx", "capx-desktop", "capx-web-manager"]:
        download_module(module)


if __name__ == "__main__":
    main()
