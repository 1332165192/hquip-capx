"""Install the pinned CLI, retrying only transient dependency-network failures."""
import os
import subprocess
import sys
import time

VERSION = "v2.12.0"
TRANSIENT = ("stream error", "INTERNAL_ERROR", "connection reset", "unexpected EOF", "TLS handshake timeout", "i/o timeout", "temporary failure")


def main():
    environment = os.environ.copy()
    # This affects only Go's dependency download process. HTTPS verification and
    # module checksum verification remain enabled; application HTTP/2 stays on.
    debug = [part for part in environment.get("GODEBUG", "").split(",") if part and not part.startswith("http2client=")]
    environment["GODEBUG"] = ",".join(debug + ["http2client=0"])
    command = ["go", "install", "github.com/wailsapp/wails/v2/cmd/wails@" + VERSION]
    for attempt in range(1, 4):
        print(f"Install Wails {VERSION}, attempt {attempt}/3", flush=True)
        result = subprocess.run(command, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = result.stdout.decode("utf-8", errors="replace")
        print(output, end="", flush=True)
        if result.returncode == 0:
            return
        if "SECURITY ERROR" in output or "checksum mismatch" in output.lower():
            raise SystemExit(result.returncode)
        if attempt == 3 or not any(marker.lower() in output.lower() for marker in TRANSIENT):
            raise SystemExit(result.returncode)
        time.sleep(attempt * 5)


if __name__ == "__main__":
    main()
