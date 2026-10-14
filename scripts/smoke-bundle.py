"""Verify freshly compiled backend/MCP startup without opening a GUI or devices."""
from pathlib import Path
import argparse
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", type=Path)
    args = parser.parse_args()
    suffix = ".exe" if os.name == "nt" else ""
    backend = (args.stage / ("capx-captured" + suffix)).resolve()
    mcp = (args.stage / ("capx-mcp" + suffix)).resolve()
    with tempfile.TemporaryDirectory(prefix="capx-ci-smoke-") as scratch:
        directory = Path(scratch)
        state = directory / "state"
        env = {**os.environ, "CAPX_AUTH":"1", "CAPX_TOKEN":"", "CAPX_TOKEN_FILE":"", "CAPX_ALLOW_ACTIVE":"0", "CAPX_DATA_DIR":str(directory/"ca"), "CAPX_DNSLOG_DEFAULTS_FILE":str(directory/"unused-defaults.json")}
        log_path = directory / "startup.log"
        with log_path.open("wb") as log:
            process = subprocess.Popen([str(backend), "-addr", "127.0.0.1:0", "-state-dir", str(state), "-instance-id", "ci-smoke", "-generation", "ci-smoke-generation"], env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic()+20
                base = None
                while time.monotonic()<deadline:
                    if process.poll() is not None: raise RuntimeError("compiled backend exited during startup")
                    match = re.search(r"listening on (http://127\.0\.0\.1:\d+)", log_path.read_text(errors="replace"))
                    if match: base = match.group(1); break
                    time.sleep(.1)
                if not base: raise RuntimeError("compiled backend startup timed out")
                token = (state/"token").read_text().strip()
                if not token or token in log_path.read_text(errors="replace"): raise RuntimeError("startup authentication/credential logging failed")
                # Explicit loopback-only requests never consult the runner's
                # proxy settings or install an interception certificate.
                client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                def api(path, body=None, auth=True):
                    headers={"Content-Type":"application/json"}
                    if auth: headers["Authorization"]="Bearer "+token
                    request=urllib.request.Request(base+path, data=None if body is None else json.dumps(body).encode(), headers=headers)
                    with client.open(request, timeout=5) as response: return response.status, json.load(response)
                try:
                    api("/api/policy", auth=False)
                except urllib.error.HTTPError as error:
                    if error.code!=401: raise
                else: raise RuntimeError("compiled backend accepted an unauthenticated API request")
                _, health=api("/health")
                identity=health.get("identity",{})
                if identity.get("instance_id")!="ci-smoke" or identity.get("generation")!="ci-smoke-generation": raise RuntimeError("compiled backend runtime identity mismatch")
                if api("/api/policy")[1].get("active_allowed") is not False: raise RuntimeError("compiled backend unexpectedly enables active mode")
                requests=[{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}, {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"capx_health","arguments":{}}}]
                result=subprocess.run([str(mcp)], input="".join(json.dumps(request)+"\n" for request in requests), env={**env,"CAPX_API":base,"CAPX_TOKEN_FILE":str(state/"token"),"CAPX_MCP_ACTIVE":"0"}, capture_output=True,text=True,timeout=15,check=True)
                replies=[json.loads(line) for line in result.stdout.splitlines() if line.strip()]
                if {reply.get("id") for reply in replies}!={1,2} or any(reply.get("error") or reply.get("result",{}).get("isError") for reply in replies): raise RuntimeError("compiled MCP handshake/health request failed")
                status,_=api("/api/runtime/shutdown",{"expected_instance_id":"ci-smoke","expected_generation":"ci-smoke-generation"})
                if status!=202: raise RuntimeError("compiled backend rejected authenticated shutdown")
                process.wait(timeout=10)
                if process.returncode!=0: raise RuntimeError("compiled backend shutdown was not clean")
                print("Compiled bundle smoke PASS: startup, token auth, identity, inactive policy, MCP, authenticated shutdown")
            finally:
                if process.poll() is None:
                    process.terminate()
                    try: process.wait(timeout=5)
                    except subprocess.TimeoutExpired: process.kill();process.wait(timeout=5)


if __name__ == "__main__":
    main()
