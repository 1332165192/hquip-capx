#!/usr/bin/env python3
"""capx M5 Frida driver.

Attaches to a target process, loads a Frida agent script, and relays the
agent's send() messages to stdout as one compact JSON object per line. capx
(Go) reads these lines and turns TLS messages into HookEvents. Binary payloads
delivered via Frida's send(msg, data) are base64-encoded into `data_b64`.

Usage: driver.py --pid <pid> --agent <script.js>
       driver.py --spawn <program> [args...] --agent <script.js>

--spawn starts the program suspended, loads the agent, then resumes it, so TLS
traffic from process startup is captured (frida.attach only sees an already-
running process). The spawned pid is reported back as {"event":"spawned"}.

Exit codes: 0 normal, 2 frida missing, 3 attach/load failure.
"""
import argparse
import base64
import json
import os
import sys
import threading


_dbg = os.environ.get("CAPX_HOOK_DEBUG")
_out_lock = threading.Lock()


def out(obj):
    line = json.dumps(obj, separators=(",", ":"))
    with _out_lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
    if _dbg:
        try:
            with open(_dbg, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--spawn", default="")
    ap.add_argument("--agent", required=True)
    args, extra = ap.parse_known_args()

    try:
        import frida
    except Exception as e:  # noqa: BLE001
        out({"event": "error", "stage": "import", "fatal": True, "msg": "frida import failed: %s" % e})
        sys.exit(2)

    try:
        with open(args.agent, "r", encoding="utf-8") as f:
            source = f.read()
    except OSError as e:
        out({"event": "error", "stage": "read", "fatal": True, "msg": "read agent: %s" % e})
        sys.exit(3)

    spawned_pid = 0
    if args.spawn:
        # Spawn suspended so the agent is in place before any TLS happens, then
        # resume after the script loads (below).
        try:
            argv = [args.spawn] + list(extra)
            spawned_pid = frida.spawn(argv)
            out({"event": "spawned", "pid": spawned_pid})
            session = frida.attach(spawned_pid)
        except Exception as e:  # noqa: BLE001
            out({"event": "error", "stage": "attach", "fatal": True, "msg": "spawn %s: %s" % (args.spawn, e)})
            if spawned_pid:
                try:
                    frida.resume(spawned_pid)
                except Exception:
                    pass
            sys.exit(3)
    else:
        if not args.pid:
            out({"event": "error", "msg": "either --pid or --spawn is required"})
            sys.exit(3)
        try:
            session = frida.attach(args.pid)
        except Exception as e:  # noqa: BLE001
            out({"event": "error", "stage": "attach", "fatal": True, "msg": "attach pid %d: %s" % (args.pid, e)})
            sys.exit(3)

    stop = threading.Event()
    failed = threading.Event()
    cleaning_up = threading.Event()

    def on_message(message, data):
        if message.get("type") == "error":
            out({"event": "error", "stage": "script", "fatal": True,
                 "msg": message.get("stack") or message.get("description", "script error")})
            failed.set()
            stop.set()
            return
        if message.get("type") != "send":
            return
        payload = message.get("payload") or {}
        ev = dict(payload) if isinstance(payload, dict) else {"event": "message", "msg": str(payload)}
        if data is not None:
            ev["data_b64"] = base64.b64encode(data).decode("ascii")
        out(ev)
        if ev.get("fatal") and (ev.get("event") == "error" or ev.get("stage") == "error"):
            failed.set()
            stop.set()

    def on_detached(reason, *rest):
        if not cleaning_up.is_set():
            out({"event": "error", "stage": "detached", "fatal": True,
                 "msg": "session detached: %s" % reason})
            failed.set()
        stop.set()

    resumed = False
    try:
        session.on("detached", on_detached)
        script = session.create_script(source)
        script.on("message", on_message)
        script.load()
        # script.load() can return normally after an asynchronous top-level JS
        # error callback. Do not report loaded or wait forever in that case.
        if failed.is_set():
            return 3
        out({"event": "loaded", "pid": spawned_pid or args.pid})
        if spawned_pid:
            frida.resume(spawned_pid)
            resumed = True
        while not stop.wait(0.5):
            pass
        return 3 if failed.is_set() else 0
    except Exception as e:  # noqa: BLE001
        out({"event": "error", "stage": "load", "fatal": True, "msg": "load script: %s" % e})
        return 3
    finally:
        cleaning_up.set()
        # Only a target spawned by this driver is resumed; attaching never
        # suspends/resumes or terminates an existing target.
        if spawned_pid and not resumed:
            try:
                frida.resume(spawned_pid)
            except Exception:
                pass
        try:
            session.detach()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
