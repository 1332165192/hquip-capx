# Capx Web Manager

Capx Web Manager manages legacy Capx processes and registered Codex project
instances from one loopback-only web UI.

## Managed instances

A managed start requires:

- `instance_id`: the value selected by the project's `.codex/config.toml`.
- `project_root`: the project directory containing that config.
- `captured_path`: a `capx-captured` build that supports runtime identity.

API, proxy, and CDP ports are allocated independently. Supplying `0` requests
an operating-system-assigned loopback port; explicit ports are validated and
never remapped. A managed start always launches an isolated Chrome or Edge
profile with the selected proxy and CDP endpoint.

The Manager publishes the verified runtime to:

```text
%LOCALAPPDATA%\capx\instances\<instance_id>.json
```

Publication occurs only after all of these checks pass:

1. The state token exists and is non-empty.
2. `/health` reports the requested `instance_id` and generation.
3. `/api/proxy/status` authenticates with that token and reports the selected proxy.
4. Chrome's `/json/version` is ready and the owning process has the expected CDP, profile, proxy, instance, and generation flags.

Manifest writes contain the token file path, never token contents. They use a
same-directory temporary file, file sync, atomic rename, and a shared OS file
lock also honored by `Register-CapxInstance.ps1`. Startup failures roll back
the new processes and do not publish a manifest.

## Lifecycle

Managed stop verifies the runtime identity and calls the authenticated
`POST /api/runtime/shutdown` endpoint. A force stop is used only when the PID
command line still matches the manifest's instance, generation, and state
directory. Verification and termination use the same Windows process handle,
so PID reuse cannot redirect a stop to another process. After stop, the live
manifest is atomically converted to an offline port/state reservation with its
PID and runtime identity fields removed. Replacement is guarded by generation,
PID, and the shared manifest lock.

On-demand MCP starts may include an owner PID. The Manager monitors that owner
and stops the matching generation when the MCP wrapper exits, including clients
that terminate their stdio process tree without a graceful shutdown handshake.

Capx holds an OS-backed lock for the entire lifetime of its `state_dir`.
Another process cannot reuse that directory, and a crashed owner releases the
kernel lock automatically. Legacy manifests without verified runtime identity
remain visible but are not eligible for a managed stop.

Legacy processes remain visible and retain their existing controls, but they
do not become registered instances until started with an instance ID and
project root.

## SRC connection templates

The start form exposes the managed `instance_id` and `project_root` because a
managed runtime must be bound to exactly one Codex or Claude project. The
project config must select the same `CAPX_INSTANCE_ID`; the Manager verifies
that binding before it starts Capx.

`Generate template` creates one editable, complete SRC session template. The
template persists only the stable instance ID and project root. API, Proxy,
CDP, state directory, and token file are resolved from the current instance
manifest when the PowerShell session starts. Template generation does not turn
automatic ports into fixed ports.

`Select directory` beside the project root opens the native Windows folder
picker. After selection, the Manager reads `.codex/config.toml`,
`.claude/config.toml`, or `.mcp.json`, fills the configured
`CAPX_INSTANCE_ID`, and can filter the table to that project's managed
instances. Instance ID and project root are a pair: both values select managed
mode; two empty values select legacy API/Proxy mode.

The JADX directory has its own native folder picker for Manager-side launching
and workspace navigation. Machine-specific tool paths are not exported into
the generated SRC template. The picker recognizes common `jadx`, `jadx-gui`,
and `bin/jadx` launchers.

Every running row also has an `SRC template` action. The endpoint uses the row
only to select the stable instance identity and runtime stage; generated text
does not contain the row's ports, state directory, token file, or token. It
contains:

- A PowerShell manifest resolver with instance, project, health, generation,
  proxy, and token-path verification.
- Runtime-generated `capture` and `capx` YAML for compatible local clients.
- Codex and Claude `CAPX_INSTANCE_ID` binding fragments.
- A token-free dynamic connection JSON object.
- A Chinese full-coverage SRC queue for fingerprinting, all parameter
  positions, identity/resource/session binding, App client surfaces, business
  state machines, evidence, retesting, progress, and Gate.

Runtime tokens are not returned in SRC template text. PowerShell reads the
manifest's `token_file` after validating that it is inside the instance state
directory and injects the token only into the current process. The durable
registry continues to store only `token_file`.

Legacy proxy browsers and ADB mappings are recorded in
`%LOCALAPPDATA%\capx-web-manager\runtime-sessions.json`. Stopping one row
cleans its Ghost process, ADB proxy/reverse mapping, and recorded proxy browser
before stopping Capx. `Stop all services` performs the same cleanup globally.
Failed ADB cleanup remains registered and can be retried after the device is
authorized again.

Manager configuration is reloaded for every request and published with a
shared OS file lock plus atomic replacement. Multiple Manager processes that
share `%LOCALAPPDATA%` therefore observe the latest complete configuration
instead of retaining divergent in-memory copies.

The Manager accepts only loopback `Host` values. Mutating browser requests
must be same-origin, JSON endpoints require `application/json`, and all UI
actions with side effects use `POST`. Clipboard text is passed to PowerShell
over standard input and is never interpolated into a command.

## Configuration

Environment variables:

| Variable | Purpose |
|---|---|
| `CAPX_MANAGER_ADDR` | Loopback Manager listen address. Omit to use the default with an automatic fallback when occupied. |
| `CAPX_INSTANCE_DIR` | Override the manifest registry, primarily for tests. |
| `ADB_PATH` | Explicit ADB executable path. |
| `CAPX_MANAGER_NO_BROWSER=1` | Do not open the Manager UI automatically. |
| `CAPX_MANAGER_BROWSER_HEADLESS=1` | Launch managed Chrome headlessly for integration tests. |

## Build and test

```powershell
cd packet-capture\capx-web-manager
go test -race ./...
go vet ./...
go build -trimpath -ldflags='-s -w -H=windowsgui' -o CapxWebManager.exe .

cd ..\capx
go test ./cmd/captured ./internal/api ./internal/proxy ./internal/store
go build -o capx-captured.exe ./cmd/captured
```

The Codex consumer contract is implemented by
`F:\111\codex_bug\framework\runtime\capx-instance.mjs`.
