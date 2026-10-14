# Mobile automation fixes (2026-10-15)

- Connect an existing operator-authorized WDA session from the App capture page and MCP. Add iOS screenshots, element lookup, tap, Unicode input, swipe, app launch, foreground lookup and home to the shared mobile API.
- Convert Retina screenshot pixels to UIKit points in the page; include coordinate metadata with MCP image results and reject out-of-screen coordinates.
- Require the backend active policy for Android and iOS device mutations, in addition to the MCP active gate.
- Accept the external CDP endpoint from the page/API without restarting the daemon. Reject target changes while a connection is active.
- Add WDA protocol, session expiry, redirect, platform routing and authorization regressions. WDA installation/signing, iOS CA trust and per-app decryption remain environment requirements.

# Changes prepared for the public source release (2026-10-14)

GitHub follow-up: add missing macOS C type headers, use an explicitly unavailable
scanner fixture for gRPC negative tests and verify real self-process opening,
and retry transient pinned Wails downloads without disabling TLS/checksum checks.

- Upgrade Go to 1.26.9 and patch x/net, x/text, x/crypto, quic-go and compress dependencies.
- Stop logging full instance tokens. Export source without user identity, keys, capture history, screenshots, caches or executables.
- Root-constrain package reads and writes using os.Root, reject unsafe member names, bound package/preview reads and prevent overwrites. Align REST and generic MCP active-mode gates.
- Verify origin certificates for HTTP/1, HTTP/2, WebSocket, repeater and turbo connections. Add explicit PEM CA configuration and rejection regression checks.
- Require phone-IP allowlists for LAN proxy access and update mobile UI.
- Replace bundled third-party F12 hooks/offsets/private protocol bridge with a standard external CDP adapter in the public tree. Keep capture and CDP operation integration.
- Make native DLL hooks opt-in. Correct pinned build scripts and build MCP on Unix too.
- Add licenses/notices, capability boundaries, contributing/security documents, CI and release-file checks.
- Fix the macOS pure-Go scanner fallback and provide a reproducible LLVM/Rust GNU native-test script (13 Windows tests passed).
- Serialize manager configuration saves before the cross-process lock to avoid concurrent requests exhausting one another's lock timeout.
- Add GitHub source-only build workflows for all application modules and native source, with artifact ZIPs/checksums and Linux native Go integration checks.
- Locate bundled backends on Windows/Linux/macOS and preserve backend authentication defaults when the Wails desktop launches it.

The private workspace's old miniapp-automator bridge is excluded from this source release; the public integration uses CDP. Existing private device/WDA helpers and signed packages are excluded.
