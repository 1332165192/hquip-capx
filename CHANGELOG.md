# Changes prepared for the public source release (2026-10-14)

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
