# Build and verification

Use Go 1.26.9 or newer with committed go.mod/go.sum. Build scripts use `-mod=readonly` and do not run unpinned `go get` or download executable runtimes.

Normal distribution uses GitHub-hosted compilation, documented in [GitHub build instructions](GITHUB_BUILD.md). The repository contains source and required frontend resources; `build-artifacts` builds all application modules, native Rust/C source and tagged Go integration. All program ZIPs/checksums live in Actions artifacts. The commands below are optional local development instructions.

Core module (`capx`): `go test ./...`, `go vet ./...`, then `scripts/build-windows.ps1` on Windows or `bash scripts/build-unix.sh` elsewhere. Both scripts build captured, the Chromium app-window launcher, and capx-mcp. Chromium/Edge is needed only for the app-window launcher; captured's web UI works in an ordinary browser.

Web manager (`capx-web-manager`): `go test ./...`, `go vet ./...`, `go build -mod=readonly -trimpath -o ../bin/capx-web-manager.exe .`. Supply the captured executable path in the manager; it does not contain a bundled daemon.

Wails desktop (`capx-desktop`): install `go install github.com/wailsapp/wails/v2/cmd/wails@v2.12.0`, then run `build.ps1`. Windows requires WebView2; Linux requires the Wails GTK/WebKit development dependencies. Prebuilt frontend source is in `frontend/dist`. Default module tests were verified on Windows; Linux/macOS Wails UI execution is not locally verified.

Optional dependencies are installed separately:

- `pcap`: build with `-tags pcap`. The pinned gopacket implementation uses Go dynamic loading on Windows, so Npcap is a runtime requirement there. Unix builds need libpcap headers/libraries. Npcap drivers/runtime are not distributed here.
- `memscan_ffi`: build `capx/native/memscan-rs` using the matching target/linker, copy the static library to its `lib` directory, then build Go with CGO and `-tags memscan_ffi`. Cargo source has no external crates. On Windows, install LLVM (clang/LLD) and `rustup toolchain install 1.95.0-x86_64-pc-windows-gnu --profile minimal`, then run `capx/scripts/test-native-windows.ps1`. The script uses the matching Rust runtime libraries rather than old MinGW linker/runtime files. All 13 Windows native tests passed locally; CGO integration still needs separate tag-specific validation. CI also tests the native source on Ubuntu.
- `native_hook`: experimental Windows-only hook. Build the DLL from `internal/hook/native/capx_hook.c` plus MinHook source using a matching compiler, place the result at `internal/api/native/capx_hook.dll`, then build with `-tags native_hook`. Disabled in default builds; this optional injector/listener has not had the same security or lifecycle validation as the default proxy. No DLL is shipped.
- Frida: install the official Python package/CLI into a private environment and configure the supported Frida discovery options. No portable Python or Frida binary is bundled. Required only for process-injection features.
- WeChat, ADB, WDA, signing certificates, SDKs and device support images are supplied by the operator. No Tencent installer, iOS profile, phone identity or certificate is distributed.

Known-vulnerability checks: `go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...` in each module. Run against freshly built binaries too when publishing binaries. Source scans do not prove all protocols, build tags or apps are safe.

Pure-Go Linux and macOS core cross-builds were verified locally. On macOS without CGO, memory scanning reports unavailable; enabling the native scanner requires the platform's compiler/permissions. Cross-compilation does not replace execution tests on those platforms.
