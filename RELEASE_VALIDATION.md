# Local release validation — 2026-10-14

Validation uses the selected public source, Go 1.26.9, Windows, temporary self-owned package/server fixtures, and freshly built executables. No user device/account traffic or private capture history is used as proof of these checks.

| Check | Result |
| --- | --- |
| Public core, Wails desktop and manager `go test ./...` / `go vet ./...` | Passed |
| Manager concurrent configuration saves | Passed after adding in-process serialization; 3 additional regression runs passed |
| New standard CDP adapter | Endpoint validation, responses, timeout and stop checks passed |
| Android/mobile proxy UI fixtures | 12 checks passed against the updated source UI |
| Fresh daemon and MCP runtime | 14 checks passed; MCP exposes 222 tools |
| Extraction junction boundary | Outside read/write rejected, including with active mode on; existing files cannot be overwritten |
| API and generic MCP policy | Token required; LAN and extraction gated; query/encoded paths checked |
| Default HTTPS upstream policy | Untrusted certificate and hostname rejected; explicit fixture CA accepted |
| Windows Rust memory scanner | 13 tests passed using pinned Rust GNU toolchain and LLVM/LLD; portable test script included |
| Linux and macOS pure-Go core builds | Cross-compilation passed; platform execution was not locally performed |
| Go source vulnerability scans | No reachable findings in the 3 default modules (govulncheck 1.9.0, database modified 2026-10-08) |
| Fresh binary vulnerability scan | Previous patched advisories are absent; one OpenPGP advisory produces package/symbol wildcard findings, described below |
| Default build license coverage | All 32 actually imported third-party modules have preserved license copies; wider module graph inventory is included |
| Public source boundary | No prohibited private/runtime file or credential-format finding in the prepared tree |
| Source-only GitHub compilation workflow | actionlint passed; 6 platform build plans checked; changed desktop backend-discovery tests and vet passed. Remote compilation has not yet run |

The remaining scanner advisory [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) concerns unmaintained `golang.org/x/crypto/openpgp` packages with no fixed version. The source report contains only module metadata for it, with no imported package or call trace. The stripped binary report includes wildcard package/symbol entries. `go list -deps ./cmd/captured` does not list OpenPGP packages. These observations do not establish a reachable OpenPGP use; the binary scan is recorded rather than described as a zero-warning result. Recheck when adding new crypto dependencies or publishing binaries.

Scope limits: GitHub CI has been written but not run remotely. No complete verification of every optional build tag, Wails production packaging, iOS/WDA integration or all apps/mini-program protocols is claimed. The public CDP tests use a standard local fixture provider; they do not prove that an arbitrary released WeChat mini-program can enable debugging. Optional native injection requires separate security/lifecycle validation.

This upload package contains source and license notices only. GitHub Actions builds the applications and native components and stores their ZIPs/checksums as downloadable artifacts. Device identities, real credentials/screenshots, author DNSLog defaults, Tencent/Npcap installers, drivers, prebuilt DLLs and old executables are excluded from the repository. The existing private running service was preserved; it has not been automatically replaced with this build. No remote repository has been published.
