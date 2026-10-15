// capx is a standalone multi-layer capture tool. It is intentionally its own
// Go module; other products use its HTTP API instead of importing this code.
module github.com/hquip/capx

go 1.26.9

require (
	github.com/google/gopacket v1.1.19
	github.com/yuin/gopher-lua v1.1.1
	golang.org/x/sys v0.48.0
)

require github.com/andybalholm/brotli v1.2.1

require golang.org/x/arch v0.7.0

require (
	github.com/bufbuild/protocompile v0.10.0
	github.com/klauspost/compress v1.18.7
	golang.org/x/crypto v0.57.0
	google.golang.org/grpc v1.64.0
	google.golang.org/protobuf v1.33.1-0.20240319125436-3039476726e4
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/time v0.7.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240318140521-94a12d6c2237 // indirect
	modernc.org/libc v1.55.3 // indirect
	modernc.org/mathutil v1.6.0 // indirect
	modernc.org/memory v1.8.0 // indirect
)

require (
	github.com/quic-go/quic-go v0.59.1
	go.uber.org/mock v0.5.2
	golang.org/x/mod v0.41.0
	golang.org/x/net v0.60.0
	golang.org/x/text v0.42.0
	golang.org/x/tools v0.49.0
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c
	howett.net/plist v1.0.1
	modernc.org/sqlite v1.34.5
	software.sslmate.com/src/go-pkcs12 v0.7.2
)
