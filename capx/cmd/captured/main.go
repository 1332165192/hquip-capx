// Command captured is the capx capture daemon. It exposes the capx HTTP API
// (REST + SSE) for clients to start captures, stream packets/flows, and run
// CE-style memory scans.
//
// The live L3/L4 sniffer (gopacket) and the Rust memory-scan engine are
// optional, behind build tags ("pcap" and "memscan_ffi"); without them the
// daemon still starts and serves the API with stub backends.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hquip/capx/internal/daemon"
	_ "github.com/hquip/capx/internal/h2boot"
	"github.com/hquip/capx/internal/runtimecfg"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:19091", "listen address for the capx HTTP API")
	grpcAddr := flag.String("grpc", "", "also serve the capx gRPC API on this address (e.g. 127.0.0.1:19092); requires building with -tags grpc")
	proxyAddr := flag.String("proxy", "", "auto-start the MITM proxy on this address (e.g. 127.0.0.1:18080); empty = start manually from the console")
	allowActive := flag.Bool("allow-active", false, "enable mutating 'active' primitives (inject/modify/attach/mem-write/load-code); off by default")
	stateDir := flag.String("state-dir", "auto", "directory to persist capture state across restarts (auto/empty = per API port; none/off = in-memory only)")
	instanceID := flag.String("instance-id", "", "stable runtime instance identity reported by /health")
	generation := flag.String("generation", "", "runtime manifest generation reported by /health")
	strictAddr := flag.Bool("strict-addr", false, "fail instead of selecting a fallback API port when the requested address is busy")
	_ = flag.CommandLine.Parse(compatArgs(os.Args[1:]))
	if strings.TrimSpace(*generation) == "" {
		value, err := runtimecfg.NewGeneration()
		if err != nil {
			log.Fatalf("generate runtime identity: %v", err)
		}
		*generation = value
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil && shouldFallbackAddr(*addr, *strictAddr) {
		log.Printf("capx: %s is busy, picking a free API port", *addr)
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		log.Fatalf("capx: cannot listen on %s: %v", *addr, err)
	}
	listenAddr := ln.Addr().String()
	persistDir := resolveStateDir(*stateDir, listenAddr)
	releaseStateLock, err := acquireStateDirLock(persistDir, strings.TrimSpace(*generation))
	if err != nil {
		_ = ln.Close()
		log.Fatalf("capx: state directory is unavailable: %v", err)
	}
	defer releaseStateLock()
	ensureInstanceTokenEnv(persistDir)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	comp := daemon.Build("")
	comp.Server.SetRuntimeIdentity(strings.TrimSpace(*instanceID), strings.TrimSpace(*generation))
	comp.Server.SetRuntimeShutdown(stop)
	if *allowActive {
		comp.SetActive(true)
	}
	defer comp.Close()
	if err := comp.EnablePersistence(persistDir); err != nil {
		log.Fatal(err)
	}
	if err := comp.StartProxy(*proxyAddr); err != nil {
		log.Fatalf("start proxy: %v", err)
	}

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           comp.Handler(),
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ReadHeaderTimeout: 10 * time.Second,
	}

	maybeStartGRPC(ctx, comp, *grpcAddr)

	go func() {
		comp.LogStartup(listenAddr)
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("capx captured shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
}

func shouldFallbackAddr(addr string, strict bool) bool {
	return !strict && addr == "127.0.0.1:19091"
}

// compatArgs makes the common typo below work instead of silently disabling
// the proxy:
//
//	capx-captured.exe -addr 127.0.0.1:19091 proxy 127.0.0.1:18080
//
// It becomes:
//
//	capx-captured.exe -addr 127.0.0.1:19091 --proxy 127.0.0.1:18080
func compatArgs(args []string) []string {
	out := make([]string, 0, len(args)+2)
	for i := 0; i < len(args); i++ {
		a := strings.TrimSpace(args[i])
		if strings.EqualFold(a, "proxy") && i+1 < len(args) {
			out = append(out, "--proxy", args[i+1])
			i++
			continue
		}
		if strings.EqualFold(a, "addr") && i+1 < len(args) {
			out = append(out, "--addr", args[i+1])
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out
}

func resolveStateDir(raw, listenAddr string) string {
	return runtimecfg.ResolveStateDir(raw, listenAddr)
}
func ensureInstanceTokenEnv(stateDir string) { runtimecfg.EnsureInstanceTokenEnv(stateDir) }
func readInstanceToken(path string) string   { return runtimecfg.ReadInstanceToken(path) }
