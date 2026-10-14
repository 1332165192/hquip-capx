// Command capx-desktop is the standalone desktop application for capx. Unlike
// `captured` (a headless daemon you point a browser at), capx-desktop starts the
// capx backend in-process and opens the Burp-style console in its own dedicated
// application window — double-click to launch, close the window to quit.
//
// The console is hosted in a chromeless Chromium "app" window (pure Go, no cgo),
// so it looks and behaves like a native desktop application rather than a
// browser tab. Everything runs locally on your machine; nothing leaves the host.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hquip/capx/internal/daemon"
	"github.com/hquip/capx/internal/desktop"
	_ "github.com/hquip/capx/internal/h2boot"
	"github.com/hquip/capx/internal/runtimecfg"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address for the in-process capx API (0 = pick a free port)")
	proxyAddr := flag.String("proxy", "", "auto-start the MITM proxy on this address (e.g. 127.0.0.1:18080)")
	allowActive := flag.Bool("allow-active", false, "enable mutating 'active' primitives (inject/modify/attach/mem-write/load-code); off by default")
	stateDir := flag.String("state-dir", "auto", "persistent desktop state directory (auto = stable desktop state; none = in-memory)")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runDesktop(ctx, *addr, *proxyAddr, *stateDir, *allowActive, desktop.OpenWithProfile); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func runDesktop(parent context.Context, addr, proxyAddr, stateDir string, allowActive bool, open func(context.Context, string, string) error) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("capx-desktop: cannot listen on %s: %w", addr, err)
	}
	defer ln.Close()
	hostPort := ln.Addr().String()
	url := "http://" + hostPort + "/"
	persistDir := runtimecfg.ResolveDesktopStateDir(stateDir)
	generation, err := runtimecfg.NewGeneration()
	if err != nil {
		return fmt.Errorf("generate desktop identity: %w", err)
	}
	release, err := runtimecfg.AcquireStateDirLock(persistDir, generation)
	if err != nil {
		_ = ln.Close()
		return fmt.Errorf("capx-desktop: state directory is unavailable: %w", err)
	}
	defer release()
	runtimecfg.EnsureInstanceTokenEnv(persistDir)
	ctx, stop := context.WithCancel(parent)
	defer stop()
	comp := daemon.Build("")
	comp.Server.SetRuntimeShutdown(stop)
	comp.Server.SetRuntimeIdentity("desktop", generation)
	comp.SetActive(allowActive)
	defer comp.Close()
	if err := comp.EnablePersistence(persistDir); err != nil {
		return err
	}
	if err := comp.StartProxy(proxyAddr); err != nil {
		return fmt.Errorf("start desktop proxy: %w", err)
	}
	profile := ""
	if persistDir != "" {
		profile = filepath.Join(persistDir, "desktop-profile")
	} else {
		profile, err = os.MkdirTemp("", "capx-desktop-profile-")
		if err != nil {
			return fmt.Errorf("capx-desktop: create browser profile: %w", err)
		}
		defer os.RemoveAll(profile)
	}

	httpSrv := &http.Server{
		Handler:           comp.Handler(),
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		comp.LogStartup(hostPort)
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("capx-desktop: server error: %v", err)
			stop()
		}
	}()

	log.Printf("capx-desktop: opening application window (%s) at %s", desktop.Mode(), url)
	if err := open(ctx, url, profile); err != nil {
		// No window backend available: keep serving and let the user open the
		// URL manually rather than exiting.
		log.Printf("capx-desktop: %v", err)
		log.Printf("capx-desktop: open this URL in your browser: %s", url)
		<-ctx.Done()
	}

	log.Printf("capx-desktop: shutting down")
	stop()
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	return nil
}
