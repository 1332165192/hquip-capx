// Package embed lets another Go program run capx in-process — no separate
// captured.exe. It is a thin, exported wrapper over internal/daemon (which the
// Go "internal" rule hides from other modules): it builds the same store +
// MITM proxy + REST/SSE API and serves it on a local listener. With the default
// build everything stays pure-Go (the live pcap sniffer and Rust memscan engine
// remain opt-in behind build tags and are not required here).
package embed

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/hquip/capx/internal/daemon"
	_ "github.com/hquip/capx/internal/h2boot"
)

// Options configures an in-process capx instance.
type Options struct {
	APIAddr     string // REST/SSE listen addr; "" => 127.0.0.1:0 (random free port)
	ProxyAddr   string // MITM proxy addr, e.g. 127.0.0.1:18080; "" => don't auto-start
	StateDir    string // persist capture state here; "" => in-memory only
	AllowActive bool   // enable mutating primitives (repeater/modify/inject/mem-write)
	DisableAuth bool   // true => no API token required (safe on a loopback single-user host)
}

// Instance is a running in-process capx backend.
type Instance struct {
	BaseURL string // http://host:port of the REST/SSE API
	Token   string // API token ("" when DisableAuth)
	Proxy   string // MITM proxy addr, if started

	comp *daemon.Components
	srv  *http.Server
	ln   net.Listener
}

// Start builds and serves a capx backend in the current process. The returned
// Instance is ready immediately (the API listener is bound before returning);
// callers reach it over BaseURL like any other capx REST/SSE client.
func Start(opts Options) (*Instance, error) {
	if opts.DisableAuth {
		_ = os.Setenv("CAPX_AUTH", "0")
	}
	apiAddr := opts.APIAddr
	if apiAddr == "" {
		apiAddr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", apiAddr)
	if err != nil {
		return nil, fmt.Errorf("capx embed listen %s: %w", apiAddr, err)
	}

	comp := daemon.Build("")
	comp.SetActive(opts.AllowActive)
	if err := comp.EnablePersistence(opts.StateDir); err != nil {
		comp.Close()
		_ = ln.Close()
		return nil, fmt.Errorf("capx embed persistence: %w", err)
	}
	if err := comp.StartProxy(opts.ProxyAddr); err != nil {
		comp.Close()
		_ = ln.Close()
		return nil, fmt.Errorf("capx embed proxy: %w", err)
	}

	inst := &Instance{
		BaseURL: "http://" + ln.Addr().String(),
		Proxy:   opts.ProxyAddr,
		comp:    comp,
		ln:      ln,
		srv: &http.Server{
			Handler:           comp.Handler(),
			ReadHeaderTimeout: 10 * time.Second,
		},
	}
	if comp.Server.AuthEnabled() {
		inst.Token = comp.Server.AuthToken()
	}
	if opts.ProxyAddr != "" && comp.Proxy != nil {
		_, inst.Proxy = comp.Proxy.Status()
	}

	go func() { _ = inst.srv.Serve(ln) }()
	return inst, nil
}

// Stop gracefully shuts the API server and releases capture resources. It also
// restores the system proxy that capx may have set during setup/prepare.
func (i *Instance) Stop() {
	if i == nil {
		return
	}
	if i.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = i.srv.Shutdown(ctx)
	}
	if i.comp != nil {
		i.comp.Close()
	}
}
