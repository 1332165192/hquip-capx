package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/hquip/capx/internal/model"
)

// http3Server is one QUIC/HTTP/3 MITM listener. It terminates QUIC with a
// per-SNI leaf signed by the capx CA, then proxies each request through the
// same HTTP pipeline as HTTP/1.1 and HTTP/2.
type http3Server struct {
	p *Proxy

	mu      sync.Mutex
	pc      net.PacketConn
	ln      *quic.Listener
	cancel  context.CancelFunc
	addr    string
	running bool
}

func (p *Proxy) http3Slot() *http3Server {
	if p.h3 == nil {
		p.h3 = &http3Server{p: p}
	}
	return p.h3
}

func (p *Proxy) extraHTTP3() *http3Server {
	if p.h3extra == nil {
		p.h3extra = &http3Server{p: p}
	}
	return p.h3extra
}

// HTTP3Status reports the primary HTTP/3 MITM listener.
func (p *Proxy) HTTP3Status() (running bool, addr string) {
	for _, h := range []*http3Server{p.h3, p.h3extra} {
		if h == nil {
			continue
		}
		h.mu.Lock()
		on, a := h.running, h.addr
		h.mu.Unlock()
		if on {
			return true, a
		}
	}
	return false, ""
}

// StartHTTP3 binds a UDP listener on addr and serves HTTP/3 MITM.
func (p *Proxy) StartHTTP3(addr string) error {
	return p.http3Slot().start(addr)
}

// StartHTTP3Extra binds a second UDP listener (transparent vs explicit proxy).
func (p *Proxy) StartHTTP3Extra(addr string) error {
	return p.extraHTTP3().start(addr)
}

func (h *http3Server) start(addr string) error {
	if h == nil {
		return fmt.Errorf("http3 listener not initialised")
	}
	h.mu.Lock()
	if h.running {
		h.mu.Unlock()
		return fmt.Errorf("http3 listener already running on %s", h.addr)
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		h.mu.Unlock()
		return err
	}
	tlsCfg := h.p.leafH3TLSConfig()
	qln, err := quic.Listen(pc, tlsCfg, &quic.Config{
		MaxIncomingStreams:    256,
		MaxIncomingUniStreams: 256,
		Allow0RTT:             false,
	})
	if err != nil {
		_ = pc.Close()
		h.mu.Unlock()
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.pc, h.ln, h.cancel, h.addr, h.running = pc, qln, cancel, pc.LocalAddr().String(), true
	h.mu.Unlock()

	h.p.st.Publish(model.Event{Source: model.SourceProxy, Kind: "http3_started",
		Data: map[string]string{"addr": h.addr}})
	go h.serve(ctx, qln)
	return nil
}

// StopHTTP3 shuts the primary HTTP/3 listener down.
func (p *Proxy) StopHTTP3() error {
	return p.http3Slot().stop()
}

func (p *Proxy) StopHTTP3Extra() error {
	return p.extraHTTP3().stop()
}

func (h *http3Server) stop() error {
	if h == nil {
		return fmt.Errorf("http3 listener not running")
	}
	h.mu.Lock()
	cancel := h.cancel
	ln := h.ln
	pc := h.pc
	h.running = false
	h.ln, h.pc, h.cancel = nil, nil, nil
	h.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if ln != nil {
		_ = ln.Close()
	}
	if pc != nil {
		_ = pc.Close()
	}
	if ln == nil && pc == nil {
		return fmt.Errorf("http3 listener not running")
	}
	return nil
}

func (h *http3Server) serve(ctx context.Context, ln *quic.Listener) {
	srv := &http3.Server{
		Handler: http.HandlerFunc(h.handle),
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	_ = srv.ServeListener(ln)
	h.p.st.Publish(model.Event{Source: model.SourceProxy, Kind: "http3_stopped",
		Data: map[string]string{"addr": h.addr}})
}

func (h *http3Server) handle(w http.ResponseWriter, r *http.Request) {
	r.URL.Scheme = "https"
	if r.Host == "" && r.TLS != nil {
		r.Host = r.TLS.ServerName
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}
	connID := h.p.nextConnID()
	if r.Method == http.MethodConnect {
		proto := r.Header.Get("Protocol")
		if proto == "" {
			proto = r.Header.Get(":protocol")
		}
		if strings.EqualFold(proto, "websocket") {
			h.p.tunnelH2WebSocket(w, r, r.Host)
			return
		}
	}
	h.p.forward(w, r, "https", connID)
}

func (p *Proxy) leafH3TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{http3.NextProtoH3},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			name := chi.ServerName
			if name == "" && p.origDst != nil && chi.Conn != nil {
				name = stripPort(p.origDst(chi.Conn))
			}
			if name == "" {
				name = "unknown.invalid"
			}
			leaf, err := p.ca.LeafFor(name)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{*leaf},
				NextProtos:   []string{http3.NextProtoH3},
				ServerName:   name,
			}, nil
		},
	}
}
