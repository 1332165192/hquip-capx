package daemon

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/hquip/capx/internal/api"
	"github.com/hquip/capx/internal/dnslog"
	"github.com/hquip/capx/internal/hook"
	"github.com/hquip/capx/internal/inline"
	"github.com/hquip/capx/internal/memscan"
	"github.com/hquip/capx/internal/mobile"
	"github.com/hquip/capx/internal/mobilevpn"
	"github.com/hquip/capx/internal/proxy"
	"github.com/hquip/capx/internal/script"
	"github.com/hquip/capx/internal/setup"
	"github.com/hquip/capx/internal/sniffer"
	"github.com/hquip/capx/internal/spoof"
	"github.com/hquip/capx/internal/store"
	"github.com/hquip/capx/internal/wxdesk"
	"github.com/hquip/capx/internal/wxhook"
)

type Components struct {
	Store     *store.Store
	Sniffer   sniffer.Sniffer
	Scanner   memscan.Scanner
	Hook      *hook.Manager
	Inline    *inline.Manager
	Script    *script.Engine
	Proxy     *proxy.Proxy
	DNSLog    *dnslog.Client
	Spoof     *spoof.Manager
	Mobile    *mobile.Controller
	MobileVPN *mobilevpn.Gateway
	Server    *api.Server

	stopPersist func()
	stopPoller  context.CancelFunc
	closeOnce   sync.Once
}

func Build(proxyAddr string) *Components {
	st := store.New(2000)
	snif := sniffer.New()
	scanner := memscan.New()
	hk := hook.New(st)
	il := inline.New(st)
	sc := script.New(st)
	dl := dnslog.New(st, dnslog.DefaultPersistPath())
	dl.UseDefaults(dnslog.DefaultSettingsPath())
	pollContext, stopPoller := context.WithCancel(context.Background())
	dl.StartPoller(pollContext)
	sp := spoof.New()

	px, err := proxy.New(st)
	if err != nil {
		log.Printf("capx: MITM proxy disabled (CA init failed): %v", err)
		px = nil
	} else {
		px.SetMutator(sc)
		px.SetOrigDstLookup(func(c net.Conn) string {
			if c == nil || il == nil {
				return ""
			}
			host, port, err := net.SplitHostPort(c.RemoteAddr().String())
			if err != nil {
				return ""
			}
			n, _ := strconv.Atoi(port)
			dst, ok := il.LookupOrigDst(net.ParseIP(host), n)
			if !ok {
				return ""
			}
			return dst
		})
	}
	if px != nil && proxyAddr != "" {
		if err := px.Start(proxyAddr); err != nil {
			log.Printf("capx: failed to auto-start proxy on %s: %v", proxyAddr, err)
		}
	}

	srv := api.New(st, snif, scanner, px, hk, il, sc, dl, sp)
	srv.SetWxhook(wxhook.New(hk))
	srv.SetWxDesktop(wxdesk.New())
	mob := mobile.New()
	srv.SetMobile(mob)
	var handleHTTP mobilevpn.HTTPHandler
	if px != nil {
		handleHTTP = px.ServeVPNConn
	}
	vpn := mobilevpn.New("", handleHTTP)
	srv.SetMobileVPN(vpn)
	return &Components{
		Store:      st,
		Sniffer:    snif,
		Scanner:    scanner,
		Hook:       hk,
		Spoof:      sp,
		Mobile:     mob,
		MobileVPN:  vpn,
		Inline:     il,
		Script:     sc,
		Proxy:      px,
		DNSLog:     dl,
		Server:     srv,
		stopPoller: stopPoller,
	}
}

func (c *Components) EnablePersistence(dir string) error {
	if dir == "" {
		return nil
	}
	if c.MobileVPN != nil {
		if err := c.MobileVPN.SetStateDir(filepath.Join(dir, "mobile-vpn")); err != nil {
			return err
		}
	}
	stop, err := c.Store.EnablePersistence(store.PersistConfig{Dir: dir})
	if err != nil {
		return fmt.Errorf("enable capture persistence: %w", err)
	}
	c.stopPersist = stop
	log.Printf("capx: store persistence enabled at %s", dir)
	if err := c.Store.EnableHTTPDisk(filepath.Join(dir, "http_history.sqlite")); err != nil {
		stop()
		c.stopPersist = nil
		return fmt.Errorf("enable HTTP disk history: %w", err)
	} else {
		log.Printf("capx: HTTP disk history enabled at %s", filepath.Join(dir, "http_history.sqlite"))
	}
	if c.Proxy != nil {
		path := filepath.Join(dir, "proxy_config.json")
		c.Proxy.UseConfigPath(path)
		log.Printf("capx: proxy scope/rules persistence isolated at %s", path)
	}
	return nil
}

// StartProxy is called only after state and SQLite high-water restoration.
// Binding earlier can assign live transactions IDs that are already on disk.
func (c *Components) StartProxy(addr string) error {
	if addr == "" {
		return nil
	}
	if c.Proxy == nil {
		return fmt.Errorf("MITM proxy unavailable (CA initialization failed)")
	}
	return c.Proxy.Start(addr)
}

func (c *Components) Close() {
	c.closeOnce.Do(func() {
		if c.MobileVPN != nil {
			if err := c.MobileVPN.Stop(); err != nil {
				log.Printf("capx: close mobile VPN: %v", err)
			}
		}
		if c.stopPoller != nil {
			c.stopPoller()
		}
		if c.Mobile != nil {
			if err := c.Mobile.Close(); err != nil {
				log.Printf("capx: restore Android capture: %v", err)
			}
		}
		if c.Server != nil {
			if err := c.Server.CloseCaptureTools(); err != nil {
				log.Printf("capx: close mini-program capture: %v", err)
			}
		}
		if c.Hook != nil {
			if err := c.Hook.Close(); err != nil {
				log.Printf("capx: close hook sessions: %v", err)
			}
		}
		if c.Inline != nil {
			_ = c.Inline.StopRedirect()
			_ = c.Inline.Stop()
		}
		if c.Proxy != nil {
			_ = c.Proxy.StopCaptureBridge()
			_ = c.Proxy.StopTransparent()
			_ = c.Proxy.Stop()
			if err := setup.ReleaseSystemProxyOwned(c.Proxy); err != nil {
				log.Printf("capx: restore system proxy: %v", err)
			}
		}
		if c.stopPersist != nil {
			c.stopPersist()
		}
		_ = c.Store.CloseHTTPDisk()
	})
}

func (c *Components) Handler() http.Handler { return c.Server.Handler() }

func (c *Components) SetActive(on bool) {
	if c != nil && c.Server != nil {
		c.Server.SetActive(on)
	}
}

func (c *Components) LogStartup(addr string) {
	log.Printf("capx captured listening on http://%s (sniffer=%s, memscan_ffi=%v, hook=%s, inline=%s, active=%v)",
		addr, c.Sniffer.Backend(), c.Scanner.Available(), c.Hook.Backend(), c.Inline.Backend(), c.Server.ActiveAllowed())
	if c.Server.AuthEnabled() {
		log.Printf("capx: API authentication enabled; read the token from this instance's private state directory")
	} else {
		log.Printf("capx: API token auth DISABLED (CAPX_AUTH=0) — only safe on a trusted single-user host")
	}
}
