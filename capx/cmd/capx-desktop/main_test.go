package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hquip/capx/internal/model"
)

// Real backend + loopback HTTP fixture; never opens a browser, installs a CA,
// touches the registry, changes a proxy setting or sends traffic off-host.
func TestDesktopPersistenceLockAndAuthenticatedShutdown(t *testing.T) {
	root := t.TempDir()
	for _, key := range []string{"HOME", "USERPROFILE", "LOCALAPPDATA"} {
		t.Setenv(key, root)
	}
	t.Setenv("CAPX_DATA_DIR", filepath.Join(root, "ca"))
	t.Setenv("CAPX_TOKEN", "")
	t.Setenv("CAPX_AUTH", "1")
	t.Setenv("CAPX_STATE_DIR", "")
	state := filepath.Join(root, "state")
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "desktop-persist-marker") }))
	defer target.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	request := func(base, path string) *http.Response {
		t.Helper()
		token, err := os.ReadFile(filepath.Join(state, "token"))
		if err != nil {
			t.Fatal(err)
		}
		method := http.MethodGet
		if path == "/api/runtime/shutdown" {
			method = http.MethodPost
		}
		req, _ := http.NewRequest(method, strings.TrimRight(base, "/")+path, nil)
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
		res, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	// A client can receive the flushed response before the proxy handler finishes
	// recording it. Wait for the observable history condition, not a scheduler
	// assumption; the persistence/restart assertions below remain unchanged.
	waitHistory := func(base, path string, count int) []model.HTTPTx {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		var history []model.HTTPTx
		for time.Now().Before(deadline) {
			resp := request(base, "/api/http")
			err := json.NewDecoder(resp.Body).Decode(&history)
			resp.Body.Close()
			if err != nil {
				t.Fatal("read captured history:", err)
			}
			if len(history) >= count {
				for _, tx := range history {
					if tx.Path == path {
						return history
					}
				}
			}
			select {
			case <-ctx.Done():
				t.Fatal("history wait cancelled:", ctx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
		t.Fatalf("capture did not enter history: path=%s count=%d history=%+v", path, count, history)
		return nil
	}
	firstOpen := func(ctx context.Context, base, profile string) error {
		if profile != filepath.Join(state, "desktop-profile") {
			t.Errorf("profile not isolated: %s", profile)
		}
		if err := runDesktop(ctx, "127.0.0.1:0", "", state, false, func(context.Context, string, string) error { t.Error("second owner opened a window"); return nil }); err == nil {
			t.Error("state lock allowed second desktop")
		}
		resp := request(base, "/api/proxy/status")
		var proxyStatus struct {
			Addr string `json:"addr"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&proxyStatus); err != nil {
			t.Error(err)
		}
		resp.Body.Close()
		proxyURL, _ := url.Parse("http://" + proxyStatus.Addr)
		transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		defer transport.CloseIdleConnections()
		response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get(target.URL + "/persist")
		if err != nil {
			t.Error(err)
			return err
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		_ = waitHistory(base, "/persist", 1)
		resp = request(base, "/api/runtime/shutdown")
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Errorf("shutdown status %d", resp.StatusCode)
		}
		<-ctx.Done()
		return nil
	}
	if err := runDesktop(ctx, "127.0.0.1:0", "127.0.0.1:0", state, false, firstOpen); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(state, "http_history.sqlite")); err != nil {
		t.Fatal(err)
	}
	secondOpen := func(ctx context.Context, base, profile string) error {
		resp := request(base, "/api/http")
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(raw), "/persist") {
			t.Errorf("restart lost HTTP history: %s", raw)
		}
		var before []model.HTTPTx
		if err := json.Unmarshal(raw, &before); err != nil || len(before) != 1 || before[0].ID != 1 {
			t.Errorf("expected one persisted ID 1: %s (%v)", raw, err)
			return nil
		}
		resp = request(base, "/api/proxy/status")
		var status struct {
			Addr string `json:"addr"`
		}
		json.NewDecoder(resp.Body).Decode(&status)
		resp.Body.Close()
		proxyURL, _ := url.Parse("http://" + status.Addr)
		transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		defer transport.CloseIdleConnections()
		response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get(target.URL + "/after-restart")
		if err != nil {
			t.Error(err)
			return err
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		after := waitHistory(base, "/after-restart", 2)
		if len(after) != 2 {
			t.Errorf("new capture overwrote old row: %+v", after)
		}
		for _, summary := range after {
			if summary.Path == "/after-restart" && summary.ID <= before[0].ID {
				t.Error("live transaction allocated before SQLite high-water restore")
			}
			resp = request(base, fmt.Sprintf("/api/http/%d", summary.ID))
			var detail model.HTTPTx
			json.NewDecoder(resp.Body).Decode(&detail)
			resp.Body.Close()
			if summary.Path != detail.Path || !strings.Contains(detail.ReqRaw, summary.Path) {
				t.Errorf("summary/detail identity mismatch: %+v %+v", summary, detail)
			}
		}
		return nil // Closing the window must also flush and release the state lock.
	}
	if err := runDesktop(ctx, "127.0.0.1:0", "127.0.0.1:0", state, false, secondOpen); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(state, ".capx-runtime.lock")); !os.IsNotExist(err) {
		t.Fatal("desktop retained lifetime state lock after exit")
	}
}

func TestDesktopPersistenceFailureDoesNotOpenWindowOrProxy(t *testing.T) {
	root := t.TempDir()
	for _, key := range []string{"HOME", "USERPROFILE", "LOCALAPPDATA"} {
		t.Setenv(key, root)
	}
	t.Setenv("CAPX_DATA_DIR", filepath.Join(root, "ca"))
	t.Setenv("CAPX_TOKEN", "")
	state := filepath.Join(root, "state")
	if err := os.MkdirAll(filepath.Join(state, "http_history.sqlite"), 0700); err != nil {
		t.Fatal(err)
	}
	opened := false
	err := runDesktop(context.Background(), "127.0.0.1:0", "127.0.0.1:0", state, false, func(context.Context, string, string) error { opened = true; return nil })
	if err == nil || opened {
		t.Fatalf("persistence failure not surfaced: err=%v opened=%v", err, opened)
	}
}
