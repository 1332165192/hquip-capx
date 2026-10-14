package dnslog

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/hquip/capx/internal/store"
)

func TestSharedDefaultsKeepPayloadStateIsolatedAndReloadCredentials(t *testing.T) {
	wantKey := "fixture-api-key"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != wantKey {
			t.Fatal("default credential was not used")
		}
		if r.URL.Path != "/api/v1/dnslog/logs" || r.URL.Query().Get("page") != "3" || r.URL.Query().Get("page_size") != "100" || r.URL.Query().Get("subdomain") != "own-subdomain" {
			t.Errorf("wrong log endpoint or pagination: %s", r.URL)
		}
		_, _ = w.Write([]byte(`{"logs":[],"total":0}`))
	}))
	defer backend.Close()
	directory := t.TempDir()
	defaults := filepath.Join(directory, "defaults.json")
	first := New(store.New(10), filepath.Join(directory, "first", "dnslog.json"))
	second := New(store.New(10), filepath.Join(directory, "second", "dnslog.json"))
	first.UseDefaults(defaults)
	second.UseDefaults(defaults)
	if err := first.ConfigureDefaults(backend.URL, wantKey); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Logs(context.Background(), 3, 200, "own-subdomain"); err != nil {
		t.Fatal(err)
	}
	state, err := os.ReadFile(first.persistPath)
	if err != nil || bytes.Contains(state, []byte(wantKey)) {
		t.Fatal("shared credential copied into instance payload state")
	}
	if err := first.ConfigureDefaults(backend.URL, "rotated-fixture-key"); err != nil {
		t.Fatal(err)
	}
	wantKey = "rotated-fixture-key"
	if _, err := second.Logs(context.Background(), 3, 100, "own-subdomain"); err != nil {
		t.Fatal(err)
	}
	if err := first.ConfigureDefaults(backend.URL, ""); err != nil {
		t.Fatal("saving the same address with blank key must preserve it")
	}
	restored := New(store.New(10), first.persistPath)
	restored.UseDefaults(defaults)
	if _, err := restored.Logs(context.Background(), 3, 100, "own-subdomain"); err != nil {
		t.Fatal(err)
	}
	if len(first.Payloads()) != 0 || len(second.Payloads()) != 0 {
		t.Fatal("reading global logs fabricated tracked payloads")
	}
}

func TestProtectedConfigAndPublicStatusDoNotReturnAPIKey(t *testing.T) {
	key := "fixture-sensitive-key"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"logs":[],"total":0}`))
	}))
	defer backend.Close()
	path := filepath.Join(t.TempDir(), "dnslog.json")
	c := New(store.New(10), path)
	if err := c.Configure(backend.URL, key); err != nil {
		t.Fatal(err)
	}
	state, _ := os.ReadFile(path)
	if bytes.Contains(state, []byte(key)) {
		t.Fatal("config stored plaintext API Key")
	}
	loaded := New(store.New(10), path)
	status := loaded.Status(context.Background())
	if !status.APIKeySet || !status.Reachable || status.UseDefaults {
		t.Fatalf("protected explicit config was not restored: %+v", status)
	}
	encoded, _ := json.Marshal(status)
	if bytes.Contains(encoded, []byte(key)) {
		t.Fatal("API Key leaked in status")
	}
	if err := c.Configure("https://user:password@example.com", key); err == nil {
		t.Fatal("accepted credential-bearing URL")
	}
}
