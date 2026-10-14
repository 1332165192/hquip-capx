package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManagerRequestGuardRejectsCrossOriginMutation(t *testing.T) {
	called := false
	handler := managerRequestGuard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18990/api/stop-all", nil)
	req.Header.Set("Origin", "https://attacker.example")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden || called {
		t.Fatalf("cross-origin mutation was not rejected: status=%d called=%v", recorder.Code, called)
	}
}

func TestClipboardTextIsPassedOnlyThroughStandardInput(t *testing.T) {
	payload := "'@\nWrite-Output CAPX_INJECTED\n@'"
	cmd := clipboardCommand(payload)
	if strings.Contains(strings.Join(cmd.Args, " "), "CAPX_INJECTED") {
		t.Fatal("clipboard text was interpolated into the PowerShell command")
	}
	got, err := io.ReadAll(cmd.Stdin)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("clipboard stdin changed: got %q", got)
	}
}

func TestManagerRequestGuardRejectsDNSRebindingHost(t *testing.T) {
	handler := managerRequestGuard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("request with a non-loopback Host reached the handler")
	}))
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18990/api/instances", nil)
	req.Host = "attacker.example"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("got status %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func TestManagerRequestGuardRequiresPostForSideEffects(t *testing.T) {
	handler := managerRequestGuard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("GET side effect reached the handler")
	}))
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18990/api/exit", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got status %d, want %d", recorder.Code, http.StatusMethodNotAllowed)
	}
}

func TestManagerRequestGuardRequiresJSONForStart(t *testing.T) {
	handler := managerRequestGuard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("text/plain JSON reached the start handler")
	}))
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18990/api/start", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "text/plain")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("got status %d, want %d", recorder.Code, http.StatusUnsupportedMediaType)
	}
}

func TestManagerRequestGuardProtectsSRCTemplateEndpoint(t *testing.T) {
	handler := managerRequestGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	getRequest := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18990/api/src-template", nil)
	getRecorder := httptest.NewRecorder()
	handler.ServeHTTP(getRecorder, getRequest)
	if getRecorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("SRC template GET got status %d", getRecorder.Code)
	}

	plainRequest := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18990/api/src-template", strings.NewReader(`{}`))
	plainRequest.Header.Set("Content-Type", "text/plain")
	plainRecorder := httptest.NewRecorder()
	handler.ServeHTTP(plainRecorder, plainRequest)
	if plainRecorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("SRC template text/plain got status %d", plainRecorder.Code)
	}
}

func TestManagerRequestGuardProtectsDirectorySelector(t *testing.T) {
	handler := managerRequestGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, test := range []struct {
		method      string
		contentType string
		want        int
	}{
		{http.MethodGet, "", http.StatusMethodNotAllowed},
		{http.MethodPost, "text/plain", http.StatusUnsupportedMediaType},
		{http.MethodPost, "application/json", http.StatusNoContent},
	} {
		request := httptest.NewRequest(test.method, "http://127.0.0.1:18990/api/select-directory", strings.NewReader(`{"kind":"project"}`))
		if test.contentType != "" {
			request.Header.Set("Content-Type", test.contentType)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != test.want {
			t.Fatalf("%s %s got %d, want %d", test.method, test.contentType, recorder.Code, test.want)
		}
	}
}

func TestManagerRequestGuardAllowsSameOriginJSON(t *testing.T) {
	called := false
	handler := managerRequestGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18990/api/start", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://127.0.0.1:18990")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent || !called {
		t.Fatalf("same-origin JSON was rejected: status=%d called=%v", recorder.Code, called)
	}
}
