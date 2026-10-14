package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRuntimeShutdownPreconditionRejectsReplacement(t *testing.T) {
	srv := &Server{}
	srv.SetRuntimeIdentity("project", "new-generation")
	called := make(chan struct{}, 1)
	srv.SetRuntimeShutdown(func() { called <- struct{}{} })
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"expected_instance_id":"project","expected_generation":"old-generation"}`, 409},
		{`{"expected_instance_id":"other","expected_generation":"new-generation"}`, 409},
		{`{"expected_instance_id":"","expected_generation":""}`, 409},
		{`{"expected_generation":"new-generation"}`, 400},
		{`{"expected_instance_id":null,"expected_generation":null}`, 400},
		{`{`, 400},
		{`{} {}`, 400},
	} {
		w := httptest.NewRecorder()
		srv.runtimeShutdownHandler(w, httptest.NewRequest(http.MethodPost, "/api/runtime/shutdown", strings.NewReader(tc.body)))
		if w.Code != tc.status {
			t.Fatalf("body=%s status=%d want=%d", tc.body, w.Code, tc.status)
		}
	}
	select {
	case <-called:
		t.Fatal("mismatched generation triggered shutdown")
	default:
	}
	w := httptest.NewRecorder()
	srv.runtimeShutdownHandler(w, httptest.NewRequest(http.MethodPost, "/api/runtime/shutdown", strings.NewReader(`{"expected_instance_id":"project","expected_generation":"new-generation"}`)))
	if w.Code != http.StatusAccepted {
		t.Fatalf("matching identity rejected: %s", w.Body.String())
	}
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("matching shutdown not invoked")
	}
}

func TestRuntimeShutdownExplicitLegacyIdentity(t *testing.T) {
	srv := &Server{}
	called := make(chan struct{}, 1)
	srv.SetRuntimeShutdown(func() { called <- struct{}{} })
	w := httptest.NewRecorder()
	srv.runtimeShutdownHandler(w, httptest.NewRequest(http.MethodPost, "/api/runtime/shutdown", strings.NewReader(`{"expected_instance_id":"","expected_generation":""}`)))
	if w.Code != http.StatusAccepted {
		t.Fatalf("legacy identity rejected: %s", w.Body.String())
	}
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("legacy shutdown not invoked")
	}
}
