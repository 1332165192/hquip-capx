package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const shutdownHealth = `{"status":"ok","sniffer":"stub","hook":"stub","inline":"stub","identity":{"instance_id":"instance-a","generation":"generation-a"}}`

func shutdownServer(t *testing.T, handler http.HandlerFunc) *Server {
	t.Helper()
	fixture := httptest.NewServer(handler)
	t.Cleanup(fixture.Close)
	return &Server{api: &apiClient{base: fixture.URL, token: "instance-token", http: fixture.Client(), active: true}}
}

func TestRegressionMCPShutdownBindsObservedIdentityAndAuthenticates(t *testing.T) {
	for _, tc := range []struct {
		name, args, health, instance, generation string
	}{
		{"auto", `{}`, shutdownHealth, "instance-a", "generation-a"},
		{"explicit", `{"expected_instance_id":"instance-a","expected_generation":"generation-a"}`, shutdownHealth, "instance-a", "generation-a"},
		{"nested", `{"body":{"expected_generation":"generation-a"}}`, shutdownHealth, "instance-a", "generation-a"},
		{"matching-duplicate", `{"expected_generation":"generation-a","body":{"expected_generation":"generation-a"}}`, shutdownHealth, "instance-a", "generation-a"},
		{"legacy-empty-identity", `{}`, `{"status":"ok","sniffer":"stub","hook":"stub","inline":"stub"}`, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var healthCalls, postCalls atomic.Int32
			s := shutdownServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer instance-token" || r.Header.Get("X-Capx-Token") != "instance-token" {
					t.Error("instance authentication was not forwarded")
					http.Error(w, "unauthorized", 401)
					return
				}
				if r.URL.Path == "/health" && r.Method == "GET" {
					healthCalls.Add(1)
					fmt.Fprint(w, tc.health)
					return
				}
				if r.URL.Path != "/api/runtime/shutdown" || r.Method != "POST" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				postCalls.Add(1)
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				id, idOK := body["expected_instance_id"].(string)
				generation, generationOK := body["expected_generation"].(string)
				if len(body) != 2 || !idOK || !generationOK || id != tc.instance || generation != tc.generation {
					t.Errorf("expected both explicit string conditions, got %#v", body)
				}
				w.WriteHeader(http.StatusAccepted)
				fmt.Fprint(w, `{"status":"shutting_down"}`)
			})
			result, isErr := s.call("capx_runtime_shutdown", json.RawMessage(tc.args))
			if isErr || !strings.Contains(result, "shutting_down") || healthCalls.Load() != 1 || postCalls.Load() != 1 {
				t.Fatalf("result=%q error=%v health=%d posts=%d", result, isErr, healthCalls.Load(), postCalls.Load())
			}
		})
	}
}

func TestRegressionMCPShutdownNeverOverridesExplicitExpectation(t *testing.T) {
	for _, args := range []string{
		`{"expected_generation":"old-generation"}`,
		`{"body":{"expected_generation":"old-generation"}}`,
		`{"expected_instance_id":"other-instance"}`,
		`{"expected_generation":""}`,
		`{"expected_instance_id":""}`,
	} {
		t.Run(args, func(t *testing.T) {
			var posts atomic.Int32
			s := shutdownServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					posts.Add(1)
				}
				fmt.Fprint(w, shutdownHealth)
			})
			result, isErr := s.call("capx_runtime_shutdown", json.RawMessage(args))
			if !isErr || !strings.Contains(result, "mismatch") || posts.Load() != 0 {
				t.Fatalf("result=%q error=%v posts=%d", result, isErr, posts.Load())
			}
		})
	}
}

func TestRegressionMCPShutdownReplacementBetweenHealthAndPost(t *testing.T) {
	var posts, stopped atomic.Int32
	s := shutdownServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			fmt.Fprint(w, shutdownHealth)
			return
		}
		posts.Add(1)
		// A new generation now occupies the same port and retains the same
		// state-directory token. Its atomic identity check must reject the old
		// condition; a token alone would have stopped this replacement.
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["expected_instance_id"] != "instance-a" || body["expected_generation"] != "generation-b" {
			http.Error(w, "runtime identity changed; replacement preserved", http.StatusConflict)
			return
		}
		stopped.Add(1)
		w.WriteHeader(http.StatusAccepted)
	})
	result, isErr := s.call("capx_runtime_shutdown", json.RawMessage(`{}`))
	if !isErr || !strings.Contains(result, "HTTP 409") || posts.Load() != 1 || stopped.Load() != 0 {
		t.Fatalf("result=%q error=%v posts=%d stopped=%d", result, isErr, posts.Load(), stopped.Load())
	}
}

func TestRegressionMCPShutdownRejectsMalformedArgumentsBeforeHTTP(t *testing.T) {
	var requests atomic.Int32
	s := shutdownServer(t, func(w http.ResponseWriter, r *http.Request) { requests.Add(1) })
	for _, args := range []string{
		`[]`, `"old-generation"`, `{`, `{"generation":"old-generation"}`,
		`{"expected_generation":null}`, `{"expected_instance_id":17}`,
		`{"body":null}`, `{"body":{"generation":"old-generation"}}`,
		`{"expected_generation":"old","body":{"expected_generation":"new"}}`,
	} {
		if result, isErr := s.call("capx_runtime_shutdown", json.RawMessage(args)); !isErr {
			t.Errorf("accepted malformed arguments %s: %s", args, result)
		}
	}
	if requests.Load() != 0 {
		t.Fatal("malformed/ambiguous shutdown arguments made HTTP requests")
	}
}

func TestRegressionMCPShutdownRequiresValidHealth(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		body string
	}{
		{"not-found", 404, shutdownHealth}, {"auth", 401, `{"error":"bad token"}`},
		{"html", 200, "<html>unrelated app</html>"}, {"generic", 200, `{"status":"ok"}`},
		{"down", 200, strings.Replace(shutdownHealth, `"ok"`, `"down"`, 1)},
		{"trailing", 200, shutdownHealth + `{}`},
		{"bad-identity", 200, strings.Replace(shutdownHealth, `"generation-a"`, `17`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var posts atomic.Int32
			s := shutdownServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					posts.Add(1)
				}
				w.WriteHeader(tc.code)
				fmt.Fprint(w, tc.body)
			})
			if result, isErr := s.call("capx_runtime_shutdown", json.RawMessage(`{}`)); !isErr || posts.Load() != 0 {
				t.Fatalf("result=%q error=%v posts=%d", result, isErr, posts.Load())
			}
		})
	}
}

func TestRegressionMCPShutdownErrorsAreNotRetriedOrHidden(t *testing.T) {
	for _, code := range []int{401, 403, 409, 404, 503} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			var posts atomic.Int32
			s := shutdownServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health" {
					fmt.Fprint(w, shutdownHealth)
					return
				}
				posts.Add(1)
				http.Error(w, "fixture failure", code)
			})
			result, isErr := s.call("capx_runtime_shutdown", json.RawMessage(`{}`))
			if !isErr || !strings.Contains(result, fmt.Sprintf("HTTP %d", code)) || posts.Load() != 1 {
				t.Fatalf("result=%q error=%v posts=%d", result, isErr, posts.Load())
			}
		})
	}
}

func TestRegressionMCPShutdownDoesNotFollowRedirects(t *testing.T) {
	for _, redirectPath := range []string{"/health", "/api/runtime/shutdown"} {
		t.Run(redirectPath, func(t *testing.T) {
			var redirected atomic.Int32
			other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				redirected.Add(1)
				fmt.Fprint(w, shutdownHealth)
			}))
			defer other.Close()
			s := shutdownServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == redirectPath {
					http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
					return
				}
				fmt.Fprint(w, shutdownHealth)
			})
			if result, isErr := s.call("capx_runtime_shutdown", json.RawMessage(`{}`)); !isErr || !strings.Contains(result, "HTTP 307") || redirected.Load() != 0 {
				t.Fatalf("result=%q error=%v redirects=%d", result, isErr, redirected.Load())
			}
		})
	}
}

func TestRegressionMCPShutdownActiveGateAndGenericCompatibility(t *testing.T) {
	var calls atomic.Int32
	s := shutdownServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if r.Method != "POST" || r.URL.Path != "/api/runtime/shutdown" || len(body) != 1 || body["custom"] != "raw" {
			t.Errorf("generic API was altered: %s %s %#v", r.Method, r.URL.Path, body)
		}
		w.WriteHeader(202)
	})
	s.api.active = false
	if result, isErr := s.call("capx_runtime_shutdown", json.RawMessage(`{}`)); !isErr || !strings.Contains(result, "CAPX_MCP_ACTIVE") {
		t.Fatalf("active gate lost: %s", result)
	}
	if calls.Load() != 0 {
		t.Fatal("inactive named tool contacted API")
	}
	s.api.active = true
	if result, isErr := s.call("capx_api", json.RawMessage(`{"method":"POST","path":"/api/runtime/shutdown","body":{"custom":"raw"}}`)); isErr {
		t.Fatal(result)
	}
	if calls.Load() != 1 {
		t.Fatal("generic API gained an implicit health/shutdown request")
	}
}

func TestRegressionMCPShutdownSchemaAdvertisesExpectations(t *testing.T) {
	route, ok := findRoute("capx_runtime_shutdown")
	if !ok || !route.Active {
		t.Fatal("shutdown route/gate missing")
	}
	schema := route.schema()
	props := schema["properties"].(map[string]any)
	for _, key := range []string{"expected_generation", "expected_instance_id"} {
		if props[key].(map[string]any)["type"] != "string" {
			t.Errorf("%s is not advertised as string", key)
		}
	}
	if schema["additionalProperties"] != false {
		t.Fatal("shutdown schema must reject misspelled expectations")
	}
}
