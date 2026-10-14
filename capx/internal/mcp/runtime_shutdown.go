package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func runtimeShutdownSchema() map[string]any {
	fields := map[string]any{
		"expected_instance_id": map[string]any{"type": "string", "description": "Expected instance ID; an explicitly empty string is significant. Omit to bind the observed health identity."},
		"expected_generation":  map[string]any{"type": "string", "description": "Expected generation; never replaced by the current generation when supplied."},
	}
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"expected_instance_id": fields["expected_instance_id"],
			"expected_generation":  fields["expected_generation"],
			"body": map[string]any{
				"type": "object", "properties": fields, "additionalProperties": false,
				"description": "Optional wrapper for the same expected identity fields; conflicting duplicate values are rejected.",
			},
		},
		"additionalProperties": false,
	}
}

// Explicit expectations are strict strings, including empty strings. Reject
// typos and conflicting wrapper/top-level values instead of silently replacing
// a caller's intended old generation with the newly observed instance.
func shutdownExpectations(args map[string]any) (map[string]string, error) {
	expected := make(map[string]string, 2)
	merge := func(fields map[string]any, wrapper bool) error {
		for key, value := range fields {
			if key == "body" && wrapper {
				continue
			}
			if key != "expected_instance_id" && key != "expected_generation" {
				return fmt.Errorf("unknown runtime shutdown argument %q", key)
			}
			text, ok := value.(string)
			if !ok {
				return fmt.Errorf("%s must be a string (empty is allowed)", key)
			}
			if previous, exists := expected[key]; exists && previous != text {
				return fmt.Errorf("conflicting runtime shutdown argument %s", key)
			}
			expected[key] = text
		}
		return nil
	}
	if err := merge(args, true); err != nil {
		return nil, err
	}
	if body, exists := args["body"]; exists {
		fields, ok := body.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("runtime shutdown body must be an object")
		}
		if err := merge(fields, false); err != nil {
			return nil, err
		}
	}
	return expected, nil
}

func (s *Server) shutdownRuntime(args map[string]any) (any, error) {
	expected, err := shutdownExpectations(args)
	if err != nil {
		return nil, err
	}
	// Keep health and shutdown pinned to this API endpoint. Do not follow a
	// redirect into another runtime, even when it shares the same credentials.
	client := *s.api
	transport := *s.api.http
	transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.http = &transport
	code, raw, err := client.do(http.MethodGet, "/health", nil, nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("GET /health: HTTP %d: %s", code, strings.TrimSpace(string(raw)))
	}
	var health struct {
		Status   string `json:"status"`
		Sniffer  string `json:"sniffer"`
		Hook     string `json:"hook"`
		Inline   string `json:"inline"`
		Identity struct {
			InstanceID string `json:"instance_id"`
			Generation string `json:"generation"`
		} `json:"identity"`
	}
	if err := json.Unmarshal(raw, &health); err != nil || health.Status != "ok" || health.Sniffer == "" || health.Hook == "" || health.Inline == "" {
		return nil, fmt.Errorf("runtime shutdown refused: response is not a valid Capx health document")
	}
	observed := map[string]string{
		"expected_instance_id": health.Identity.InstanceID,
		"expected_generation":  health.Identity.Generation,
	}
	for key, value := range expected {
		if observed[key] != value {
			return nil, fmt.Errorf("runtime shutdown refused: %s mismatch (expected %q, observed %q); no shutdown requested", key, value, observed[key])
		}
	}
	// Both keys are always emitted, including for legacy identity-less health.
	// The server checks them atomically so a port replacement after GET /health
	// produces an HTTP 409 rather than shutting down the replacement generation.
	code, raw, err = client.do(http.MethodPost, "/api/runtime/shutdown", nil, observed)
	if err != nil {
		return nil, err
	}
	if code != http.StatusAccepted && code != http.StatusOK {
		return nil, fmt.Errorf("POST /api/runtime/shutdown: HTTP %d: %s", code, strings.TrimSpace(string(raw)))
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return map[string]any{"ok": true}, nil
	}
	var result any
	if json.Unmarshal(raw, &result) != nil {
		return string(raw), nil
	}
	return result, nil
}
