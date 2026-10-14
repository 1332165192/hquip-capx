package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestParseTemplateAndRender(t *testing.T) {
	tp := parseTemplate("GET /?a=§x§&b=§y§ HTTP/1.1")
	if tp.markers() != 2 {
		t.Fatalf("markers = %d, want 2", tp.markers())
	}
	if tp.bases[0] != "x" || tp.bases[1] != "y" {
		t.Fatalf("bases = %v", tp.bases)
	}
	got := tp.render([]string{"1", "2"})
	if got != "GET /?a=1&b=2 HTTP/1.1" {
		t.Fatalf("render = %q", got)
	}
}

func TestPayloadProcessing(t *testing.T) {
	cases := []struct {
		p    PayloadProcessing
		in   string
		want string
	}{
		{PayloadProcessing{Encode: "url"}, "a b&c", "a+b%26c"},
		{PayloadProcessing{Encode: "urlall"}, "AB", "%41%42"},
		{PayloadProcessing{Encode: "base64"}, "hi", "aGk="},
		{PayloadProcessing{Encode: "hex"}, "AB", "4142"},
		{PayloadProcessing{Prefix: "<", Suffix: ">"}, "x", "<x>"},
		{PayloadProcessing{Case: "upper"}, "ab", "AB"},
		{PayloadProcessing{Case: "lower", Prefix: "P"}, "AB", "Pab"},
	}
	for i, c := range cases {
		if got := c.p.apply(c.in); got != c.want {
			t.Errorf("case %d: apply(%q) = %q, want %q", i, c.in, got, c.want)
		}
	}
}

func TestBuildVectorsSniper(t *testing.T) {
	sets := [][]string{{"p1", "p2"}}
	v := buildVectors(IntruderSniper, 2, sets, nil)
	// 2 positions x 2 payloads = 4; non-target slots empty (filled later).
	if len(v) != 4 {
		t.Fatalf("sniper vectors = %d, want 4", len(v))
	}
	if v[0][0] != "p1" || v[0][1] != "" {
		t.Fatalf("first sniper vector = %v, want [p1 \"\"]", v[0])
	}
	if v[2][1] != "p1" || v[2][0] != "" {
		t.Fatalf("third sniper vector = %v, want [\"\" p1]", v[2])
	}
}

func TestBuildVectorsBattering(t *testing.T) {
	v := buildVectors(IntruderBattering, 2, [][]string{{"p1", "p2"}}, nil)
	want := [][]string{{"p1", "p1"}, {"p2", "p2"}}
	if !reflect.DeepEqual(v, want) {
		t.Fatalf("battering = %v, want %v", v, want)
	}
}

func TestBuildVectorsPitchfork(t *testing.T) {
	sets := [][]string{{"a1", "a2", "a3"}, {"b1", "b2"}}
	v := buildVectors(IntruderPitchfork, 2, sets, nil)
	want := [][]string{{"a1", "b1"}, {"a2", "b2"}} // lockstep, min length 2
	if !reflect.DeepEqual(v, want) {
		t.Fatalf("pitchfork = %v, want %v", v, want)
	}
}

func TestBuildVectorsCluster(t *testing.T) {
	sets := [][]string{{"a1", "a2"}, {"b1", "b2"}}
	v := buildVectors(IntruderCluster, 2, sets, nil)
	if len(v) != 4 {
		t.Fatalf("cluster vectors = %d, want 4", len(v))
	}
	var got []string
	for _, x := range v {
		got = append(got, strings.Join(x, "+"))
	}
	sort.Strings(got)
	want := []string{"a1+b1", "a1+b2", "a2+b1", "a2+b2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cluster = %v, want %v", got, want)
	}
}

func TestRunIntruderSniperWithGrep(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("u")
		if q == "admin" {
			fmt.Fprint(w, "WELCOME token=SECRET123 home")
			return
		}
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	cfg := IntruderConfig{
		Scheme:      "http",
		Host:        host,
		Template:    fmt.Sprintf("GET /?u=§guest§ HTTP/1.1\r\nHost: %s\r\n\r\n", host),
		Mode:        IntruderSniper,
		PayloadSets: [][]string{{"guest", "admin"}},
		GrepMatch:   []string{"WELCOME"},
		GrepExtract: []string{`token=(\w+)`},
		Concurrency: 4,
	}
	res, err := RunIntruder(cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("results = %d, want 2", len(res))
	}
	// results are index-ordered: 0 = guest (403), 1 = admin (200, matched)
	if res[0].Status != http.StatusForbidden || res[0].Matched {
		t.Fatalf("guest result = %+v", res[0])
	}
	if res[1].Status != http.StatusOK || !res[1].Matched {
		t.Fatalf("admin result = %+v", res[1])
	}
	if len(res[1].Extracts) != 1 || res[1].Extracts[0] != "SECRET123" {
		t.Fatalf("admin extracts = %v, want [SECRET123]", res[1].Extracts)
	}
}

func TestRunIntruderErrors(t *testing.T) {
	if _, err := RunIntruder(IntruderConfig{Template: "nokers"}); err == nil {
		t.Fatal("expected error for missingkers")
	}
	if _, err := RunIntruder(IntruderConfig{Template: "a=§x§ b=§y§", Mode: IntruderPitchfork, PayloadSets: [][]string{{"1"}}}); err == nil {
		t.Fatal("expected error for too few payload sets in pitchfork")
	}
}
