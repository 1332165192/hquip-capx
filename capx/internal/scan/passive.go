// Package scan implements passive, non-intrusive issue detection over captured
// HTTP transactions (Burp's "passive scan" style): it never sends traffic, it
// only inspects what was already captured. Findings cover missing/weak security
// headers, secrets/PII leaked in responses, permissive CORS, and reflected
// parameters (a reflected-XSS smell). The detectors are pure functions so they
// are unit-testable without a live target.
package scan

import (
	"net/url"
	"regexp"
	"strings"
)

// Severity levels for a finding.
const (
	SevInfo = "info"
	SevLow  = "low"
	SevMed  = "medium"
	SevHigh = "high"
)

// Finding is one passive issue detected on a transaction.
type Finding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
}

// Tx is the subset of an HTTP transaction the passive scanner needs. The api
// layer adapts model.HTTPTx into this so the scanner has no model dependency.
type Tx struct {
	Scheme   string
	Method   string
	Host     string
	URL      string
	Status   int
	MIME     string
	RawQuery string
	ReqHdr   map[string]string
	RespHdr  map[string]string
	RespRaw  string
	RespBody string
}

// secretPatterns flags high-confidence credential/key shapes in responses.
var secretPatterns = []struct {
	rule string
	re   *regexp.Regexp
}{
	{"aws_access_key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"google_api_key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"slack_token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z\-]{10,48}`)},
	{"github_token", regexp.MustCompile(`ghp_[0-9A-Za-z]{36}`)},
	{"private_key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)},
	{"bearer_secret", regexp.MustCompile(`(?i)(authorization|api[_-]?key|secret|password)["'\s:=]+[A-Za-z0-9+/\-_]{16,}`)},
}

// piiPatterns flags personal data in responses.
var piiPatterns = []struct {
	rule string
	re   *regexp.Regexp
}{
	{"email", regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)},
	{"credit_card", regexp.MustCompile(`\b(?:\d[ \-]?){13,16}\b`)},
}

// ScanTx runs every passive detector over one transaction.
func ScanTx(tx Tx) []Finding {
	var out []Finding
	out = append(out, checkSecurityHeaders(tx)...)
	out = append(out, checkCORS(tx)...)
	out = append(out, checkSecrets(tx)...)
	out = append(out, checkReflection(tx)...)
	out = append(out, checkCookies(tx)...)
	out = append(out, checkAltSvc(tx)...)
	return out
}

func header(h map[string]string, name string) string {
	if h == nil {
		return ""
	}
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// checkSecurityHeaders flags missing response hardening headers on HTML pages.
func checkSecurityHeaders(tx Tx) []Finding {
	if !strings.Contains(strings.ToLower(tx.MIME), "html") {
		return nil
	}
	var out []Finding
	want := []struct {
		name, rule, title, sev string
	}{
		{"Content-Security-Policy", "missing_csp", "Missing Content-Security-Policy", SevMed},
		{"X-Content-Type-Options", "missing_xcto", "Missing X-Content-Type-Options: nosniff", SevLow},
		{"Strict-Transport-Security", "missing_hsts", "Missing Strict-Transport-Security (HTTPS only)", SevLow},
		{"X-Frame-Options", "missing_xfo", "Missing X-Frame-Options / frame-ancestors", SevLow},
	}
	for _, h := range want {
		if h.rule == "missing_hsts" && tx.Scheme != "https" {
			continue
		}
		if header(tx.RespHdr, h.name) == "" {
			out = append(out, Finding{Rule: h.rule, Severity: h.sev, Title: h.title})
		}
	}
	return out
}

// checkCORS flags permissive Access-Control-Allow-Origin, worst with credentials.
func checkCORS(tx Tx) []Finding {
	acao := header(tx.RespHdr, "Access-Control-Allow-Origin")
	if acao == "" {
		return nil
	}
	creds := strings.EqualFold(header(tx.RespHdr, "Access-Control-Allow-Credentials"), "true")
	if acao == "*" {
		sev := SevLow
		if creds {
			sev = SevHigh // * + credentials is invalid-but-dangerous if honored
		}
		return []Finding{{Rule: "cors_wildcard", Severity: sev, Title: "Permissive CORS: Access-Control-Allow-Origin: *", Detail: "credentials=" + boolStr(creds)}}
	}
	// Reflecting the request Origin with credentials = effectively any origin.
	if creds && acao == header(tx.ReqHdr, "Origin") && acao != "" {
		return []Finding{{Rule: "cors_reflect_origin", Severity: SevHigh, Title: "CORS reflects request Origin with credentials", Detail: acao}}
	}
	return nil
}

// checkSecrets flags secrets/PII in the response body.
func checkSecrets(tx Tx) []Finding {
	var out []Finding
	for _, p := range secretPatterns {
		if p.re.MatchString(tx.RespBody) {
			out = append(out, Finding{Rule: "secret_" + p.rule, Severity: SevHigh, Title: "Possible secret in response: " + p.rule})
		}
	}
	for _, p := range piiPatterns {
		if m := p.re.FindString(tx.RespBody); m != "" {
			if p.rule == "credit_card" && !luhnValid(m) {
				continue
			}
			out = append(out, Finding{Rule: "pii_" + p.rule, Severity: SevMed, Title: "Possible PII in response: " + p.rule})
		}
	}
	return out
}

// checkReflection flags request query/param values reflected verbatim in an
// HTML response (a reflected-XSS smell worth manual follow-up).
func checkReflection(tx Tx) []Finding {
	if !strings.Contains(strings.ToLower(tx.MIME), "html") || tx.RawQuery == "" {
		return nil
	}
	vals, err := url.ParseQuery(tx.RawQuery)
	if err != nil {
		return nil
	}
	var out []Finding
	for k, vs := range vals {
		for _, v := range vs {
			if len(v) < 4 {
				continue // too short to be meaningful
			}
			if strings.Contains(tx.RespBody, v) {
				out = append(out, Finding{Rule: "reflected_param", Severity: SevLow,
					Title: "Request parameter reflected in HTML response", Detail: k + "=" + v})
			}
		}
	}
	return out
}

// checkCookies flags cookies set without baseline browser protections.
func checkCookies(tx Tx) []Finding {
	cookies := headerValues(tx, "Set-Cookie")
	if len(cookies) == 0 {
		return nil
	}
	var out []Finding
	for _, sc := range cookies {
		c := parseCookie(sc)
		if c.name == "" || c.deleted {
			continue
		}
		detail := c.name
		if tx.Scheme == "https" && !c.attrs["secure"] {
			out = append(out, Finding{Rule: "cookie_no_secure", Severity: SevLow, Title: "Set-Cookie without Secure on HTTPS", Detail: detail})
		}
		if !c.attrs["httponly"] && sensitiveCookieName(c.name) {
			out = append(out, Finding{Rule: "cookie_no_httponly", Severity: SevLow, Title: "Sensitive cookie without HttpOnly", Detail: detail})
		}
		if strings.EqualFold(c.attrValue["samesite"], "none") && !c.attrs["secure"] {
			out = append(out, Finding{Rule: "cookie_samesite_none_no_secure", Severity: SevMed, Title: "SameSite=None cookie without Secure", Detail: detail})
		}
		if c.attrs["partitioned"] && !c.attrs["secure"] {
			out = append(out, Finding{Rule: "cookie_partitioned_no_secure", Severity: SevMed, Title: "Partitioned cookie without Secure", Detail: detail})
		}
	}
	return out
}

func checkAltSvc(tx Tx) []Finding {
	alts := headerValues(tx, "Alt-Svc")
	for _, v := range alts {
		low := strings.ToLower(v)
		if strings.Contains(low, `h3="`) || strings.Contains(low, "h3-") {
			return []Finding{{Rule: "altsvc_h3_advertised", Severity: SevInfo, Title: "HTTP/3 Alt-Svc advertised", Detail: "Clients may switch to QUIC; disable QUIC or capture QUIC when proxying this target."}}
		}
	}
	return nil
}

type parsedCookie struct {
	name      string
	attrs     map[string]bool
	attrValue map[string]string
	deleted   bool
}

func parseCookie(sc string) parsedCookie {
	c := parsedCookie{attrs: map[string]bool{}, attrValue: map[string]string{}}
	parts := strings.Split(sc, ";")
	if len(parts) == 0 {
		return c
	}
	first := strings.TrimSpace(parts[0])
	if eq := strings.IndexByte(first, '='); eq > 0 {
		c.name = strings.TrimSpace(first[:eq])
		if strings.TrimSpace(first[eq+1:]) == "" {
			c.deleted = true
		}
	}
	low := strings.ToLower(sc)
	if strings.Contains(low, "expires=thu, 01 jan 1970") || strings.Contains(low, "max-age=0") {
		c.deleted = true
	}
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		k, v, ok := strings.Cut(p, "=")
		key := strings.ToLower(strings.TrimSpace(k))
		c.attrs[key] = true
		if ok {
			c.attrValue[key] = strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return c
}

func sensitiveCookieName(name string) bool {
	low := strings.ToLower(name)
	for _, ker := range []string{"session", "sess", "token", "csrf", "auth", "jwt", "sid", "sso"} {
		if strings.Contains(low, ker) {
			return true
		}
	}
	return false
}

func headerValues(tx Tx, name string) []string {
	vals := rawHeaderValues(tx.RespRaw, name)
	if len(vals) > 0 {
		return vals
	}
	if v := header(tx.RespHdr, name); v != "" {
		return []string{v}
	}
	return nil
}

func rawHeaderValues(raw, name string) []string {
	if raw == "" {
		return nil
	}
	name = strings.ToLower(name) + ":"
	head := raw
	if i := strings.Index(head, "\r\n\r\n"); i >= 0 {
		head = head[:i]
	} else if i := strings.Index(head, "\n\n"); i >= 0 {
		head = head[:i]
	}
	var vals []string
	for _, line := range strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(strings.ToLower(line), name) {
			vals = append(vals, strings.TrimSpace(line[len(name):]))
		}
	}
	return vals
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// luhnValid checks the Luhn checksum to cut credit-card false positives.
func luhnValid(s string) bool {
	var digits []int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		}
	}
	if len(digits) < 13 {
		return false
	}
	sum := 0
	dbl := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if dbl {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		dbl = !dbl
	}
	return sum%10 == 0
}
