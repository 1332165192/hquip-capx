package scan

import "testing"

func hasRule(fs []Finding, rule string) bool {
	for _, f := range fs {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestSecurityHeaders(t *testing.T) {
	tx := Tx{Scheme: "https", MIME: "text/html", Status: 200, RespHdr: map[string]string{}}
	fs := ScanTx(tx)
	for _, want := range []string{"missing_csp", "missing_xcto", "missing_hsts", "missing_xfo"} {
		if !hasRule(fs, want) {
			t.Errorf("expected %s finding", want)
		}
	}
	// With all headers present, none should fire.
	tx.RespHdr = map[string]string{
		"Content-Security-Policy":   "default-src 'self'",
		"X-Content-Type-Options":    "nosniff",
		"Strict-Transport-Security": "max-age=63072000",
		"X-Frame-Options":           "DENY",
	}
	if fs := ScanTx(tx); hasRule(fs, "missing_csp") {
		t.Error("csp should not be flagged when present")
	}
}

func TestCORS(t *testing.T) {
	tx := Tx{MIME: "application/json", RespHdr: map[string]string{
		"Access-Control-Allow-Origin":      "*",
		"Access-Control-Allow-Credentials": "true",
	}}
	fs := ScanTx(tx)
	if !hasRule(fs, "cors_wildcard") {
		t.Fatal("expected cors_wildcard")
	}
	for _, f := range fs {
		if f.Rule == "cors_wildcard" && f.Severity != SevHigh {
			t.Fatalf("wildcard+creds should be high, got %s", f.Severity)
		}
	}
}

func TestSecretsAndPII(t *testing.T) {
	tx := Tx{MIME: "application/json", RespBody: `{"key":"AKIAIOSFODNN7EXAMPLE","email":"a@b.com"}`}
	fs := ScanTx(tx)
	if !hasRule(fs, "secret_aws_access_key") {
		t.Error("expected aws key finding")
	}
	if !hasRule(fs, "pii_email") {
		t.Error("expected email finding")
	}
}

func TestReflection(t *testing.T) {
	tx := Tx{MIME: "text/html", RawQuery: "q=<script>alert", RespBody: "<html>you searched <script>alert</html>"}
	if !hasRule(ScanTx(tx), "reflected_param") {
		t.Error("expected reflected_param finding")
	}
}

func TestLuhn(t *testing.T) {
	if !luhnValid("4111111111111111") { // valid test Visa
		t.Error("valid card rejected")
	}
	if luhnValid("4111111111111112") {
		t.Error("invalid card accepted")
	}
}

func TestCookieAndAltSvcFindings(t *testing.T) {
	tx := Tx{
		Scheme: "https",
		RespRaw: "HTTP/1.1 200 OK\r\n" +
			"Alt-Svc: h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000\r\n" +
			"Set-Cookie: csrfToken=abc; Path=/; Secure; SameSite=None\r\n" +
			"Set-Cookie: sid=xyz; Path=/; SameSite=None\r\n" +
			"Set-Cookie: old=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; httponly\r\n\r\n",
	}
	fs := ScanTx(tx)
	for _, want := range []string{"cookie_no_httponly", "cookie_no_secure", "cookie_samesite_none_no_secure", "altsvc_h3_advertised"} {
		if !hasRule(fs, want) {
			t.Errorf("expected %s finding", want)
		}
	}
}

func TestVolcengineHeaderSample(t *testing.T) {
	tx := Tx{
		Scheme: "https",
		RespRaw: "HTTP/1.1 200 OK\r\n" +
			"Alt-Svc: h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000\r\n" +
			"Cache-Control: no-store\r\n" +
			"Content-Encoding: br\r\n" +
			"Content-Security-Policy: frame-ancestors vip.byted.org ad.oceanengine.com 'self' *.volcengine.com\r\n" +
			"Content-Type: text/html; charset=utf-8\r\n" +
			"Set-Cookie: csrfToken=a6cc68a3cab6bd20f9b3411511b1e2e0; Domain=volcengine.com; Path=/; Secure; SameSite=None\r\n" +
			"Set-Cookie: csrfToken=a6cc68a3cab6bd20f9b3411511b1e2e0; Domain=volcengine.com; Path=/; Secure; Partitioned; SameSite=None\r\n" +
			"Set-Cookie: csrfToken=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; httponly\r\n" +
			"Set-Cookie: __spti=11_000J3SVMZ/xPtPrMwlQ3ilQxfn2UtC; max-age=15552000; domain=.volcengine.com; path=/; secure; SameSite=None\r\n" +
			"Set-Cookie: __sptiho=3511_000J3SVMZ/xPtPrMwlQ3ilQxfn2UtC_bEv/KoxCOM4AcC; max-age=15552000; domain=.volcengine.com; path=/; HttpOnly; secure; SameSite=None\r\n" +
			"Set-Cookie: __spti=11_000J3SVMZ/xPtPrMwlQ3ilQxfn2UtC; max-age=15552000; domain=.volcengine.com; path=/; secure; SameSite=None; Partitioned\r\n" +
			"Set-Cookie: __sptiho=3511_000J3SVMZ/xPtPrMwlQ3ilQxfn2UtC_bEv/KoxCOM4AcC; max-age=15552000; domain=.volcengine.com; path=/; HttpOnly; secure; SameSite=None; Partitioned\r\n" +
			"Set-Cookie: p_c_check=1; Domain=volcengine.com; Path=/; Secure; Partitioned; SameSite=None\r\n\r\n",
	}
	fs := ScanTx(tx)
	if !hasRule(fs, "altsvc_h3_advertised") {
		t.Fatal("expected HTTP/3 Alt-Svc finding")
	}
	if !hasRule(fs, "cookie_no_httponly") {
		t.Fatal("expected csrfToken without HttpOnly finding")
	}
	for _, unexpected := range []string{"cookie_no_secure", "cookie_samesite_none_no_secure", "cookie_partitioned_no_secure"} {
		if hasRule(fs, unexpected) {
			t.Fatalf("did not expect %s for the supplied secure cookies", unexpected)
		}
	}
}
