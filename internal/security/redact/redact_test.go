package redact

import (
	"strings"
	"testing"
)

func TestString_RedactsKnownCredentialShapes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
	}{
		{"bearer token", "Authorization: Bearer abcdef1234567890"},
		{"basic auth", "Authorization: Basic dXNlcjpwYXNzMTIzNDU="},
		{"stripe live key", "sk_live_abcdefABCDEF1234567890"},
		{"aws access key id", "AKIAIOSFODNN7EXAMPLE"},
		{"aws secret key", "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG"},
		{"url password", "https://example.com/login?password=SuperSecret123"},
		{"github pat", "ghp_ABCD1234EFGH5678IJKL9012MNOP345678QR"},
		{"slack token", "xoxb-1234567890123-1234567890123-abcdefABCDEF"},
		{"generic api key", "api_key=FAKEFAKEFAKEFAKEFAKEFAKEFAKE0000"},
		{"mysql dsn", "mysql://admin:password123@localhost:3306/db"},
		{"jwt token", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJ"},
		{
			"pem private key",
			"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ\n-----END RSA PRIVATE KEY-----",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := String(tc.input)
			if got == tc.input {
				t.Errorf("expected redaction, input unchanged: %q", got)
			}
			if !strings.Contains(got, Redacted) {
				t.Errorf("expected output to contain %q, got %q", Redacted, got)
			}
		})
	}
}

func TestString_PreservesSafeContent(t *testing.T) {
	t.Parallel()

	safe := []string{
		"",
		"ls -la /var/log",
		"SELECT * FROM users WHERE id = 1",
		"[INFO] Server started on port 8080",
		"gcp_instance_name=prod-server-01",
	}
	for _, in := range safe {
		if got := String(in); got != in {
			t.Errorf("String(%q) = %q; want unchanged", in, got)
		}
	}
}
