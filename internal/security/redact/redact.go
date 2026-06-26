// Package redact provides credential-redaction patterns shared across the
// SecOps subsystems (audit/SIEM export, shell command logging, etc.).
//
// The patterns cover common credential shapes (Bearer tokens, AWS/GCP/GitHub
// keys, database DSNs, JWTs, private keys, and more). Redaction is best-effort
// and conservative: it is intended to keep secrets out of logs and exports,
// not as a guarantee that no secret can ever leak.
package redact

import "regexp"

// Redacted is the placeholder substituted for detected credentials.
const Redacted = "***REDACTED***"

// patterns holds the credential patterns used to redact sensitive data.
// Covers the credential types documented in SECOPS_FEATURES.md:
//
//  1. Bearer token          (Authorization: Bearer xxx)
//  2. Basic auth            (Authorization: Basic xxx)
//  3. Stripe live key       (sk_live_)
//  4. Stripe test key       (sk_test_)
//  5. AWS access key ID     (AKIA*, ASIA*)
//  6. AWS secret access key (aws_secret_access_key=)
//  7. URL password          (?password=)
//  8. Azure SAS token       (?sig=)
//  9. Generic password/secret/token field
//
// 10. PEM private key       (header + body, multiline)
// 11. GitHub PAT            (ghp_*, github_pat_*)
// 12. GCP credentials       (gcp_*, GOOGLE_*)
// 13. Slack token           (xox[baprs]-*)
// 14. Generic API key       (api_key=, apikey=, api-key=)
// 15. Database DSN          (mysql://, postgres://, mongodb://, redis://)
// 16. JWT token             (eyJ...)
var patterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_-]+`),
	regexp.MustCompile(`(?i)basic\s+[A-Za-z0-9+/=]{8,}`),
	regexp.MustCompile(`(?i)sk_live_[A-Za-z0-9_-]+`),
	regexp.MustCompile(`(?i)sk_test_[A-Za-z0-9_-]+`),
	regexp.MustCompile(`(?i)AKIA[A-Za-z0-9]+`),
	regexp.MustCompile(`(?i)ASIA[A-Za-z0-9]+`),
	regexp.MustCompile(`(?i)aws_secret_access_key[=:]\s*\S+`),
	regexp.MustCompile(`(?i)[?&]password=[^&\s]+`),
	regexp.MustCompile(`(?i)[?&]sig=[A-Za-z0-9%+/=]{20,}`),
	regexp.MustCompile(`(?i)(password|passwd|secret|token)\s*[=:]\s*['"]?[A-Za-z0-9_@#$%^&*!\-]{8,}`),
	regexp.MustCompile(`(?s)-----BEGIN[^-]*PRIVATE KEY-----[^-]*-----END[^-]*PRIVATE KEY-----`),
	regexp.MustCompile(`-----BEGIN[^-]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)ghp_[a-zA-Z0-9]{36}`),
	regexp.MustCompile(`(?i)github_pat_[a-zA-Z0-9_]{22,}`),
	regexp.MustCompile(`(?i)gcp_(credentials|service_account|api_key|access_token|refresh_token|secret_key|auth|key)[a-zA-Z0-9_-]*`),
	regexp.MustCompile(`(?i)_GOOGLE[a-zA-Z0-9_-]+|GOOGLE_[A-Z0-9_]+`),
	regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`),
	regexp.MustCompile(`(?i)(api_key|apikey|api-key)\s*[=:]\s*['"]?[A-Za-z0-9_\-]{20,}`),
	regexp.MustCompile(`(?i)(mysql|postgres|mongodb|redis|postgresql)://[^@\s]+:[^@\s]+@`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
}

// String applies all credential-redaction patterns to s, replacing each match
// with Redacted. The empty string is returned unchanged.
func String(s string) string {
	if s == "" {
		return s
	}
	result := s
	for _, re := range patterns {
		result = re.ReplaceAllString(result, Redacted)
	}
	return result
}
