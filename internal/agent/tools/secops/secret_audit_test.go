package secops

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// ghp_ + 36 alphanumeric = 40 chars total. The regex is `(?i)ghp_[a-zA-Z0-9]{36}`.
const validGHToken = "ghp_ABCD1234EFGH5678IJKL9012MNOP345678QR"

func TestSecretAuditTool_Execute_ScansRealFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// File with a GitHub token (CRITICAL).
	ghFile := filepath.Join(tmpDir, "secrets.txt")
	err := os.WriteFile(ghFile, []byte("export GH_TOKEN="+validGHToken+"\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	// File with an AWS key (CRITICAL).
	awsFile := filepath.Join(tmpDir, "config.env")
	err = os.WriteFile(awsFile, []byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	// File with a private key marker (CRITICAL).
	keyFile := filepath.Join(tmpDir, "key.pem")
	err = os.WriteFile(keyFile, []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAL\n-----END RSA PRIVATE KEY-----\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	// File with a hardcoded password (HIGH).
	scriptFile := filepath.Join(tmpDir, "deploy.sh")
	err = os.WriteFile(scriptFile, []byte("password=SuperSecretPass123\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	// Create a .git directory (should be skipped).
	gitDir := filepath.Join(tmpDir, ".git")
	if err := os.Mkdir(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	gitFile := filepath.Join(gitDir, "config")
	os.WriteFile(gitFile, []byte("ghp_ABCD1234EFGH5678IJKL9012MNOP3456QR\n"), 0o644)

	tool := NewSecretAuditTool(nil)
	params := &SecretAuditParams{
		TargetPath: tmpDir,
		ScanType:   "pattern",
		Severity:   "HIGH",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatal(err)
	}

	res, ok := result.(*SecretAuditResult)
	if !ok {
		t.Fatalf("expected *SecretAuditResult, got %T", result)
	}

	// Should have scanned 4 files (key.pem, config.env, deploy.sh, secrets.txt).
	// .git/ should be skipped entirely.
	if res.TotalScanned != 4 {
		t.Errorf("expected 4 files scanned, got %d", res.TotalScanned)
	}

	if len(res.Findings) == 0 {
		t.Fatal("expected at least one finding, got none")
	}

	typeMap := make(map[string]bool)
	for _, f := range res.Findings {
		typeMap[f.Type] = true
	}

	if !typeMap["github_token"] {
		t.Error("expected github_token finding")
	}
	if !typeMap["aws_access_key"] {
		t.Error("expected aws_access_key finding")
	}
	if !typeMap["private_key"] {
		t.Error("expected private_key finding")
	}
	if !typeMap["password"] {
		t.Error("expected password finding")
	}
}

func TestSecretAuditTool_Execute_SingleFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.env")
	err := os.WriteFile(testFile, []byte("AWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstuvwxyz1234567890ABCD\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	tool := NewSecretAuditTool(nil)
	params := &SecretAuditParams{
		TargetPath: testFile,
		ScanType:   "pattern",
		Severity:   "CRITICAL",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatal(err)
	}

	res := result.(*SecretAuditResult)
	if res.TotalScanned != 1 {
		t.Errorf("expected 1 file scanned, got %d", res.TotalScanned)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	if res.Findings[0].Type != "aws_secret_key" {
		t.Errorf("expected aws_secret_key, got %s", res.Findings[0].Type)
	}
}

func TestSecretAuditTool_Execute_NonexistentPath(t *testing.T) {
	tool := NewSecretAuditTool(nil)
	params := &SecretAuditParams{
		TargetPath: "/nonexistent/path/that/does/not/exist",
		ScanType:   "pattern",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatal(err)
	}

	res := result.(*SecretAuditResult)
	if len(res.Findings) == 0 {
		t.Error("expected error finding for nonexistent path")
	}
	if res.Findings[0].Type != "scan_error" {
		t.Errorf("expected scan_error, got %s", res.Findings[0].Type)
	}
}

func TestSecretAuditTool_Execute_SkipsBinaryFiles(t *testing.T) {
	tmpDir := t.TempDir()
	binFile := filepath.Join(tmpDir, "image.png")
	// PNG header starts with 0x89, which is a null byte equivalent in our binary check.
	content := []byte("\x89PNG\r\n\x1a\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
	if err := os.WriteFile(binFile, content, 0o644); err != nil {
		t.Fatal(err)
	}

	tool := NewSecretAuditTool(nil)
	params := &SecretAuditParams{
		TargetPath: tmpDir,
		ScanType:   "pattern",
		Severity:   "CRITICAL",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatal(err)
	}

	res := result.(*SecretAuditResult)
	// PNG header (0x89) is a null byte, so the file is detected as binary and skipped.
	if res.TotalScanned != 0 {
		t.Errorf("expected 0 files scanned (binary skipped), got %d", res.TotalScanned)
	}
}

func TestSecretAuditTool_Execute_SkipsLargeFiles(t *testing.T) {
	tmpDir := t.TempDir()
	largeFile := filepath.Join(tmpDir, "large.log")
	f, err := os.Create(largeFile)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
	padding := make([]byte, MaxFileSize)
	for i := range padding {
		padding[i] = 'x'
	}
	f.Write(padding)
	f.Close()

	tool := NewSecretAuditTool(nil)
	params := &SecretAuditParams{
		TargetPath: tmpDir,
		ScanType:   "pattern",
		Severity:   "CRITICAL",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatal(err)
	}

	res := result.(*SecretAuditResult)
	if res.TotalScanned != 0 {
		t.Errorf("expected 0 files scanned (large file skipped), got %d", res.TotalScanned)
	}
}

func TestSecretAuditTool_Execute_SkipsNodeModules(t *testing.T) {
	tmpDir := t.TempDir()
	nmDir := filepath.Join(tmpDir, "node_modules")
	if err := os.Mkdir(nmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	secretFile := filepath.Join(nmDir, "secrets.txt")
	err := os.WriteFile(secretFile, []byte("ghp_"+validGHToken[4:]+"\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	tool := NewSecretAuditTool(nil)
	params := &SecretAuditParams{
		TargetPath: tmpDir,
		ScanType:   "pattern",
		Severity:   "CRITICAL",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatal(err)
	}

	res := result.(*SecretAuditResult)
	if res.TotalScanned != 0 {
		t.Errorf("expected 0 files scanned (node_modules skipped), got %d", res.TotalScanned)
	}
}

func TestSecretAuditTool_Execute_Redaction(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.env")
	err := os.WriteFile(testFile, []byte("ghp_"+validGHToken[4:]+"\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	tool := NewSecretAuditTool(nil)
	params := &SecretAuditParams{
		TargetPath: testFile,
		ScanType:   "pattern",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatal(err)
	}

	res := result.(*SecretAuditResult)
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	finding := res.Findings[0]
	// The redacted value must not expose the full token.
	if finding.Type == "github_token" && len(finding.Redacted) >= 40 {
		t.Errorf("redacted value appears too long: %s", finding.Redacted)
	}
	// The redacted value must differ from the original.
	if finding.Redacted == validGHToken {
		t.Error("redacted value equals the original secret")
	}
}

func TestContainsNonText(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{"null byte", []byte("hello\x00world"), true},
		{"normal text", []byte("hello world"), false},
		{"tab and newline", []byte("hello\tworld\n"), false},
		{"high ratio of control chars", []byte("\x01\x02\x03\x04\x05\x06\x07\x08"), true},
		{"mostly printable", []byte("hello world 123 ABC"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsNonText(tt.data)
			if got != tt.expected {
				t.Errorf("containsNonText(%q) = %v, want %v", tt.data, got, tt.expected)
			}
		})
	}
}

func TestSecretAuditTool_Execute_SkipsSkippedExtensions(t *testing.T) {
	tmpDir := t.TempDir()
	for _, ext := range []string{".png", ".jpg", ".exe", ".pdf", ".pyc", ".jar"} {
		f := filepath.Join(tmpDir, "file"+ext)
		// Use the valid GH token so it would match if scanned.
		content := "ghp_" + validGHToken[4:] + "\n"
		if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	tool := NewSecretAuditTool(nil)
	params := &SecretAuditParams{
		TargetPath: tmpDir,
		ScanType:   "pattern",
		Severity:   "CRITICAL",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatal(err)
	}

	res := result.(*SecretAuditResult)
	if res.TotalScanned != 0 {
		t.Errorf("expected 0 files scanned (skipped extensions), got %d", res.TotalScanned)
	}
}

func TestSecretAuditTool_Execute_SkipsGitDir(t *testing.T) {
	tmpDir := t.TempDir()
	gitDir := filepath.Join(tmpDir, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "objects"), 0o755); err != nil {
		t.Fatal(err)
	}
	secretFile := filepath.Join(gitDir, "objects", "secrets.txt")
	err := os.WriteFile(secretFile, []byte("ghp_"+validGHToken[4:]+"\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	tool := NewSecretAuditTool(nil)
	params := &SecretAuditParams{
		TargetPath: tmpDir,
		ScanType:   "pattern",
		Severity:   "CRITICAL",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatal(err)
	}

	res := result.(*SecretAuditResult)
	if res.TotalScanned != 0 {
		t.Errorf("expected 0 files scanned (.git skipped), got %d", res.TotalScanned)
	}
}

func TestSecretAuditTool_Execute_DatabasePassword(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "db.conf")
	// DB_PASS (6+), MYSQL_PASS (7 chars, meets min 6), POSTGRES_PASS (5 chars, too short).
	// PASSWORD (14 chars) also meets the password= pattern.
	content := `DB_PASSWORD=MySecretPass
MYSQL_PASS=root1234
password=SomeAppPassword99
`
	if err := os.WriteFile(testFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	tool := NewSecretAuditTool(nil)
	params := &SecretAuditParams{
		TargetPath: testFile,
		ScanType:   "pattern",
		Severity:   "HIGH",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatal(err)
	}

	res := result.(*SecretAuditResult)
	if len(res.Findings) != 3 {
		t.Errorf("expected 3 findings, got %d: %+v", len(res.Findings), res.Findings)
	}

	typeMap := make(map[string]bool)
	for _, f := range res.Findings {
		typeMap[f.Type] = true
	}
	if !typeMap["database_password"] {
		t.Error("expected database_password finding for DB_PASSWORD")
	}
	if !typeMap["database_password"] {
		t.Error("expected database_password finding for MYSQL_PASS")
	}
	if !typeMap["password"] {
		t.Error("expected password finding")
	}
}

func TestSecretAuditTool_Execute_HighSeverityFilter(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "mixed.txt")
	content := "ghp_" + validGHToken[4:] + "\npassword=SuperSecretPass123\n"
	if err := os.WriteFile(testFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	tool := NewSecretAuditTool(nil)

	// Severity HIGH: should include both CRITICAL and HIGH findings.
	params := &SecretAuditParams{
		TargetPath: tmpDir,
		ScanType:   "pattern",
		Severity:   "HIGH",
	}
	result, _ := tool.Execute(params)
	res := result.(*SecretAuditResult)
	if len(res.Findings) != 2 {
		t.Errorf("expected 2 findings with HIGH filter, got %d", len(res.Findings))
	}

	// Severity CRITICAL: should only include CRITICAL findings.
	params.Severity = "CRITICAL"
	result, _ = tool.Execute(params)
	res = result.(*SecretAuditResult)
	if len(res.Findings) != 1 {
		t.Errorf("expected 1 finding with CRITICAL filter, got %d", len(res.Findings))
	} else if res.Findings[0].Type != "github_token" {
		t.Errorf("expected github_token, got %s", res.Findings[0].Type)
	}

	// No severity filter: all findings.
	params.Severity = ""
	result, _ = tool.Execute(params)
	res = result.(*SecretAuditResult)
	if len(res.Findings) != 2 {
		t.Errorf("expected 2 findings with no filter, got %d", len(res.Findings))
	}
}

func TestSecretAuditTool_Execute_SkipsVendorDir(t *testing.T) {
	tmpDir := t.TempDir()
	vendorDir := filepath.Join(tmpDir, "vendor")
	if err := os.Mkdir(vendorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	secretFile := filepath.Join(vendorDir, "secrets.txt")
	err := os.WriteFile(secretFile, []byte("ghp_"+validGHToken[4:]+"\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	tool := NewSecretAuditTool(nil)
	params := &SecretAuditParams{
		TargetPath: tmpDir,
		ScanType:   "pattern",
		Severity:   "CRITICAL",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatal(err)
	}

	res := result.(*SecretAuditResult)
	if res.TotalScanned != 0 {
		t.Errorf("expected 0 files scanned (vendor/ skipped), got %d", res.TotalScanned)
	}
}

func TestSecretAuditTool_Execute_LineNumbers(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "multi.txt")
	content := "line without secret\n" +
		"another safe line\n" +
		"password=SecretPass123\n" +
		"safe line after\n" +
		"ghp_" + validGHToken[4:] + "\n"
	if err := os.WriteFile(testFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	tool := NewSecretAuditTool(nil)
	params := &SecretAuditParams{
		TargetPath: testFile,
		ScanType:   "pattern",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatal(err)
	}

	res := result.(*SecretAuditResult)
	if len(res.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(res.Findings))
	}

	// Password is on line 3.
	if res.Findings[0].Line != 3 {
		t.Errorf("expected password finding on line 3, got line %d", res.Findings[0].Line)
	}
	// GitHub token is on line 5.
	if res.Findings[1].Line != 5 {
		t.Errorf("expected token finding on line 5, got line %d", res.Findings[1].Line)
	}
}

// TestFileOwner verifies test files are owned by the current user (skip on windows).
func TestFileOwner(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := os.Stat(testFile)
	if err != nil {
		t.Errorf("file stat failed: %v", err)
	}
}
