package secops

import (
	"os"
	"path/filepath"
	"testing"
)

// installFixedSSHStub prepends a temp directory containing an `ssh` stub onto
// PATH that prints a fixed canned response (or fails). Unlike a command-matching
// stub, a fixed response per test is deterministic and avoids races.
func installFixedSSHStub(t *testing.T, response string, fail bool) {
	t.Helper()
	dir := t.TempDir()

	var body string
	if fail {
		body = "#!/bin/sh\necho remote command failed >&2\nexit 1\n"
	} else {
		respFile := filepath.Join(dir, "resp")
		if err := os.WriteFile(respFile, []byte(response), 0o644); err != nil {
			t.Fatalf("write resp: %v", err)
		}
		body = "#!/bin/sh\ncat " + respFile + "\nexit 0\n"
	}

	stub := filepath.Join(dir, "ssh")
	if err := os.WriteFile(stub, []byte(body), 0o755); err != nil {
		t.Fatalf("write ssh stub: %v", err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}

// auditRemoteParams returns audit params that route every *ForParams helper through
// the remote (ssh) path so the stub controls the output.
func auditRemoteParams() *ConfigAuditParams {
	return &ConfigAuditParams{
		RemoteHost: "10.0.0.50",
		RemoteUser: "audit",
	}
}

// TestConfigurationAudit_RemoteBranches exercises the remote read path
// (runRemoteCommand -> ssh stub) for every rule family and both the ok and
// failure branches, restoring coverage of the remote auditRule statements.
func TestConfigurationAudit_RemoteBranches(t *testing.T) {
	ruleProviders := map[string]func(*ConfigAuditParams) []*ConfigAuditRule{
		"ssh":      NewConfigurationAuditTool(nil).getSSHRules,
		"sudo":     NewConfigurationAuditTool(nil).getSudoRules,
		"firewall": NewConfigurationAuditTool(nil).getFirewallRules,
		"kernel":   NewConfigurationAuditTool(nil).getKernelRules,
		"sysctl":   NewConfigurationAuditTool(nil).getSysctlRules,
	}

	t.Run("good response sets a status", func(t *testing.T) {
		installFixedSSHStub(t, "no\n0\n2\n644\n0\n", false)
		tool := NewConfigurationAuditTool(nil)
		params := auditRemoteParams()
		for family, provider := range ruleProviders {
			for _, rule := range provider(params) {
				tool.auditRule(rule, params)
				if rule.Status == "" {
					t.Errorf("family %s rule %s: expected status set, got empty", family, rule.ID)
				}
			}
		}
	})

	t.Run("failing remote yields a status too", func(t *testing.T) {
		installFixedSSHStub(t, "", true)
		tool := NewConfigurationAuditTool(nil)
		params := auditRemoteParams()
		for family, provider := range ruleProviders {
			for _, rule := range provider(params) {
				tool.auditRule(rule, params)
				if rule.Status == "" {
					t.Errorf("family %s rule %s: expected status set on failure, got empty", family, rule.ID)
				}
			}
		}
	})
}

func TestConfigurationAudit_RemoteReadHelpers(t *testing.T) {
	t.Run("sshd config value found", func(t *testing.T) {
		installFixedSSHStub(t, "no", false)
		if v, ok := remoteReadSSHDConfigValue(auditRemoteParams(), "PermitRootLogin"); !ok || v != "no" {
			t.Errorf("expected no/true, got %q/%v", v, ok)
		}
	})

	t.Run("sshd config value missing", func(t *testing.T) {
		installFixedSSHStub(t, "", true)
		if _, ok := remoteReadSSHDConfigValue(auditRemoteParams(), "PermitRootLogin"); ok {
			t.Error("expected ok=false on remote failure")
		}
	})

	t.Run("sudo policy lines returned", func(t *testing.T) {
		installFixedSSHStub(t, "%admin ALL=(ALL) NOPASSWD: ALL\nDefaults log_output\n", false)
		lines, ok := readRemoteSudoPolicyLines(auditRemoteParams())
		if !ok {
			t.Fatal("expected ok=true for sudo policy lines")
		}
		if len(lines) == 0 {
			t.Error("expected at least one parsed sudo line")
		}
	})

	t.Run("sudo policy missing", func(t *testing.T) {
		installFixedSSHStub(t, "", true)
		if _, ok := readRemoteSudoPolicyLines(auditRemoteParams()); ok {
			t.Error("expected ok=false on remote failure")
		}
	})

	t.Run("runRemoteCommand nil params and no host", func(t *testing.T) {
		if _, ok := runRemoteCommand(nil, "echo"); ok {
			t.Error("expected ok=false for nil params")
		}
		if _, ok := runRemoteCommand(&ConfigAuditParams{}, "echo"); ok {
			t.Error("expected ok=false when RemoteHost empty")
		}
	})
}
