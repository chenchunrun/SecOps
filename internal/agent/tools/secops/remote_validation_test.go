package secops

import (
	"strings"
	"testing"
)

func TestValidateRemoteSSHParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		host      string
		user      string
		keyPath   string
		proxyJump string
		port      int
		wantErr   bool
	}{
		{
			name:    "local-only allowed",
			port:    0,
			wantErr: false,
		},
		{
			name:    "remote host with user allowed",
			host:    "10.0.0.8",
			user:    "ops",
			port:    22,
			wantErr: false,
		},
		{
			name:      "remote host with key and jump allowed",
			host:      "prod-app-1",
			user:      "deploy",
			keyPath:   "~/.ssh/id_ed25519",
			proxyJump: "bastion",
			port:      2222,
			wantErr:   false,
		},
		{
			name:    "remote options without host rejected",
			user:    "ops",
			port:    22,
			wantErr: true,
		},
		{
			name:    "host starting with dash rejected",
			host:    "-bad-host",
			port:    22,
			wantErr: true,
		},
		{
			name:    "invalid user rejected",
			host:    "10.0.0.8",
			user:    "ops user",
			port:    22,
			wantErr: true,
		},
		{
			name:    "invalid port rejected",
			host:    "10.0.0.8",
			user:    "ops",
			port:    70000,
			wantErr: true,
		},
		{
			name:    "key path starting with dash rejected",
			host:    "10.0.0.8",
			user:    "ops",
			keyPath: "-i /tmp/key",
			port:    22,
			wantErr: true,
		},
		{
			name:      "proxy jump starting with dash rejected",
			host:      "10.0.0.8",
			user:      "ops",
			proxyJump: "-J bad",
			port:      22,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRemoteSSHParams(tt.host, tt.user, tt.keyPath, tt.proxyJump, tt.port)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error but got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestDefaultSSHOptionArgsContainsHardeningOptions(t *testing.T) {
	t.Parallel()

	args := defaultSSHOptionArgs()
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "BatchMode=yes") {
		t.Fatalf("expected BatchMode option in %q", joined)
	}
	if !strings.Contains(joined, "ConnectTimeout=10") {
		t.Fatalf("expected ConnectTimeout option in %q", joined)
	}
	if !strings.Contains(joined, "ServerAliveInterval=15") {
		t.Fatalf("expected ServerAliveInterval option in %q", joined)
	}
	if !strings.Contains(joined, "ServerAliveCountMax=2") {
		t.Fatalf("expected ServerAliveCountMax option in %q", joined)
	}
}
