package app

import (
	"testing"

	"github.com/chenchunrun/SecOps/internal/config"
)

func TestBuildAuditExporters_SyslogEnabled(t *testing.T) {
	cfg := &config.Config{
		Audit: &config.Audit{
			Export: &config.AuditExport{
				Syslog: &config.AuditSyslog{
					Enabled: true,
					Network: "udp",
					Address: "127.0.0.1:514",
					AppName: "secops-agent",
				},
			},
		},
	}

	exporters := buildAuditExporters(cfg)
	if len(exporters) != 1 {
		t.Fatalf("expected 1 exporter, got %d", len(exporters))
	}
}

func TestBuildAuditExporters_SyslogDisabledOrMissingAddress(t *testing.T) {
	cases := []*config.Config{
		{},
		{Audit: &config.Audit{}},
		{Audit: &config.Audit{Export: &config.AuditExport{Syslog: &config.AuditSyslog{Enabled: false, Address: "127.0.0.1:514"}}}},
		{Audit: &config.Audit{Export: &config.AuditExport{Syslog: &config.AuditSyslog{Enabled: true}}}},
	}

	for _, cfg := range cases {
		exporters := buildAuditExporters(cfg)
		if len(exporters) != 0 {
			t.Fatalf("expected 0 exporters, got %d", len(exporters))
		}
	}
}
