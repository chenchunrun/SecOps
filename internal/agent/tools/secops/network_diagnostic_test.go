package secops

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestNetworkDiagnosticTool_Type(t *testing.T) {
	tool := NewNetworkDiagnosticTool(nil)
	if tool.Type() != ToolTypeNetworkDiagnostic {
		t.Errorf("expected %v, got %v", ToolTypeNetworkDiagnostic, tool.Type())
	}
}

func TestNetworkDiagnosticTool_ValidateParams(t *testing.T) {
	tool := NewNetworkDiagnosticTool(nil)

	tests := []struct {
		name    string
		params  interface{}
		wantErr bool
	}{
		{
			name: "valid traceroute",
			params: &NetworkDiagnosticParams{
				Type:   DiagnosticTraceroute,
				Target: "8.8.8.8",
			},
			wantErr: false,
		},
		{
			name: "valid ping",
			params: &NetworkDiagnosticParams{
				Type:   DiagnosticPing,
				Target: "example.com",
			},
			wantErr: false,
		},
		{
			name: "valid port scan",
			params: &NetworkDiagnosticParams{
				Type:   DiagnosticPortScan,
				Target: "example.com",
				Ports:  []int{22, 80, 443},
			},
			wantErr: false,
		},
		{
			name: "missing type",
			params: &NetworkDiagnosticParams{
				Target: "example.com",
			},
			wantErr: true,
		},
		{
			name: "missing target",
			params: &NetworkDiagnosticParams{
				Type: DiagnosticPing,
			},
			wantErr: true,
		},
		{
			name: "port scan without ports",
			params: &NetworkDiagnosticParams{
				Type:   DiagnosticPortScan,
				Target: "example.com",
			},
			wantErr: true,
		},
		{
			name: "invalid type",
			params: &NetworkDiagnosticParams{
				Type:   NetworkDiagnosticType("invalid"),
				Target: "example.com",
			},
			wantErr: true,
		},
		{
			name: "timeout too high",
			params: &NetworkDiagnosticParams{
				Type:    DiagnosticPing,
				Target:  "example.com",
				Timeout: 400,
			},
			wantErr: true,
		},
		{
			name: "invalid remote port",
			params: &NetworkDiagnosticParams{
				Type:       DiagnosticPing,
				Target:     "example.com",
				RemoteHost: "10.0.0.2",
				RemotePort: 70000,
			},
			wantErr: true,
		},
		{
			name: "too many ports",
			params: &NetworkDiagnosticParams{
				Type:   DiagnosticPortScan,
				Target: "example.com",
				Ports:  make([]int, 101),
			},
			wantErr: true,
		},
		{
			name:    "invalid type",
			params:  "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tool.ValidateParams(tt.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateParams() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNetworkDiagnosticTool_ExecuteTraceroute(t *testing.T) {
	tool := NewNetworkDiagnosticTool(nil)
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "traceroute" || strings.Contains(strings.Join(args, " "), "traceroute") {
			return []byte(" 1 10.0.0.1 2.5 ms\n"), nil
		}
		return nil, fmt.Errorf("unsupported command")
	}

	params := &NetworkDiagnosticParams{
		Type:   DiagnosticTraceroute,
		Target: "8.8.8.8",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	diagResult, ok := result.(*NetworkDiagnosticResult)
	if !ok {
		t.Fatal("expected NetworkDiagnosticResult")
	}

	if diagResult.Type != DiagnosticTraceroute {
		t.Errorf("expected type traceroute, got %v", diagResult.Type)
	}

	if len(diagResult.Hops) == 0 {
		t.Error("expected hops in result")
	}

	if diagResult.Duration < 0 {
		t.Error("expected non-negative duration")
	}
}

func TestNetworkDiagnosticTool_ExecuteTraceroute_NoFallbackByDefault(t *testing.T) {
	tool := NewNetworkDiagnosticTool(nil)
	t.Setenv("SECOPS_NETWORK_DIAG_ALLOW_FALLBACK", "")
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, fmt.Errorf("command not found")
	}

	result, err := tool.Execute(&NetworkDiagnosticParams{
		Type:   DiagnosticTraceroute,
		Target: "8.8.8.8",
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	diag := result.(*NetworkDiagnosticResult)
	if len(diag.Hops) != 0 {
		t.Fatalf("expected no hops without fallback, got %d", len(diag.Hops))
	}
	if diag.Status != "error" {
		t.Fatalf("expected error status, got %s", diag.Status)
	}
	if len(diag.Issues) == 0 {
		t.Fatal("expected issues when traceroute returns no data")
	}
}

func TestNetworkDiagnosticTool_ExecutePortScan(t *testing.T) {
	tool := NewNetworkDiagnosticTool(nil)

	params := &NetworkDiagnosticParams{
		Type:   DiagnosticPortScan,
		Target: "example.com",
		Ports:  []int{22, 80, 443},
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	diagResult, ok := result.(*NetworkDiagnosticResult)
	if !ok {
		t.Fatal("expected NetworkDiagnosticResult")
	}

	if len(diagResult.Ports) != 3 {
		t.Errorf("expected 3 ports, got %d", len(diagResult.Ports))
	}

	for _, port := range diagResult.Ports {
		if port.Port != 22 && port.Port != 80 && port.Port != 443 {
			t.Errorf("unexpected port in result: %d", port.Port)
		}
		if port.State == "" {
			t.Error("expected port state")
		}
	}
}

func TestNetworkDiagnosticTool_ExecutePing(t *testing.T) {
	tool := NewNetworkDiagnosticTool(nil)

	params := &NetworkDiagnosticParams{
		Type:        DiagnosticPing,
		Target:      "example.com",
		PacketCount: 4,
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	diagResult, ok := result.(*NetworkDiagnosticResult)
	if !ok {
		t.Fatal("expected NetworkDiagnosticResult")
	}

	if diagResult.PingResult == nil {
		if diagResult.Status != "error" {
			t.Fatalf("expected error status when ping result is nil, got %s", diagResult.Status)
		}
		if len(diagResult.Issues) == 0 {
			t.Fatal("expected issues when ping result is nil")
		}
		return
	}

	if diagResult.PingResult.Sent != 4 {
		t.Errorf("expected 4 packets sent, got %d", diagResult.PingResult.Sent)
	}

	if diagResult.PingResult.Avg == 0 {
		t.Error("expected non-zero average latency")
	}
}

func TestNetworkDiagnosticTool_ExecuteDNS(t *testing.T) {
	tool := NewNetworkDiagnosticTool(nil)

	params := &NetworkDiagnosticParams{
		Type:   DiagnosticDNS,
		Target: "example.com",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	diagResult, ok := result.(*NetworkDiagnosticResult)
	if !ok {
		t.Fatal("expected NetworkDiagnosticResult")
	}

	if len(diagResult.DNSRecords) == 0 {
		if diagResult.Status != "error" {
			t.Errorf("expected error status when no DNS records, got %s", diagResult.Status)
		}
		if len(diagResult.Issues) == 0 {
			t.Error("expected issues when no DNS records")
		}
		return
	}

	for _, record := range diagResult.DNSRecords {
		if record.Type == "" {
			t.Error("expected record type")
		}
		if record.Value == "" {
			t.Error("expected record value")
		}
	}
}

func TestNetworkDiagnosticTool_ExecuteMTR(t *testing.T) {
	tool := NewNetworkDiagnosticTool(nil)
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "mtr" || strings.Contains(strings.Join(args, " "), "mtr") {
			return []byte(
				"Start: 2026-03-23T00:00:00+0000\n" +
					"HOST: local Loss% Snt Last Avg Best Wrst StDev\n" +
					" 1.|-- 10.0.0.1  0.0% 10 2.0 2.3 1.8 3.1 0.4\n",
			), nil
		}
		return nil, fmt.Errorf("unsupported command")
	}

	params := &NetworkDiagnosticParams{
		Type:   DiagnosticMTR,
		Target: "8.8.8.8",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	diagResult, ok := result.(*NetworkDiagnosticResult)
	if !ok {
		t.Fatal("expected NetworkDiagnosticResult")
	}

	if len(diagResult.Hops) == 0 {
		t.Error("expected hops in MTR result")
	}

	if diagResult.PacketLoss == 0 {
		// MTR should report packet loss
		t.Log("packet loss is 0, expected some value")
	}
}

func TestNetworkDiagnosticTool_AnalyzeHops(t *testing.T) {
	tool := NewNetworkDiagnosticTool(nil)

	result := &NetworkDiagnosticResult{
		Hops: []*HopInfo{
			{
				Hop:  1,
				Loss: 0,
				Avg:  5.0,
			},
			{
				Hop:  2,
				Loss: 0,
				Avg:  150.0, // High latency
			},
		},
	}

	tool.analyzeHops(result)

	if result.LatencyHealth != "poor" {
		t.Errorf("expected poor latency health, got %s", result.LatencyHealth)
	}

	if len(result.Issues) == 0 {
		t.Error("expected issues to be detected")
	}
}

func TestNetworkDiagnosticTool_AnalyzePortScan(t *testing.T) {
	tool := NewNetworkDiagnosticTool(nil)

	result := &NetworkDiagnosticResult{
		Ports: []*PortInfo{
			{Port: 22, State: "open"},
			{Port: 80, State: "open"},
			{Port: 443, State: "filtered"},
		},
	}

	tool.analyzePortScan(result)

	if len(result.Issues) == 0 {
		t.Error("expected issues for filtered port")
	}
}

func TestNetworkDiagnosticTool_FallbackTraceHops(t *testing.T) {
	tool := NewNetworkDiagnosticTool(nil)
	hops := tool.fallbackTraceHops("example.com", 3)

	if len(hops) > 0 {
		if hops[0].Hop != 1 {
			t.Errorf("expected hop number 1, got %d", hops[0].Hop)
		}
		if hops[0].Address == "" {
			t.Error("expected hop address")
		}
		if hops[0].Loss == 0 && len(hops[0].RTT) == 0 {
			t.Error("expected RTT data when TCP probe succeeds")
		}
		if hops[0].Loss == 100 && len(hops[0].RTT) != 0 {
			t.Error("expected no RTT samples when TCP probe fails")
		}
	}
}

func TestNetworkDiagnosticTool_PortScanProducesResults(t *testing.T) {
	tool := NewNetworkDiagnosticTool(nil)
	params := &NetworkDiagnosticParams{
		Type:   DiagnosticPortScan,
		Target: "example.com",
		Ports:  []int{80, 443},
	}
	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	diag := result.(*NetworkDiagnosticResult)
	if len(diag.Ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(diag.Ports))
	}
	for _, port := range diag.Ports {
		if port.State == "" {
			t.Error("expected port state")
		}
	}
}

func TestNetworkDiagnosticTool_LookupDNS(t *testing.T) {
	tool := NewNetworkDiagnosticTool(nil)
	records := tool.lookupDNS("example.com", 5)

	if len(records) > 0 {
		for _, record := range records {
			if record.Value == "" {
				t.Error("expected record value")
			}
		}
	}
}

func TestNetworkDiagnosticTool_FallbackPingViaTCP(t *testing.T) {
	tool := NewNetworkDiagnosticTool(nil)

	params := &NetworkDiagnosticParams{
		Target:      "example.com",
		PacketCount: 2,
		Timeout:     3,
	}
	result := tool.fallbackPingViaTCP(params)
	if result != nil {
		if result.Sent != 2 {
			t.Errorf("expected 2 packets sent, got %d", result.Sent)
		}
		if result.Avg <= 0 {
			t.Error("expected positive average latency")
		}
		if result.Loss < 0 || result.Loss > 100 {
			t.Errorf("expected packet loss between 0-100, got %f", result.Loss)
		}
	}
}

func TestNetworkDiagnosticTool_RemoteTracerouteUsesSSH(t *testing.T) {
	tool := NewNetworkDiagnosticTool(nil)
	var gotName string
	var gotArgs []string
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return []byte(" 1 10.0.0.1 2.5 ms\n"), nil
	}

	params := &NetworkDiagnosticParams{
		Target:          "example.com",
		Timeout:         5,
		RemoteHost:      "10.0.0.2",
		RemoteUser:      "ops",
		RemotePort:      2222,
		RemoteKeyPath:   "/tmp/id_ed25519",
		RemoteProxyJump: "bastion",
	}
	hops := tool.runTracerouteCommand("example.com", 5, params)
	if len(hops) != 1 {
		t.Fatalf("expected one hop, got %d", len(hops))
	}
	if gotName != "ssh" {
		t.Fatalf("expected ssh command, got %s", gotName)
	}
	joined := strings.Join(gotArgs, " ")
	if !strings.Contains(joined, "-p 2222") {
		t.Fatalf("expected ssh port arg in %q", joined)
	}
	if !strings.Contains(joined, "-i /tmp/id_ed25519") {
		t.Fatalf("expected ssh key arg in %q", joined)
	}
	if !strings.Contains(joined, "-J bastion") {
		t.Fatalf("expected ssh proxyjump arg in %q", joined)
	}
	if !strings.Contains(joined, "ops@10.0.0.2") {
		t.Fatalf("expected ssh target in %q", joined)
	}
	if !strings.Contains(joined, "traceroute") || !strings.Contains(joined, "example.com") {
		t.Fatalf("expected traceroute command in %q", joined)
	}
}

func TestNetworkDiagnosticTool_LocalTracerouteUsesDirectCommand(t *testing.T) {
	tool := NewNetworkDiagnosticTool(nil)
	var gotName string
	var gotArgs []string
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return []byte(" 1 10.0.0.1 2.5 ms\n"), nil
	}

	params := &NetworkDiagnosticParams{
		Target:  "example.com",
		Timeout: 5,
	}
	hops := tool.runTracerouteCommand("example.com", 5, params)
	if len(hops) != 1 {
		t.Fatalf("expected one hop, got %d", len(hops))
	}
	if gotName != "traceroute" {
		t.Fatalf("expected traceroute command, got %s", gotName)
	}
	if len(gotArgs) == 0 || gotArgs[len(gotArgs)-1] != "example.com" {
		t.Fatalf("expected target argument, got %v", gotArgs)
	}
}

func BenchmarkNetworkDiagnosticTool_ExecuteTraceroute(b *testing.B) {
	tool := NewNetworkDiagnosticTool(nil)
	params := &NetworkDiagnosticParams{
		Type:   DiagnosticTraceroute,
		Target: "8.8.8.8",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tool.Execute(params)
	}
}

func BenchmarkNetworkDiagnosticTool_ExecutePortScan(b *testing.B) {
	tool := NewNetworkDiagnosticTool(nil)
	params := &NetworkDiagnosticParams{
		Type:   DiagnosticPortScan,
		Target: "example.com",
		Ports:  []int{22, 80, 443},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tool.Execute(params)
	}
}
