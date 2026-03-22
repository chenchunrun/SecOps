package secops

import (
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

	if diagResult.Duration == 0 {
		t.Error("expected non-zero duration")
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
		t.Fatal("expected ping result")
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
		t.Error("expected DNS records")
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
				Hop:    1,
				Loss:   0,
				Avg:    5.0,
			},
			{
				Hop:    2,
				Loss:   0,
				Avg:    150.0, // High latency
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

func TestNetworkDiagnosticTool_GetMockTracerouteHops(t *testing.T) {
	tool := NewNetworkDiagnosticTool(nil)
	hops := tool.getMockTracerouteHops()

	if len(hops) == 0 {
		t.Error("expected mock hops")
	}

	for i, hop := range hops {
		if hop.Hop != i+1 {
			t.Errorf("expected hop number %d, got %d", i+1, hop.Hop)
		}
		if hop.Address == "" {
			t.Error("expected hop address")
		}
		if len(hop.RTT) == 0 {
			t.Error("expected RTT data")
		}
	}
}

func TestNetworkDiagnosticTool_GetMockPortScanResults(t *testing.T) {
	tool := NewNetworkDiagnosticTool(nil)
	ports := []int{22, 80, 443, 3306}

	results := tool.getMockPortScanResults(ports)

	if len(results) != len(ports) {
		t.Errorf("expected %d results, got %d", len(ports), len(results))
	}

	for _, port := range results {
		if port.State == "" {
			t.Error("expected port state")
		}
	}
}

func TestNetworkDiagnosticTool_GetMockDNSRecords(t *testing.T) {
	tool := NewNetworkDiagnosticTool(nil)
	records := tool.getMockDNSRecords()

	if len(records) == 0 {
		t.Error("expected DNS records")
	}

	recordTypes := make(map[string]bool)
	for _, record := range records {
		recordTypes[record.Type] = true
		if record.Value == "" {
			t.Error("expected record value")
		}
	}

	if !recordTypes["A"] {
		t.Error("expected A record")
	}
}

func TestNetworkDiagnosticTool_GetMockPingResult(t *testing.T) {
	tool := NewNetworkDiagnosticTool(nil)

	params := &NetworkDiagnosticParams{
		PacketCount: 10,
	}

	result := tool.getMockPingResult(params)

	if result.Sent != 10 {
		t.Errorf("expected 10 packets sent, got %d", result.Sent)
	}

	if result.Avg <= 0 {
		t.Error("expected positive average latency")
	}

	if result.Loss < 0 || result.Loss > 100 {
		t.Errorf("expected packet loss between 0-100, got %f", result.Loss)
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
