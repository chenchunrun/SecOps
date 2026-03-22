package secops

import (
	"fmt"
	"time"
)

// NetworkDiagnosticType 网络诊断类型
type NetworkDiagnosticType string

const (
	DiagnosticTraceroute NetworkDiagnosticType = "traceroute"
	DiagnosticMTR        NetworkDiagnosticType = "mtr"
	DiagnosticPortScan   NetworkDiagnosticType = "port_scan"
	DiagnosticDNS        NetworkDiagnosticType = "dns"
	DiagnosticPing       NetworkDiagnosticType = "ping"
)

// NetworkDiagnosticParams 网络诊断参数
type NetworkDiagnosticParams struct {
	Type          NetworkDiagnosticType `json:"type"`
	Target        string                `json:"target"`          // IP 或域名
	Ports         []int                 `json:"ports,omitempty"` // 端口列表（用于端口扫描）
	Timeout       int                   `json:"timeout,omitempty"`
	PacketCount   int                   `json:"packet_count,omitempty"`  // ping 包数
	PacketSize    int                   `json:"packet_size,omitempty"`   // 包大小
	CheckLatency  bool                  `json:"check_latency,omitempty"` // 检查延迟
	CheckPacketLoss bool                `json:"check_packet_loss,omitempty"`
}

// HopInfo 路由跳转信息
type HopInfo struct {
	Hop     int       `json:"hop"`
	Address string    `json:"address"`
	Host    string    `json:"host,omitempty"`
	RTT     []float64 `json:"rtt"` // 往返时间
	Loss    float64   `json:"loss"`
	Last    float64   `json:"last"`
	Avg     float64   `json:"avg"`
	Best    float64   `json:"best"`
	Worst   float64   `json:"worst"`
	StdDev  float64   `json:"stddev"`
}

// PortInfo 端口信息
type PortInfo struct {
	Port    int    `json:"port"`
	State   string `json:"state"`   // open, closed, filtered
	Service string `json:"service"` // 服务名
	Banner  string `json:"banner,omitempty"`
}

// DNSRecord DNS 记录
type DNSRecord struct {
	Type  string   `json:"type"` // A, AAAA, MX, NS, CNAME, TXT
	Name  string   `json:"name"`
	Value string   `json:"value"`
	TTL   uint32   `json:"ttl,omitempty"`
	Class string   `json:"class,omitempty"`
}

// PingResult Ping 结果
type PingResult struct {
	Sent     int     `json:"sent"`
	Received int     `json:"received"`
	Loss     float64 `json:"loss"`
	Min      float64 `json:"min"`
	Avg      float64 `json:"avg"`
	Max      float64 `json:"max"`
	StdDev   float64 `json:"stddev"`
}

// NetworkDiagnosticResult 网络诊断结果
type NetworkDiagnosticResult struct {
	Timestamp      time.Time      `json:"timestamp"`
	Type           NetworkDiagnosticType `json:"type"`
	Target         string         `json:"target"`
	Status         string         `json:"status"` // success, timeout, error
	Duration       int            `json:"duration"` // 诊断耗时（毫秒）
	Hops           []*HopInfo     `json:"hops,omitempty"`
	Ports          []*PortInfo    `json:"ports,omitempty"`
	DNSRecords     []*DNSRecord   `json:"dns_records,omitempty"`
	PingResult     *PingResult    `json:"ping_result,omitempty"`
	LatencyHealth  string         `json:"latency_health,omitempty"` // good, fair, poor
	PacketLoss     float64        `json:"packet_loss,omitempty"`
	Issues         []string       `json:"issues,omitempty"`
	Recommendations []string      `json:"recommendations,omitempty"`
}

// NetworkDiagnosticTool 网络诊断工具
type NetworkDiagnosticTool struct {
	registry *SecOpsToolRegistry
}

// NewNetworkDiagnosticTool 创建网络诊断工具
func NewNetworkDiagnosticTool(registry *SecOpsToolRegistry) *NetworkDiagnosticTool {
	return &NetworkDiagnosticTool{
		registry: registry,
	}
}

// Type 实现 Tool.Type
func (ndt *NetworkDiagnosticTool) Type() ToolType {
	return ToolTypeNetworkDiagnostic
}

// Name 实现 Tool.Name
func (ndt *NetworkDiagnosticTool) Name() string {
	return "Network Diagnostics"
}

// Description 实现 Tool.Description
func (ndt *NetworkDiagnosticTool) Description() string {
	return "Perform network diagnostics (traceroute, MTR, port scan, DNS lookup, ping)"
}

// RequiredCapabilities 实现 Tool.RequiredCapabilities
func (ndt *NetworkDiagnosticTool) RequiredCapabilities() []string {
	return []string{
		"network:scan",
		"network:query",
		"system:execute",
	}
}

// ValidateParams 实现 Tool.ValidateParams
func (ndt *NetworkDiagnosticTool) ValidateParams(params interface{}) error {
	p, ok := params.(*NetworkDiagnosticParams)
	if !ok {
		return ErrInvalidParams
	}

	if p.Type == "" {
		return fmt.Errorf("diagnostic type is required")
	}

	if !ndt.isValidType(p.Type) {
		return fmt.Errorf("invalid diagnostic type: %s", p.Type)
	}

	if p.Target == "" {
		return fmt.Errorf("target is required")
	}

	if p.Timeout == 0 {
		p.Timeout = 30
	}

	if p.Timeout > 300 {
		return fmt.Errorf("timeout cannot exceed 300 seconds")
	}

	if p.Type == DiagnosticPortScan && len(p.Ports) == 0 {
		return fmt.Errorf("ports are required for port scan")
	}

	if len(p.Ports) > 100 {
		return fmt.Errorf("port list exceeds maximum of 100 ports")
	}

	return nil
}

// Execute 实现 Tool.Execute
func (ndt *NetworkDiagnosticTool) Execute(params interface{}) (interface{}, error) {
	p, ok := params.(*NetworkDiagnosticParams)
	if !ok {
		return nil, ErrInvalidParams
	}

	if err := ndt.ValidateParams(p); err != nil {
		return nil, err
	}

	result := &NetworkDiagnosticResult{
		Timestamp:       time.Now(),
		Type:            p.Type,
		Target:          p.Target,
		Status:          "success",
		Issues:          make([]string, 0),
		Recommendations: make([]string, 0),
	}

	// 执行诊断
	switch p.Type {
	case DiagnosticTraceroute:
		ndt.performTraceroute(p, result)
	case DiagnosticMTR:
		ndt.performMTR(p, result)
	case DiagnosticPortScan:
		ndt.performPortScan(p, result)
	case DiagnosticDNS:
		ndt.performDNSLookup(p, result)
	case DiagnosticPing:
		ndt.performPing(p, result)
	}

	// 分析结果
	ndt.analyzeResults(result, p)

	return result, nil
}

// 私有方法

// isValidType 检查诊断类型是否有效
func (ndt *NetworkDiagnosticTool) isValidType(t NetworkDiagnosticType) bool {
	switch t {
	case DiagnosticTraceroute, DiagnosticMTR, DiagnosticPortScan, DiagnosticDNS, DiagnosticPing:
		return true
	default:
		return false
	}
}

// performTraceroute 执行 traceroute
func (ndt *NetworkDiagnosticTool) performTraceroute(params *NetworkDiagnosticParams, result *NetworkDiagnosticResult) {
	result.Hops = ndt.getMockTracerouteHops()
	result.Duration = 2500
}

// performMTR 执行 MTR
func (ndt *NetworkDiagnosticTool) performMTR(params *NetworkDiagnosticParams, result *NetworkDiagnosticResult) {
	result.Hops = ndt.getMockMTRHops()
	result.PacketLoss = 0.5
	result.Duration = 5000
}

// performPortScan 执行端口扫描
func (ndt *NetworkDiagnosticTool) performPortScan(params *NetworkDiagnosticParams, result *NetworkDiagnosticResult) {
	result.Ports = ndt.getMockPortScanResults(params.Ports)
	result.Duration = 3000
}

// performDNSLookup 执行 DNS 查询
func (ndt *NetworkDiagnosticTool) performDNSLookup(params *NetworkDiagnosticParams, result *NetworkDiagnosticResult) {
	result.DNSRecords = ndt.getMockDNSRecords()
	result.Duration = 500
}

// performPing 执行 ping
func (ndt *NetworkDiagnosticTool) performPing(params *NetworkDiagnosticParams, result *NetworkDiagnosticResult) {
	result.PingResult = ndt.getMockPingResult(params)
	result.Duration = 1000
}

// getMockTracerouteHops 获取模拟的 traceroute 跳转
func (ndt *NetworkDiagnosticTool) getMockTracerouteHops() []*HopInfo {
	return []*HopInfo{
		{
			Hop:     1,
			Address: "192.168.1.1",
			Host:    "gateway.local",
			RTT:     []float64{1.5, 1.6, 1.4},
			Loss:    0,
			Last:    1.5,
			Avg:     1.5,
			Best:    1.4,
			Worst:   1.6,
			StdDev:  0.1,
		},
		{
			Hop:     2,
			Address: "10.0.0.1",
			Host:    "isp-router.net",
			RTT:     []float64{5.2, 5.3, 5.1},
			Loss:    0,
			Last:    5.2,
			Avg:     5.2,
			Best:    5.1,
			Worst:   5.3,
			StdDev:  0.1,
		},
		{
			Hop:     3,
			Address: "8.8.8.8",
			Host:    "google-dns.com",
			RTT:     []float64{15.2, 15.4, 15.1},
			Loss:    0,
			Last:    15.2,
			Avg:     15.2,
			Best:    15.1,
			Worst:   15.4,
			StdDev:  0.15,
		},
	}
}

// getMockMTRHops 获取模拟的 MTR 跳转
func (ndt *NetworkDiagnosticTool) getMockMTRHops() []*HopInfo {
	return []*HopInfo{
		{
			Hop:     1,
			Address: "192.168.1.1",
			Host:    "gateway.local",
			RTT:     []float64{1.5, 1.6, 1.4, 1.5, 1.6},
			Loss:    0,
			Last:    1.5,
			Avg:     1.52,
			Best:    1.4,
			Worst:   1.6,
			StdDev:  0.08,
		},
		{
			Hop:     2,
			Address: "10.0.0.1",
			Host:    "isp-router.net",
			RTT:     []float64{5.2, 5.3, 5.1, 5.2, 5.4},
			Loss:    0,
			Last:    5.4,
			Avg:     5.24,
			Best:    5.1,
			Worst:   5.4,
			StdDev:  0.12,
		},
	}
}

// getMockPortScanResults 获取模拟的端口扫描结果
func (ndt *NetworkDiagnosticTool) getMockPortScanResults(ports []int) []*PortInfo {
	portStates := map[int]string{
		22:   "open",
		80:   "open",
		443:  "open",
		3306: "closed",
		5432: "filtered",
	}

	portServices := map[int]string{
		22:   "ssh",
		80:   "http",
		443:  "https",
		3306: "mysql",
		5432: "postgresql",
	}

	results := make([]*PortInfo, 0)
	for _, port := range ports {
		state, ok := portStates[port]
		if !ok {
			state = "closed"
		}

		service, _ := portServices[port]

		results = append(results, &PortInfo{
			Port:    port,
			State:   state,
			Service: service,
		})
	}

	return results
}

// getMockDNSRecords 获取模拟的 DNS 记录
func (ndt *NetworkDiagnosticTool) getMockDNSRecords() []*DNSRecord {
	return []*DNSRecord{
		{
			Type:  "A",
			Name:  "example.com",
			Value: "93.184.216.34",
			TTL:   3600,
			Class: "IN",
		},
		{
			Type:  "AAAA",
			Name:  "example.com",
			Value: "2606:2800:220:1:248:1893:25c8:1946",
			TTL:   3600,
			Class: "IN",
		},
		{
			Type:  "MX",
			Name:  "example.com",
			Value: "10 mail.example.com",
			TTL:   3600,
			Class: "IN",
		},
		{
			Type:  "NS",
			Name:  "example.com",
			Value: "ns1.example.com",
			TTL:   3600,
			Class: "IN",
		},
	}
}

// getMockPingResult 获取模拟的 ping 结果
func (ndt *NetworkDiagnosticTool) getMockPingResult(params *NetworkDiagnosticParams) *PingResult {
	count := params.PacketCount
	if count == 0 {
		count = 4
	}

	return &PingResult{
		Sent:     count,
		Received: count,
		Loss:     0,
		Min:      15.1,
		Avg:      15.25,
		Max:      15.5,
		StdDev:   0.15,
	}
}

// analyzeResults 分析诊断结果
func (ndt *NetworkDiagnosticTool) analyzeResults(result *NetworkDiagnosticResult, params *NetworkDiagnosticParams) {
	switch params.Type {
	case DiagnosticTraceroute, DiagnosticMTR:
		ndt.analyzeHops(result)
	case DiagnosticPortScan:
		ndt.analyzePortScan(result)
	case DiagnosticPing:
		ndt.analyzePing(result)
	}
}

// analyzeHops 分析跳转
func (ndt *NetworkDiagnosticTool) analyzeHops(result *NetworkDiagnosticResult) {
	if len(result.Hops) == 0 {
		result.Status = "error"
		result.Issues = append(result.Issues, "No hops returned")
		return
	}

	// 检查丢包
	for _, hop := range result.Hops {
		if hop.Loss > 10 {
			result.Issues = append(result.Issues,
				fmt.Sprintf("Hop %d has high packet loss: %.1f%%", hop.Hop, hop.Loss))
		}
	}

	// 检查延迟
	lastHop := result.Hops[len(result.Hops)-1]
	if lastHop.Avg > 100 {
		result.LatencyHealth = "poor"
		result.Issues = append(result.Issues,
			fmt.Sprintf("High latency to target: %.1fms", lastHop.Avg))
	} else if lastHop.Avg > 50 {
		result.LatencyHealth = "fair"
	} else {
		result.LatencyHealth = "good"
	}

	// 生成建议
	if len(result.Issues) > 0 {
		result.Recommendations = append(result.Recommendations,
			"Check network connectivity and ISP routing")
	}
}

// analyzePortScan 分析端口扫描
func (ndt *NetworkDiagnosticTool) analyzePortScan(result *NetworkDiagnosticResult) {
	openCount := 0
	filteredCount := 0

	for _, port := range result.Ports {
		if port.State == "open" {
			openCount++
		} else if port.State == "filtered" {
			filteredCount++
		}
	}

	if filteredCount > 0 {
		result.Issues = append(result.Issues,
			fmt.Sprintf("%d ports are filtered (possible firewall)", filteredCount))
	}

	if openCount == 0 {
		result.Recommendations = append(result.Recommendations,
			"No open ports found on target")
	}
}

// analyzePing 分析 ping 结果
func (ndt *NetworkDiagnosticTool) analyzePing(result *NetworkDiagnosticResult) {
	if result.PingResult == nil {
		result.Status = "error"
		result.Issues = append(result.Issues, "Ping failed")
		return
	}

	if result.PingResult.Loss > 0 {
		result.Issues = append(result.Issues,
			fmt.Sprintf("Packet loss: %.1f%%", result.PingResult.Loss))
		result.Recommendations = append(result.Recommendations,
			"Check network stability")
	}

	if result.PingResult.Avg > 100 {
		result.LatencyHealth = "poor"
	} else if result.PingResult.Avg > 50 {
		result.LatencyHealth = "fair"
	} else {
		result.LatencyHealth = "good"
	}
}
