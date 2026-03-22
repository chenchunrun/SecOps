package secops

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
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
	Type            NetworkDiagnosticType `json:"type"`
	Target          string                `json:"target"`          // IP 或域名
	Ports           []int                 `json:"ports,omitempty"` // 端口列表（用于端口扫描）
	Timeout         int                   `json:"timeout,omitempty"`
	PacketCount     int                   `json:"packet_count,omitempty"`  // ping 包数
	PacketSize      int                   `json:"packet_size,omitempty"`   // 包大小
	CheckLatency    bool                  `json:"check_latency,omitempty"` // 检查延迟
	CheckPacketLoss bool                  `json:"check_packet_loss,omitempty"`
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
	Type  string `json:"type"` // A, AAAA, MX, NS, CNAME, TXT
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl,omitempty"`
	Class string `json:"class,omitempty"`
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
	Timestamp       time.Time             `json:"timestamp"`
	Type            NetworkDiagnosticType `json:"type"`
	Target          string                `json:"target"`
	Status          string                `json:"status"`   // success, timeout, error
	Duration        int                   `json:"duration"` // 诊断耗时（毫秒）
	Hops            []*HopInfo            `json:"hops,omitempty"`
	Ports           []*PortInfo           `json:"ports,omitempty"`
	DNSRecords      []*DNSRecord          `json:"dns_records,omitempty"`
	PingResult      *PingResult           `json:"ping_result,omitempty"`
	LatencyHealth   string                `json:"latency_health,omitempty"` // good, fair, poor
	PacketLoss      float64               `json:"packet_loss,omitempty"`
	Issues          []string              `json:"issues,omitempty"`
	Recommendations []string              `json:"recommendations,omitempty"`
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
	start := time.Now()
	hops := ndt.runTracerouteCommand(params.Target, params.Timeout)
	if len(hops) == 0 {
		hops = ndt.fallbackTraceHops(params.Target, params.Timeout)
	}
	result.Hops = hops
	result.Duration = int(time.Since(start).Milliseconds())
}

// performMTR 执行 MTR
func (ndt *NetworkDiagnosticTool) performMTR(params *NetworkDiagnosticParams, result *NetworkDiagnosticResult) {
	start := time.Now()
	hops := ndt.runMTRCommand(params.Target, params.Timeout)
	if len(hops) == 0 {
		hops = ndt.fallbackTraceHops(params.Target, params.Timeout)
	}
	result.Hops = hops
	result.PacketLoss = ndt.averageLoss(hops)
	result.Duration = int(time.Since(start).Milliseconds())
}

// performPortScan 执行端口扫描
func (ndt *NetworkDiagnosticTool) performPortScan(params *NetworkDiagnosticParams, result *NetworkDiagnosticResult) {
	start := time.Now()
	results := make([]*PortInfo, 0, len(params.Ports))
	timeout := time.Duration(params.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	for _, port := range params.Ports {
		address := net.JoinHostPort(params.Target, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", address, timeout)
		state := "closed"
		if err == nil {
			state = "open"
			_ = conn.Close()
		}

		service := ""
		if svc := portToService(port); svc != "" {
			service = svc
		}

		results = append(results, &PortInfo{
			Port:    port,
			State:   state,
			Service: service,
		})
	}

	result.Ports = results
	result.Duration = int(time.Since(start).Milliseconds())
}

// performDNSLookup 执行 DNS 查询
func (ndt *NetworkDiagnosticTool) performDNSLookup(params *NetworkDiagnosticParams, result *NetworkDiagnosticResult) {
	start := time.Now()
	records := ndt.lookupDNS(params.Target, params.Timeout)
	result.DNSRecords = records
	if len(records) == 0 {
		result.Status = "error"
		result.Issues = append(result.Issues, "DNS lookup returned no records")
	}
	result.Duration = int(time.Since(start).Milliseconds())
}

// performPing 执行 ping
func (ndt *NetworkDiagnosticTool) performPing(params *NetworkDiagnosticParams, result *NetworkDiagnosticResult) {
	start := time.Now()
	pingResult := ndt.runPing(params)
	if pingResult == nil {
		pingResult = ndt.fallbackPingViaTCP(params)
	}
	result.PingResult = pingResult
	if pingResult == nil {
		result.Status = "error"
		result.Issues = append(result.Issues, "Ping failed")
	}
	result.Duration = int(time.Since(start).Milliseconds())
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

func (ndt *NetworkDiagnosticTool) runTracerouteCommand(target string, timeoutSec int) []*HopInfo {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "traceroute", "-n", "-q", "1", target)
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return nil
	}

	lines := strings.Split(string(out), "\n")
	re := regexp.MustCompile(`^\s*(\d+)\s+([0-9a-fA-F\.:]+)\s+([0-9.]+)\s*ms`)
	hops := make([]*HopInfo, 0, len(lines))
	for _, line := range lines {
		m := re.FindStringSubmatch(line)
		if len(m) != 4 {
			continue
		}
		hop, _ := strconv.Atoi(m[1])
		rtt, _ := strconv.ParseFloat(m[3], 64)
		hops = append(hops, &HopInfo{
			Hop:     hop,
			Address: m[2],
			RTT:     []float64{rtt},
			Last:    rtt,
			Avg:     rtt,
			Best:    rtt,
			Worst:   rtt,
			StdDev:  0,
		})
	}
	return hops
}

func (ndt *NetworkDiagnosticTool) runMTRCommand(target string, timeoutSec int) []*HopInfo {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "mtr", "--report", "--report-cycles", "3", "--no-dns", target)
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return nil
	}

	lines := strings.Split(string(out), "\n")
	re := regexp.MustCompile(`^\s*(\d+)\.\|\-\-\s+([0-9a-fA-F\.:]+)\s+([0-9.]+)%\s+\d+\s+([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)`)
	hops := make([]*HopInfo, 0, len(lines))
	for _, line := range lines {
		m := re.FindStringSubmatch(line)
		if len(m) != 9 {
			continue
		}
		hop, _ := strconv.Atoi(m[1])
		loss, _ := strconv.ParseFloat(m[3], 64)
		last, _ := strconv.ParseFloat(m[4], 64)
		avg, _ := strconv.ParseFloat(m[5], 64)
		best, _ := strconv.ParseFloat(m[6], 64)
		worst, _ := strconv.ParseFloat(m[7], 64)
		stddev, _ := strconv.ParseFloat(m[8], 64)
		hops = append(hops, &HopInfo{
			Hop:     hop,
			Address: m[2],
			RTT:     []float64{last, avg, best, worst},
			Loss:    loss,
			Last:    last,
			Avg:     avg,
			Best:    best,
			Worst:   worst,
			StdDev:  stddev,
		})
	}
	return hops
}

func (ndt *NetworkDiagnosticTool) runPing(params *NetworkDiagnosticParams) *PingResult {
	count := params.PacketCount
	if count <= 0 {
		count = 4
	}

	timeout := params.Timeout
	if timeout <= 0 {
		timeout = 30
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ping", "-c", strconv.Itoa(count), params.Target)
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return nil
	}

	output := string(out)
	lossRe := regexp.MustCompile(`(\d+(?:\.\d+)?)%\s+packet loss`)
	rttRe := regexp.MustCompile(`(?:round-trip|rtt) min/avg/max/(?:stddev|mdev) = ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)`)

	loss := 0.0
	min := 0.0
	avg := 0.0
	max := 0.0
	stddev := 0.0

	if m := lossRe.FindStringSubmatch(output); len(m) == 2 {
		loss, _ = strconv.ParseFloat(m[1], 64)
	}
	if m := rttRe.FindStringSubmatch(output); len(m) == 5 {
		min, _ = strconv.ParseFloat(m[1], 64)
		avg, _ = strconv.ParseFloat(m[2], 64)
		max, _ = strconv.ParseFloat(m[3], 64)
		stddev, _ = strconv.ParseFloat(m[4], 64)
	}

	received := int(float64(count) * (100 - loss) / 100)
	if received < 0 {
		received = 0
	}
	if avg <= 0 {
		return nil
	}
	return &PingResult{
		Sent:     count,
		Received: received,
		Loss:     loss,
		Min:      min,
		Avg:      avg,
		Max:      max,
		StdDev:   stddev,
	}
}

func (ndt *NetworkDiagnosticTool) lookupDNS(target string, timeoutSec int) []*DNSRecord {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	records := make([]*DNSRecord, 0)
	resolver := net.DefaultResolver

	if ips, err := resolver.LookupIP(ctx, "ip", target); err == nil {
		for _, ip := range ips {
			rt := "A"
			if ip.To4() == nil {
				rt = "AAAA"
			}
			records = append(records, &DNSRecord{Type: rt, Name: target, Value: ip.String(), Class: "IN"})
		}
	}
	if mxs, err := resolver.LookupMX(ctx, target); err == nil {
		for _, mx := range mxs {
			records = append(records, &DNSRecord{Type: "MX", Name: target, Value: fmt.Sprintf("%d %s", mx.Pref, strings.TrimSuffix(mx.Host, ".")), Class: "IN"})
		}
	}
	if nss, err := resolver.LookupNS(ctx, target); err == nil {
		for _, ns := range nss {
			records = append(records, &DNSRecord{Type: "NS", Name: target, Value: strings.TrimSuffix(ns.Host, "."), Class: "IN"})
		}
	}
	if txts, err := resolver.LookupTXT(ctx, target); err == nil {
		for _, txt := range txts {
			records = append(records, &DNSRecord{Type: "TXT", Name: target, Value: txt, Class: "IN"})
		}
	}
	if cname, err := resolver.LookupCNAME(ctx, target); err == nil && cname != "" {
		records = append(records, &DNSRecord{Type: "CNAME", Name: target, Value: strings.TrimSuffix(cname, "."), Class: "IN"})
	}

	return records
}

func (ndt *NetworkDiagnosticTool) averageLoss(hops []*HopInfo) float64 {
	if len(hops) == 0 {
		return 0
	}
	total := 0.0
	for _, hop := range hops {
		total += hop.Loss
	}
	return total / float64(len(hops))
}

func (ndt *NetworkDiagnosticTool) fallbackTraceHops(target string, timeoutSec int) []*HopInfo {
	timeout := time.Duration(timeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	address := target
	if ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip", target); err == nil && len(ips) > 0 {
		address = ips[0].String()
	}

	if rtt, ok := measureTCPRTT(target, timeout, []int{443, 80}); ok {
		return []*HopInfo{
			{
				Hop:     1,
				Address: address,
				RTT:     []float64{rtt},
				Loss:    0,
				Last:    rtt,
				Avg:     rtt,
				Best:    rtt,
				Worst:   rtt,
			},
		}
	}

	return []*HopInfo{
		{
			Hop:     1,
			Address: address,
			RTT:     nil,
			Loss:    100,
			Last:    0,
			Avg:     0,
			Best:    0,
			Worst:   0,
		},
	}
}

func (ndt *NetworkDiagnosticTool) fallbackPingViaTCP(params *NetworkDiagnosticParams) *PingResult {
	count := params.PacketCount
	if count <= 0 {
		count = 4
	}
	timeout := time.Duration(params.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	samples := make([]float64, 0, count)
	received := 0
	for i := 0; i < count; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(params.Target, "443"), timeout)
		if err != nil {
			continue
		}
		_ = conn.Close()
		received++
		lat := float64(time.Since(start).Microseconds()) / 1000
		if lat <= 0 {
			lat = 1
		}
		samples = append(samples, lat)
	}
	if received == 0 {
		return nil
	}

	min, max, sum := samples[0], samples[0], 0.0
	for _, s := range samples {
		if s < min {
			min = s
		}
		if s > max {
			max = s
		}
		sum += s
	}
	avg := sum / float64(len(samples))
	loss := (float64(count-received) / float64(count)) * 100

	return &PingResult{
		Sent:     count,
		Received: received,
		Loss:     loss,
		Min:      min,
		Avg:      avg,
		Max:      max,
		StdDev:   0,
	}
}

func measureTCPRTT(target string, timeout time.Duration, ports []int) (float64, bool) {
	for _, port := range ports {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(target, strconv.Itoa(port)), timeout)
		if err != nil {
			continue
		}
		_ = conn.Close()
		rtt := float64(time.Since(start).Milliseconds())
		if rtt <= 0 {
			rtt = 1
		}
		return rtt, true
	}
	return 0, false
}

func portToService(port int) string {
	switch port {
	case 22:
		return "ssh"
	case 53:
		return "dns"
	case 80:
		return "http"
	case 443:
		return "https"
	case 3306:
		return "mysql"
	case 5432:
		return "postgresql"
	default:
		return ""
	}
}
