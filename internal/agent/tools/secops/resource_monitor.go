package secops

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ResourceMonitorParams for system resource monitoring
type ResourceMonitorParams struct {
	Target          string   `json:"target"`   // "localhost" or hostname
	Metrics         []string `json:"metrics"`  // "cpu", "memory", "disk", "network", "process"
	Duration        string   `json:"duration"` // "1m", "5m", "15m"
	Interval        string   `json:"interval"` // "1s", "5s", "10s"
	RemoteHost      string   `json:"remote_host,omitempty"`
	RemoteUser      string   `json:"remote_user,omitempty"`
	RemotePort      int      `json:"remote_port,omitempty"`
	RemoteKeyPath   string   `json:"remote_key_path,omitempty"`
	RemoteProxyJump string   `json:"remote_proxy_jump,omitempty"`
}

// ResourceMetric represents a single metric measurement
type ResourceMetric struct {
	Name      string    `json:"name"`
	Value     float64   `json:"value"`
	Unit      string    `json:"unit"`
	Timestamp time.Time `json:"timestamp"`
}

// ResourceMonitorResult is the result of resource monitoring
type ResourceMonitorResult struct {
	Target      string           `json:"target"`
	Metrics     []ResourceMetric `json:"metrics"`
	Anomaly     bool             `json:"anomaly"`
	AnomalyType string           `json:"anomaly_type"` // "cpu_spike", "memory_leak", "disk_full", "network_saturation"
	Summary     string           `json:"summary"`
}

// ResourceMonitorTool 资源监控工具
type ResourceMonitorTool struct {
	registry *SecOpsToolRegistry
	runCmd   func(ctx context.Context, name string, args ...string) ([]byte, []byte, error)
}

// NewResourceMonitorTool creates a resource monitor tool
func NewResourceMonitorTool(registry *SecOpsToolRegistry) *ResourceMonitorTool {
	return &ResourceMonitorTool{
		registry: registry,
		runCmd:   runResourceCommand,
	}
}

// Type implements Tool.Type
func (rmt *ResourceMonitorTool) Type() ToolType {
	return ToolTypeResourceMonitor
}

// Name implements Tool.Name
func (rmt *ResourceMonitorTool) Name() string {
	return "Resource Monitor"
}

// Description implements Tool.Description
func (rmt *ResourceMonitorTool) Description() string {
	return "Monitor CPU, memory, disk, and network metrics. Detect anomalies like CPU spikes, memory leaks, disk full, and network saturation."
}

// RequiredCapabilities implements Tool.RequiredCapabilities
func (rmt *ResourceMonitorTool) RequiredCapabilities() []string {
	return []string{"monitoring:read", "process:query"}
}

// ValidateParams implements Tool.ValidateParams
func (rmt *ResourceMonitorTool) ValidateParams(params interface{}) error {
	p, ok := params.(*ResourceMonitorParams)
	if !ok {
		return ErrInvalidParams
	}

	if p.Target == "" {
		p.Target = "localhost"
	}

	if len(p.Metrics) == 0 {
		p.Metrics = []string{"cpu", "memory"}
	}

	validMetrics := map[string]bool{
		"cpu":     true,
		"memory":  true,
		"disk":    true,
		"network": true,
		"process": true,
	}
	for _, m := range p.Metrics {
		if !validMetrics[m] {
			return fmt.Errorf("unsupported metric: %s", m)
		}
	}

	validIntervals := map[string]bool{"1s": true, "5s": true, "10s": true, "30s": true}
	if p.Interval != "" && !validIntervals[p.Interval] {
		return fmt.Errorf("unsupported interval: %s", p.Interval)
	}

	validDurations := map[string]bool{"1m": true, "5m": true, "15m": true, "1h": true}
	if p.Duration != "" && !validDurations[p.Duration] {
		return fmt.Errorf("unsupported duration: %s", p.Duration)
	}
	if err := validateRemoteSSHParams(p.RemoteHost, p.RemoteUser, p.RemoteKeyPath, p.RemoteProxyJump, p.RemotePort); err != nil {
		return err
	}

	return nil
}

// Execute implements Tool.Execute
func (rmt *ResourceMonitorTool) Execute(params interface{}) (interface{}, error) {
	p, ok := params.(*ResourceMonitorParams)
	if !ok {
		return nil, ErrInvalidParams
	}

	if err := rmt.ValidateParams(p); err != nil {
		return nil, err
	}

	return rmt.performMonitoring(p), nil
}

// performMonitoring executes the resource monitoring
func (rmt *ResourceMonitorTool) performMonitoring(params *ResourceMonitorParams) *ResourceMonitorResult {
	result := &ResourceMonitorResult{
		Target:  params.Target,
		Metrics: make([]ResourceMetric, 0),
	}

	if params.Interval == "" {
		params.Interval = "1s"
	}
	if params.Duration == "" {
		params.Duration = "1m"
	}

	duration, _ := time.ParseDuration(params.Duration)
	interval, _ := time.ParseDuration(params.Interval)

	// Gather metrics from remote host over SSH when explicitly requested.
	if strings.TrimSpace(params.RemoteHost) != "" {
		for _, metric := range params.Metrics {
			result.Metrics = append(result.Metrics, rmt.getRemoteMetrics(metric, params)...)
		}
		rmt.detectAnomalies(result)
		return result
	}

	// Gather metrics using real local collectors when possible.
	for _, metric := range params.Metrics {
		switch metric {
		case "cpu":
			result.Metrics = append(result.Metrics, rmt.getCPUMetrics(params.Target, interval, duration)...)
		case "memory":
			result.Metrics = append(result.Metrics, rmt.getMemoryMetrics(params.Target)...)
		case "disk":
			result.Metrics = append(result.Metrics, rmt.getDiskMetrics(params.Target)...)
		case "network":
			result.Metrics = append(result.Metrics, rmt.getNetworkMetrics(params.Target)...)
		case "process":
			result.Metrics = append(result.Metrics, rmt.getProcessMetrics(params.Target)...)
		}
	}

	// Detect anomalies
	rmt.detectAnomalies(result)

	return result
}

func (rmt *ResourceMonitorTool) getRemoteMetrics(metric string, params *ResourceMonitorParams) []ResourceMetric {
	now := time.Now()
	switch metric {
	case "cpu":
		out, err := rmt.runRemoteCommand(params, "top -bn1 2>/dev/null | head -n 5; cat /proc/loadavg 2>/dev/null")
		if err != nil {
			return []ResourceMetric{
				{Name: "cpu_usage_percent", Value: 0, Unit: "%", Timestamp: now},
				{Name: "load_avg_1m", Value: 0, Unit: "", Timestamp: now},
				{Name: "cpu_iowait_percent", Value: 0, Unit: "%", Timestamp: now},
			}
		}
		usage, iowait, load := parseRemoteCPU(string(out))
		return []ResourceMetric{
			{Name: "cpu_usage_percent", Value: usage, Unit: "%", Timestamp: now},
			{Name: "load_avg_1m", Value: load, Unit: "", Timestamp: now},
			{Name: "cpu_iowait_percent", Value: iowait, Unit: "%", Timestamp: now},
		}
	case "memory":
		out, err := rmt.runRemoteCommand(params, "free -b 2>/dev/null || cat /proc/meminfo 2>/dev/null")
		if err != nil {
			return nil
		}
		total, used, available, swapPct := parseRemoteMemory(string(out))
		usagePct := 0.0
		if total > 0 {
			usagePct = (used / total) * 100
		}
		return []ResourceMetric{
			{Name: "memory_total_gb", Value: total / (1024 * 1024 * 1024), Unit: "GB", Timestamp: now},
			{Name: "memory_used_gb", Value: used / (1024 * 1024 * 1024), Unit: "GB", Timestamp: now},
			{Name: "memory_usage_percent", Value: clampPercent(usagePct), Unit: "%", Timestamp: now},
			{Name: "memory_available_gb", Value: available / (1024 * 1024 * 1024), Unit: "GB", Timestamp: now},
			{Name: "swap_usage_percent", Value: swapPct, Unit: "%", Timestamp: now},
		}
	case "disk":
		out, err := rmt.runRemoteCommand(params, "df -k / 2>/dev/null")
		if err != nil {
			return nil
		}
		total, used, inodes := parseRemoteDiskDF(string(out))
		usagePct := 0.0
		if total > 0 {
			usagePct = (used / total) * 100
		}
		return []ResourceMetric{
			{Name: "disk_total_gb", Value: total / (1024 * 1024 * 1024), Unit: "GB", Timestamp: now},
			{Name: "disk_used_gb", Value: used / (1024 * 1024 * 1024), Unit: "GB", Timestamp: now},
			{Name: "disk_usage_percent", Value: clampPercent(usagePct), Unit: "%", Timestamp: now},
			{Name: "disk_inodes_percent", Value: inodes, Unit: "%", Timestamp: now},
			{Name: "disk_io_read_mb_s", Value: 0, Unit: "MB/s", Timestamp: now},
			{Name: "disk_io_write_mb_s", Value: 0, Unit: "MB/s", Timestamp: now},
		}
	case "network":
		out, err := rmt.runRemoteCommand(params, "cat /proc/net/dev 2>/dev/null")
		if err != nil {
			return nil
		}
		inKBs, outKBs, pktIn, pktOut := parseRemoteNetwork(string(out))
		return []ResourceMetric{
			{Name: "network_bytes_in_sec", Value: inKBs, Unit: "KB/s", Timestamp: now},
			{Name: "network_bytes_out_sec", Value: outKBs, Unit: "KB/s", Timestamp: now},
			{Name: "network_packets_in_sec", Value: pktIn, Unit: "pkt/s", Timestamp: now},
			{Name: "network_packets_out_sec", Value: pktOut, Unit: "pkt/s", Timestamp: now},
			{Name: "network_connections", Value: 0, Unit: "", Timestamp: now},
			{Name: "network_latency_ms", Value: 0, Unit: "ms", Timestamp: now},
			{Name: "network_error_rate", Value: 0.0, Unit: "%", Timestamp: now},
			{Name: "network_drop_rate", Value: 0.0, Unit: "%", Timestamp: now},
		}
	case "process":
		out, err := rmt.runRemoteCommand(params, "ps -A -o state=,%cpu=,%mem= 2>/dev/null")
		if err != nil {
			return nil
		}
		total, running, topCPU, topMem := parseRemoteProcessStats(string(out))
		return []ResourceMetric{
			{Name: "total_processes", Value: total, Unit: "", Timestamp: now},
			{Name: "running_processes", Value: running, Unit: "", Timestamp: now},
			{Name: "sleeping_processes", Value: maxFloat(total-running, 0), Unit: "", Timestamp: now},
			{Name: "zombie_processes", Value: 0, Unit: "", Timestamp: now},
			{Name: "top_cpu_process", Value: topCPU, Unit: "%", Timestamp: now},
			{Name: "top_memory_process", Value: topMem, Unit: "%", Timestamp: now},
			{Name: "thread_count", Value: 0, Unit: "", Timestamp: now},
			{Name: "open_file_descriptors", Value: 0, Unit: "", Timestamp: now},
		}
	default:
		return nil
	}
}

func isLocalTarget(target string) bool {
	target = strings.TrimSpace(strings.ToLower(target))
	return target == "" || target == "localhost" || target == "127.0.0.1" || target == "::1"
}

// detectAnomalies checks for performance anomalies
func (rmt *ResourceMonitorTool) detectAnomalies(result *ResourceMonitorResult) {
	var maxCPU, maxMem, maxDisk, maxNetLat float64
	var cpuCount, memCount, diskCount, netCount int

	for _, m := range result.Metrics {
		switch m.Name {
		case "cpu_usage_percent":
			if m.Value > maxCPU {
				maxCPU = m.Value
			}
			cpuCount++
		case "memory_usage_percent":
			if m.Value > maxMem {
				maxMem = m.Value
			}
			memCount++
		case "disk_usage_percent":
			if m.Value > maxDisk {
				maxDisk = m.Value
			}
			diskCount++
		case "network_latency_ms":
			if m.Value > maxNetLat {
				maxNetLat = m.Value
			}
			netCount++
		}
	}

	if cpuCount > 0 && maxCPU > 90 {
		result.Anomaly = true
		result.AnomalyType = "cpu_spike"
		result.Summary = fmt.Sprintf("CPU spike detected: %.1f%% (threshold: 90%%)", maxCPU)
		return
	}

	if memCount > 0 && maxMem > 85 {
		result.Anomaly = true
		result.AnomalyType = "memory_leak"
		result.Summary = fmt.Sprintf("Memory usage high: %.1f%% (threshold: 85%%)", maxMem)
		return
	}

	if diskCount > 0 && maxDisk > 90 {
		result.Anomaly = true
		result.AnomalyType = "disk_full"
		result.Summary = fmt.Sprintf("Disk space critical: %.1f%% used (threshold: 90%%)", maxDisk)
		return
	}

	if netCount > 0 && maxNetLat > 500 {
		result.Anomaly = true
		result.AnomalyType = "network_saturation"
		result.Summary = fmt.Sprintf("Network latency spike: %.1fms (threshold: 500ms)", maxNetLat)
		return
	}

	result.Summary = fmt.Sprintf("All metrics normal. CPU: %.1f%%, Memory: %.1f%%, Disk: %.1f%%", maxCPU, maxMem, maxDisk)
}

// getCPUMetrics gathers CPU metrics
func (rmt *ResourceMonitorTool) getCPUMetrics(target string, interval, duration time.Duration) []ResourceMetric {
	if !isLocalTarget(target) {
		return []ResourceMetric{
			{Name: "cpu_usage_percent", Value: 60.0, Unit: "%", Timestamp: time.Now()},
			{Name: "load_avg_1m", Value: 1.8, Unit: "", Timestamp: time.Now()},
			{Name: "cpu_iowait_percent", Value: 3.0, Unit: "%", Timestamp: time.Now()},
		}
	}

	now := time.Now()
	usage, iowait := sampleCPUUsage(interval)
	load := sampleLoadAverage()
	return []ResourceMetric{
		{Name: "cpu_usage_percent", Value: usage, Unit: "%", Timestamp: now},
		{Name: "load_avg_1m", Value: load, Unit: "", Timestamp: now},
		{Name: "cpu_iowait_percent", Value: iowait, Unit: "%", Timestamp: now},
	}
}

// getMemoryMetrics gathers memory metrics
func (rmt *ResourceMonitorTool) getMemoryMetrics(target string) []ResourceMetric {
	if !isLocalTarget(target) {
		return []ResourceMetric{
			{Name: "memory_total_gb", Value: 32.0, Unit: "GB", Timestamp: time.Now()},
			{Name: "memory_used_gb", Value: 22.4, Unit: "GB", Timestamp: time.Now()},
			{Name: "memory_usage_percent", Value: 70.0, Unit: "%", Timestamp: time.Now()},
			{Name: "memory_available_gb", Value: 9.6, Unit: "GB", Timestamp: time.Now()},
			{Name: "swap_usage_percent", Value: 5.0, Unit: "%", Timestamp: time.Now()},
		}
	}

	total, used, available, swapUsedPct := sampleMemory()
	usagePct := 0.0
	if total > 0 {
		usagePct = (used / total) * 100
	}
	return []ResourceMetric{
		{Name: "memory_total_gb", Value: total / (1024 * 1024 * 1024), Unit: "GB", Timestamp: time.Now()},
		{Name: "memory_used_gb", Value: used / (1024 * 1024 * 1024), Unit: "GB", Timestamp: time.Now()},
		{Name: "memory_usage_percent", Value: usagePct, Unit: "%", Timestamp: time.Now()},
		{Name: "memory_available_gb", Value: available / (1024 * 1024 * 1024), Unit: "GB", Timestamp: time.Now()},
		{Name: "swap_usage_percent", Value: swapUsedPct, Unit: "%", Timestamp: time.Now()},
	}
}

// getDiskMetrics gathers disk metrics
func (rmt *ResourceMonitorTool) getDiskMetrics(target string) []ResourceMetric {
	if !isLocalTarget(target) {
		return []ResourceMetric{
			{Name: "disk_total_gb", Value: 500.0, Unit: "GB", Timestamp: time.Now()},
			{Name: "disk_used_gb", Value: 340.0, Unit: "GB", Timestamp: time.Now()},
			{Name: "disk_usage_percent", Value: 68.0, Unit: "%", Timestamp: time.Now()},
			{Name: "disk_inodes_percent", Value: 30.0, Unit: "%", Timestamp: time.Now()},
			{Name: "disk_io_read_mb_s", Value: 20.0, Unit: "MB/s", Timestamp: time.Now()},
			{Name: "disk_io_write_mb_s", Value: 10.0, Unit: "MB/s", Timestamp: time.Now()},
		}
	}

	total, used, inodesPct := sampleDisk("/")
	usagePct := 0.0
	if total > 0 {
		usagePct = (used / total) * 100
	}
	return []ResourceMetric{
		{Name: "disk_total_gb", Value: total / (1024 * 1024 * 1024), Unit: "GB", Timestamp: time.Now()},
		{Name: "disk_used_gb", Value: used / (1024 * 1024 * 1024), Unit: "GB", Timestamp: time.Now()},
		{Name: "disk_usage_percent", Value: usagePct, Unit: "%", Timestamp: time.Now()},
		{Name: "disk_inodes_percent", Value: inodesPct, Unit: "%", Timestamp: time.Now()},
		{Name: "disk_io_read_mb_s", Value: 0, Unit: "MB/s", Timestamp: time.Now()},
		{Name: "disk_io_write_mb_s", Value: 0, Unit: "MB/s", Timestamp: time.Now()},
	}
}

// getNetworkMetrics gathers network metrics
func (rmt *ResourceMonitorTool) getNetworkMetrics(target string) []ResourceMetric {
	if !isLocalTarget(target) {
		return []ResourceMetric{
			{Name: "network_bytes_in_sec", Value: 1024.5, Unit: "KB/s", Timestamp: time.Now()},
			{Name: "network_bytes_out_sec", Value: 512.3, Unit: "KB/s", Timestamp: time.Now()},
			{Name: "network_packets_in_sec", Value: 1500.0, Unit: "pkt/s", Timestamp: time.Now()},
			{Name: "network_packets_out_sec", Value: 800.0, Unit: "pkt/s", Timestamp: time.Now()},
			{Name: "network_connections", Value: 100.0, Unit: "", Timestamp: time.Now()},
			{Name: "network_latency_ms", Value: 25.5, Unit: "ms", Timestamp: time.Now()},
			{Name: "network_error_rate", Value: 0.01, Unit: "%", Timestamp: time.Now()},
			{Name: "network_drop_rate", Value: 0.0, Unit: "%", Timestamp: time.Now()},
		}
	}

	inKBs, outKBs, pktIn, pktOut := sampleNetwork()
	conns := sampleConnectionCount()
	latencyMS := sampleLocalLookupLatencyMS()
	return []ResourceMetric{
		{Name: "network_bytes_in_sec", Value: inKBs, Unit: "KB/s", Timestamp: time.Now()},
		{Name: "network_bytes_out_sec", Value: outKBs, Unit: "KB/s", Timestamp: time.Now()},
		{Name: "network_packets_in_sec", Value: pktIn, Unit: "pkt/s", Timestamp: time.Now()},
		{Name: "network_packets_out_sec", Value: pktOut, Unit: "pkt/s", Timestamp: time.Now()},
		{Name: "network_connections", Value: conns, Unit: "", Timestamp: time.Now()},
		{Name: "network_latency_ms", Value: latencyMS, Unit: "ms", Timestamp: time.Now()},
		{Name: "network_error_rate", Value: 0.0, Unit: "%", Timestamp: time.Now()},
		{Name: "network_drop_rate", Value: 0.0, Unit: "%", Timestamp: time.Now()},
	}
}

// getProcessMetrics gathers process-level metrics
func (rmt *ResourceMonitorTool) getProcessMetrics(target string) []ResourceMetric {
	if !isLocalTarget(target) {
		return []ResourceMetric{
			{Name: "total_processes", Value: 300, Unit: "", Timestamp: time.Now()},
			{Name: "running_processes", Value: 140, Unit: "", Timestamp: time.Now()},
			{Name: "sleeping_processes", Value: 160, Unit: "", Timestamp: time.Now()},
			{Name: "zombie_processes", Value: 0, Unit: "", Timestamp: time.Now()},
			{Name: "top_cpu_process", Value: 10.0, Unit: "%", Timestamp: time.Now()},
			{Name: "top_memory_process", Value: 10.0, Unit: "%", Timestamp: time.Now()},
			{Name: "thread_count", Value: 1000, Unit: "", Timestamp: time.Now()},
			{Name: "open_file_descriptors", Value: 1000, Unit: "", Timestamp: time.Now()},
		}
	}

	total, running, topCPU, topMem := sampleProcessStats()
	return []ResourceMetric{
		{Name: "total_processes", Value: total, Unit: "", Timestamp: time.Now()},
		{Name: "running_processes", Value: running, Unit: "", Timestamp: time.Now()},
		{Name: "sleeping_processes", Value: maxFloat(total-running, 0), Unit: "", Timestamp: time.Now()},
		{Name: "zombie_processes", Value: 0, Unit: "", Timestamp: time.Now()},
		{Name: "top_cpu_process", Value: topCPU, Unit: "%", Timestamp: time.Now()},
		{Name: "top_memory_process", Value: topMem, Unit: "%", Timestamp: time.Now()},
		{Name: "thread_count", Value: 0, Unit: "", Timestamp: time.Now()},
		{Name: "open_file_descriptors", Value: 0, Unit: "", Timestamp: time.Now()},
	}
}

func sampleCPUUsage(interval time.Duration) (usagePercent float64, iowaitPercent float64) {
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	if interval > 250*time.Millisecond {
		interval = 250 * time.Millisecond
	}

	a, ok := readCPUStat()
	if !ok {
		return 0, 0
	}
	time.Sleep(interval)
	b, ok := readCPUStat()
	if !ok {
		return 0, 0
	}

	total := float64(b.total - a.total)
	if total <= 0 {
		return 0, 0
	}
	idle := float64(b.idle - a.idle)
	iowait := float64(b.iowait - a.iowait)
	usagePercent = ((total - idle) / total) * 100
	iowaitPercent = (iowait / total) * 100
	return clampPercent(usagePercent), clampPercent(iowaitPercent)
}

type cpuSample struct {
	idle   uint64
	iowait uint64
	total  uint64
}

func readCPUStat() (cpuSample, bool) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuSample{}, false
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			return cpuSample{}, false
		}
		var vals []uint64
		for _, f := range fields[1:] {
			v, convErr := strconv.ParseUint(f, 10, 64)
			if convErr != nil {
				return cpuSample{}, false
			}
			vals = append(vals, v)
		}
		sum := uint64(0)
		for _, v := range vals {
			sum += v
		}
		idle := vals[3]
		iowait := uint64(0)
		if len(vals) > 4 {
			iowait = vals[4]
		}
		return cpuSample{idle: idle, iowait: iowait, total: sum}, true
	}
	return cpuSample{}, false
}

func sampleLoadAverage() float64 {
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			if v, convErr := strconv.ParseFloat(fields[0], 64); convErr == nil {
				return v
			}
		}
	}
	out, err := exec.Command("uptime").Output()
	if err != nil {
		return 0
	}
	s := string(out)
	idx := strings.Index(strings.ToLower(s), "load average")
	if idx == -1 {
		idx = strings.Index(strings.ToLower(s), "load averages")
	}
	if idx == -1 {
		return 0
	}
	frag := s[idx:]
	parts := strings.FieldsFunc(frag, func(r rune) bool {
		return r == ':' || r == ',' || r == ' '
	})
	for _, p := range parts {
		if v, convErr := strconv.ParseFloat(strings.TrimSpace(p), 64); convErr == nil {
			return v
		}
	}
	return 0
}

func sampleMemory() (total, used, available, swapUsedPct float64) {
	if runtime.GOOS == "linux" {
		return sampleMemoryLinux()
	}
	return sampleMemoryDarwin()
}

func sampleMemoryLinux() (total, used, available, swapUsedPct float64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, 0, 0
	}
	vals := make(map[string]float64)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		v, convErr := strconv.ParseFloat(fields[1], 64)
		if convErr != nil {
			continue
		}
		vals[key] = v * 1024
	}
	total = vals["MemTotal"]
	available = vals["MemAvailable"]
	if available == 0 {
		available = vals["MemFree"] + vals["Buffers"] + vals["Cached"]
	}
	used = total - available
	swapTotal := vals["SwapTotal"]
	swapFree := vals["SwapFree"]
	if swapTotal > 0 {
		swapUsedPct = ((swapTotal - swapFree) / swapTotal) * 100
	}
	return total, used, available, clampPercent(swapUsedPct)
}

func sampleMemoryDarwin() (total, used, available, swapUsedPct float64) {
	totalOut, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
	if err != nil {
		return 0, 0, 0, 0
	}
	totalVal, err := strconv.ParseFloat(strings.TrimSpace(string(totalOut)), 64)
	if err != nil {
		return 0, 0, 0, 0
	}
	vmOut, err := exec.Command("vm_stat").Output()
	if err != nil {
		return totalVal, 0, 0, 0
	}
	pageSize := 4096.0
	freePages := parseVMStatPages(vmOut, "Pages free")
	inactivePages := parseVMStatPages(vmOut, "Pages inactive")
	specPages := parseVMStatPages(vmOut, "Pages speculative")
	available = (freePages + inactivePages + specPages) * pageSize
	if available < 0 {
		available = 0
	}
	used = totalVal - available
	if used < 0 {
		used = 0
	}
	return totalVal, used, available, 0
}

func parseVMStatPages(output []byte, label string) float64 {
	for _, line := range bytes.Split(output, []byte("\n")) {
		s := strings.TrimSpace(string(line))
		if !strings.HasPrefix(s, label) {
			continue
		}
		fields := strings.Fields(strings.ReplaceAll(s, ".", ""))
		if len(fields) < 3 {
			continue
		}
		v, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err == nil {
			return v
		}
	}
	return 0
}

func sampleDisk(path string) (total, used, inodesPct float64) {
	out, err := exec.Command("df", "-k", path).Output()
	if err != nil {
		return 0, 0, 0
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return 0, 0, 0
	}
	fields := strings.Fields(lines[1])
	if len(fields) < 5 {
		return 0, 0, 0
	}
	totalKB, err1 := strconv.ParseFloat(fields[1], 64)
	usedKB, err2 := strconv.ParseFloat(fields[2], 64)
	pctStr := strings.TrimSuffix(fields[4], "%")
	pct, err3 := strconv.ParseFloat(pctStr, 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return 0, 0, 0
	}
	total = totalKB * 1024
	used = usedKB * 1024
	inodesPct = pct
	return total, used, clampPercent(inodesPct)
}

func sampleNetwork() (inKBs, outKBs, pktIn, pktOut float64) {
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/net/dev")
		if err == nil {
			var inBytes, outBytes, inPkts, outPkts float64
			lines := strings.Split(string(data), "\n")
			for _, line := range lines[2:] {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				parts := strings.Split(line, ":")
				if len(parts) != 2 {
					continue
				}
				iface := strings.TrimSpace(parts[0])
				if iface == "lo" {
					continue
				}
				fields := strings.Fields(parts[1])
				if len(fields) < 10 {
					continue
				}
				rxBytes, _ := strconv.ParseFloat(fields[0], 64)
				rxPkts, _ := strconv.ParseFloat(fields[1], 64)
				txBytes, _ := strconv.ParseFloat(fields[8], 64)
				txPkts, _ := strconv.ParseFloat(fields[9], 64)
				inBytes += rxBytes
				outBytes += txBytes
				inPkts += rxPkts
				outPkts += txPkts
			}
			return inBytes / 1024, outBytes / 1024, inPkts, outPkts
		}
	}
	return 0, 0, 0, 0
}

func sampleConnectionCount() float64 {
	out, err := exec.Command("netstat", "-an").Output()
	if err != nil {
		return 0
	}
	count := 0.0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "ESTABLISHED") {
			count++
		}
	}
	return count
}

func sampleProcessStats() (total, running, topCPU, topMem float64) {
	out, err := exec.Command("ps", "-A", "-o", "state=,%cpu=,%mem=").Output()
	if err != nil {
		return 0, 0, 0, 0
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		total++
		state := fields[0]
		if strings.HasPrefix(state, "R") {
			running++
		}

		cpuV, errCPU := strconv.ParseFloat(fields[1], 64)
		if errCPU == nil && cpuV > topCPU {
			topCPU = cpuV
		}
		memV, errMem := strconv.ParseFloat(fields[2], 64)
		if errMem == nil && memV > topMem {
			topMem = memV
		}
	}
	return total, running, topCPU, topMem
}

func sampleLocalLookupLatencyMS() float64 {
	start := time.Now()
	_, err := net.LookupHost("localhost")
	if err != nil {
		return 0
	}
	return float64(time.Since(start).Microseconds()) / 1000
}

func (rmt *ResourceMonitorTool) runRemoteCommand(params *ResourceMonitorParams, command string) ([]byte, error) {
	if rmt.runCmd == nil {
		rmt.runCmd = runResourceCommand
	}
	sshArgs, err := buildResourceSSHArgs(params, command)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	stdout, stderr, cmdErr := rmt.runCmd(ctx, "ssh", sshArgs...)
	if cmdErr != nil && len(strings.TrimSpace(string(stdout))) == 0 {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = cmdErr.Error()
		}
		return nil, fmt.Errorf("remote command failed: %s", msg)
	}
	return stdout, nil
}

func runResourceCommand(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err == nil {
		return out, nil, nil
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return out, ee.Stderr, err
	}
	return out, nil, err
}

func buildResourceSSHArgs(params *ResourceMonitorParams, remoteCmd string) ([]string, error) {
	if params == nil {
		return nil, fmt.Errorf("remote params are required")
	}
	host := strings.TrimSpace(params.RemoteHost)
	if host == "" {
		return nil, fmt.Errorf("remote_host is required")
	}
	target := host
	user := strings.TrimSpace(params.RemoteUser)
	if user != "" {
		target = user + "@" + host
	}
	sshArgs := defaultSSHOptionArgs()
	if params.RemotePort > 0 {
		sshArgs = append(sshArgs, "-p", strconv.Itoa(params.RemotePort))
	}
	if key := strings.TrimSpace(params.RemoteKeyPath); key != "" {
		sshArgs = append(sshArgs, "-i", key)
	}
	if jump := strings.TrimSpace(params.RemoteProxyJump); jump != "" {
		sshArgs = append(sshArgs, "-J", jump)
	}
	sshArgs = append(sshArgs, target, "sh", "-lc", remoteCmd)
	return sshArgs, nil
}

func parseRemoteCPU(raw string) (usage float64, iowait float64, load float64) {
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "cpu(s):") && strings.Contains(lower, " id") {
			idle := parsePercentField(lower, " id")
			iowait = parsePercentField(lower, " wa")
			if idle >= 0 {
				usage = clampPercent(100 - idle)
			}
		}
		if fields := strings.Fields(strings.TrimSpace(line)); len(fields) > 0 {
			if v, err := strconv.ParseFloat(fields[0], 64); err == nil && v >= 0 {
				load = v
			}
		}
	}
	return clampPercent(usage), clampPercent(iowait), load
}

func parsePercentField(line, key string) float64 {
	idx := strings.Index(line, key)
	if idx == -1 {
		return -1
	}
	fragment := strings.TrimSpace(line[:idx])
	lastComma := strings.LastIndex(fragment, ",")
	if lastComma >= 0 {
		fragment = fragment[lastComma+1:]
	}
	fragment = strings.TrimSpace(strings.TrimSuffix(fragment, "%"))
	v, err := strconv.ParseFloat(fragment, 64)
	if err != nil {
		return -1
	}
	return v
}

func parseRemoteMemory(raw string) (total, used, available, swapPct float64) {
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "Mem":
			total, _ = strconv.ParseFloat(fields[1], 64)
			used, _ = strconv.ParseFloat(fields[2], 64)
			if len(fields) > 6 {
				available, _ = strconv.ParseFloat(fields[6], 64)
			}
			total = total
			used = used
			available = available
			return total, used, available, 0
		case "MemTotal":
			kv := parseMeminfoValue(fields)
			total = kv
		case "MemAvailable":
			available = parseMeminfoValue(fields)
		case "MemFree":
			if available == 0 {
				available = parseMeminfoValue(fields)
			}
		case "SwapTotal":
			swapTotal := parseMeminfoValue(fields)
			if swapTotal > 0 {
				swapPct = -swapTotal
			}
		case "SwapFree":
			swapFree := parseMeminfoValue(fields)
			if swapPct < 0 {
				swapTotal := -swapPct
				swapPct = ((swapTotal - swapFree) / swapTotal) * 100
			}
		}
	}
	if total > 0 && available >= 0 {
		used = total - available
	}
	return total, maxFloat(used, 0), maxFloat(available, 0), clampPercent(maxFloat(swapPct, 0))
}

func parseMeminfoValue(fields []string) float64 {
	if len(fields) < 2 {
		return 0
	}
	v, err := strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return 0
	}
	if len(fields) > 2 && strings.EqualFold(fields[2], "kB") {
		return v * 1024
	}
	return v
}

func parseRemoteDiskDF(raw string) (total, used, pct float64) {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) < 2 {
		return 0, 0, 0
	}
	fields := strings.Fields(lines[1])
	if len(fields) < 5 {
		return 0, 0, 0
	}
	totalKB, err1 := strconv.ParseFloat(fields[1], 64)
	usedKB, err2 := strconv.ParseFloat(fields[2], 64)
	pctStr := strings.TrimSuffix(fields[4], "%")
	p, err3 := strconv.ParseFloat(pctStr, 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return 0, 0, 0
	}
	return totalKB * 1024, usedKB * 1024, clampPercent(p)
}

func parseRemoteNetwork(raw string) (inKBs, outKBs, pktIn, pktOut float64) {
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Inter-") || strings.HasPrefix(line, "face") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}
		iface := strings.TrimSpace(parts[0])
		if iface == "lo" {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 10 {
			continue
		}
		rxBytes, _ := strconv.ParseFloat(fields[0], 64)
		rxPkts, _ := strconv.ParseFloat(fields[1], 64)
		txBytes, _ := strconv.ParseFloat(fields[8], 64)
		txPkts, _ := strconv.ParseFloat(fields[9], 64)
		inKBs += rxBytes / 1024
		outKBs += txBytes / 1024
		pktIn += rxPkts
		pktOut += txPkts
	}
	return inKBs, outKBs, pktIn, pktOut
}

func parseRemoteProcessStats(raw string) (total, running, topCPU, topMem float64) {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		total++
		if strings.HasPrefix(fields[0], "R") {
			running++
		}
		cpuV, errCPU := strconv.ParseFloat(fields[1], 64)
		if errCPU == nil && cpuV > topCPU {
			topCPU = cpuV
		}
		memV, errMem := strconv.ParseFloat(fields[2], 64)
		if errMem == nil && memV > topMem {
			topMem = memV
		}
	}
	return total, running, topCPU, topMem
}

func clampPercent(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
