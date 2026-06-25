package secops

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// 这些测试专门覆盖 resource_monitor.go 中覆盖率较低的纯解析函数与远程 SSH 采集路径。
// 解析函数是纯函数，可直接表驱动断言；远程采集函数通过覆盖 tool.runCmd 注入伪造的
// 远程 stdout 来驱动。对硬编码读取 /proc/* 的本地采集函数（readCPUStat / sampleNetwork /
// sampleMemoryLinux），在 macOS 上 /proc 不存在，仅能命中错误返回分支——这些场景单独
// 标注，不依赖任何真实子进程或网络。

// --- 纯解析函数 -----------------------------------------------------------

func TestParseRemoteCPU_各类输出(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		wantUsage   float64
		wantIowait  float64
		wantLoad    float64
	}{
		{
			name:        "标准top输出含空闲与iowait",
			raw:         "%Cpu(s):  5.0 us,  2.0 sy,  0.0 ni, 90.0 id,  3.0 wa,  0.0 hi,  0.0 si\n0.50 0.42 1.20 2/300 1234",
			wantUsage:   10.0,
			wantIowait:  3.0,
			wantLoad:    0.5,
		},
		{
			name:        "空闲为100时使用率为0",
			raw:         "%Cpu(s):  0.0 us,  0.0 sy,  0.0 ni,100.0 id,  0.0 wa\n1.00 0.80 0.50",
			wantUsage:   0.0,
			wantIowait:  0.0,
			wantLoad:    1.0,
		},
		{
			name:        "空输出全部归零",
			raw:         "",
			wantUsage:   0.0,
			wantIowait:  0.0,
			wantLoad:    0.0,
		},
		{
			name:        "负值load被丢弃",
			raw:         "no cpu line here\n-1.0 bad load",
			wantUsage:   0.0,
			wantIowait:  0.0,
			wantLoad:    0.0,
		},
		{
			name:        "cpu行带id触发usage计算并取首字段load",
			raw:         "%Cpu(s):  10.0 us, 90.0 id,  0.0 wa\n2.50 loadavg",
			wantUsage:   10.0, // 100 - 90 idle
			wantIowait:  0.0,
			wantLoad:    2.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			usage, iowait, load := parseRemoteCPU(tt.raw)
			if usage != tt.wantUsage {
				t.Errorf("usage = %v, want %v", usage, tt.wantUsage)
			}
			if iowait != tt.wantIowait {
				t.Errorf("iowait = %v, want %v", iowait, tt.wantIowait)
			}
			if load != tt.wantLoad {
				t.Errorf("load = %v, want %v", load, tt.wantLoad)
			}
		})
	}
}

func TestParsePercentField_边界(t *testing.T) {
	tests := []struct {
		name string
		line string
		key  string
		want float64
	}{
		{name: "命中id", line: "5.0 us, 2.0 sy, 90.0 id", key: " id", want: 90.0},
		{name: "命中wa", line: "5.0 us, 2.0 sy, 3.0 wa", key: " wa", want: 3.0},
		{name: "带百分号", line: "12.5% wa", key: " wa", want: 12.5},
		{name: "key不存在", line: "5.0 us", key: " id", want: -1},
		{name: "非数字", line: "abc wa", key: " wa", want: -1},
		{name: "逗号后取末段", line: "x, y, 7.0 wa", key: " wa", want: 7.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parsePercentField(tt.line, tt.key)
			if got != tt.want {
				t.Errorf("parsePercentField = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseRemoteMemory_free与meminfo格式(t *testing.T) {
	tests := []struct {
		name           string
		raw            string
		wantTotal      float64
		wantUsed       float64
		wantAvailable  float64
		wantSwapPct    float64
	}{
		{
			// free -b 风格：Mem: total used shared buff/cache available
			name:          "free字节输出带available列",
			raw:           "              total        used        free      shared  buff/cache   available\nMem:     17179869184  8589934592  2147483648   100000000   6442450944   6442450944",
			wantTotal:     17179869184,
			wantUsed:      8589934592,
			wantAvailable: 6442450944,
			wantSwapPct:   0.0,
		},
		{
			name:          "free输出无available列退化为0",
			raw:           "Mem: 1000 400 600",
			wantTotal:     1000,
			wantUsed:      400,
			wantAvailable: 0,
			wantSwapPct:   0.0,
		},
		{
			name:   "meminfo格式含swap",
			raw:    "MemTotal:       16384 kB\nMemFree:          4096 kB\nMemAvailable:    8192 kB\nBuffers:          512 kB\nCached:          1024 kB\nSwapTotal:       2048 kB\nSwapFree:        1024 kB",
			// MemTotal 16384*1024 = 16777216; MemAvailable 8192*1024=8388608; used=8388608
			// swap (2048-1024)/2048*100 = 50
			wantTotal:     16777216,
			wantUsed:      8388608,
			wantAvailable: 8388608,
			wantSwapPct:   50.0,
		},
		{
			name:          "meminfo无MemAvailable时回退到MemFree",
			raw:           "MemTotal:       1024 kB\nMemFree:         256 kB\nSwapTotal:          0 kB\nSwapFree:           0 kB",
			wantTotal:     1048576,
			wantUsed:      786432, // 1048576 - 262144
			wantAvailable: 262144,
			wantSwapPct:   0.0,
		},
		{
			name:          "空输出归零",
			raw:           "",
			wantTotal:     0,
			wantUsed:      0,
			wantAvailable: 0,
			wantSwapPct:   0,
		},
		{
			name:          "字段不足三列被跳过",
			raw:           "garbage line\nMem: short",
			wantTotal:     0,
			wantUsed:      0,
			wantAvailable: 0,
			wantSwapPct:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			total, used, avail, swap := parseRemoteMemory(tt.raw)
			if total != tt.wantTotal {
				t.Errorf("total = %v, want %v", total, tt.wantTotal)
			}
			if used != tt.wantUsed {
				t.Errorf("used = %v, want %v", used, tt.wantUsed)
			}
			if avail != tt.wantAvailable {
				t.Errorf("available = %v, want %v", avail, tt.wantAvailable)
			}
			if swap != tt.wantSwapPct {
				t.Errorf("swapPct = %v, want %v", swap, tt.wantSwapPct)
			}
		})
	}
}

func TestParseMeminfoValue(t *testing.T) {
	tests := []struct {
		name   string
		fields []string
		want   float64
	}{
		{name: "kB单位换算字节", fields: []string{"MemTotal:", "16384", "kB"}, want: 16777216},
		{name: "无单位原值返回", fields: []string{"Mem:", "999"}, want: 999},
		{name: "大写KB换算", fields: []string{"X:", "1", "KB"}, want: 1024},
		{name: "非数字返回0", fields: []string{"X:", "abc"}, want: 0},
		{name: "字段不足返回0", fields: []string{"X:"}, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseMeminfoValue(tt.fields); got != tt.want {
				t.Errorf("parseMeminfoValue = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseRemoteDiskDF(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantTotal float64
		wantUsed  float64
		wantPct   float64
	}{
		{
			name: "标准df输出",
			raw:  "Filesystem     1K-blocks      Used Available Use% Mounted on\n/dev/sda1       524288000 340000000 184288000  65% /",
			// total=524288000*1024, used=340000000*1024
			wantTotal: 524288000 * 1024,
			wantUsed:  340000000 * 1024,
			wantPct:   65.0,
		},
		{name: "只有表头返回零", raw: "Filesystem 1K-blocks Used", wantTotal: 0, wantUsed: 0, wantPct: 0},
		{name: "字段不足返回零", raw: "header\n/dev/x 1 2", wantTotal: 0, wantUsed: 0, wantPct: 0},
		{name: "非数字返回零", raw: "header\n/dev/x a b c d e%", wantTotal: 0, wantUsed: 0, wantPct: 0},
		{name: "空字符串返回零", raw: "", wantTotal: 0, wantUsed: 0, wantPct: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			total, used, pct := parseRemoteDiskDF(tt.raw)
			if total != tt.wantTotal || used != tt.wantUsed || pct != tt.wantPct {
				t.Errorf("parseRemoteDiskDF = (%v,%v,%v), want (%v,%v,%v)",
					total, used, pct, tt.wantTotal, tt.wantUsed, tt.wantPct)
			}
		})
	}
}

func TestParseRemoteNetwork(t *testing.T) {
	// 构造 /proc/net/dev 格式：Inter-| Receive | Transmit；每行 iface: rxBytes rxPkt ... txBytes txPkt
	const devOut = "Inter-|   Receive                                                |  Transmit\n" +
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
		"  eth0: 1048576 1000    0    0    0     0          0         0 2097152 2000    0    0    0     0       0          0\n" +
		"  lo:   1024 10 0 0 0 0 0 0 1024 10 0 0 0 0 0 0\n" +
		"  eth1: 1024 4 0 0 0 0 0 0 512 2 0 0 0 0 0 0\n" +
		"  shortline:\n"
	// eth0: in=1048576/1024=1024KB out=2097152/1024=2048KB pktIn=1000 pktOut=2000
	// lo 被跳过
	// eth1 累加：in+=1024/1024=1KB out+=512/1024=0.5KB pktIn+=4 pktOut+=2
	inKB, outKB, pktIn, pktOut := parseRemoteNetwork(devOut)
	if inKB != 1025 {
		t.Errorf("inKBs = %v, want 1025", inKB)
	}
	if outKB != 2048.5 {
		t.Errorf("outKBs = %v, want 2048.5", outKB)
	}
	if pktIn != 1004 {
		t.Errorf("pktIn = %v, want 1004", pktIn)
	}
	if pktOut != 2002 {
		t.Errorf("pktOut = %v, want 2002", pktOut)
	}

	// 边界：空 / 表头行 / 字段不足
	if a, b, c, d := parseRemoteNetwork(""); a != 0 || b != 0 || c != 0 || d != 0 {
		t.Errorf("空输入应全零, got (%v,%v,%v,%v)", a, b, c, d)
	}
	if a, b, c, d := parseRemoteNetwork("Inter-| xxx\nface | yyy\nbadline-no-colon"); a != 0 || b != 0 || c != 0 || d != 0 {
		t.Errorf("无有效接口应全零, got (%v,%v,%v,%v)", a, b, c, d)
	}
}

func TestParseRemoteProcessStats(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantTotal  float64
		wantRun    float64
		wantTopCPU float64
		wantTopMem float64
	}{
		{
			name:       "混合进程状态",
			raw:         "R 50.0 5.0\nS 1.0 2.0\nR 80.0 60.0\nD 0.5 0.1",
			wantTotal:  4,
			wantRun:    2,
			wantTopCPU: 80.0,
			wantTopMem: 60.0,
		},
		{
			name:       "空输入归零",
			raw:         "",
			wantTotal:  0,
			wantRun:    0,
			wantTopCPU: 0,
			wantTopMem: 0,
		},
		{
			name:       "两字段行被跳过",
			raw:         "R 1.0\nS a", // "S a" 仅2字段，跳过
			wantTotal:  0,
			wantTopCPU: 0,
		},
		{
			name:       "非数字CPU/mem被忽略但仍计数",
			raw:         "R x y\nZ 0 0", // "R x y" 3字段→total++ running++；cpu/mem解析失败
			wantTotal:  2,
			wantRun:    1,
			wantTopCPU: 0,
			wantTopMem: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			total, run, cpu, mem := parseRemoteProcessStats(tt.raw)
			if total != tt.wantTotal {
				t.Errorf("total = %v, want %v", total, tt.wantTotal)
			}
			if run != tt.wantRun {
				t.Errorf("running = %v, want %v", run, tt.wantRun)
			}
			if cpu != tt.wantTopCPU {
				t.Errorf("topCPU = %v, want %v", cpu, tt.wantTopCPU)
			}
			if mem != tt.wantTopMem {
				t.Errorf("topMem = %v, want %v", mem, tt.wantTopMem)
			}
		})
	}
}

// --- 远程采集路径 getRemoteMetrics / runRemoteCommand -----------------------

func newRemoteTool(stdout string, err error) *ResourceMonitorTool {
	t := NewResourceMonitorTool(nil)
	t.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		if err != nil {
			return nil, []byte("stderr-blob"), err
		}
		return []byte(stdout), nil, nil
	}
	return t
}

func remoteParams() *ResourceMonitorParams {
	return &ResourceMonitorParams{
		Target:      "10.0.0.9",
		RemoteHost:  "10.0.0.9",
		RemoteUser:  "ops",
		RemotePort:    22,
		RemoteKeyPath: "/tmp/id_ed25519",
		Metrics:       []string{"cpu"},
	}
}

func TestGetRemoteMetrics_CPU(t *testing.T) {
	out := "%Cpu(s):  5.0 us,  2.0 sy, 90.0 id, 3.0 wa\n0.50 loadavg\n"
	tool := newRemoteTool(out, nil)
	m := tool.getRemoteMetrics("cpu", remoteParams())
	if len(m) != 3 {
		t.Fatalf("期望3个cpu指标, got %d (%+v)", len(m), m)
	}
	if m[0].Name != "cpu_usage_percent" || m[0].Value != 10.0 {
		t.Errorf("cpu_usage_percent = %+v, want 10.0", m[0])
	}
	if m[1].Name != "load_avg_1m" || m[1].Value != 0.5 {
		t.Errorf("load_avg_1m = %+v, want 0.5", m[1])
	}
	if m[2].Name != "cpu_iowait_percent" || m[2].Value != 3.0 {
		t.Errorf("cpu_iowait_percent = %+v, want 3.0", m[2])
	}
}

func TestGetRemoteMetrics_CPU错误降级零值(t *testing.T) {
	tool := newRemoteTool("", errors.New("ssh dial failed"))
	m := tool.getRemoteMetrics("cpu", remoteParams())
	if len(m) != 3 {
		t.Fatalf("错误路径仍应返回3个零值指标, got %d", len(m))
	}
	for _, met := range m {
		if met.Value != 0 {
			t.Errorf("期望错误降级为0, got %+v", met)
		}
	}
}

func TestGetRemoteMetrics_Memory解析(t *testing.T) {
	out := "Mem: 17179869184 8589934592 0 0 6442450944 6442450944\n"
	tool := newRemoteTool(out, nil)
	m := tool.getRemoteMetrics("memory", remoteParams())
	if len(m) != 5 {
		t.Fatalf("期望5个memory指标, got %d (%+v)", len(m), m)
	}
	// usagePct = used/total*100 = 8589934592/17179869184*100 = 50
	findByName := func(name string) *ResourceMetric {
		for i := range m {
			if m[i].Name == name {
				return &m[i]
			}
		}
		return nil
	}
	if mem := findByName("memory_usage_percent"); mem == nil || mem.Value != 50.0 {
		t.Errorf("memory_usage_percent = %+v, want 50", mem)
	}
	if mem := findByName("memory_total_gb"); mem == nil || mem.Value != 16.0 {
		t.Errorf("memory_total_gb = %+v, want 16", mem)
	}
}

func TestGetRemoteMetrics_Memory错误返回nil(t *testing.T) {
	tool := newRemoteTool("", errors.New("boom"))
	if m := tool.getRemoteMetrics("memory", remoteParams()); m != nil {
		t.Errorf("memory错误路径应返回nil, got %+v", m)
	}
}

func TestGetRemoteMetrics_Disk解析(t *testing.T) {
	out := "Filesystem 1K-blocks Used Avail Use% Mounted\n/dev/sda1 524288000 340000000 184288000 65% /\n"
	tool := newRemoteTool(out, nil)
	m := tool.getRemoteMetrics("disk", remoteParams())
	if len(m) != 6 {
		t.Fatalf("期望6个disk指标, got %d (%+v)", len(m), m)
	}
	// usagePct = 65
	var pct *ResourceMetric
	for i := range m {
		if m[i].Name == "disk_usage_percent" {
			pct = &m[i]
		}
	}
	if pct == nil || pct.Value < 64.8 || pct.Value > 64.9 {
		t.Errorf("disk_usage_percent = %+v, want ~64.85", pct)
	}
}

func TestGetRemoteMetrics_Disk错误返回nil(t *testing.T) {
	tool := newRemoteTool("", errors.New("boom"))
	if m := tool.getRemoteMetrics("disk", remoteParams()); m != nil {
		t.Errorf("disk错误路径应返回nil, got %+v", m)
	}
}

func TestGetRemoteMetrics_Network解析(t *testing.T) {
	out := "Inter-| recv | trans\n face | b p | b p\n eth0: 1048576 1000 0 0 0 0 0 0 2097152 2000 0 0 0 0 0 0\n"
	tool := newRemoteTool(out, nil)
	m := tool.getRemoteMetrics("network", remoteParams())
	if len(m) != 8 {
		t.Fatalf("期望8个network指标, got %d (%+v)", len(m), m)
	}
	// inKBs=1024, outKBs=2048, pktIn=1000, pktOut=2000
	if m[0].Name != "network_bytes_in_sec" || m[0].Value != 1024 {
		t.Errorf("network_bytes_in_sec = %+v, want 1024", m[0])
	}
	if m[1].Name != "network_bytes_out_sec" || m[1].Value != 2048 {
		t.Errorf("network_bytes_out_sec = %+v, want 2048", m[1])
	}
}

func TestGetRemoteMetrics_Process解析(t *testing.T) {
	out := "R 50.0 5.0\nS 1.0 2.0\nR 80.0 60.0\n"
	tool := newRemoteTool(out, nil)
	m := tool.getRemoteMetrics("process", remoteParams())
	if len(m) != 8 {
		t.Fatalf("期望8个process指标, got %d (%+v)", len(m), m)
	}
	// total=3 running=2 sleeping=max(3-2,0)=1 topCPU=80 topMem=60
	findByName := func(n string) float64 {
		for i := range m {
			if m[i].Name == n {
				return m[i].Value
			}
		}
		return -1
	}
	if v := findByName("total_processes"); v != 3 {
		t.Errorf("total_processes = %v, want 3", v)
	}
	if v := findByName("running_processes"); v != 2 {
		t.Errorf("running_processes = %v, want 2", v)
	}
	if v := findByName("sleeping_processes"); v != 1 {
		t.Errorf("sleeping_processes = %v, want 1", v)
	}
	if v := findByName("top_cpu_process"); v != 80 {
		t.Errorf("top_cpu_process = %v, want 80", v)
	}
}

func TestGetRemoteMetrics_未知metric返回nil(t *testing.T) {
	tool := newRemoteTool("anything", nil)
	if m := tool.getRemoteMetrics("unknown-metric", remoteParams()); m != nil {
		t.Errorf("未知metric应返回nil, got %+v", m)
	}
}

func TestRunRemoteCommand_成功路径(t *testing.T) {
	tool := NewResourceMonitorTool(nil)
	var gotName string
	var gotArgs []string
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return []byte("remote-output"), nil, nil
	}
	out, err := tool.runRemoteCommand(remoteParams(), "uptime")
	if err != nil {
		t.Fatalf("期望无错误, got %v", err)
	}
	if string(out) != "remote-output" {
		t.Errorf("stdout = %q, want remote-output", string(out))
	}
	if gotName != "ssh" {
		t.Errorf("命令名为 %q, want ssh", gotName)
	}
	if !strings.Contains(strings.Join(gotArgs, " "), "ops@10.0.0.9") {
		t.Errorf("ssh参数缺少目标: %q", strings.Join(gotArgs, " "))
	}
}

func TestRunRemoteCommand_错误且有stdout仍返回stdout(t *testing.T) {
	tool := NewResourceMonitorTool(nil)
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		// cmdErr != nil 但 stdout 非空：函数保留 stdout 返回
		return []byte("partial"), []byte("ignored"), errors.New("exit code 1")
	}
	out, err := tool.runRemoteCommand(remoteParams(), "top")
	if err != nil {
		t.Fatalf("stdout非空时不应返回错误, got %v", err)
	}
	if string(out) != "partial" {
		t.Errorf("stdout = %q, want partial", string(out))
	}
}

func TestRunRemoteCommand_错误且空stdout返回error(t *testing.T) {
	tool := NewResourceMonitorTool(nil)
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		return nil, []byte("permission denied"), errors.New("exit 255")
	}
	out, err := tool.runRemoteCommand(remoteParams(), "uptime")
	if err == nil {
		t.Fatal("期望错误, got nil")
	}
	if out != nil {
		t.Errorf("期望 nil stdout, got %q", string(out))
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("错误信息应包含stderr, got %v", err)
	}

	// stderr 为空时回退到 cmdErr 文本
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		return nil, nil, errors.New("dial tcp: timeout")
	}
	if _, err := tool.runRemoteCommand(remoteParams(), "uptime"); err == nil ||
		!strings.Contains(err.Error(), "dial tcp: timeout") {
		t.Errorf("空stderr应回退到cmdErr, got %v", err)
	}
}

// --- buildResourceSSHArgs 边界 ---------------------------------------------

func TestBuildResourceSSHArgs(t *testing.T) {
	t.Run("nil参数报错", func(t *testing.T) {
		_, err := buildResourceSSHArgs(nil, "uptime")
		if err == nil {
			t.Error("期望 nil 参数报错")
		}
	})
	t.Run("空host报错", func(t *testing.T) {
		_, err := buildResourceSSHArgs(&ResourceMonitorParams{}, "uptime")
		if err == nil {
			t.Error("期望空 host 报错")
		}
	})
	t.Run("全选项拼装", func(t *testing.T) {
		args, err := buildResourceSSHArgs(&ResourceMonitorParams{
			RemoteHost:      "10.0.0.9",
			RemoteUser:      "ops",
			RemotePort:      2222,
			RemoteKeyPath:   "/tmp/key",
			RemoteProxyJump: "bastion",
		}, "uptime")
		if err != nil {
			t.Fatalf("意外错误: %v", err)
		}
		joined := strings.Join(args, " ")
		for _, want := range []string{"ops@10.0.0.9", "-p 2222", "-i /tmp/key", "-J bastion", "uptime"} {
			if !strings.Contains(joined, want) {
				t.Errorf("缺少 %q in %q", want, joined)
			}
		}
	})
	t.Run("无user时不拼@", func(t *testing.T) {
		args, err := buildResourceSSHArgs(&ResourceMonitorParams{RemoteHost: "10.0.0.9"}, "uptime")
		if err != nil {
			t.Fatalf("意外错误: %v", err)
		}
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "@") {
			t.Errorf("无user不应包含@, got %q", joined)
		}
		if !strings.Contains(joined, "10.0.0.9") {
			t.Errorf("应包含host, got %q", joined)
		}
	})
}

// --- runResourceCommand 真实命令 -------------------------------------------
// 该函数在远程模式下被覆盖，未覆盖时为0%。这里用安全内建命令 echo / /bin/false
// 分别驱动成功与失败（ExitError）分支，无任何网络或危险子进程。

func TestRunResourceCommand_成功(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, stderr, err := runResourceCommand(ctx, "echo", "hello-secops")
	if err != nil {
		t.Fatalf("echo 不应报错: %v", err)
	}
	if strings.TrimSpace(string(out)) != "hello-secops" {
		t.Errorf("stdout = %q, want hello-secops", string(out))
	}
	if stderr != nil {
		t.Errorf("成功路径 stderr 应为 nil, got %q", string(stderr))
	}
}

func TestRunResourceCommand_失败ExitError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// false 必然非0退出，触发 ExitError 分支
	_, _, err := runResourceCommand(ctx, "false")
	if err == nil {
		t.Fatal("期望 false 产生错误")
	}
}

func TestRunResourceCommand_命令不存在(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := runResourceCommand(ctx, "/this/binary/does/not/exist")
	if err == nil {
		t.Fatal("期望不存在的命令产生错误")
	}
}

// --- 硬编码 /proc 的本地采集函数（macOS上仅错误返回分支） -------------------
// 这些函数在 macOS 上因 /proc 不存在，只能命中错误早返回分支。直接调用以
// 至少覆盖这些路径并确保不 panic；不依赖于真实子进程或网络。

func TestSampleMemoryLinux_非Linux返回零(t *testing.T) {
	// /proc/meminfo 在 macOS 上不存在，ReadFile 失败 → 返回 (0,0,0,0)
	total, used, avail, swap := sampleMemoryLinux()
	if total != 0 || used != 0 || avail != 0 || swap != 0 {
		t.Errorf("sampleMemoryLinux 在无 /proc 环境应全零, got (%v,%v,%v,%v)",
			total, used, avail, swap)
	}
}

func TestReadCPUStat_非Linux返回false(t *testing.T) {
	// /proc/stat 在 macOS 上不存在
	if _, ok := readCPUStat(); ok {
		t.Error("readCPUStat 在无 /proc 环境应返回 ok=false")
	}
}

func TestSampleNetwork_非Linux返回零(t *testing.T) {
	// runtime.GOOS != linux → 直接返回 (0,0,0,0)，不读 /proc
	in, out, pin, pout := sampleNetwork()
	if in != 0 || out != 0 || pin != 0 || pout != 0 {
		t.Errorf("sampleNetwork 在非 Linux 应全零, got (%v,%v,%v,%v)",
			in, out, pin, pout)
	}
}

func TestSampleCPUUsage_无CPUStat环境返回零(t *testing.T) {
	// readCPUStat 失败 → 直接 (0,0)，不睡眠。interval 极小避免拖慢。
	usage, iowait := sampleCPUUsage(time.Millisecond)
	if usage != 0 || iowait != 0 {
		t.Errorf("无CPU stat 环境 sampleCPUUsage 应为 (0,0), got (%v,%v)", usage, iowait)
	}
}

// --- Execute / ValidateParams 远程分支补充覆盖 -----------------------------

func TestResourceMonitor_Execute远程采集汇总(t *testing.T) {
	tool := NewResourceMonitorTool(nil)
	cpuOut := "%Cpu(s): 99.0 us, 0.0 id, 0.0 wa\n0.5 load\n" // usage=100 (clamp)
	memOut := "Mem: 17179869184 16000000000 0 0 1000000000 1000000000\n" // ~93%
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		// 根据 ssh args 末尾的远程命令路由返回不同 stdout
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "top -bn1"):
			return []byte(cpuOut), nil, nil
		case strings.Contains(joined, "free -b") || strings.Contains(joined, "/proc/meminfo"):
			return []byte(memOut), nil, nil
		default:
			return []byte(""), nil, nil
		}
	}
	res, err := tool.Execute(&ResourceMonitorParams{
		Target:     "remotehost",
		Metrics:    []string{"cpu", "memory"},
		RemoteHost: "10.0.0.9",
		RemoteUser: "ops",
	})
	if err != nil {
		t.Fatalf("Execute 意外错误: %v", err)
	}
	rm, ok := res.(*ResourceMonitorResult)
	if !ok {
		t.Fatalf("期望 *ResourceMonitorResult, got %T", res)
	}
	if len(rm.Metrics) != 3+5 {
		t.Fatalf("期望8个指标(3cpu+5mem), got %d", len(rm.Metrics))
	}
	// cpu usage 100 → 触发 cpu_spike 异常
	if !rm.Anomaly || rm.AnomalyType != "cpu_spike" {
		t.Errorf("期望 cpu_spike 异常, got anomaly=%v type=%q summary=%q",
			rm.Anomaly, rm.AnomalyType, rm.Summary)
	}
}

func TestResourceMonitor_ValidateParams_无效metric与interval(t *testing.T) {
	tool := NewResourceMonitorTool(nil)
	if err := tool.ValidateParams(&ResourceMonitorParams{Metrics: []string{"bogus"}}); err == nil {
		t.Error("无效 metric 应报错")
	}
	if err := tool.ValidateParams(&ResourceMonitorParams{Interval: "99s"}); err == nil {
		t.Error("无效 interval 应报错")
	}
	if err := tool.ValidateParams(&ResourceMonitorParams{Duration: "2m"}); err == nil {
		t.Error("无效 duration 应报错")
	}
}
