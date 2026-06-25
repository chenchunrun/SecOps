package attack

import (
	"testing"
)

func TestMapEvidenceEvent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		event         EvidenceEvent
		wantTechnique string // 期望至少命中该技术 ID；空表示无命中
		wantMinScore  float64
	}{
		{
			name:          "暴力破解 T1110",
			event:         EvidenceEvent{Source: "auth", Action: "brute force detected"},
			wantTechnique: "T1110",
			wantMinScore:  0.5,
		},
		{
			name:          "有效账号 T1078",
			event:         EvidenceEvent{Source: "iam", Action: "valid account used"},
			wantTechnique: "T1078",
			wantMinScore:  0.6,
		},
		{
			name:          "凭证暴露 T1552",
			event:         EvidenceEvent{Source: "git", Raw: "api key committed to repo"},
			wantTechnique: "T1552",
			wantMinScore:  0.65,
		},
		{
			name:          "远程服务 T1021",
			event:         EvidenceEvent{Source: "sshd", Action: "remote execution via ssh"},
			wantTechnique: "T1021",
			wantMinScore:  0.55,
		},
		{
			name:          "指标移除 T1070",
			event:         EvidenceEvent{Source: "auditd", Action: "log cleared"},
			wantTechnique: "T1070",
			wantMinScore:  0.7,
		},
		{
			name:          "账号发现 T1087",
			event:         EvidenceEvent{Source: "shell", Action: "enumerate users"},
			wantTechnique: "T1087",
			wantMinScore:  0.4,
		},
		{
			name:          "字段内容参与匹配",
			event:         EvidenceEvent{EventType: "scan", Fields: map[string]string{"finding": "private key in config"}},
			wantTechnique: "T1552",
			wantMinScore:  0.65,
		},
		{
			name:  "无匹配但有 EventType 触发低置信兜底 T1078",
			event: EvidenceEvent{EventType: "anomaly", Source: "edr"},
			wantTechnique: "T1078",
			wantMinScore:  0.1, // 兜底分数 0.15
		},
		{
			name:          "无匹配且无 EventType 返回空",
			event:         EvidenceEvent{Source: "noise"}, // 仅 Source，无 EventType、无触发词
			wantTechnique: "",
		},
		{
			name:  "大小写不敏感匹配",
			event: EvidenceEvent{Action: "BRUTE FORCE attempt"},
			wantTechnique: "T1110",
			wantMinScore:  0.5,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mappings := mapEvidenceEvent(tc.event)
			if tc.wantTechnique == "" {
				if len(mappings) != 0 {
					t.Fatalf("expected no mappings, got %d: %+v", len(mappings), mappings)
				}
				return
			}

			found := false
			for _, m := range mappings {
				if m.TechniqueID == tc.wantTechnique {
					found = true
					if m.Score < tc.wantMinScore {
						t.Errorf("score for %s = %.2f, want >= %.2f", tc.wantTechnique, m.Score, tc.wantMinScore)
					}
					if m.Reason == "" {
						t.Errorf("expected non-empty reason for %s", tc.wantTechnique)
					}
				}
			}
			if !found {
				t.Errorf("expected technique %s in mappings, got %+v", tc.wantTechnique, mappings)
			}
		})
	}
}

func TestMapEvidenceEvent_MultipleMatches(t *testing.T) {
	t.Parallel()

	// 单条证据文本同时命中多个技术分类。
	event := EvidenceEvent{
		EventType: "incident",
		Action:    "brute force then used api key over ssh",
	}
	mappings := mapEvidenceEvent(event)

	seen := make(map[string]bool)
	for _, m := range mappings {
		seen[m.TechniqueID] = true
	}
	for _, id := range []string{"T1110", "T1552", "T1021"} {
		if !seen[id] {
			t.Errorf("expected multi-match to include %s, got %+v", id, mappings)
		}
	}
}

func TestContainsAny(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		text     string
		patterns []string
		want     bool
	}{
		{name: "命中第一个", text: "brute force", patterns: []string{"brute force", "x"}, want: true},
		{name: "命中后续", text: "abc", patterns: []string{"z", "b"}, want: true},
		{name: "全部未命中", text: "abc", patterns: []string{"z", "y"}, want: false},
		{name: "空模式", text: "abc", patterns: nil, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := containsAny(tc.text, tc.patterns...); got != tc.want {
				t.Errorf("containsAny(%q, %v) = %v, want %v", tc.text, tc.patterns, got, tc.want)
			}
		})
	}
}

func TestFlattenFields(t *testing.T) {
	t.Parallel()

	t.Run("空 map", func(t *testing.T) {
		t.Parallel()
		if got := flattenFields(nil); got != "" {
			t.Errorf("expected empty string for nil fields, got %q", got)
		}
	})

	t.Run("有内容", func(t *testing.T) {
		t.Parallel()
		got := flattenFields(map[string]string{"k1": "v1", "k2": "v2"})
		if got == "" {
			t.Fatal("expected non-empty flattened string")
		}
		for _, fragment := range []string{"k1", "v1", "k2", "v2"} {
			if !containsAny(got, fragment) {
				t.Errorf("expected flattened output to contain %q, got %q", fragment, got)
			}
		}
	})
}
