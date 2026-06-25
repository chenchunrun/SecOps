package attack

import (
	"testing"
)

func TestNewKnowledgeBase(t *testing.T) {
	t.Parallel()

	kb := NewKnowledgeBase()
	if kb == nil {
		t.Fatal("expected non-nil knowledge base")
	}

	// 内置语料库应包含全部 6 个 ATT&CK 技术。
	for _, id := range []string{"T1110", "T1078", "T1552", "T1021", "T1070", "T1087"} {
		if _, ok := kb.Get(id); !ok {
			t.Errorf("expected technique %s to be present in knowledge base", id)
		}
	}
}

func TestKnowledgeBase_Get(t *testing.T) {
	t.Parallel()

	kb := NewKnowledgeBase()

	tests := []struct {
		name      string
		id        string
		wantFound bool
		wantName  string
	}{
		{name: "已知技术 T1110", id: "T1110", wantFound: true, wantName: "Brute Force"},
		{name: "已知技术 T1552", id: "T1552", wantFound: true, wantName: "Unsecured Credentials"},
		{name: "已知技术 T1087", id: "T1087", wantFound: true, wantName: "Account Discovery"},
		{name: "未知技术", id: "T9999", wantFound: false, wantName: ""},
		{name: "空 ID", id: "", wantFound: false, wantName: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			technique, ok := kb.Get(tc.id)
			if ok != tc.wantFound {
				t.Fatalf("Get(%q) found = %v, want %v", tc.id, ok, tc.wantFound)
			}
			if ok && technique.Name != tc.wantName {
				t.Errorf("Get(%q) name = %q, want %q", tc.id, technique.Name, tc.wantName)
			}
			if !ok && technique.ID != "" {
				t.Errorf("expected zero-value technique for missing id, got %+v", technique)
			}
		})
	}
}

func TestKnowledgeBase_Get_NilReceiver(t *testing.T) {
	t.Parallel()

	var kb *KnowledgeBase
	technique, ok := kb.Get("T1110")
	if ok {
		t.Errorf("expected Get on nil receiver to return false, got ok=true %+v", technique)
	}
}

func TestKnowledgeBase_TacticsFor(t *testing.T) {
	t.Parallel()

	kb := NewKnowledgeBase()

	tests := []struct {
		name       string
		ids        []string
		wantMinLen int
		wantSubset []string
	}{
		{
			name:       "单技术",
			ids:        []string{"T1110"},
			wantMinLen: 1,
			wantSubset: []string{"Credential Access"},
		},
		{
			name:       "多技术战术去重",
			ids:        []string{"T1078", "T1070"}, // 均含 Defense Evasion，应去重
			wantMinLen: 4,                          // T1078 有 4 个战术 + T1070 的 Defense Evasion 已去重
			wantSubset: []string{"Defense Evasion", "Persistence"},
		},
		{
			name:       "包含未知技术 ID 应被跳过",
			ids:        []string{"T1021", "T0000"},
			wantMinLen: 1,
			wantSubset: []string{"Lateral Movement"},
		},
		{
			name:       "空输入",
			ids:        nil,
			wantMinLen: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tactics := kb.TacticsFor(tc.ids)
			if len(tactics) < tc.wantMinLen {
				t.Fatalf("TacticsFor(%v) returned %d tactics, want >= %d", tc.ids, len(tactics), tc.wantMinLen)
			}

			// 验证无重复且子集存在。
			seen := make(map[string]bool)
			for _, tactic := range tactics {
				if seen[tactic] {
					t.Errorf("duplicate tactic %q in TacticsFor(%v)", tactic, tc.ids)
				}
				seen[tactic] = true
			}
			for _, want := range tc.wantSubset {
				if !seen[want] {
					t.Errorf("expected tactic %q in TacticsFor(%v), got %v", want, tc.ids, tactics)
				}
			}
		})
	}
}
