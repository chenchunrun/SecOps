package attack

import "strings"

// KnowledgeBase stores a reduced ATT&CK corpus for local reasoning.
type KnowledgeBase struct {
	techniques map[string]Technique
}

// NewKnowledgeBase returns the built-in reduced ATT&CK knowledge base.
func NewKnowledgeBase() *KnowledgeBase {
	entries := []Technique{
		{
			ID:          "T1110",
			Name:        "Brute Force",
			TacticIDs:   []string{"Credential Access"},
			Platforms:   []string{"Linux", "Windows", "Cloud"},
			DataSources: []string{"Authentication Logs", "Network Traffic"},
			Detections:  []string{"Failed login burst", "Repeated auth attempts"},
			Mitigations: []string{"MFA", "Lockout policy", "Rate limiting"},
		},
		{
			ID:          "T1078",
			Name:        "Valid Accounts",
			TacticIDs:   []string{"Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"},
			Platforms:   []string{"Linux", "Windows", "Cloud"},
			DataSources: []string{"Authentication Logs", "IAM Audit Logs"},
			Detections:  []string{"Successful auth after failures", "Impossible travel", "Unexpected principal use"},
			Mitigations: []string{"MFA", "Credential rotation", "Conditional access"},
		},
		{
			ID:          "T1552",
			Name:        "Unsecured Credentials",
			TacticIDs:   []string{"Credential Access"},
			Platforms:   []string{"Linux", "Windows", "Cloud"},
			DataSources: []string{"File Access", "Secret Scans", "Repository Events"},
			Detections:  []string{"Secrets in files", "Credential exposure in logs"},
			Mitigations: []string{"Secret scanning", "Vault storage", "Credential hygiene"},
		},
		{
			ID:          "T1021",
			Name:        "Remote Services",
			TacticIDs:   []string{"Lateral Movement"},
			Platforms:   []string{"Linux", "Windows"},
			DataSources: []string{"SSH Logs", "Remote Session Events", "Process Launch"},
			Detections:  []string{"Unexpected remote execution", "Lateral service access"},
			Mitigations: []string{"Network segmentation", "JIT access", "Session monitoring"},
		},
		{
			ID:          "T1070",
			Name:        "Indicator Removal on Host",
			TacticIDs:   []string{"Defense Evasion"},
			Platforms:   []string{"Linux", "Windows"},
			DataSources: []string{"Audit Logs", "File Modification", "Shell History"},
			Detections:  []string{"Log clearing", "History tampering", "Audit deletion"},
			Mitigations: []string{"Immutable logging", "Centralized audit forwarding"},
		},
		{
			ID:          "T1087",
			Name:        "Account Discovery",
			TacticIDs:   []string{"Discovery"},
			Platforms:   []string{"Linux", "Windows", "Cloud"},
			DataSources: []string{"IAM Audit Logs", "Command Execution", "Directory Queries"},
			Detections:  []string{"User enumeration", "Privilege review anomalies"},
			Mitigations: []string{"Least privilege", "Directory query monitoring"},
		},
	}

	kb := &KnowledgeBase{techniques: make(map[string]Technique, len(entries))}
	for _, entry := range entries {
		kb.techniques[entry.ID] = entry
	}
	return kb
}

// Get returns a technique by ID.
func (kb *KnowledgeBase) Get(id string) (Technique, bool) {
	if kb == nil {
		return Technique{}, false
	}
	technique, ok := kb.techniques[id]
	return technique, ok
}

// TacticsFor returns the unique tactics covered by the given technique IDs.
func (kb *KnowledgeBase) TacticsFor(ids []string) []string {
	if kb == nil {
		return nil
	}

	seen := make(map[string]struct{})
	var tactics []string
	for _, id := range ids {
		technique, ok := kb.Get(id)
		if !ok {
			continue
		}
		for _, tactic := range technique.TacticIDs {
			key := strings.TrimSpace(tactic)
			if key == "" {
				continue
			}
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			tactics = append(tactics, key)
		}
	}
	return tactics
}
