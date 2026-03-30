package attack

import (
	"fmt"
	"strings"
)

type evidenceMapping struct {
	TechniqueID string
	Score       float64
	Reason      string
}

func mapEvidenceEvent(event EvidenceEvent) []evidenceMapping {
	text := strings.ToLower(strings.Join([]string{
		event.Source,
		event.EventType,
		event.Actor,
		event.Target,
		event.Action,
		event.Severity,
		event.Raw,
		flattenFields(event.Fields),
	}, " "))

	matches := make([]evidenceMapping, 0, 4)
	appendMatch := func(id string, score float64, reason string) {
		matches = append(matches, evidenceMapping{
			TechniqueID: id,
			Score:       score,
			Reason:      reason,
		})
	}

	switch {
	case containsAny(text, "failed login burst", "brute force", "password spray", "many failed logins", "50 failed attempts"):
		appendMatch("T1110", 0.55, "Evidence suggests repeated authentication attempts consistent with brute force behavior.")
	}

	switch {
	case containsAny(text, "successful login after failures", "valid account", "impossible travel", "unexpected login", "suspicious login"):
		appendMatch("T1078", 0.65, "Evidence indicates suspicious use of legitimate credentials or accounts.")
	}

	switch {
	case containsAny(text, "secret exposure", "credential exposure", "api key", "token leaked", "unsecured credentials", "private key"):
		appendMatch("T1552", 0.7, "Evidence shows credentials may be exposed in files, logs, or repositories.")
	}

	switch {
	case containsAny(text, "remote execution", "ssh", "lateral movement", "remote service", "wmi", "psexec"):
		appendMatch("T1021", 0.6, "Evidence points to remote service usage associated with lateral movement.")
	}

	switch {
	case containsAny(text, "log cleared", "history deleted", "audit tamper", "indicator removal", "rm /var/log", "truncate log"):
		appendMatch("T1070", 0.75, "Evidence suggests attempts to remove or tamper with host indicators.")
	}

	switch {
	case containsAny(text, "enumerate users", "account discovery", "list users", "iam review", "sudoers review", "whoami", "getent passwd"):
		appendMatch("T1087", 0.45, "Evidence suggests account or identity discovery activity.")
	}

	if len(matches) == 0 && event.EventType != "" {
		matches = append(matches, evidenceMapping{
			TechniqueID: "T1078",
			Score:       0.15,
			Reason:      fmt.Sprintf("Event type %q has weak overlap with account misuse patterns; included as low-confidence candidate.", event.EventType),
		})
	}

	return matches
}

func containsAny(text string, patterns ...string) bool {
	for _, pattern := range patterns {
		if strings.Contains(text, pattern) {
			return true
		}
	}
	return false
}

func flattenFields(fields map[string]string) string {
	if len(fields) == 0 {
		return ""
	}
	parts := make([]string, 0, len(fields)*2)
	for k, v := range fields {
		parts = append(parts, k, v)
	}
	return strings.Join(parts, " ")
}
