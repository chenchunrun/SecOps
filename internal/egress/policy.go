// Package egress provides deterministic outbound network policy and
// short-lived credential leases for execution runtimes.
package egress

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

var (
	ErrInvalidPolicy      = errors.New("invalid egress policy")
	ErrInvalidDestination = errors.New("invalid egress destination")
	ErrEgressDenied       = errors.New("egress denied")
)

// Protocol identifies an outbound application or transport protocol.
type Protocol string

const (
	ProtocolHTTP  Protocol = "http"
	ProtocolHTTPS Protocol = "https"
	ProtocolSSH   Protocol = "ssh"
	ProtocolTCP   Protocol = "tcp"
)

// Rule is trusted policy configuration. CredentialRefs contains identifiers,
// never credential values.
type Rule struct {
	ID             string   `json:"id"`
	Protocol       Protocol `json:"protocol"`
	Host           string   `json:"host"`
	Ports          []int    `json:"ports"`
	CredentialRefs []string `json:"credential_refs,omitempty"`
}

// Request describes the destination and credential identifiers required by an
// execution. It intentionally carries no credential values.
type Request struct {
	Protocol       Protocol `json:"protocol"`
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	CredentialRefs []string `json:"credential_refs,omitempty"`
}

// Decision is the explainable result of an egress authorization attempt.
type Decision struct {
	Allowed bool    `json:"allowed"`
	RuleID  string  `json:"rule_id,omitempty"`
	Request Request `json:"request"`
	Reason  string  `json:"reason"`
}

// Policy evaluates outbound destinations with default-deny semantics.
type Policy struct {
	rules []Rule
}

// NewPolicy validates and deterministically orders trusted rules.
func NewPolicy(rules []Rule) (*Policy, error) {
	normalized := make([]Rule, 0, len(rules))
	ids := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		rule.ID = strings.TrimSpace(rule.ID)
		rule.Host = normalizeHost(rule.Host)
		if rule.ID == "" || !validProtocol(rule.Protocol) || !validRuleHost(rule.Host) {
			return nil, fmt.Errorf("%w: rule identity, protocol, and host are required", ErrInvalidPolicy)
		}
		if _, exists := ids[rule.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate rule %q", ErrInvalidPolicy, rule.ID)
		}
		ids[rule.ID] = struct{}{}
		ports, err := normalizePorts(rule.Ports)
		if err != nil || len(ports) == 0 {
			return nil, fmt.Errorf("%w: rule %q has invalid ports", ErrInvalidPolicy, rule.ID)
		}
		credentials, err := normalizeReferences(rule.CredentialRefs)
		if err != nil {
			return nil, fmt.Errorf("%w: rule %q has invalid credential references", ErrInvalidPolicy, rule.ID)
		}
		rule.Ports = ports
		rule.CredentialRefs = credentials
		normalized = append(normalized, rule)
	}
	sort.Slice(normalized, func(i, j int) bool {
		leftWildcard := strings.HasPrefix(normalized[i].Host, "*.")
		rightWildcard := strings.HasPrefix(normalized[j].Host, "*.")
		if leftWildcard != rightWildcard {
			return !leftWildcard
		}
		return normalized[i].ID < normalized[j].ID
	})
	return &Policy{rules: normalized}, nil
}

// Authorize selects the first deterministic rule satisfying all destination
// and credential-reference constraints.
func (p *Policy) Authorize(request Request) (Decision, error) {
	normalized, err := normalizeRequest(request)
	if err != nil {
		return Decision{
			Allowed: false,
			Request: normalized,
			Reason:  "Destination is invalid.",
		}, err
	}
	for _, rule := range p.rules {
		if rule.Protocol != normalized.Protocol || !hostMatches(rule.Host, normalized.Host) ||
			!containsPort(rule.Ports, normalized.Port) ||
			!referencesAllowed(rule.CredentialRefs, normalized.CredentialRefs) {
			continue
		}
		return Decision{
			Allowed: true,
			RuleID:  rule.ID,
			Request: normalized,
			Reason:  "Destination satisfies trusted egress policy.",
		}, nil
	}
	return Decision{
		Allowed: false,
		Request: normalized,
		Reason:  "No trusted egress rule satisfies the destination and credential references.",
	}, ErrEgressDenied
}

func normalizeRequest(request Request) (Request, error) {
	request.Host = normalizeHost(request.Host)
	credentials, err := normalizeReferences(request.CredentialRefs)
	request.CredentialRefs = credentials
	if err != nil || !validProtocol(request.Protocol) || !validRequestHost(request.Host) || request.Port < 1 || request.Port > 65535 {
		return request, ErrInvalidDestination
	}
	return request, nil
}

func validProtocol(protocol Protocol) bool {
	switch protocol {
	case ProtocolHTTP, ProtocolHTTPS, ProtocolSSH, ProtocolTCP:
		return true
	default:
		return false
	}
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func validRuleHost(host string) bool {
	if strings.HasPrefix(host, "*.") {
		return validRequestHost(strings.TrimPrefix(host, "*."))
	}
	return validRequestHost(host) && !strings.Contains(host, "*")
}

func validRequestHost(host string) bool {
	if host == "" || strings.ContainsAny(host, "*/\\:@[] ") || strings.Contains(host, "..") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, character := range label {
			if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
				return false
			}
		}
	}
	return true
}

func hostMatches(pattern, host string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return pattern == host
	}
	suffix := strings.TrimPrefix(pattern, "*")
	return strings.HasSuffix(host, suffix) && host != strings.TrimPrefix(suffix, ".")
}

func normalizePorts(ports []int) ([]int, error) {
	seen := make(map[int]struct{}, len(ports))
	normalized := make([]int, 0, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, ErrInvalidPolicy
		}
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		normalized = append(normalized, port)
	}
	sort.Ints(normalized)
	return normalized, nil
}

func normalizeReferences(references []string) ([]string, error) {
	seen := make(map[string]struct{}, len(references))
	normalized := make([]string, 0, len(references))
	for _, reference := range references {
		reference = strings.TrimSpace(reference)
		if reference == "" {
			return nil, ErrInvalidDestination
		}
		if _, exists := seen[reference]; exists {
			continue
		}
		seen[reference] = struct{}{}
		normalized = append(normalized, reference)
	}
	sort.Strings(normalized)
	return normalized, nil
}

func containsPort(ports []int, required int) bool {
	index := sort.SearchInts(ports, required)
	return index < len(ports) && ports[index] == required
}

func referencesAllowed(allowed, required []string) bool {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, reference := range allowed {
		allowedSet[reference] = struct{}{}
	}
	for _, reference := range required {
		if _, exists := allowedSet[reference]; !exists {
			return false
		}
	}
	return true
}
