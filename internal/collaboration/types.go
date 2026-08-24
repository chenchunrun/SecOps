// Package collaboration implements durable, least-privilege agent handoffs.
package collaboration

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/chenchunrun/SecOps/internal/security/promptguard"
)

var (
	ErrAlreadyExists    = errors.New("handoff already exists")
	ErrNotFound         = errors.New("handoff not found")
	ErrPermissionDenied = errors.New("handoff capability denied")
	ErrInvalidHandoff   = errors.New("invalid handoff")
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Role string

const (
	RolePlanner  Role = "planner"
	RoleSecurity Role = "security_expert"
	RoleOperator Role = "operator"
	RoleCoder    Role = "coder"
	RoleChecker  Role = "checker"
	RoleReporter Role = "reporter"
)

type HandoffEnvelope struct {
	ID                    string    `json:"id"`
	TaskID                string    `json:"task_id"`
	Producer              string    `json:"producer"`
	ProducerRole          Role      `json:"producer_role"`
	Consumer              string    `json:"consumer"`
	ConsumerRole          Role      `json:"consumer_role"`
	Objective             string    `json:"objective"`
	EvidenceIDs           []string  `json:"evidence_ids"`
	UnverifiedAssumptions []string  `json:"unverified_assumptions,omitempty"`
	RequiredCapabilities  []string  `json:"required_capabilities"`
	ExpectedOutputSchema  string    `json:"expected_output_schema"`
	CreatedAt             time.Time `json:"created_at"`
}

func (h HandoffEnvelope) Validate() error {
	if !validID(h.ID) || !validID(h.TaskID) || !validID(h.Producer) || !validID(h.Consumer) || !validRole(h.ProducerRole) || !validRole(h.ConsumerRole) {
		return ErrInvalidHandoff
	}
	if h.Producer == h.Consumer {
		return fmt.Errorf("%w: producer and consumer identities must differ", ErrInvalidHandoff)
	}
	if strings.TrimSpace(h.Objective) == "" || promptguard.ContainsInjection(h.Objective) {
		return fmt.Errorf("%w: objective is empty or contains instruction hijacking", ErrInvalidHandoff)
	}
	for _, assumption := range h.UnverifiedAssumptions {
		if promptguard.ContainsInjection(assumption) {
			return fmt.Errorf("%w: assumption contains instruction hijacking", ErrInvalidHandoff)
		}
	}
	if len(h.RequiredCapabilities) == 0 || strings.TrimSpace(h.ExpectedOutputSchema) == "" {
		return fmt.Errorf("%w: capabilities and output schema are required", ErrInvalidHandoff)
	}
	for _, value := range append(append([]string(nil), h.EvidenceIDs...), h.RequiredCapabilities...) {
		if !validID(strings.ReplaceAll(value, ":", "-")) {
			return ErrInvalidHandoff
		}
	}
	return nil
}

type TaskNode struct {
	ID                   string   `json:"id"`
	Role                 Role     `json:"role"`
	Dependencies         []string `json:"dependencies,omitempty"`
	RequiredCapabilities []string `json:"required_capabilities"`
	ExpectedOutputSchema string   `json:"expected_output_schema"`
}

type TaskGraph struct {
	TaskID string     `json:"task_id"`
	Nodes  []TaskNode `json:"nodes"`
}

func (g TaskGraph) Validate() error {
	if !validID(g.TaskID) || len(g.Nodes) == 0 {
		return errors.New("task graph requires task_id and nodes")
	}
	nodes := make(map[string]TaskNode, len(g.Nodes))
	for _, node := range g.Nodes {
		if !validID(node.ID) || !validRole(node.Role) || len(node.RequiredCapabilities) == 0 || strings.TrimSpace(node.ExpectedOutputSchema) == "" {
			return fmt.Errorf("invalid task node %q", node.ID)
		}
		if _, exists := nodes[node.ID]; exists {
			return fmt.Errorf("duplicate task node %q", node.ID)
		}
		nodes[node.ID] = node
	}
	visiting := make(map[string]bool)
	visited := make(map[string]bool)
	var visit func(string) error
	visit = func(id string) error {
		if visiting[id] {
			return fmt.Errorf("task graph contains cycle at %q", id)
		}
		if visited[id] {
			return nil
		}
		node, ok := nodes[id]
		if !ok {
			return fmt.Errorf("task graph dependency %q does not exist", id)
		}
		visiting[id] = true
		for _, dependency := range node.Dependencies {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		visiting[id] = false
		visited[id] = true
		return nil
	}
	for id := range nodes {
		if err := visit(id); err != nil {
			return err
		}
	}
	return nil
}

func validID(value string) bool { return identifierPattern.MatchString(value) }

func validRole(role Role) bool {
	switch role {
	case RolePlanner, RoleSecurity, RoleOperator, RoleCoder, RoleChecker, RoleReporter:
		return true
	default:
		return false
	}
}
