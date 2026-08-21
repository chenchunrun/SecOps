package collaboration

import (
	"errors"
	"strings"
)

type PlanRequest struct {
	TaskID           string
	Objective        string
	RequiresOperator bool
	RequiresCoder    bool
	HighRisk         bool
}

type Planner struct{}

func (Planner) Build(request PlanRequest) (TaskGraph, error) {
	if !validID(request.TaskID) || strings.TrimSpace(request.Objective) == "" {
		return TaskGraph{}, errors.New("plan request requires task_id and objective")
	}
	nodes := []TaskNode{{
		ID: "security-maker", Role: RoleSecurity,
		RequiredCapabilities: []string{"evidence:read", "finding:write"},
		ExpectedOutputSchema: "finding-v1",
	}}
	lastMaker := "security-maker"
	if request.RequiresOperator {
		nodes = append(nodes, TaskNode{
			ID: "operator", Role: RoleOperator, Dependencies: []string{lastMaker},
			RequiredCapabilities: []string{"computer:exec"}, ExpectedOutputSchema: "action-result-v1",
		})
		lastMaker = "operator"
	}
	if request.RequiresCoder {
		nodes = append(nodes, TaskNode{
			ID: "coder", Role: RoleCoder, Dependencies: []string{lastMaker},
			RequiredCapabilities: []string{"workspace:write"}, ExpectedOutputSchema: "change-set-v1",
		})
		lastMaker = "coder"
	}
	checkerCapabilities := []string{"evidence:read", "verification:write"}
	if request.HighRisk {
		checkerCapabilities = append(checkerCapabilities, "high_risk:verify")
	}
	nodes = append(nodes,
		TaskNode{
			ID: "independent-checker", Role: RoleChecker, Dependencies: []string{lastMaker},
			RequiredCapabilities: checkerCapabilities, ExpectedOutputSchema: "verification-v1",
		},
		TaskNode{
			ID: "reporter", Role: RoleReporter, Dependencies: []string{"independent-checker"},
			RequiredCapabilities: []string{"evidence:read", "report:write"}, ExpectedOutputSchema: "security-report-v1",
		},
	)
	graph := TaskGraph{TaskID: request.TaskID, Nodes: nodes}
	if err := graph.Validate(); err != nil {
		return TaskGraph{}, err
	}
	return graph, nil
}
