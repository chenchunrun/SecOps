// Package workbench renders security workbench views using terminal-default colors.
package workbench

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/x/ansi"

	workbenchstate "github.com/chenchunrun/SecOps/internal/workbench"
)

type View string

const (
	ViewTask         View = "Task"
	ViewEvidence     View = "Evidence"
	ViewApproval     View = "Approval"
	ViewVerification View = "Verification"
)

type Component struct {
	view     View
	snapshot workbenchstate.Snapshot
}

func New() *Component { return &Component{view: ViewTask} }

func (c *Component) SetView(view View) {
	switch view {
	case ViewTask, ViewEvidence, ViewApproval, ViewVerification:
		c.view = view
	}
}

func (c *Component) SetSnapshot(snapshot workbenchstate.Snapshot) { c.snapshot = snapshot }

func (c *Component) Render(width int) string {
	lines := []string{fmt.Sprintf("[%s]", c.view)}
	switch c.view {
	case ViewTask:
		for _, task := range c.snapshot.Tasks {
			lines = append(lines, fmt.Sprintf("%s  %s  agent=%s skill=%s", task.ID, task.State, fallback(task.CurrentAgent), fallback(task.CurrentSkill)))
		}
	case ViewEvidence:
		for _, item := range c.snapshot.Evidence {
			lines = append(lines, fmt.Sprintf("%s  source=%s trust=%s completeness=%s hash=%s", item.ID, item.Source, item.Trust, item.Completeness, item.ContentHash))
		}
	case ViewApproval:
		for _, approval := range c.snapshot.Approvals {
			parameters := make([]string, 0, len(approval.Parameters))
			for key, value := range approval.Parameters {
				parameters = append(parameters, key+"="+value)
			}
			sort.Strings(parameters)
			lines = append(lines, fmt.Sprintf("%s  risk=%s action=%s target=%s params={%s} status=%s", approval.ID, approval.Risk, approval.Action, approval.Target, strings.Join(parameters, ","), approval.Status))
		}
	case ViewVerification:
		for _, verification := range c.snapshot.Verifications {
			lines = append(lines, fmt.Sprintf("%s  checker=%s verdict=%s reason=%s", verification.FindingID, verification.CheckerID, verification.Verdict, verification.Reason))
		}
	}
	for index, line := range lines {
		lines[index] = ansi.Truncate(line, width, "...")
	}
	return strings.Join(lines, "\n")
}

func fallback(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
