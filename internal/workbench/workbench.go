// Package workbench provides observable security-task state and controls.
package workbench

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

type Task struct {
	ID           string
	Title        string
	State        string
	Dependencies []string
	CurrentAgent string
	CurrentSkill string
	StartedAt    time.Time
}

type EvidenceItem struct {
	ID           string
	TaskID       string
	Source       string
	Trust        string
	Completeness string
	ContentHash  string
}

type Approval struct {
	ID         string
	TaskID     string
	Action     string
	Risk       string
	Target     string
	Parameters map[string]string
	Status     string
}

type Verification struct {
	FindingID string
	TaskID    string
	CheckerID string
	Verdict   string
	Reason    string
}

type Metrics struct {
	TasksStarted          int64
	TasksSucceeded        int64
	TasksFailed           int64
	AgentDuration         time.Duration
	SkillDuration         time.Duration
	ModelTokens           int64
	ModelCostMicros       int64
	ToolFailures          int64
	Retries               int64
	PermissionDenials     int64
	UnsupportedClaims     int64
	CheckerRejections     int64
	EvidenceItems         int64
	CompleteEvidenceItems int64
}

func (m Metrics) TaskSuccessRate() float64 {
	completed := m.TasksSucceeded + m.TasksFailed
	if completed == 0 {
		return 0
	}
	return float64(m.TasksSucceeded) / float64(completed)
}

func (m Metrics) EvidenceCompletenessRate() float64 {
	if m.EvidenceItems == 0 {
		return 0
	}
	return float64(m.CompleteEvidenceItems) / float64(m.EvidenceItems)
}

type TaskController interface {
	Pause(context.Context, string) error
	Resume(context.Context, string) error
	Cancel(context.Context, string) error
}

type Workbench struct {
	mu            sync.RWMutex
	controller    TaskController
	tasks         map[string]Task
	evidence      map[string]EvidenceItem
	approvals     map[string]Approval
	verifications map[string]Verification
	metrics       Metrics
}

func New(controller TaskController) *Workbench {
	return &Workbench{
		controller: controller, tasks: make(map[string]Task), evidence: make(map[string]EvidenceItem),
		approvals: make(map[string]Approval), verifications: make(map[string]Verification),
	}
}

func (w *Workbench) UpsertTask(task Task) error {
	if task.ID == "" || task.Title == "" || task.State == "" {
		return errors.New("workbench task requires id, title, and state")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.tasks[task.ID] = task
	return nil
}

func (w *Workbench) AddEvidence(item EvidenceItem) error {
	if item.ID == "" || item.TaskID == "" || item.Source == "" || item.ContentHash == "" {
		return errors.New("workbench evidence requires id, task, source, and hash")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, exists := w.evidence[item.ID]; !exists {
		w.metrics.EvidenceItems++
		if item.Completeness == "complete" {
			w.metrics.CompleteEvidenceItems++
		}
	}
	w.evidence[item.ID] = item
	return nil
}

func (w *Workbench) AddApproval(approval Approval) error {
	if approval.ID == "" || approval.TaskID == "" || approval.Action == "" || approval.Risk == "" || approval.Target == "" {
		return errors.New("workbench approval requires id, task, action, risk, and target")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.approvals[approval.ID] = approval
	return nil
}

func (w *Workbench) AddVerification(verification Verification) error {
	if verification.FindingID == "" || verification.TaskID == "" || verification.CheckerID == "" || verification.Verdict == "" {
		return errors.New("workbench verification requires finding, task, checker, and verdict")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.verifications[verification.FindingID] = verification
	if verification.Verdict == "rejected" || verification.Verdict == "needs_evidence" {
		w.metrics.CheckerRejections++
	}
	return nil
}

func (w *Workbench) Snapshot() Snapshot {
	w.mu.RLock()
	defer w.mu.RUnlock()
	snapshot := Snapshot{Metrics: w.metrics}
	for _, task := range w.tasks {
		snapshot.Tasks = append(snapshot.Tasks, task)
	}
	for _, item := range w.evidence {
		snapshot.Evidence = append(snapshot.Evidence, item)
	}
	for _, approval := range w.approvals {
		snapshot.Approvals = append(snapshot.Approvals, approval)
	}
	for _, verification := range w.verifications {
		snapshot.Verifications = append(snapshot.Verifications, verification)
	}
	sort.Slice(snapshot.Tasks, func(i, j int) bool { return snapshot.Tasks[i].ID < snapshot.Tasks[j].ID })
	sort.Slice(snapshot.Evidence, func(i, j int) bool { return snapshot.Evidence[i].ID < snapshot.Evidence[j].ID })
	sort.Slice(snapshot.Approvals, func(i, j int) bool { return snapshot.Approvals[i].ID < snapshot.Approvals[j].ID })
	sort.Slice(snapshot.Verifications, func(i, j int) bool { return snapshot.Verifications[i].FindingID < snapshot.Verifications[j].FindingID })
	return snapshot
}

type Snapshot struct {
	Tasks         []Task
	Evidence      []EvidenceItem
	Approvals     []Approval
	Verifications []Verification
	Metrics       Metrics
}

func (w *Workbench) Observe(update func(*Metrics)) {
	if update == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	update(&w.metrics)
}

func (w *Workbench) Pause(ctx context.Context, taskID string) error {
	if w.controller == nil {
		return errors.New("workbench task controller is unavailable")
	}
	return w.controller.Pause(ctx, taskID)
}

func (w *Workbench) Resume(ctx context.Context, taskID string) error {
	if w.controller == nil {
		return errors.New("workbench task controller is unavailable")
	}
	return w.controller.Resume(ctx, taskID)
}

func (w *Workbench) Cancel(ctx context.Context, taskID string) error {
	if w.controller == nil {
		return errors.New("workbench task controller is unavailable")
	}
	return w.controller.Cancel(ctx, taskID)
}
