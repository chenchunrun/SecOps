package skills

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

var (
	ErrCapabilityDenied = errors.New("skill capability denied")
	ErrInvalidOutput    = errors.New("invalid structured skill output")
	ErrOutputLimit      = errors.New("skill output limit exceeded")
)

type RuntimeRequest struct {
	Platform            string
	ActiveParameters    map[string]bool
	SignedScope         bool
	GrantedCapabilities map[string]bool
	Input               map[string]interface{}
}

type RuntimeInput struct {
	Data  map[string]interface{}
	Trust string
}

type RuntimeResult struct {
	Risk   RiskLevel
	Output map[string]interface{}
}

type SkillExecutor interface {
	Execute(ctx context.Context, manifest SkillManifest, input RuntimeInput) (map[string]interface{}, error)
}

type Runner struct {
	executor SkillExecutor
}

func NewRunner(executor SkillExecutor) (*Runner, error) {
	if executor == nil {
		return nil, errors.New("initialize skill runner: executor is nil")
	}
	return &Runner{executor: executor}, nil
}

func (r *Runner) Run(ctx context.Context, manifest SkillManifest, request RuntimeRequest) (RuntimeResult, error) {
	risk, err := manifest.AuthorizeExecution(ExecutionRequest{
		Platform: request.Platform, ActiveParameters: request.ActiveParameters, SignedScope: request.SignedScope,
	})
	if err != nil {
		return RuntimeResult{}, err
	}
	for _, capability := range manifest.Capabilities.Required {
		if !request.GrantedCapabilities[capability] {
			return RuntimeResult{}, fmt.Errorf("%w: %s", ErrCapabilityDenied, capability)
		}
	}
	if taskID, ok := request.Input["task_id"].(string); !ok || taskID == "" {
		return RuntimeResult{}, errors.New("skill input requires task_id")
	}
	runCtx, cancel := context.WithTimeout(ctx, manifest.Runtime.Timeout)
	defer cancel()
	output, err := r.executor.Execute(runCtx, manifest, RuntimeInput{
		Data: cloneMap(request.Input), Trust: "untrusted",
	})
	if err != nil {
		if runCtx.Err() != nil {
			return RuntimeResult{}, fmt.Errorf("execute skill %s: %w", manifest.Name, runCtx.Err())
		}
		return RuntimeResult{}, fmt.Errorf("execute skill %s: %w", manifest.Name, err)
	}
	if err := validateStructuredOutput(output); err != nil {
		return RuntimeResult{}, err
	}
	encoded, err := json.Marshal(output)
	if err != nil {
		return RuntimeResult{}, fmt.Errorf("encode skill output: %w", err)
	}
	if int64(len(encoded)) > manifest.Runtime.OutputLimit {
		return RuntimeResult{}, ErrOutputLimit
	}
	return RuntimeResult{Risk: risk, Output: output}, nil
}

func validateStructuredOutput(output map[string]interface{}) error {
	for _, field := range []string{"task_id", "evidence_ids", "facts", "findings", "verification"} {
		if _, ok := output[field]; !ok {
			return fmt.Errorf("%w: missing %s", ErrInvalidOutput, field)
		}
	}
	return nil
}

func cloneMap(input map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}
