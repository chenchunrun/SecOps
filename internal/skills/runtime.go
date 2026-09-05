package skills

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/chenchunrun/SecOps/internal/evidence"
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
	evidence EvidenceReader
}

// EvidenceReader verifies that skill citations refer to stored task evidence.
type EvidenceReader interface {
	GetEvidence(context.Context, string) (evidence.Evidence, []byte, error)
}

func NewRunner(executor SkillExecutor, readers ...EvidenceReader) (*Runner, error) {
	if executor == nil {
		return nil, errors.New("initialize skill runner: executor is nil")
	}
	runner := &Runner{executor: executor}
	if len(readers) > 0 {
		runner.evidence = readers[0]
	}
	return runner, nil
}

func (r *Runner) Run(ctx context.Context, manifest SkillManifest, request RuntimeRequest) (RuntimeResult, error) {
	if err := ctx.Err(); err != nil {
		return RuntimeResult{}, err
	}
	if manifest.inputValidator == nil || manifest.outputValidator == nil {
		return RuntimeResult{}, errors.New("skill must be loaded with validated schema contracts")
	}
	if err := manifest.inputValidator.Validate(request.Input); err != nil {
		return RuntimeResult{}, fmt.Errorf("invalid skill input: %w", err)
	}
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
	if err := runCtx.Err(); err != nil {
		return RuntimeResult{}, err
	}
	encoded, err := json.Marshal(output)
	if err != nil {
		return RuntimeResult{}, fmt.Errorf("encode skill output: %w", err)
	}
	if int64(len(encoded)) > manifest.Runtime.OutputLimit {
		return RuntimeResult{}, ErrOutputLimit
	}
	// Normalize typed slices and maps to their JSON representation.
	if err := json.Unmarshal(encoded, &output); err != nil {
		return RuntimeResult{}, err
	}
	if err := manifest.outputValidator.Validate(output); err != nil {
		return RuntimeResult{}, fmt.Errorf("%w: %v", ErrInvalidOutput, err)
	}
	if output["task_id"] != request.Input["task_id"] {
		return RuntimeResult{}, fmt.Errorf("%w: task_id mismatch", ErrInvalidOutput)
	}
	if err := r.validateReferences(ctx, request.Input["task_id"].(string), output); err != nil {
		return RuntimeResult{}, err
	}
	return RuntimeResult{Risk: risk, Output: output}, nil
}

func (r *Runner) validateReferences(ctx context.Context, taskID string, value interface{}) error {
	switch value := value.(type) {
	case map[string]interface{}:
		if id, ok := value["task_id"]; ok && id != taskID {
			return fmt.Errorf("%w: cross-task record", ErrInvalidOutput)
		}
		for key, child := range value {
			if key == "evidence_ids" {
				ids, ok := child.([]interface{})
				if !ok {
					return fmt.Errorf("%w: evidence_ids must be an array", ErrInvalidOutput)
				}
				for _, rawID := range ids {
					id, ok := rawID.(string)
					if !ok || id == "" || r.evidence == nil {
						return fmt.Errorf("%w: evidence citation cannot be verified", ErrInvalidOutput)
					}
					item, _, err := r.evidence.GetEvidence(ctx, id)
					if err != nil || item.TaskID != taskID || item.Completeness != evidence.CompletenessComplete {
						return fmt.Errorf("%w: invalid evidence citation %s", ErrInvalidOutput, id)
					}
				}
			}
			if err := r.validateReferences(ctx, taskID, child); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, child := range value {
			if err := r.validateReferences(ctx, taskID, child); err != nil {
				return err
			}
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
