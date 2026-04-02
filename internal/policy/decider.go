package policy

import (
	"context"
	"fmt"
)

type BashEvaluator interface {
	EvaluateBash(ctx context.Context, req Request) (Decision, error)
}

type SecOpsEvaluator interface {
	EvaluateSecOps(ctx context.Context, req Request) (Decision, error)
}

type DefaultDecider struct {
	bash   BashEvaluator
	secops SecOpsEvaluator
}

func NewDefaultDecider(bash BashEvaluator, secops SecOpsEvaluator) *DefaultDecider {
	return &DefaultDecider{
		bash:   bash,
		secops: secops,
	}
}

func (d *DefaultDecider) Decide(ctx context.Context, req Request) (Decision, error) {
	switch req.PolicyKind {
	case "bash":
		if d.bash == nil {
			return Decision{}, fmt.Errorf("bash evaluator is not configured")
		}
		return d.bash.EvaluateBash(ctx, req)
	case "secops":
		if d.secops == nil {
			return Decision{}, fmt.Errorf("secops evaluator is not configured")
		}
		return d.secops.EvaluateSecOps(ctx, req)
	default:
		return Decision{
			Allowed: true,
			Reason:  "no policy evaluator configured",
			AuditFields: map[string]any{
				"tool_name": req.ToolName,
				"policy":    "default-allow",
			},
		}, nil
	}
}
