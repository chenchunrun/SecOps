package registry

import (
	"encoding/json"

	"github.com/chenchunrun/SecOps/internal/agent/tools/secops"
)

type Descriptor struct {
	ToolType secops.ToolType
	Decode   func(raw json.RawMessage) (any, error)
}

func decodeJSONInto[T any](raw json.RawMessage) (any, error) {
	var params T
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, err
	}
	return &params, nil
}
