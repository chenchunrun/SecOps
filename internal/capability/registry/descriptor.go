package registry

import (
	"encoding/json"
	"reflect"
)

// ExecutionProfile describes where a capability-backed tool may execute.
type ExecutionProfile string

// Metadata captures capability and policy information associated with a
// registered descriptor.
type Metadata struct {
	RequiredCapabilities []string
	ExecutionProfile     ExecutionProfile
	PolicyTags           []string
}

// Clone returns a defensive copy so registry callers cannot mutate stored
// metadata slices.
func (m Metadata) Clone() Metadata {
	return Metadata{
		RequiredCapabilities: append([]string(nil), m.RequiredCapabilities...),
		ExecutionProfile:     m.ExecutionProfile,
		PolicyTags:           append([]string(nil), m.PolicyTags...),
	}
}

type Descriptor struct {
	Key        string
	Metadata   Metadata
	Decode     func(raw json.RawMessage) (any, error)
	ParamsType reflect.Type // params struct type; used to generate JSON schema for the LLM
}

func decodeJSONInto[T any](raw json.RawMessage) (any, error) {
	var params T
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, err
	}
	return &params, nil
}
