package registry

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
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
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, errors.New("tool parameters must be a JSON object")
	}
	var params T
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&params); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("tool parameters must contain exactly one JSON object")
	}
	return &params, nil
}
