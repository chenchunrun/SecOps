package registry

import (
	"encoding/json"
	"fmt"
)

// Spec is the data-first representation of a registry entry before it is
// materialized into a Descriptor.
type Spec struct {
	Key      string
	Metadata Metadata
	Decode   func(raw json.RawMessage) (any, error)
}

// NewToolSpec builds a Spec directly from a runtime tool implementation.
func NewToolSpec[T any, Key ~string, Tool interface {
	Type() Key
	RequiredCapabilities() []string
}](tool Tool, profile ExecutionProfile, policyTags ...string) Spec {
	return Spec{
		Key: string(tool.Type()),
		Metadata: Metadata{
			RequiredCapabilities: append([]string(nil), tool.RequiredCapabilities()...),
			ExecutionProfile:     profile,
			PolicyTags:           append([]string(nil), policyTags...),
		},
		Decode: decodeJSONInto[T],
	}
}

// Descriptor converts the data-first Spec into the runtime Descriptor shape.
func (s Spec) Descriptor() Descriptor {
	return Descriptor{
		Key:      s.Key,
		Metadata: s.Metadata.Clone(),
		Decode:   s.Decode,
	}
}

// SpecsToDescriptors materializes a list of Specs into runtime Descriptors.
func SpecsToDescriptors(specs ...Spec) []Descriptor {
	descs := make([]Descriptor, 0, len(specs))
	for _, spec := range specs {
		descs = append(descs, spec.Descriptor())
	}
	return descs
}

// ToolDatasetEntry keeps one dataset row able to produce both registry Spec
// metadata and a runtime tool instance for the same logical tool.
type ToolDatasetEntry[Registry any] struct {
	Spec    func() Spec
	NewTool func(*Registry) any
}

// NewToolDatasetEntry creates a reusable dataset row from a constructor so one
// declaration can drive both capability registry metadata and runtime tool
// registration.
func NewToolDatasetEntry[T any, Key ~string, Registry any, Tool interface {
	Type() Key
	RequiredCapabilities() []string
}](ctor func(*Registry) Tool, profile ExecutionProfile, policyTags ...string) ToolDatasetEntry[Registry] {
	return ToolDatasetEntry[Registry]{
		Spec: func() Spec {
			return NewToolSpec[T](ctor(nil), profile, policyTags...)
		},
		NewTool: func(reg *Registry) any {
			return ctor(reg)
		},
	}
}

// ToolDatasetSpecs projects a dataset into the Specs needed by the capability
// registry.
func ToolDatasetSpecs[Registry any](entries ...ToolDatasetEntry[Registry]) []Spec {
	specs := make([]Spec, 0, len(entries))
	for _, entry := range entries {
		specs = append(specs, entry.Spec())
	}
	return specs
}

// RegisterToolDataset walks a shared dataset and delegates concrete tool
// registration to the caller-provided register function.
func RegisterToolDataset[Registry any, Tool any](
	registry *Registry,
	register func(*Registry, Tool) error,
	entries ...ToolDatasetEntry[Registry],
) error {
	if registry == nil {
		return fmt.Errorf("registry is nil")
	}

	for _, entry := range entries {
		tool, ok := entry.NewTool(registry).(Tool)
		if !ok {
			return fmt.Errorf("dataset entry returned unexpected tool type")
		}
		if err := register(registry, tool); err != nil {
			return err
		}
	}

	return nil
}
