package registry

import (
	"fmt"
	"sort"

	"github.com/chenchunrun/SecOps/internal/agent/tools/secops"
)

type Registry struct {
	descriptors map[secops.ToolType]Descriptor
}

func New() *Registry {
	return &Registry{
		descriptors: make(map[secops.ToolType]Descriptor),
	}
}

func (r *Registry) Register(desc Descriptor) error {
	if r == nil {
		return fmt.Errorf("registry is nil")
	}
	if desc.ToolType == "" {
		return fmt.Errorf("tool type is required")
	}
	if desc.Decode == nil {
		return fmt.Errorf("decode function is required")
	}
	r.descriptors[desc.ToolType] = desc
	return nil
}

func (r *Registry) Get(toolType secops.ToolType) (Descriptor, bool) {
	if r == nil {
		return Descriptor{}, false
	}
	desc, ok := r.descriptors[toolType]
	return desc, ok
}

func (r *Registry) MustGet(toolType secops.ToolType) Descriptor {
	desc, ok := r.Get(toolType)
	if !ok {
		panic(fmt.Sprintf("missing descriptor for tool type %s", toolType))
	}
	return desc
}

func (r *Registry) List() []Descriptor {
	if r == nil {
		return nil
	}
	out := make([]Descriptor, 0, len(r.descriptors))
	for _, desc := range r.descriptors {
		out = append(out, desc)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ToolType < out[j].ToolType
	})
	return out
}
