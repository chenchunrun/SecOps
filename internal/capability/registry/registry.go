package registry

import (
	"encoding/json"
	"fmt"
	"sort"
)

type Registry struct {
	descriptors map[string]Descriptor
}

func New() *Registry {
	return &Registry{
		descriptors: make(map[string]Descriptor),
	}
}

func (r *Registry) Register(desc Descriptor) error {
	if r == nil {
		return fmt.Errorf("registry is nil")
	}
	if desc.Key == "" {
		return fmt.Errorf("descriptor key is required")
	}
	if desc.Decode == nil {
		return fmt.Errorf("decode function is required")
	}
	r.descriptors[desc.Key] = desc
	return nil
}

func (r *Registry) RegisterAll(descs ...Descriptor) error {
	if r == nil {
		return fmt.Errorf("registry is nil")
	}

	for _, desc := range descs {
		if err := r.Register(desc); err != nil {
			return err
		}
	}

	return nil
}

func (r *Registry) Get(key string) (Descriptor, bool) {
	if r == nil {
		return Descriptor{}, false
	}
	desc, ok := r.descriptors[key]
	return desc, ok
}

func (r *Registry) MustGet(key string) Descriptor {
	desc, ok := r.Get(key)
	if !ok {
		panic(fmt.Sprintf("missing descriptor for key %s", key))
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
		return out[i].Key < out[j].Key
	})
	return out
}

func (r *Registry) Decode(key string, raw json.RawMessage) (any, error) {
	if r == nil {
		return nil, fmt.Errorf("registry is nil")
	}

	desc, ok := r.Get(key)
	if !ok {
		return nil, fmt.Errorf("unsupported descriptor key: %s", key)
	}

	return desc.Decode(raw)
}

func (r *Registry) MetadataFor(key string) (Metadata, bool) {
	desc, ok := r.Get(key)
	if !ok {
		return Metadata{}, false
	}
	return desc.Metadata.Clone(), true
}

func (r *Registry) RequiredCapabilities(key string) []string {
	metadata, ok := r.MetadataFor(key)
	if !ok || len(metadata.RequiredCapabilities) == 0 {
		return nil
	}
	return metadata.RequiredCapabilities
}

func (r *Registry) PolicyTags(key string) []string {
	metadata, ok := r.MetadataFor(key)
	if !ok || len(metadata.PolicyTags) == 0 {
		return nil
	}
	return metadata.PolicyTags
}

func (r *Registry) ExecutionProfileFor(key string) (ExecutionProfile, bool) {
	metadata, ok := r.MetadataFor(key)
	if !ok {
		return "", false
	}
	return metadata.ExecutionProfile, true
}

func MustNew(descs ...Descriptor) *Registry {
	reg := New()
	if err := reg.RegisterAll(descs...); err != nil {
		panic(err)
	}
	return reg
}
