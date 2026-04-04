// Package registry centralizes capability-aware tool registration metadata.
//
// The intended layering is:
//
//   - Spec is the data-first form of a capability descriptor.
//   - ToolDatasetEntry lets one dataset row produce both Spec metadata and a
//     runtime tool instance.
//   - RegisterToolDataset wires a shared dataset into a concrete runtime
//     registry without duplicating constructor lists.
//
// For a fixed tool family such as SecOps, keep one package-local dataset that:
//
//  1. declares each tool constructor once,
//  2. derives Specs for capability metadata,
//  3. derives Descriptors for policy/runtime decoding, and
//  4. derives runtime tool registration from the same source.
//
// Dynamic tool families discovered at runtime, such as MCP tools, are usually
// not a good fit for this static dataset pattern.
package registry
