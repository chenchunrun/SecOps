// Package tools contains built-in agent tools and the fixed toolset builders
// that materialize them for coordinator wiring.
//
// Fixed built-in tool families should be declared through a dataset-backed
// Build*ToolSet helper instead of being appended one-by-one in
// coordinator.buildTools. This keeps each family on a single source of truth
// for:
//   - the concrete tool constructors,
//   - name/uniqueness tests, and
//   - coordinator wiring.
//
// Dynamic tool families remain separate:
//   - MCP server-discovered tools are populated at runtime from configured
//     servers.
//   - Capability-driven SecOps tools are registered through the capability
//     registry layer.
package tools
