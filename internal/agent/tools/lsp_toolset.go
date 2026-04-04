package tools

import (
	"charm.land/fantasy"
	"github.com/chenchunrun/SecOps/internal/lsp"
)

type lspToolDatasetEntry struct {
	name  string
	build func(*lsp.Manager) fantasy.AgentTool
}

// lspToolDataset is the single source of truth for the built-in fixed LSP
// tool family.
func lspToolDataset() []lspToolDatasetEntry {
	return []lspToolDatasetEntry{
		{name: DiagnosticsToolName, build: NewDiagnosticsTool},
		{name: ReferencesToolName, build: NewReferencesTool},
		{name: LSPRestartToolName, build: NewLSPRestartTool},
	}
}

// BuildLSPToolSet materializes the fixed LSP tool family from the shared
// dataset.
func BuildLSPToolSet(lspManager *lsp.Manager) []fantasy.AgentTool {
	entries := lspToolDataset()
	tools := make([]fantasy.AgentTool, 0, len(entries))
	for _, entry := range entries {
		tools = append(tools, entry.build(lspManager))
	}
	return tools
}

func lspToolNames() []string {
	entries := lspToolDataset()
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.name)
	}
	return names
}
