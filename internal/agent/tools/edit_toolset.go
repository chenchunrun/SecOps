package tools

import (
	"charm.land/fantasy"
	"github.com/chenchunrun/SecOps/internal/filetracker"
	"github.com/chenchunrun/SecOps/internal/history"
	"github.com/chenchunrun/SecOps/internal/lsp"
	"github.com/chenchunrun/SecOps/internal/permission"
)

type editToolDatasetEntry struct {
	name  string
	build func(*lsp.Manager, permission.Service, history.Service, filetracker.Service, string) fantasy.AgentTool
}

// editToolDataset is the single source of truth for the fixed file-mutation
// tool family.
func editToolDataset() []editToolDatasetEntry {
	return []editToolDatasetEntry{
		{name: EditToolName, build: NewEditTool},
		{name: MultiEditToolName, build: NewMultiEditTool},
		{name: WriteToolName, build: NewWriteTool},
	}
}

func BuildEditToolSet(
	lspManager *lsp.Manager,
	permissions permission.Service,
	files history.Service,
	filetracker filetracker.Service,
	workingDir string,
) []fantasy.AgentTool {
	entries := editToolDataset()
	tools := make([]fantasy.AgentTool, 0, len(entries))
	for _, entry := range entries {
		tools = append(tools, entry.build(lspManager, permissions, files, filetracker, workingDir))
	}
	return tools
}

func editToolNames() []string {
	entries := editToolDataset()
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.name)
	}
	return names
}
