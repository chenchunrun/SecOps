package tools

import (
	"charm.land/fantasy"
	"github.com/chenchunrun/SecOps/internal/filetracker"
	"github.com/chenchunrun/SecOps/internal/lsp"
	"github.com/chenchunrun/SecOps/internal/permission"
	"github.com/chenchunrun/SecOps/internal/session"
)

type runtimeToolDatasetEntry struct {
	name  string
	build func(*lsp.Manager, permission.Service, filetracker.Service, session.Service, string, []string) fantasy.AgentTool
}

// runtimeToolDataset is the single source of truth for the fixed agent runtime
// helper tools that expose session state or local file-reading capabilities.
func runtimeToolDataset() []runtimeToolDatasetEntry {
	return []runtimeToolDatasetEntry{
		{
			name: TodosToolName,
			build: func(_ *lsp.Manager, _ permission.Service, _ filetracker.Service, sessions session.Service, _ string, _ []string) fantasy.AgentTool {
				return NewTodosTool(sessions)
			},
		},
		{
			name: ViewToolName,
			build: func(lspManager *lsp.Manager, permissions permission.Service, tracker filetracker.Service, _ session.Service, workingDir string, skillsPaths []string) fantasy.AgentTool {
				return NewViewTool(lspManager, permissions, tracker, workingDir, skillsPaths...)
			},
		},
	}
}

func BuildRuntimeToolSet(
	lspManager *lsp.Manager,
	permissions permission.Service,
	tracker filetracker.Service,
	sessions session.Service,
	workingDir string,
	skillsPaths []string,
) []fantasy.AgentTool {
	entries := runtimeToolDataset()
	tools := make([]fantasy.AgentTool, 0, len(entries))
	for _, entry := range entries {
		tools = append(tools, entry.build(lspManager, permissions, tracker, sessions, workingDir, skillsPaths))
	}
	return tools
}

func runtimeToolNames() []string {
	entries := runtimeToolDataset()
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.name)
	}
	return names
}
