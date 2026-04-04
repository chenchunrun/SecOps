package tools

import (
	"charm.land/fantasy"
	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/permission"
)

type searchToolDatasetEntry struct {
	name  string
	build func(permission.Service, string, config.ToolGrep, config.ToolLs) fantasy.AgentTool
}

// searchToolDataset is the single source of truth for the fixed file search
// and navigation helper tools.
func searchToolDataset() []searchToolDatasetEntry {
	return []searchToolDatasetEntry{
		{
			name: GlobToolName,
			build: func(_ permission.Service, workingDir string, _ config.ToolGrep, _ config.ToolLs) fantasy.AgentTool {
				return NewGlobTool(workingDir)
			},
		},
		{
			name: GrepToolName,
			build: func(_ permission.Service, workingDir string, grepConfig config.ToolGrep, _ config.ToolLs) fantasy.AgentTool {
				return NewGrepTool(workingDir, grepConfig)
			},
		},
		{
			name: LSToolName,
			build: func(permissions permission.Service, workingDir string, _ config.ToolGrep, lsConfig config.ToolLs) fantasy.AgentTool {
				return NewLsTool(permissions, workingDir, lsConfig)
			},
		},
	}
}

func BuildSearchToolSet(
	permissions permission.Service,
	workingDir string,
	grepConfig config.ToolGrep,
	lsConfig config.ToolLs,
) []fantasy.AgentTool {
	entries := searchToolDataset()
	tools := make([]fantasy.AgentTool, 0, len(entries))
	for _, entry := range entries {
		tools = append(tools, entry.build(permissions, workingDir, grepConfig, lsConfig))
	}
	return tools
}

func searchToolNames() []string {
	entries := searchToolDataset()
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.name)
	}
	return names
}
