package tools

import (
	"charm.land/fantasy"
	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/permission"
)

type bashToolDatasetEntry struct {
	name  string
	build func(permission.Service, string, *config.Attribution, string, *config.Remote) fantasy.AgentTool
}

// bashToolDataset is the single source of truth for the fixed shell execution
// tool entry.
func bashToolDataset() []bashToolDatasetEntry {
	return []bashToolDatasetEntry{
		{
			name: BashToolName,
			build: func(permissions permission.Service, workingDir string, attribution *config.Attribution, modelName string, remote *config.Remote) fantasy.AgentTool {
				return NewBashTool(permissions, workingDir, attribution, modelName, remote)
			},
		},
	}
}

func BuildBashToolSet(
	permissions permission.Service,
	workingDir string,
	attribution *config.Attribution,
	modelName string,
	remote *config.Remote,
) []fantasy.AgentTool {
	entries := bashToolDataset()
	tools := make([]fantasy.AgentTool, 0, len(entries))
	for _, entry := range entries {
		tools = append(tools, entry.build(permissions, workingDir, attribution, modelName, remote))
	}
	return tools
}

func bashToolNames() []string {
	entries := bashToolDataset()
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.name)
	}
	return names
}
