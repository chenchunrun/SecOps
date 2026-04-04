package tools

import (
	"charm.land/fantasy"
	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/permission"
)

type mcpToolDatasetEntry struct {
	name  string
	build func(*config.ConfigStore, permission.Service) fantasy.AgentTool
}

// mcpToolDataset covers the fixed built-in MCP helper tools. Dynamic MCP tools
// discovered from configured servers are handled separately.
func mcpToolDataset() []mcpToolDatasetEntry {
	return []mcpToolDatasetEntry{
		{name: ListMCPResourcesToolName, build: NewListMCPResourcesTool},
		{name: ReadMCPResourceToolName, build: NewReadMCPResourceTool},
	}
}

func BuildMCPToolSet(cfg *config.ConfigStore, permissions permission.Service) []fantasy.AgentTool {
	entries := mcpToolDataset()
	tools := make([]fantasy.AgentTool, 0, len(entries))
	for _, entry := range entries {
		tools = append(tools, entry.build(cfg, permissions))
	}
	return tools
}

func mcpToolNames() []string {
	entries := mcpToolDataset()
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.name)
	}
	return names
}
