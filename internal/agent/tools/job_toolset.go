package tools

import "charm.land/fantasy"

type jobToolDatasetEntry struct {
	name  string
	build func() fantasy.AgentTool
}

// jobToolDataset is the single source of truth for background job helper
// tools.
func jobToolDataset() []jobToolDatasetEntry {
	return []jobToolDatasetEntry{
		{name: JobOutputToolName, build: NewJobOutputTool},
		{name: JobKillToolName, build: NewJobKillTool},
	}
}

func BuildJobToolSet() []fantasy.AgentTool {
	entries := jobToolDataset()
	tools := make([]fantasy.AgentTool, 0, len(entries))
	for _, entry := range entries {
		tools = append(tools, entry.build())
	}
	return tools
}

func jobToolNames() []string {
	entries := jobToolDataset()
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.name)
	}
	return names
}
