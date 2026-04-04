package tools

import (
	"net/http"

	"charm.land/fantasy"
	"github.com/chenchunrun/SecOps/internal/permission"
)

type remoteToolDatasetEntry struct {
	name  string
	build func(permission.Service, string, *http.Client) fantasy.AgentTool
}

// remoteToolDataset is the single source of truth for the fixed remote content
// and network-backed helper tools.
func remoteToolDataset() []remoteToolDatasetEntry {
	return []remoteToolDatasetEntry{
		{
			name: DownloadToolName,
			build: func(permissions permission.Service, workingDir string, client *http.Client) fantasy.AgentTool {
				return NewDownloadTool(permissions, workingDir, client)
			},
		},
		{
			name: FetchToolName,
			build: func(permissions permission.Service, workingDir string, client *http.Client) fantasy.AgentTool {
				return NewFetchTool(permissions, workingDir, client)
			},
		},
		{
			name: SourcegraphToolName,
			build: func(_ permission.Service, _ string, client *http.Client) fantasy.AgentTool {
				return NewSourcegraphTool(client)
			},
		},
	}
}

func BuildRemoteToolSet(
	permissions permission.Service,
	workingDir string,
	client *http.Client,
) []fantasy.AgentTool {
	entries := remoteToolDataset()
	tools := make([]fantasy.AgentTool, 0, len(entries))
	for _, entry := range entries {
		tools = append(tools, entry.build(permissions, workingDir, client))
	}
	return tools
}

func remoteToolNames() []string {
	entries := remoteToolDataset()
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.name)
	}
	return names
}
