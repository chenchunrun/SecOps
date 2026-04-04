package tools

// FixedBuiltInToolNames returns the fixed non-SecOps built-in tool names used
// by coordinator wiring and config defaults. Dynamic MCP tools and
// capability-registered SecOps tools are handled separately.
func FixedBuiltInToolNames() []string {
	var names []string
	names = append(names, bashToolNames()...)
	names = append(names, jobToolNames()...)
	names = append(names, remoteToolNames()...)
	names = append(names, editToolNames()...)
	names = append(names, lspToolNames()...)
	names = append(names, AgenticFetchToolName)
	names = append(names, searchToolNames()...)
	names = append(names, runtimeToolNames()...)
	names = append(names, mcpToolNames()...)
	names = append(names, "todo")
	return names
}

// ReadOnlyBuiltInToolNames returns the fixed built-in tool names intended for
// the task/read-only agent profile.
func ReadOnlyBuiltInToolNames() []string {
	names := append([]string(nil), searchToolNames()...)
	names = append(names, SourcegraphToolName)
	names = append(names, ViewToolName)
	return names
}

// SecOpsRuntimeSupportToolNames returns the fixed non-SecOps support tool
// names available to the SecOps-focused agent profiles.
func SecOpsRuntimeSupportToolNames() []string {
	names := []string{
		BashToolName,
		GlobToolName,
		GrepToolName,
		LSToolName,
		ViewToolName,
		FetchToolName,
		DownloadToolName,
		SourcegraphToolName,
		TodosToolName,
		"todo",
	}
	return names
}
