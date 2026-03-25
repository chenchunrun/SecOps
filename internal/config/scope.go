package config

// Scope determines which config file is targeted for read/write operations.
type Scope int

const (
	// ScopeGlobal targets the global data config (~/.local/share/crush/crush.json).
	ScopeGlobal Scope = iota
	// ScopeGlobalConfig targets the global user config (~/.config/crush/crush.json).
	ScopeGlobalConfig
	// ScopeWorkspace targets the workspace config (.crush/crush.json).
	ScopeWorkspace
)
