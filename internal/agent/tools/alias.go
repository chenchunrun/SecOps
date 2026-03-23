package tools

import (
	"context"

	"charm.land/fantasy"
)

// AliasTool wraps an existing tool and exposes it under an alternative name.
// This keeps backward compatibility with providers/models that emit legacy
// function names.
type AliasTool struct {
	base fantasy.AgentTool
	name string
	desc string
}

func NewAliasTool(base fantasy.AgentTool, aliasName string, aliasDesc string) fantasy.AgentTool {
	if aliasDesc == "" {
		aliasDesc = base.Info().Description
	}
	return &AliasTool{
		base: base,
		name: aliasName,
		desc: aliasDesc,
	}
}

func (a *AliasTool) Info() fantasy.ToolInfo {
	return fantasy.ToolInfo{
		Name:        a.name,
		Description: a.desc,
	}
}

func (a *AliasTool) Run(ctx context.Context, call fantasy.ToolCall) (fantasy.ToolResponse, error) {
	return a.base.Run(ctx, call)
}

func (a *AliasTool) ProviderOptions() fantasy.ProviderOptions {
	return a.base.ProviderOptions()
}

func (a *AliasTool) SetProviderOptions(opts fantasy.ProviderOptions) {
	a.base.SetProviderOptions(opts)
}
