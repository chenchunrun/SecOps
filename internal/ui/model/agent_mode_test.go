package model

import (
	"testing"

	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/ui/dialog"
	"github.com/stretchr/testify/require"
)

func TestParseAgentDirective(t *testing.T) {
	t.Parallel()

	target, prompt := parseAgentDirective("/ops 请检查监控异常")
	require.Equal(t, config.AgentOpsAgent, target)
	require.Equal(t, "请检查监控异常", prompt)

	target, prompt = parseAgentDirective("/sec 做一次合规审计")
	require.Equal(t, config.AgentSecurityExpertAgent, target)
	require.Equal(t, "做一次合规审计", prompt)

	target, prompt = parseAgentDirective("/coder 写一个单元测试")
	require.Equal(t, config.AgentCoder, target)
	require.Equal(t, "写一个单元测试", prompt)
}

func TestRouteAgentByMode(t *testing.T) {
	t.Parallel()

	target, prompt := routeAgentByMode("请帮我做漏洞扫描", dialog.AgentModeAuto)
	require.Equal(t, config.AgentSecurityExpertAgent, target)
	require.Equal(t, "请帮我做漏洞扫描", prompt)

	target, prompt = routeAgentByMode("请帮我回滚发布", dialog.AgentModeAuto)
	require.Equal(t, config.AgentOpsAgent, target)
	require.Equal(t, "请帮我回滚发布", prompt)

	target, prompt = routeAgentByMode("重构这个函数", dialog.AgentModeAuto)
	require.Equal(t, config.AgentCoder, target)
	require.Equal(t, "重构这个函数", prompt)

	target, prompt = routeAgentByMode("任意任务", dialog.AgentModeOps)
	require.Equal(t, config.AgentOpsAgent, target)
	require.Equal(t, "任意任务", prompt)

	target, prompt = routeAgentByMode("任意任务", dialog.AgentModeSecurity)
	require.Equal(t, config.AgentSecurityExpertAgent, target)
	require.Equal(t, "任意任务", prompt)

	target, prompt = routeAgentByMode("任意任务", dialog.AgentModeCoder)
	require.Equal(t, config.AgentCoder, target)
	require.Equal(t, "任意任务", prompt)
}

func TestRouteAgentByMode_ExplicitDirectiveTakesPrecedence(t *testing.T) {
	t.Parallel()

	target, prompt := routeAgentByMode("/ops 请排查CPU告警", dialog.AgentModeSecurity)
	require.Equal(t, config.AgentOpsAgent, target)
	require.Equal(t, "请排查CPU告警", prompt)

	target, prompt = routeAgentByMode("/sec 做漏洞复核", dialog.AgentModeOps)
	require.Equal(t, config.AgentSecurityExpertAgent, target)
	require.Equal(t, "做漏洞复核", prompt)

	target, prompt = routeAgentByMode("/coder 写单元测试", dialog.AgentModeOps)
	require.Equal(t, config.AgentCoder, target)
	require.Equal(t, "写单元测试", prompt)
}
