package model

import (
	"strings"
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

	target, prompt = parseAgentDirective("/security 做一次深度安全分析")
	require.Equal(t, config.AgentSecurityExpertAgent, target)
	require.Equal(t, "做一次深度安全分析", prompt)

	target, prompt = parseAgentDirective("/coder 写一个单元测试")
	require.Equal(t, config.AgentCoder, target)
	require.Equal(t, "写一个单元测试", prompt)

	target, prompt = parseAgentDirective("/securityaudit 仅文本")
	require.Equal(t, "", target)
	require.Equal(t, "/securityaudit 仅文本", prompt)
}

func TestRouteAgentByMode(t *testing.T) {
	t.Parallel()

	target, prompt := routeAgentByMode("请帮我做漏洞扫描", dialog.AgentModeAuto)
	require.Equal(t, config.AgentSecurityExpertAgent, target)
	require.Equal(t, "请帮我做漏洞扫描", prompt)

	target, prompt = routeAgentByMode("请帮我回滚发布", dialog.AgentModeAuto)
	require.Equal(t, config.AgentOpsAgent, target)
	require.Equal(t, "请帮我回滚发布", prompt)

	target, prompt = routeAgentByMode("生产环境 CPU 高并且延迟抖动，请先做监控排障", dialog.AgentModeAuto)
	require.Equal(t, config.AgentOpsAgent, target)
	require.Equal(t, "生产环境 CPU 高并且延迟抖动，请先做监控排障", prompt)

	target, prompt = routeAgentByMode("请研判异常登录并检查是否存在凭证泄露风险", dialog.AgentModeAuto)
	require.Equal(t, config.AgentSecurityExpertAgent, target)
	require.Equal(t, "请研判异常登录并检查是否存在凭证泄露风险", prompt)

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

func TestParseSlashControlCommand(t *testing.T) {
	t.Parallel()

	cmd, ok := parseSlashControlCommand("/fast")
	require.True(t, ok)
	require.NotNil(t, cmd.runMode)
	require.Equal(t, dialog.RunModeFast, *cmd.runMode)

	cmd, ok = parseSlashControlCommand("/run deep")
	require.True(t, ok)
	require.NotNil(t, cmd.runMode)
	require.Equal(t, dialog.RunModeDeep, *cmd.runMode)

	cmd, ok = parseSlashControlCommand("/ops")
	require.True(t, ok)
	require.NotNil(t, cmd.agentMode)
	require.Equal(t, dialog.AgentModeOps, *cmd.agentMode)

	cmd, ok = parseSlashControlCommand("/agent security")
	require.True(t, ok)
	require.NotNil(t, cmd.agentMode)
	require.Equal(t, dialog.AgentModeSecurity, *cmd.agentMode)

	_, ok = parseSlashControlCommand("/ops 检查磁盘")
	require.False(t, ok)
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

func TestAgentModeInfoMessage(t *testing.T) {
	t.Parallel()

	require.Contains(t, agentModeInfoMessage(dialog.AgentModeOps), "monitoring")
	require.Contains(t, agentModeInfoMessage(dialog.AgentModeSecurity), "vulnerabilities")
	require.Contains(t, agentModeInfoMessage(dialog.AgentModeCoder), "debugging")
	require.Contains(t, agentModeInfoMessage(dialog.AgentModeAuto), "route by operational")
}

func TestReadyPlaceholdersForMode(t *testing.T) {
	t.Parallel()

	require.NotEmpty(t, readyPlaceholdersForMode(dialog.AgentModeOps))
	require.NotEmpty(t, readyPlaceholdersForMode(dialog.AgentModeSecurity))
	require.NotEmpty(t, readyPlaceholdersForMode(dialog.AgentModeCoder))
	require.NotEmpty(t, readyPlaceholdersForMode(dialog.AgentModeAuto))
	require.Contains(t, strings.Join(readyPlaceholdersForMode(dialog.AgentModeOps), " "), "monitoring")
	require.Contains(t, strings.Join(readyPlaceholdersForMode(dialog.AgentModeSecurity), " "), "Security")
}

func TestAutoRouteInfoMessage(t *testing.T) {
	t.Parallel()

	require.Contains(t, autoRouteInfoMessage(config.AgentOpsAgent), "Auto routed to Ops")
	require.Contains(t, autoRouteInfoMessage(config.AgentSecurityExpertAgent), "Auto routed to Security")
	require.Contains(t, autoRouteInfoMessage(config.AgentCoder), "Auto routed to Coder")
	require.Equal(t, "", autoRouteInfoMessage(""))
}
