package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/execution"
	"github.com/chenchunrun/SecOps/internal/sandbox"
)

// mandatorySandboxRunner adapts a sandbox backend to the execution package's
// SandboxRunner interface so local command execution can be forced through an
// isolated environment under strict governance.
type mandatorySandboxRunner struct {
	executor sandbox.SandboxExecutor
	base     sandbox.SandboxConfig
}

func (r *mandatorySandboxRunner) RunSandboxed(ctx context.Context, command, workingDir string) (string, error) {
	cfg := r.base
	result, err := r.executor.Execute(ctx, command, cfg)
	if result != nil {
		if err != nil && strings.TrimSpace(result.Output) == "" {
			return "", err
		}
		return result.Output, err
	}
	return "", err
}

// InstallMandatorySandbox enables forced sandboxed command execution when strict
// governance is configured. It selects the backend (docker/ssh/local) from
// cfg.Sandbox and installs it process-wide. When strict governance is off it
// clears any previously installed sandbox so the setting is not sticky.
func InstallMandatorySandbox(cfg *config.Config) {
	if cfg == nil || !cfg.GovernanceStrict() {
		execution.SetMandatorySandbox(nil)
		return
	}

	mode := "docker"
	sb := cfg.Sandbox
	if sb != nil && strings.TrimSpace(sb.Mode) != "" {
		mode = strings.ToLower(strings.TrimSpace(sb.Mode))
	}

	base := sandbox.DefaultSandboxConfig()
	base.Mode = mode
	if sb != nil {
		if sb.TimeoutMs > 0 {
			base.TimeoutSeconds = sb.TimeoutMs / 1000
		}
		base.DockerImage = strings.TrimSpace(sb.Image)
	}

	var executor sandbox.SandboxExecutor
	switch mode {
	case "docker":
		executor = sandbox.NewDockerExecutor()
	case "ssh":
		if sb == nil || strings.TrimSpace(sb.Host) == "" {
			slog.Warn("Strict governance ssh sandbox requested but no host configured; sandbox disabled")
			execution.SetMandatorySandbox(nil)
			return
		}
		base.SSHTarget = sshTarget(sb.User, sb.Host)
		executor = &sandbox.SSHExecutor{User: strings.TrimSpace(sb.User), KeyPath: strings.TrimSpace(sb.KeyPath)}
	case "local":
		executor = sandbox.NewLocalExecutor()
	default:
		slog.Warn("Unknown strict sandbox mode; defaulting to docker", "mode", mode)
		executor = sandbox.NewDockerExecutor()
		base.Mode = "docker"
	}

	slog.Info("Strict governance: mandatory command sandbox enabled", "mode", base.Mode)
	execution.SetMandatorySandbox(&mandatorySandboxRunner{executor: executor, base: base})
}

func sshTarget(user, host string) string {
	host = strings.TrimSpace(host)
	user = strings.TrimSpace(user)
	if user == "" {
		return host
	}
	return fmt.Sprintf("%s@%s", user, host)
}
