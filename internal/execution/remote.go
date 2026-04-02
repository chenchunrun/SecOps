package execution

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type remoteExecutor struct {
	handler RemoteHandler
}

func NewRemoteExecutor(middlewares ...RemoteMiddleware) RemoteExecutor {
	base := func(ctx context.Context, req RemoteRequest) (RemoteResult, error) {
		host := strings.TrimSpace(req.TargetHost)
		if host == "" {
			return RemoteResult{}, &RemoteExecutionError{
				Kind:  RemoteErrorKindStart,
				Cause: fmt.Errorf("remote_host is required for remote execution"),
			}
		}

		target := formatRemoteTarget(req.TargetUser, host)
		args := []string{"-o", "BatchMode=yes"}
		if req.TargetPort > 0 {
			args = append(args, "-p", strconv.Itoa(req.TargetPort))
		}
		if key := strings.TrimSpace(req.KeyPath); key != "" {
			args = append(args, "-i", key)
		}
		if jump := strings.TrimSpace(req.ProxyJump); jump != "" {
			args = append(args, "-J", jump)
		}

		remoteCommand := strings.TrimSpace(req.Command)
		if wd := strings.TrimSpace(req.RemoteWorkingDir); wd != "" {
			remoteCommand = "cd " + shellQuoteSingle(wd) + " && " + remoteCommand
		}

		args = append(args, target, "sh", "-lc", remoteCommand)
		cmd := exec.CommandContext(ctx, "ssh", args...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		return RemoteResult{
			Output:           formatExecutionOutput(stdout.String(), stderr.String(), err),
			WorkingDirectory: defaultString(strings.TrimSpace(req.RemoteWorkingDir), "~"),
			RemoteTarget:     target,
		}, err
	}

	return remoteExecutor{
		handler: ChainRemoteMiddlewares(base, append([]RemoteMiddleware{ErrorClassificationRemoteMiddleware(), PolicyRemoteMiddleware(), AuditRemoteMiddleware()}, middlewares...)...),
	}
}

func (e remoteExecutor) Execute(ctx context.Context, req RemoteRequest) (RemoteResult, error) {
	return e.handler(ctx, req)
}

func formatRemoteTarget(user, host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	user = strings.TrimSpace(user)
	if user == "" {
		return host
	}
	return user + "@" + host
}

func shellQuoteSingle(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
