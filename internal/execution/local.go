package execution

import (
	"cmp"
	"context"
	"fmt"
	"time"

	"github.com/chenchunrun/SecOps/internal/shell"
)

const DefaultAutoBackgroundAfter = 60

type localExecutor struct {
	handler LocalHandler
}

func NewLocalExecutor(middlewares ...LocalMiddleware) LocalExecutor {
	base := func(ctx context.Context, req LocalRequest) (LocalResult, error) {
		if req.RunInBackground {
			return runImmediatelyInBackground(req)
		}
		return runWithAutoBackground(ctx, req)
	}
	allMiddlewares := make([]LocalMiddleware, 0, len(middlewares)+1)
	allMiddlewares = append(allMiddlewares, ErrorClassificationMiddleware())
	allMiddlewares = append(allMiddlewares, PolicyLocalMiddleware())
	allMiddlewares = append(allMiddlewares, AuditLocalMiddleware())
	allMiddlewares = append(allMiddlewares, middlewares...)

	return localExecutor{
		handler: ChainLocalMiddlewares(base, allMiddlewares...),
	}
}

func (e localExecutor) Execute(ctx context.Context, req LocalRequest) (LocalResult, error) {
	return e.handler(ctx, req)
}

func runImmediatelyInBackground(req LocalRequest) (LocalResult, error) {
	bgManager := shell.GetBackgroundShellManager()
	bgManager.Cleanup()
	bgShell, err := bgManager.Start(context.Background(), req.WorkingDir, req.BlockFuncs, req.Command, req.Description)
	if err != nil {
		return LocalResult{}, &LocalExecutionError{Kind: LocalErrorKindStart, Cause: fmt.Errorf("error starting background shell: %w", err)}
	}

	time.Sleep(1 * time.Second)
	stdout, stderr, done, execErr := bgShell.GetOutput()
	if done {
		bgManager.Remove(bgShell.ID)

		interrupted := shell.IsInterrupt(execErr)
		exitCode := shell.ExitCode(execErr)
		if exitCode == 0 && !interrupted && execErr != nil {
			return LocalResult{}, fmt.Errorf("[Job %s] error executing command: %w", bgShell.ID, execErr)
		}

		return LocalResult{
			Output:           formatOutput(stdout, stderr, execErr),
			WorkingDirectory: bgShell.WorkingDir,
			Background:       false,
		}, nil
	}

	return LocalResult{
		WorkingDirectory: bgShell.WorkingDir,
		Background:       true,
		ShellID:          bgShell.ID,
	}, nil
}

func runWithAutoBackground(ctx context.Context, req LocalRequest) (LocalResult, error) {
	bgManager := shell.GetBackgroundShellManager()
	bgManager.Cleanup()
	bgShell, err := bgManager.Start(context.Background(), req.WorkingDir, req.BlockFuncs, req.Command, req.Description)
	if err != nil {
		return LocalResult{}, &LocalExecutionError{Kind: LocalErrorKindStart, Cause: fmt.Errorf("error starting shell: %w", err)}
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	autoBackgroundAfter := time.Duration(cmp.Or(req.AutoBackgroundAfter, DefaultAutoBackgroundAfter)) * time.Second
	timeout := time.After(autoBackgroundAfter)

	var stdout, stderr string
	var done bool
	var execErr error

waitLoop:
	for {
		select {
		case <-ticker.C:
			stdout, stderr, done, execErr = bgShell.GetOutput()
			if done {
				break waitLoop
			}
		case <-timeout:
			stdout, stderr, done, execErr = bgShell.GetOutput()
			break waitLoop
		case <-ctx.Done():
			bgManager.Kill(bgShell.ID)
			return LocalResult{}, ctx.Err()
		}
	}

	if done {
		bgManager.Remove(bgShell.ID)

		interrupted := shell.IsInterrupt(execErr)
		exitCode := shell.ExitCode(execErr)
		if exitCode == 0 && !interrupted && execErr != nil {
			return LocalResult{}, fmt.Errorf("[Job %s] error executing command: %w", bgShell.ID, execErr)
		}

		return LocalResult{
			Output:           formatOutput(stdout, stderr, execErr),
			WorkingDirectory: bgShell.WorkingDir,
			Background:       false,
		}, nil
	}

	return LocalResult{
		WorkingDirectory: bgShell.WorkingDir,
		Background:       true,
		ShellID:          bgShell.ID,
	}, nil
}

func formatOutput(stdout, stderr string, execErr error) string {
	interrupted := shell.IsInterrupt(execErr)
	exitCode := shell.ExitCode(execErr)

	errorMessage := stderr
	if errorMessage == "" && execErr != nil {
		errorMessage = execErr.Error()
	}

	hasBothOutputs := stdout != "" && stderr != ""
	if hasBothOutputs {
		stdout += "\n"
	}

	if interrupted {
		if errorMessage != "" {
			errorMessage += "\n"
		}
		errorMessage += "Command was aborted before completion"
	} else if exitCode != 0 {
		if errorMessage != "" {
			errorMessage += "\n"
		}
		errorMessage += fmt.Sprintf("Exit code %d", exitCode)
	}

	if errorMessage != "" {
		stdout += "\n" + errorMessage
	}

	return stdout
}
