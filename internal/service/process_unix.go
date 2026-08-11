//go:build !windows

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const unixServiceStopGrace = 250 * time.Millisecond

func configureServiceProcess(command *exec.Cmd) {
	if command.SysProcAttr == nil {
		command.SysProcAttr = &syscall.SysProcAttr{}
	}
	command.SysProcAttr.Setpgid = true
}

func stopServiceProcess(ctx context.Context, process *os.Process, done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	default:
	}
	if err := signalProcessGroup(process.Pid, syscall.SIGTERM); err != nil {
		return fmt.Errorf("terminate local service process group: %w", err)
	}
	timer := time.NewTimer(unixServiceStopGrace)
	defer timer.Stop()
	select {
	case <-done:
		if err := signalProcessGroup(process.Pid, syscall.SIGKILL); err != nil {
			return fmt.Errorf("clean local service process group: %w", err)
		}
		return nil
	case <-timer.C:
	case <-ctx.Done():
		_ = signalProcessGroup(process.Pid, syscall.SIGKILL)
		return fmt.Errorf("stop local service process group: %w", ctx.Err())
	}
	if err := signalProcessGroup(process.Pid, syscall.SIGKILL); err != nil {
		return fmt.Errorf("kill local service process group: %w", err)
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("wait for local service process group: %w", ctx.Err())
	}
}

func signalProcessGroup(processID int, signal syscall.Signal) error {
	err := syscall.Kill(-processID, signal)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}
