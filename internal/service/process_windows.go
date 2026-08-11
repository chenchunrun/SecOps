//go:build windows

package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

const windowsCreateNewProcessGroup = 0x00000200

func configureServiceProcess(command *exec.Cmd) {
	if command.SysProcAttr == nil {
		command.SysProcAttr = &syscall.SysProcAttr{}
	}
	command.SysProcAttr.CreationFlags |= windowsCreateNewProcessGroup
}

func stopServiceProcess(ctx context.Context, process *os.Process, done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	default:
	}
	command := exec.CommandContext(ctx, "taskkill", "/PID", strconv.Itoa(process.Pid), "/T", "/F")
	output, err := command.CombinedOutput()
	if err != nil {
		select {
		case <-done:
			return nil
		default:
			return fmt.Errorf("kill Windows service process tree: %w: %s", err, strings.TrimSpace(string(output)))
		}
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("wait for Windows service process tree: %w", ctx.Err())
	}
}
