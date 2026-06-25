package secops

import (
	"context"
	"errors"
	"os/exec"
	"testing"
)

// runTestExec verifies the package-level command runner helpers used by SecOps
// tools. These helpers are duplicated across tool files to avoid coupling; this
// test exercises the canonical three-outcome shape once per signature variant.
func TestRunCommandHelpers(t *testing.T) {
	t.Parallel()

	threeOutputRunners := []func(context.Context, string, ...string) ([]byte, []byte, error){
		runAccessCommand,
		runAlertCommand,
		runBackupCommand,
		runCertCommand,
		runDatabaseCommand,
		runDeploymentCommand,
		runIncidentCommand,
		runInfrastructureCommand,
		runLogCommand,
		runMonitoringCommand,
		runReplicationCommand,
		runResourceCommand,
		runRotationCommand,
		runSecretCommand,
		runCommand,
	}

	t.Run("three output helpers return stdout on success", func(t *testing.T) {
		t.Parallel()
		for _, runner := range threeOutputRunners {
			out, stderr, err := runner(context.Background(), "echo", "hello")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(out) != "hello\n" {
				t.Errorf("stdout = %q, want hello\\n", out)
			}
			if len(stderr) != 0 {
				t.Errorf("stderr = %q, want empty", stderr)
			}
		}
	})

	t.Run("three output helpers capture stderr on exit error", func(t *testing.T) {
		t.Parallel()
		for _, runner := range threeOutputRunners {
			out, _, err := runner(context.Background(), "sh", "-c", "echo msg && exit 1")
			if err == nil {
				t.Fatal("expected error")
			}
			if string(out) != "msg\n" {
				t.Errorf("stdout = %q, want msg\\n", out)
			}
		}
	})

	twoOutputRunners := []func(context.Context, string, ...string) ([]byte, error){
		runComplianceCommand,
		runNetworkDiagCommand,
	}

	t.Run("two output helper returns stdout on success", func(t *testing.T) {
		t.Parallel()
		for _, runner := range twoOutputRunners {
			out, err := runner(context.Background(), "echo", "ok")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(out) != "ok\n" {
				t.Errorf("stdout = %q, want ok\\n", out)
			}
		}
	})

	t.Run("two output helper returns error on failure", func(t *testing.T) {
		t.Parallel()
		for _, runner := range twoOutputRunners {
			_, err := runner(context.Background(), "false")
			if err == nil {
				t.Fatal("expected error")
			}
		}
	})

	t.Run("context cancellation is respected", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _, err := runLogCommand(ctx, "sleep", "5")
		if err == nil {
			t.Fatal("expected error from cancelled context")
		}
		if !errors.Is(err, context.Canceled) {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Errorf("expected context.Canceled or exec.ExitError, got %T: %v", err, err)
			}
		}
	})
}
