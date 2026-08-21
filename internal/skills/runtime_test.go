package skills

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCoreSkillRuntimeContracts(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"phishing-analysis", "auth-log-analysis", "linux-ir", "code-audit",
		"sca-analyzer", "prompt-injection-detect", "ttp-extractor", "redteam-intrusion-hunter",
	} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			manifest := loadCommittedManifest(t, name)
			platform := manifest.Runtime.Platforms[0]
			grants := capabilityGrants(manifest)

			successExecutor := &contractExecutor{output: validRuntimeOutput("task-contract")}
			runner, err := NewRunner(successExecutor)
			require.NoError(t, err)
			result, err := runner.Run(context.Background(), manifest, RuntimeRequest{
				Platform: platform, SignedScope: manifest.Authorization.Required,
				GrantedCapabilities: grants, Input: map[string]interface{}{"task_id": "task-contract", "parameters": map[string]interface{}{}},
			})
			require.NoError(t, err)
			require.Equal(t, manifest.Risk.Base, result.Risk)
			require.Equal(t, "untrusted", successExecutor.lastInput.Trust)

			failureRunner, err := NewRunner(&contractExecutor{err: errors.New("tool failed")})
			require.NoError(t, err)
			_, err = failureRunner.Run(context.Background(), manifest, RuntimeRequest{
				Platform: platform, SignedScope: manifest.Authorization.Required,
				GrantedCapabilities: grants, Input: map[string]interface{}{"task_id": "task-failure"},
			})
			require.ErrorContains(t, err, "tool failed")

			timeoutManifest := manifest
			timeoutManifest.Runtime.Timeout = 10 * time.Millisecond
			timeoutRunner, err := NewRunner(&contractExecutor{wait: true})
			require.NoError(t, err)
			_, err = timeoutRunner.Run(context.Background(), timeoutManifest, RuntimeRequest{
				Platform: platform, SignedScope: manifest.Authorization.Required,
				GrantedCapabilities: grants, Input: map[string]interface{}{"task_id": "task-timeout"},
			})
			require.ErrorIs(t, err, context.DeadlineExceeded)

			_, err = runner.Run(context.Background(), manifest, RuntimeRequest{
				Platform: platform, SignedScope: manifest.Authorization.Required,
				GrantedCapabilities: map[string]bool{}, Input: map[string]interface{}{"task_id": "task-denied"},
			})
			require.ErrorIs(t, err, ErrCapabilityDenied)
		})
	}
}

func TestRunnerRejectsInvalidAndOversizedOutput(t *testing.T) {
	t.Parallel()
	manifest := loadCommittedManifest(t, "phishing-analysis")
	grants := capabilityGrants(manifest)
	manifest.Runtime.OutputLimit = 8
	runner, err := NewRunner(&contractExecutor{output: validRuntimeOutput("task-output")})
	require.NoError(t, err)
	_, err = runner.Run(context.Background(), manifest, RuntimeRequest{
		Platform: runtime.GOOS, GrantedCapabilities: grants, Input: map[string]interface{}{"task_id": "task-output"},
	})
	require.ErrorIs(t, err, ErrOutputLimit)

	runner, err = NewRunner(&contractExecutor{output: map[string]interface{}{"task_id": "missing-fields"}})
	require.NoError(t, err)
	manifest.Runtime.OutputLimit = 1024
	_, err = runner.Run(context.Background(), manifest, RuntimeRequest{
		Platform: runtime.GOOS, GrantedCapabilities: grants, Input: map[string]interface{}{"task_id": "missing-fields"},
	})
	require.ErrorIs(t, err, ErrInvalidOutput)
}

type contractExecutor struct {
	output    map[string]interface{}
	err       error
	wait      bool
	lastInput RuntimeInput
}

func (e *contractExecutor) Execute(ctx context.Context, _ SkillManifest, input RuntimeInput) (map[string]interface{}, error) {
	e.lastInput = input
	if e.wait {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return e.output, e.err
}

func loadCommittedManifest(t *testing.T, name string) SkillManifest {
	t.Helper()
	root := repoRoot(t)
	content, err := exec.CommandContext(t.Context(), "git", "show", "HEAD:skills/"+name+"/SKILL.md").Output()
	require.NoError(t, err)
	manifest, err := LoadManifestWithSkillContent(filepath.Join(root, "skills", name, "manifest.yaml"), content)
	require.NoError(t, err)
	return *manifest
}

func capabilityGrants(manifest SkillManifest) map[string]bool {
	grants := make(map[string]bool, len(manifest.Capabilities.Required))
	for _, capability := range manifest.Capabilities.Required {
		grants[capability] = true
	}
	return grants
}

func validRuntimeOutput(taskID string) map[string]interface{} {
	return map[string]interface{}{
		"task_id": taskID, "evidence_ids": []string{"evidence-1"}, "facts": []interface{}{},
		"findings": []interface{}{}, "verification": []interface{}{},
	}
}
