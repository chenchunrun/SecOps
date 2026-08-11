package sandbox

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLocalCommandReceivesTransientEnvironment(t *testing.T) {
	t.Setenv("SECOPS_EXISTING_VALUE", "old")

	command := NewLocalExecutor().buildCommand(context.Background(), "echo test", SandboxConfig{
		Environment: map[string]string{
			"SECOPS_EXISTING_VALUE": "replacement",
			"SECOPS_PROXY_TOKEN":    "secret-value",
		},
	})

	require.Equal(t, "replacement", environmentValue(command.Env, "SECOPS_EXISTING_VALUE"))
	require.Equal(t, "secret-value", environmentValue(command.Env, "SECOPS_PROXY_TOKEN"))
	require.Equal(t, 1, environmentCount(command.Env, "SECOPS_EXISTING_VALUE"))
}

func TestDockerCommandPassesOnlyEnvironmentNamesAsArguments(t *testing.T) {
	t.Parallel()

	const secret = "secret-value-must-not-enter-process-arguments"
	config := SandboxConfig{
		DockerImage: "alpine:latest",
		Environment: map[string]string{
			"PROXY_TOKEN": secret,
			"REGION":      "test",
		},
	}
	executor := NewDockerExecutor()
	args := executor.buildDockerArgs("echo test", config)
	joined := strings.Join(args, " ")
	require.NotContains(t, joined, secret)
	require.Contains(t, joined, "--env PROXY_TOKEN")
	require.Contains(t, joined, "--env REGION")

	environment := executor.buildDockerEnvironment(config)
	require.Equal(t, secret, environmentValue(environment, "PROXY_TOKEN"))
	require.Equal(t, "test", environmentValue(environment, "REGION"))
}

func TestTransientEnvironmentIsExcludedFromJSON(t *testing.T) {
	t.Parallel()

	data, err := json.Marshal(SandboxConfig{
		Environment: map[string]string{"PROXY_TOKEN": "secret-value"},
	})
	require.NoError(t, err)
	require.NotContains(t, string(data), "PROXY_TOKEN")
	require.NotContains(t, string(data), "secret-value")
}

func environmentValue(environment []string, name string) string {
	prefix := name + "="
	for _, value := range environment {
		if strings.HasPrefix(value, prefix) {
			return strings.TrimPrefix(value, prefix)
		}
	}
	return ""
}

func environmentCount(environment []string, name string) int {
	prefix := name + "="
	count := 0
	for _, value := range environment {
		if strings.HasPrefix(value, prefix) {
			count++
		}
	}
	return count
}
