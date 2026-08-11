package bootstrap

import (
	"fmt"

	"github.com/chenchunrun/SecOps/internal/egress"
	"github.com/chenchunrun/SecOps/internal/scheduler"
)

// NewConfiguredProtectedScheduledTaskRuntime builds protected execution from a
// secret-free egress configuration file. Credential values remain in the
// process environment until a short-lived lease is issued.
func NewConfiguredProtectedScheduledTaskRuntime(
	runtime *ComputerRuntime,
	runtimeScheduler *scheduler.Scheduler,
	configPath string,
) (*ProtectedScheduledTaskRuntime, error) {
	config, err := egress.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("load protected task egress config: %w", err)
	}
	source, err := egress.NewEnvironmentSource(config.CredentialEnvironment)
	if err != nil {
		return nil, fmt.Errorf("create protected task credential source: %w", err)
	}
	broker, err := egress.NewBroker(source, config.MaxCredentialTTL)
	if err != nil {
		return nil, fmt.Errorf("create protected task credential broker: %w", err)
	}
	observer, err := egress.NewFileObserver(config.AuditPath)
	if err != nil {
		return nil, fmt.Errorf("create protected task egress observer: %w", err)
	}
	return NewProtectedScheduledTaskRuntime(
		runtime,
		runtimeScheduler,
		config.Policy,
		broker,
		WithEgressObserver(observer),
	)
}
