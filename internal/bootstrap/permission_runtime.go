package bootstrap

import (
	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/permission"
)

func NewPermissionService(store *config.ConfigStore) permission.Service {
	cfg := store.Config()

	skipPermissionsRequests := cfg.Permissions != nil && cfg.Permissions.SkipRequests
	var allowedTools []string
	var bypassIntentMarkers []string
	var extraBypassIntentMarkers []string

	if cfg.Permissions != nil && cfg.Permissions.AllowedTools != nil {
		allowedTools = cfg.Permissions.AllowedTools
	}
	if cfg.Permissions != nil {
		bypassIntentMarkers = cfg.Permissions.BypassIntentMarkers
		extraBypassIntentMarkers = cfg.Permissions.ExtraBypassIntentMarkers
	}

	svc := permission.NewPermissionServiceWithBypassMarkers(
		store.WorkingDir(),
		skipPermissionsRequests,
		allowedTools,
		bypassIntentMarkers,
		extraBypassIntentMarkers,
	)

	// Activate strict governance when configured. SetGovernanceStrict is not
	// part of the Service interface (to avoid disturbing mocks), so reach it via
	// type assertion.
	if cfg.GovernanceStrict() {
		if gs, ok := svc.(interface{ SetGovernanceStrict(bool) }); ok {
			gs.SetGovernanceStrict(true)
		}
	}

	return svc
}
