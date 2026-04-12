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

	return permission.NewPermissionServiceWithBypassMarkers(
		store.WorkingDir(),
		skipPermissionsRequests,
		allowedTools,
		bypassIntentMarkers,
		extraBypassIntentMarkers,
	)
}
