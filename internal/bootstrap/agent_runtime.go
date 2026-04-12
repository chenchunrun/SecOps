package bootstrap

import (
	"context"

	"github.com/chenchunrun/SecOps/internal/agent"
	"github.com/chenchunrun/SecOps/internal/agent/notify"
	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/filetracker"
	"github.com/chenchunrun/SecOps/internal/history"
	"github.com/chenchunrun/SecOps/internal/lsp"
	"github.com/chenchunrun/SecOps/internal/message"
	"github.com/chenchunrun/SecOps/internal/orchestrator"
	"github.com/chenchunrun/SecOps/internal/permission"
	"github.com/chenchunrun/SecOps/internal/pubsub"
	"github.com/chenchunrun/SecOps/internal/session"
)

type AgentCoordinatorDeps struct {
	Config             *config.ConfigStore
	Sessions           session.Service
	Messages           message.Service
	Permissions        permission.Service
	History            history.Service
	FileTracker        filetracker.Service
	LSPManager         *lsp.Manager
	AgentNotifications pubsub.Publisher[notify.Notification]
}

func NewAgentCoordinator(ctx context.Context, deps AgentCoordinatorDeps) (agent.Coordinator, error) {
	baseCoordinator, err := agent.NewCoordinator(
		ctx,
		deps.Config,
		deps.Sessions,
		deps.Messages,
		deps.Permissions,
		deps.History,
		deps.FileTracker,
		deps.LSPManager,
		deps.AgentNotifications,
	)
	if err != nil {
		return nil, err
	}

	return orchestrator.NewTurnOrchestrator(baseCoordinator), nil
}
