package model

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/chenchunrun/SecOps/internal/audit"
	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/permission"
	"github.com/chenchunrun/SecOps/internal/security"
	"github.com/chenchunrun/SecOps/internal/ui/util"
)

type capabilityCommandKind int

const (
	capabilityCommandList capabilityCommandKind = iota + 1
	capabilityCommandAuthorize
	capabilityCommandRevoke
)

const defaultCapabilityTTL = 30 * time.Minute

var capabilityNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*$`)

type capabilityControlCommand struct {
	kind       capabilityCommandKind
	capability string
	target     string
	ttl        time.Duration
}

func parseCapabilityControlCommand(content string) (capabilityControlCommand, bool, error) {
	fields := strings.Fields(strings.TrimSpace(content))
	if len(fields) == 0 {
		return capabilityControlCommand{}, false, nil
	}
	command := strings.ToLower(fields[0])
	if command == "/capabilities" {
		if len(fields) != 1 {
			return capabilityControlCommand{}, true, fmt.Errorf("usage: /capabilities")
		}
		return capabilityControlCommand{kind: capabilityCommandList}, true, nil
	}
	if command != "/authorize" && command != "/revoke" {
		return capabilityControlCommand{}, false, nil
	}
	if len(fields) < 2 {
		return capabilityControlCommand{}, true, fmt.Errorf("usage: %s <capability> --target <target> [--ttl 30m]", command)
	}
	result := capabilityControlCommand{
		capability: strings.ToLower(strings.TrimSpace(fields[1])),
		ttl:        defaultCapabilityTTL,
	}
	if command == "/authorize" {
		result.kind = capabilityCommandAuthorize
	} else {
		result.kind = capabilityCommandRevoke
	}
	if !capabilityNamePattern.MatchString(result.capability) {
		return capabilityControlCommand{}, true, fmt.Errorf("invalid capability %q; expected namespace:action", fields[1])
	}

	for i := 2; i < len(fields); i++ {
		field := fields[i]
		switch {
		case field == "--target" && i+1 < len(fields):
			i++
			result.target = fields[i]
		case strings.HasPrefix(field, "--target="):
			result.target = strings.TrimPrefix(field, "--target=")
		case field == "--ttl" && i+1 < len(fields):
			if result.kind != capabilityCommandAuthorize {
				return capabilityControlCommand{}, true, fmt.Errorf("--ttl is only valid with /authorize")
			}
			i++
			ttl, err := time.ParseDuration(fields[i])
			if err != nil {
				return capabilityControlCommand{}, true, fmt.Errorf("invalid ttl %q: %w", fields[i], err)
			}
			result.ttl = ttl
		case strings.HasPrefix(field, "--ttl="):
			if result.kind != capabilityCommandAuthorize {
				return capabilityControlCommand{}, true, fmt.Errorf("--ttl is only valid with /authorize")
			}
			ttl, err := time.ParseDuration(strings.TrimPrefix(field, "--ttl="))
			if err != nil {
				return capabilityControlCommand{}, true, fmt.Errorf("invalid ttl %q: %w", field, err)
			}
			result.ttl = ttl
		default:
			return capabilityControlCommand{}, true, fmt.Errorf("unknown or incomplete option %q", field)
		}
	}
	result.target = strings.TrimSpace(result.target)
	result.target = strings.Trim(result.target, "\"'")
	if result.kind == capabilityCommandAuthorize && result.target == "" {
		return capabilityControlCommand{}, true, fmt.Errorf("/authorize requires --target")
	}
	if result.kind == capabilityCommandAuthorize && result.target == "*" {
		return capabilityControlCommand{}, true, fmt.Errorf("/authorize requires a bounded target; '*' is not allowed")
	}
	if result.ttl <= 0 || result.ttl > 24*time.Hour {
		return capabilityControlCommand{}, true, fmt.Errorf("ttl must be greater than zero and no more than 24h")
	}
	return result, true, nil
}

func (m *UI) applyCapabilityControlCommand(command capabilityControlCommand) tea.Cmd {
	if m.com == nil || m.com.App == nil || m.com.App.SecOpsPermissions == nil {
		return util.ReportError(fmt.Errorf("SecOps capability service is unavailable"))
	}
	if !m.hasSession() || strings.TrimSpace(m.session.ID) == "" {
		return util.ReportWarn("Start or open a session before managing temporary capabilities")
	}
	sessionID := m.session.ID
	subject := activeCapabilitySubject(m.com.App.AgentCoordinator.ActiveAgentID())
	service := m.com.App.SecOpsPermissions

	return func() tea.Msg {
		switch command.kind {
		case capabilityCommandList:
			return util.NewInfoMsg(formatCapabilities(service, sessionID, subject))
		case capabilityCommandAuthorize:
			return authorizeSessionCapability(service, sessionID, subject, command)
		case capabilityCommandRevoke:
			return revokeSessionCapability(service, sessionID, subject, command)
		default:
			return util.NewErrorMsg(fmt.Errorf("unsupported capability command"))
		}
	}
}

func activeCapabilitySubject(agentID string) string {
	switch strings.TrimSpace(agentID) {
	case config.AgentSecurityExpertAgent:
		return "analyst"
	case config.AgentOpsAgent:
		return "operator"
	case "":
		return "viewer"
	default:
		return strings.TrimSpace(agentID)
	}
}

func authorizeSessionCapability(
	service permission.SecOpsService,
	sessionID, subject string,
	command capabilityControlCommand,
) tea.Msg {
	authorization, err := security.IssueSessionEngagementAuthorization(
		sessionID,
		command.capability,
		command.target,
		"interactive-user",
		command.ttl,
	)
	if err != nil {
		return util.NewErrorMsg(fmt.Errorf("issue scoped authorization: %w", err))
	}
	var previous permission.CapabilityGrant
	hadPrevious := false
	for _, existing := range service.ListSessionCapabilities(sessionID, subject) {
		if existing.Capability == command.capability && existing.Target == authorization.Targets[0] {
			previous = existing
			hadPrevious = true
			break
		}
	}
	grant := permission.CapabilityGrant{
		SessionID:       sessionID,
		Subject:         subject,
		Capability:      command.capability,
		Target:          authorization.Targets[0],
		AuthorizationID: authorization.ID,
		GrantedBy:       "interactive-user",
		GrantedAt:       authorization.NotBefore,
		ExpiresAt:       authorization.ExpiresAt,
	}
	if err := service.GrantSessionCapability(grant); err != nil {
		_ = security.RevokeGlobalEngagementAuthorization(authorization.ID)
		return util.NewErrorMsg(fmt.Errorf("grant session capability: %w", err))
	}
	event := audit.NewAuditEventBuilder(audit.EventTypeCapabilityGranted).
		WithSession(sessionID).
		WithUser(subject, subject).
		WithAction("authorize_session_capability").
		WithResource("capability", command.capability, authorization.Targets[0]).
		WithApproval(authorization.ID, "interactive-user").
		WithDetail("authorization_id", authorization.ID).
		WithDetail("expires_at", authorization.ExpiresAt.Format(time.RFC3339)).
		WithResult(audit.ResultSuccess).
		Build()
	if err := audit.RecordGlobalDurable(event); err != nil {
		service.RevokeSessionCapability(sessionID, subject, command.capability, authorization.Targets[0])
		if hadPrevious {
			_ = service.GrantSessionCapability(previous)
		}
		_ = security.RevokeGlobalEngagementAuthorization(authorization.ID)
		return util.NewErrorMsg(fmt.Errorf("record capability authorization: %w", err))
	}
	if hadPrevious && previous.AuthorizationID != "" && previous.AuthorizationID != authorization.ID {
		_ = security.RevokeGlobalEngagementAuthorization(previous.AuthorizationID)
	}
	return util.NewInfoMsg(fmt.Sprintf(
		"Authorized %s for %s on %s until %s (authorization_id=%s)",
		command.capability,
		subject,
		authorization.Targets[0],
		authorization.ExpiresAt.Local().Format("2006-01-02 15:04:05 MST"),
		authorization.ID,
	))
}

func revokeSessionCapability(
	service permission.SecOpsService,
	sessionID, subject string,
	command capabilityControlCommand,
) tea.Msg {
	removed := service.RevokeSessionCapability(sessionID, subject, command.capability, command.target)
	if len(removed) == 0 {
		return util.NewWarnMsg("No matching temporary capability grant was found")
	}
	for _, grant := range removed {
		if grant.AuthorizationID != "" {
			_ = security.RevokeGlobalEngagementAuthorization(grant.AuthorizationID)
		}
		event := audit.NewAuditEventBuilder(audit.EventTypeCapabilityRevoked).
			WithSession(sessionID).
			WithUser(subject, subject).
			WithAction("revoke_session_capability").
			WithResource("capability", grant.Capability, grant.Target).
			WithDetail("authorization_id", grant.AuthorizationID).
			WithResult(audit.ResultSuccess).
			Build()
		if err := audit.RecordGlobalDurable(event); err != nil {
			return util.NewErrorMsg(fmt.Errorf("capability revoked but audit persistence failed: %w", err))
		}
	}
	return util.NewInfoMsg(fmt.Sprintf("Revoked %d temporary grant(s) for %s", len(removed), command.capability))
}

func formatCapabilities(service permission.SecOpsService, sessionID, subject string) string {
	role := subject
	defaultSet := make(map[string]struct{})
	for _, inheritedRole := range capabilityDisplayRoles(role) {
		for _, capability := range security.GetCapabilitiesForRole(inheritedRole) {
			defaultSet[capability.Name] = struct{}{}
		}
	}
	defaultNames := make([]string, 0, len(defaultSet))
	for capability := range defaultSet {
		defaultNames = append(defaultNames, capability)
	}
	sort.Strings(defaultNames)
	persistentNames := service.ListCapabilities(subject)
	sort.Strings(persistentNames)
	grants := service.ListSessionCapabilities(sessionID, subject)
	sort.Slice(grants, func(i, j int) bool {
		if grants[i].Capability == grants[j].Capability {
			return grants[i].Target < grants[j].Target
		}
		return grants[i].Capability < grants[j].Capability
	})

	var output strings.Builder
	fmt.Fprintf(&output, "Role: %s\nDefault capabilities: %s", role, strings.Join(defaultNames, ", "))
	if len(defaultNames) == 0 {
		output.WriteString("none")
	}
	output.WriteString("\nPersistent config grants: ")
	if len(persistentNames) == 0 {
		output.WriteString("none")
	} else {
		output.WriteString(strings.Join(persistentNames, ", "))
	}
	output.WriteString("\nTemporary session grants:")
	if len(grants) == 0 {
		output.WriteString(" none")
		return output.String()
	}
	for _, grant := range grants {
		fmt.Fprintf(
			&output,
			"\n- %s target=%s expires=%s authorization_id=%s",
			grant.Capability,
			grant.Target,
			grant.ExpiresAt.Local().Format("2006-01-02 15:04:05 MST"),
			grant.AuthorizationID,
		)
	}
	return output.String()
}

func capabilityDisplayRoles(role string) []string {
	switch role {
	case "admin":
		return []string{"admin", "operator", "viewer", "responder", "analyst"}
	case "operator":
		return []string{"operator", "viewer"}
	case "responder":
		return []string{"responder", "analyst", "viewer"}
	case "analyst":
		return []string{"analyst", "viewer"}
	default:
		return []string{role}
	}
}
