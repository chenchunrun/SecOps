package quality

type ActionClass string

const (
	ActionReadOnlyInvestigation ActionClass = "read_only_investigation"
	ActionApprovedResponse      ActionClass = "approved_response"
	ActionAutomaticResponse     ActionClass = "automatic_response"
	ActionRedTeam               ActionClass = "red_team"
)

type ReleasePolicy struct {
	ReadOnlyInvestigation bool
	ApprovedResponse      bool
	AutomaticResponse     bool
	RedTeam               bool
	EmergencyRollback     bool
}

func DefaultReleasePolicy() ReleasePolicy {
	return ReleasePolicy{ReadOnlyInvestigation: true}
}

func (p ReleasePolicy) Allows(action ActionClass, approved, signedScope bool) bool {
	if p.EmergencyRollback {
		return action == ActionReadOnlyInvestigation && p.ReadOnlyInvestigation
	}
	switch action {
	case ActionReadOnlyInvestigation:
		return p.ReadOnlyInvestigation
	case ActionApprovedResponse:
		return p.ApprovedResponse && approved
	case ActionAutomaticResponse:
		return p.AutomaticResponse
	case ActionRedTeam:
		return p.RedTeam && signedScope
	default:
		return false
	}
}
