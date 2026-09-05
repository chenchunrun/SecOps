package connectors

import (
	"context"
	"errors"
	"time"
)

type ApprovalRecord struct {
	Scope      ApprovalRequest
	ApprovedBy string
	NotBefore  time.Time
	ExpiresAt  time.Time
	Revoked    bool
}

type ApprovalStore interface {
	GetApproval(context.Context, string) (ApprovalRecord, error)
}

// StoredApprovalVerifier reloads the authoritative record on every write.
type StoredApprovalVerifier struct{ Store ApprovalStore }

func (v StoredApprovalVerifier) VerifyApproval(ctx context.Context, request ApprovalRequest) error {
	if v.Store == nil || request.ApprovalID == "" || request.SessionID == "" {
		return errors.New("approval store and scoped identity are required")
	}
	record, err := v.Store.GetApproval(ctx, request.ApprovalID)
	if err != nil {
		return err
	}
	now := time.Now()
	if record.Scope != request || record.ApprovedBy == "" || record.Revoked || record.NotBefore.IsZero() || now.Before(record.NotBefore) || !now.Before(record.ExpiresAt) {
		return errors.New("approval is expired, revoked, or does not match this operation")
	}
	return nil
}
