package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// GenesisSignature is the seed value prepended to the first event in a hash
// chain. Using a fixed, well-known constant makes the chain reproducible while
// still binding every subsequent entry to its predecessor.
const GenesisSignature = "secops-audit-genesis-v1"

// canonicalEventBytes returns a deterministic byte representation of an event
// used as the signing input. The Signature field itself is excluded so that
// signing is idempotent. Map-valued fields (Details) are encoded with
// encoding/json, which emits object keys in sorted order, keeping the output
// stable across runs.
func canonicalEventBytes(e *AuditEvent) []byte {
	var b strings.Builder
	write := func(label, value string) {
		b.WriteString(label)
		b.WriteByte('=')
		b.WriteString(value)
		b.WriteByte('\n')
	}

	write("id", e.ID)
	write("event_type", string(e.EventType))
	write("timestamp", strconv.FormatInt(e.Timestamp.UTC().UnixNano(), 10))
	write("session_id", e.SessionID)
	write("user_id", e.UserID)
	write("username", e.Username)
	write("source_ip", e.SourceIP)
	write("action", e.Action)
	write("resource_type", e.ResourceType)
	write("resource_name", e.ResourceName)
	write("resource_path", e.ResourcePath)
	write("transport", e.Transport)
	write("target_host", e.TargetHost)
	write("target_env", e.TargetEnv)
	write("target_id", e.TargetID)
	write("result", string(e.Result))
	write("error_msg", e.ErrorMsg)
	write("risk_score", strconv.Itoa(e.RiskScore))
	write("risk_level", e.RiskLevel)
	write("severity", e.Severity)
	write("approval_id", e.ApprovalID)
	write("approved_by", e.ApprovedBy)
	write("approved_at", strconv.FormatInt(e.ApprovedAt.UTC().UnixNano(), 10))
	write("reason", e.Reason)

	if len(e.Details) > 0 {
		if detailsJSON, err := json.Marshal(e.Details); err == nil {
			write("details", string(detailsJSON))
		}
	}
	if e.ChangeData != nil {
		if changeJSON, err := json.Marshal(e.ChangeData); err == nil {
			write("change_data", string(changeJSON))
		}
	}
	return []byte(b.String())
}

// ComputeSignature returns the chained signature for an event given the prior
// event's signature: SHA256(prevSig || canonical(event)). Any modification to a
// stored event or reordering of the chain invalidates every signature that
// follows it, making tampering detectable via VerifyChain.
func ComputeSignature(prevSig string, e *AuditEvent) string {
	h := sha256.New()
	h.Write([]byte(prevSig))
	h.Write(canonicalEventBytes(e))
	return hex.EncodeToString(h.Sum(nil))
}

// signingChain tracks the most recent signature so successive events can be
// linked. It is safe for concurrent use.
type signingChain struct {
	mu      sync.Mutex
	lastSig string
}

func newSigningChain(lastSig string) *signingChain {
	if lastSig == "" {
		lastSig = GenesisSignature
	}
	return &signingChain{lastSig: lastSig}
}

// sign assigns a chained signature to the event and advances the chain.
func (c *signingChain) sign(e *AuditEvent) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	sig := ComputeSignature(c.lastSig, e)
	e.Signature = sig
	c.lastSig = sig
	return sig
}

// VerifyChain recomputes signatures for events in chronological order and
// returns an error identifying the first event whose stored signature does not
// match, which indicates tampering, deletion, or reordering. Events must be
// supplied in ascending timestamp order (the order ListEvents returns them).
func VerifyChain(events []*AuditEvent) error {
	prev := GenesisSignature
	for i, e := range events {
		if e == nil {
			return fmt.Errorf("audit chain broken: nil event at index %d", i)
		}
		want := ComputeSignature(prev, e)
		if e.Signature != want {
			return fmt.Errorf(
				"audit chain broken at index %d (event %s): signature mismatch",
				i, e.ID,
			)
		}
		prev = e.Signature
	}
	return nil
}
