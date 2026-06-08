// Package handoff parses structured agent-to-agent transfer blocks embedded in
// Markdown assistant messages (Crush Handoff v1).
package handoff

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Size limits guard against oversized or abusive payloads.
const (
	MaxJSONBodyBytes = 32 * 1024
	MaxSummaryBytes  = 8 * 1024
	MaxFollowups     = 64
	MaxPathEntries   = 256
	MaxPathLen       = 4096
	// MaxPromptInjectionBytes caps the serialized handoff embedded in user prompts.
	MaxPromptInjectionBytes = 16 * 1024
)

// ErrNoValidHandoff is returned when Markdown contains no qualifying block.
var ErrNoValidHandoff = errors.New("no valid handoff block found")

// Handoff is the normalized v1 payload after JSON parsing and validation.
type Handoff struct {
	Version      int      `json:"handoff_version"`
	FromAgent    string   `json:"from_agent"`
	ToAgent      string   `json:"to_agent"`
	Summary      string   `json:"summary"`
	TouchedPaths []string `json:"touched_paths"`
	RiskLevel    string   `json:"risk_level,omitempty"`
	Followups    []string `json:"followups"`
	AuditRef     string   `json:"audit_ref,omitempty"`
}

type wireHandoff struct {
	HandoffVersion any      `json:"handoff_version"`
	SourceAgent    string   `json:"source_agent,omitempty"`
	FromAgent      string   `json:"from_agent,omitempty"`
	TargetAgent    string   `json:"target_agent,omitempty"`
	ToAgent        string   `json:"to_agent,omitempty"`
	Summary        string   `json:"summary,omitempty"`
	TouchedPaths   []string `json:"touched_paths,omitempty"`
	RiskLevel      string   `json:"risk_level,omitempty"`
	Followups      []string `json:"followups,omitempty"`
	AuditRef       string   `json:"audit_ref,omitempty"`
}

var markdownFenceRE = regexp.MustCompile("(?s)```([a-zA-Z0-9._+-]*)[ \t]*\n(.*?)```")

// ParseJSON parses and validates Handoff JSON (not necessarily from Markdown).
func ParseJSON(raw []byte) (*Handoff, error) {
	if len(raw) > MaxJSONBodyBytes {
		return nil, fmt.Errorf("handoff json exceeds max size (%d bytes)", MaxJSONBodyBytes)
	}
	trim := bytes.TrimSpace(raw)
	var w wireHandoff
	if err := json.Unmarshal(trim, &w); err != nil {
		return nil, fmt.Errorf("handoff json: %w", err)
	}

	ver, err := coerceVersion(w.HandoffVersion)
	if err != nil {
		return nil, err
	}
	from := strings.TrimSpace(w.FromAgent)
	if from == "" {
		from = strings.TrimSpace(w.SourceAgent)
	}
	to := strings.TrimSpace(w.ToAgent)
	if to == "" {
		to = strings.TrimSpace(w.TargetAgent)
	}

	out := &Handoff{
		Version:      ver,
		FromAgent:    from,
		ToAgent:      to,
		Summary:      strings.TrimSpace(w.Summary),
		TouchedPaths: append([]string(nil), w.TouchedPaths...),
		RiskLevel:    strings.TrimSpace(strings.ToLower(w.RiskLevel)),
		Followups:    append([]string(nil), w.Followups...),
		AuditRef:     strings.TrimSpace(w.AuditRef),
	}
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return out, nil
}

// ExtractFromMarkdown finds fenced blocks whose info string is explicitly
// ```crush-handoff or ```handoff and returns the first body that unmarshals as
// a valid Handoff v1 payload. Bare and generic (e.g. ```json) fences are
// intentionally ignored to keep the prompt-injection surface scoped to the
// dedicated handoff namespace.
func ExtractFromMarkdown(md string) (*Handoff, error) {
	matches := markdownFenceRE.FindAllStringSubmatch(md, -1)
	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		info := strings.TrimSpace(strings.ToLower(m[1]))
		body := strings.TrimSpace(m[2])
		if len(body) > MaxJSONBodyBytes {
			continue
		}
		if !fenceLanguageAllowed(info) {
			continue
		}
		h, err := ParseJSON([]byte(body))
		if err != nil {
			continue
		}
		return h, nil
	}
	return nil, ErrNoValidHandoff
}

func fenceLanguageAllowed(info string) bool {
	switch info {
	case "handoff", "crush-handoff":
		return true
	default:
		return false
	}
}

func coerceVersion(v any) (int, error) {
	switch t := v.(type) {
	case nil:
		return 0, errors.New("handoff_version is required")
	case float64:
		i := int(t)
		if float64(i) != t {
			return 0, fmt.Errorf("handoff_version must be integral, got %v", t)
		}
		if i != 1 {
			return 0, fmt.Errorf("unsupported handoff_version %d (only 1 supported)", i)
		}
		return i, nil
	case json.Number:
		i64, err := t.Int64()
		if err != nil {
			return 0, fmt.Errorf("handoff_version: %w", err)
		}
		if i64 != 1 {
			return 0, fmt.Errorf("unsupported handoff_version %d (only 1 supported)", i64)
		}
		return int(i64), nil
	case string:
		s := strings.TrimSpace(strings.TrimPrefix(t, "v"))
		if s != "1" {
			return 0, fmt.Errorf("unsupported handoff_version %q (only 1 supported)", t)
		}
		return 1, nil
	default:
		return 0, fmt.Errorf("unsupported handoff_version type %T", v)
	}
}

// Validate checks semantic constraints on Handoff fields.
func (h *Handoff) Validate() error {
	if h == nil {
		return errors.New("handoff is nil")
	}
	if h.Version != 1 {
		return fmt.Errorf("handoff_version must be 1, got %d", h.Version)
	}
	if h.FromAgent == "" {
		return errors.New("from_agent or source_agent is required")
	}
	if h.ToAgent == "" {
		// A missing target would otherwise broadcast the handoff into every
		// consuming agent in the session; require an explicit recipient.
		return errors.New("to_agent or target_agent is required")
	}
	if h.Summary == "" {
		return errors.New("summary is required")
	}
	if len(h.Summary) > MaxSummaryBytes {
		return fmt.Errorf("summary exceeds %d bytes", MaxSummaryBytes)
	}
	if len(h.Followups) > MaxFollowups {
		return fmt.Errorf("followups exceeds %d entries", MaxFollowups)
	}
	if len(h.TouchedPaths) > MaxPathEntries {
		return fmt.Errorf("touched_paths exceeds %d entries", MaxPathEntries)
	}
	switch h.RiskLevel {
	case "", "informational", "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("invalid risk_level %q", h.RiskLevel)
	}
	for _, p := range h.TouchedPaths {
		if err := validateSafePath(p); err != nil {
			return err
		}
	}
	return nil
}

type promptInjectionWire struct {
	HandoffVersion int    `json:"handoff_version"`
	FromAgent      string `json:"from_agent"`
	ToAgent        string `json:"to_agent"`
	Summary        string `json:"summary"`
	RiskLevel      string `json:"risk_level,omitempty"`
	AuditRef       string `json:"audit_ref,omitempty"`
}

func truncateUTF8ByBytes(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	s = s[:maxBytes]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// FormatForPrompt wraps a validated Handoff as a stable, length-bounded block for
// the next agent turn.
func FormatForPrompt(h *Handoff) string {
	if h == nil {
		return ""
	}

	raw, err := json.Marshal(h)
	if err != nil {
		return ""
	}

	var slim promptInjectionWire
	usingSlim := false
	if len(raw) > MaxPromptInjectionBytes {
		slim = promptInjectionWire{
			HandoffVersion: h.Version,
			FromAgent:      h.FromAgent,
			ToAgent:        h.ToAgent,
			Summary:        truncateUTF8ByBytes(h.Summary, MaxSummaryBytes),
			RiskLevel:      h.RiskLevel,
			AuditRef:       h.AuditRef,
		}
		raw, err = json.Marshal(slim)
		if err != nil {
			return ""
		}
		usingSlim = true
	}

	for usingSlim && len(raw) > MaxPromptInjectionBytes && len(slim.Summary) > 256 {
		slim.Summary = truncateUTF8ByBytes(slim.Summary, len(slim.Summary)*2/3)
		raw, err = json.Marshal(slim)
		if err != nil {
			return ""
		}
	}

	if len(raw) > MaxPromptInjectionBytes {
		return ""
	}

	var b strings.Builder
	b.Grow(len(raw) + 80)
	b.WriteString("<structured_handoff>\n```crush-handoff\n")
	b.Write(raw)
	b.WriteString("\n```\n</structured_handoff>\n\n")
	return b.String()
}

func validateSafePath(p string) error {
	s := filepath.ToSlash(strings.TrimSpace(p))
	if s == "" {
		return errors.New("touched_paths entry is empty")
	}
	if strings.Contains(s, "\x00") {
		return fmt.Errorf("touched_paths entry contains NUL: %q", p)
	}
	if len(p) > MaxPathLen {
		return fmt.Errorf("touched_paths entry exceeds %d chars", MaxPathLen)
	}
	if filepath.IsAbs(p) {
		// Absolute paths are rejected to avoid handing off unintended host paths.
		return fmt.Errorf("touched_paths must be relative-workspace paths, got absolute %q", p)
	}
	clean := filepath.ToSlash(filepath.Clean(s))
	segs := strings.Split(clean, "/")
	for _, seg := range segs {
		if seg == ".." {
			return fmt.Errorf(`touched_paths entry %q contains ".."`, p)
		}
	}
	return nil
}
