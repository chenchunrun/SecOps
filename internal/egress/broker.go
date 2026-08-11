package egress

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidBroker         = errors.New("invalid credential broker")
	ErrInvalidBinding        = errors.New("invalid credential binding")
	ErrInvalidLeaseTTL       = errors.New("invalid credential lease ttl")
	ErrCredentialUnavailable = errors.New("credential unavailable")
	ErrLeaseExpired          = errors.New("credential lease expired")
	ErrLeaseRevoked          = errors.New("credential lease revoked")
)

var environmentNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Source resolves opaque credential references from storage outside execution
// environments.
type Source interface {
	Resolve(ctx context.Context, reference string) ([]byte, error)
}

// Binding maps an opaque credential reference to a transient environment name.
type Binding struct {
	Reference   string
	Environment string
}

// BrokerOption customizes Broker behavior.
type BrokerOption func(*Broker)

// WithClock supplies a clock for deterministic expiry checks.
func WithClock(clock func() time.Time) BrokerOption {
	return func(broker *Broker) {
		if clock != nil {
			broker.clock = clock
		}
	}
}

// Broker issues bounded in-memory credential leases.
type Broker struct {
	source Source
	maxTTL time.Duration
	clock  func() time.Time
}

// NewBroker creates a credential broker with an enforced maximum lease TTL.
func NewBroker(source Source, maxTTL time.Duration, options ...BrokerOption) (*Broker, error) {
	if source == nil || maxTTL <= 0 {
		return nil, ErrInvalidBroker
	}
	broker := &Broker{source: source, maxTTL: maxTTL, clock: time.Now}
	for _, option := range options {
		if option != nil {
			option(broker)
		}
	}
	return broker, nil
}

// Lease owns resolved secret bytes until expiry or revocation.
type Lease struct {
	mu        sync.Mutex
	values    map[string][]byte
	expiresAt time.Time
	clock     func() time.Time
	revoked   bool
}

// Issue resolves all bindings or returns no lease. Secret bytes resolved before
// a later failure are cleared before returning.
func (b *Broker) Issue(ctx context.Context, bindings []Binding, ttl time.Duration) (*Lease, error) {
	if ttl <= 0 || ttl > b.maxTTL {
		return nil, ErrInvalidLeaseTTL
	}
	normalized, err := normalizeBindings(bindings)
	if err != nil {
		return nil, err
	}
	values := make(map[string][]byte, len(normalized))
	for _, binding := range normalized {
		if err := ctx.Err(); err != nil {
			clearValues(values)
			return nil, fmt.Errorf("issue credential lease: %w", err)
		}
		value, resolveErr := b.source.Resolve(ctx, binding.Reference)
		if resolveErr != nil || len(value) == 0 {
			clearBytes(value)
			clearValues(values)
			return nil, fmt.Errorf("%w: reference %q", ErrCredentialUnavailable, binding.Reference)
		}
		values[binding.Environment] = append([]byte(nil), value...)
		clearBytes(value)
	}
	return &Lease{
		values:    values,
		expiresAt: b.clock().UTC().Add(ttl),
		clock:     b.clock,
	}, nil
}

// ExpiresAt returns the immutable lease expiry time.
func (l *Lease) ExpiresAt() time.Time {
	return l.expiresAt
}

// Environment returns a copy suitable for one execution request.
func (l *Lease) Environment() (map[string]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.revoked {
		return nil, ErrLeaseRevoked
	}
	if !l.clock().Before(l.expiresAt) {
		clearValues(l.values)
		return nil, ErrLeaseExpired
	}
	environment := make(map[string]string, len(l.values))
	for name, value := range l.values {
		environment[name] = string(value)
	}
	return environment, nil
}

// Revoke clears retained secret bytes. It is idempotent.
func (l *Lease) Revoke() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.revoked {
		return
	}
	clearValues(l.values)
	l.revoked = true
}

func normalizeBindings(bindings []Binding) ([]Binding, error) {
	if len(bindings) == 0 {
		return nil, ErrInvalidBinding
	}
	seenEnvironment := make(map[string]struct{}, len(bindings))
	normalized := make([]Binding, 0, len(bindings))
	for _, binding := range bindings {
		binding.Reference = strings.TrimSpace(binding.Reference)
		binding.Environment = strings.TrimSpace(binding.Environment)
		if binding.Reference == "" || !environmentNamePattern.MatchString(binding.Environment) {
			return nil, ErrInvalidBinding
		}
		if _, exists := seenEnvironment[binding.Environment]; exists {
			return nil, ErrInvalidBinding
		}
		seenEnvironment[binding.Environment] = struct{}{}
		normalized = append(normalized, binding)
	}
	return normalized, nil
}

func clearValues(values map[string][]byte) {
	for name, value := range values {
		clearBytes(value)
		delete(values, name)
	}
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
