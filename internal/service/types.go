// Package service manages durable background processes and declared ports
// independently from the backend that hosts them.
package service

import (
	"context"
	"errors"
	"time"

	"github.com/chenchunrun/SecOps/internal/computer"
)

type ID string

type State string

const (
	StateProvisioning State = "provisioning"
	StateStarting     State = "starting"
	StateRunning      State = "running"
	StateStopping     State = "stopping"
	StateStopped      State = "stopped"
	StateInterrupted  State = "interrupted"
	StateFailed       State = "failed"
	StateDestroyed    State = "destroyed"
)

type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

var (
	ErrInvalidService     = errors.New("invalid durable service")
	ErrNotFound           = errors.New("durable service not found")
	ErrAlreadyExists      = errors.New("durable service already exists")
	ErrConflict           = errors.New("durable service version conflict")
	ErrPortConflict       = errors.New("service port conflict")
	ErrBackendUnsupported = errors.New("service backend unsupported")
	ErrReadinessFailed    = errors.New("service readiness failed")
)

// Port is a backend-neutral logical port claim.
type Port struct {
	Name     string   `json:"name"`
	Protocol Protocol `json:"protocol"`
	Number   int      `json:"number"`
}

// Spec is the durable, secret-free declaration of a background service.
type Spec struct {
	Command          string          `json:"command"`
	WorkingDirectory string          `json:"working_directory,omitempty"`
	Ports            []Port          `json:"ports,omitempty"`
	Readiness        *ReadinessProbe `json:"readiness,omitempty"`
	Health           *HealthCheck    `json:"health,omitempty"`
}

// ReadinessProbe waits for a declared TCP port before a service is running.
type ReadinessProbe struct {
	Port     string        `json:"port"`
	Host     string        `json:"host,omitempty"`
	Timeout  time.Duration `json:"timeout"`
	Interval time.Duration `json:"interval"`
}

// HealthCheck continuously probes a running service and requires consecutive
// failures before automatic termination.
type HealthCheck struct {
	Probe            ReadinessProbe `json:"probe"`
	Period           time.Duration  `json:"period"`
	FailureThreshold int            `json:"failure_threshold"`
}

// LogPaths identify output evidence stored outside the service process.
type LogPaths struct {
	Stdout string `json:"stdout,omitempty"`
	Stderr string `json:"stderr,omitempty"`
}

type Submission struct {
	ID         ID
	ComputerID computer.ID
	Spec       Spec
}

// Service is the durable lifecycle record for one background process.
type Service struct {
	ID         ID          `json:"id"`
	ComputerID computer.ID `json:"computer_id"`
	State      State       `json:"state"`
	Spec       Spec        `json:"spec"`
	ProcessID  int         `json:"process_id,omitempty"`
	Logs       LogPaths    `json:"logs,omitempty"`
	Error      string      `json:"error,omitempty"`
	CreatedAt  time.Time   `json:"created_at"`
	UpdatedAt  time.Time   `json:"updated_at"`
	StartedAt  time.Time   `json:"started_at,omitempty"`
	FinishedAt time.Time   `json:"finished_at,omitempty"`
	Version    uint64      `json:"version"`
}

// Process is a backend process handle retained only by the live manager.
type Process interface {
	PID() int
	Logs() LogPaths
	Wait() error
	Stop(ctx context.Context) error
}

// Launcher adapts service lifecycle operations to a Computer backend.
type Launcher interface {
	Start(ctx context.Context, machine computer.Computer, spec Spec) (Process, error)
}

// ReadinessVerifier validates that a launched service can accept traffic.
type ReadinessVerifier interface {
	WaitReady(ctx context.Context, machine computer.Computer, service Service) error
}

// HealthVerifier performs one bounded health check for a running service.
type HealthVerifier interface {
	CheckHealth(ctx context.Context, machine computer.Computer, service Service) error
}

type ComputerResolver interface {
	Get(id computer.ID) (computer.Computer, error)
}

func (s State) valid() bool {
	switch s {
	case StateProvisioning, StateStarting, StateRunning, StateStopping,
		StateStopped, StateInterrupted, StateFailed, StateDestroyed:
		return true
	default:
		return false
	}
}

func (s State) claimsPorts() bool {
	switch s {
	case StateProvisioning, StateStarting, StateRunning, StateStopping,
		StateInterrupted, StateFailed:
		return true
	default:
		return false
	}
}
