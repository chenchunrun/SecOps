package service

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/chenchunrun/SecOps/internal/computer"
)

// TCPReadinessVerifier probes a declared port from the manager environment.
type TCPReadinessVerifier struct{}

func NewTCPReadinessVerifier() *TCPReadinessVerifier {
	return &TCPReadinessVerifier{}
}

func (*TCPReadinessVerifier) WaitReady(ctx context.Context, _ computer.Computer, service Service) error {
	probe := service.Spec.Readiness
	if probe == nil {
		return nil
	}
	port, ok := readinessPort(service.Spec.Ports, probe.Port)
	if !ok {
		return ErrInvalidService
	}
	host := strings.TrimSpace(probe.Host)
	if host == "" {
		host = "127.0.0.1"
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	probeContext, cancel := context.WithTimeout(ctx, probe.Timeout)
	defer cancel()

	for {
		dialer := &net.Dialer{Timeout: probe.Interval}
		connection, err := dialer.DialContext(probeContext, "tcp", address)
		if err == nil {
			if closeErr := connection.Close(); closeErr != nil {
				return fmt.Errorf("%w: close probe connection to %s: %v", ErrReadinessFailed, address, closeErr)
			}
			return nil
		}
		timer := time.NewTimer(probe.Interval)
		select {
		case <-probeContext.Done():
			timer.Stop()
			return fmt.Errorf("%w: %s: %v", ErrReadinessFailed, address, probeContext.Err())
		case <-timer.C:
		}
	}
}

func readinessPort(ports []Port, name string) (int, bool) {
	name = strings.TrimSpace(name)
	for _, port := range ports {
		if strings.TrimSpace(port.Name) == name && port.Protocol == ProtocolTCP {
			return port.Number, true
		}
	}
	return 0, false
}
