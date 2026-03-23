package secops

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	sshHostPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:\-\[\]]*$`)
	sshUserPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)
)

func validateRemoteSSHParams(host, user, keyPath, proxyJump string, port int) error {
	host = strings.TrimSpace(host)
	user = strings.TrimSpace(user)
	keyPath = strings.TrimSpace(keyPath)
	proxyJump = strings.TrimSpace(proxyJump)

	if port < 0 || port > 65535 {
		return fmt.Errorf("remote_port must be between 0 and 65535")
	}

	if host == "" {
		if user != "" || port > 0 || keyPath != "" || proxyJump != "" {
			return fmt.Errorf("remote_host is required when remote ssh options are set")
		}
		return nil
	}

	if strings.HasPrefix(host, "-") || !sshHostPattern.MatchString(host) {
		return fmt.Errorf("remote_host has invalid format")
	}
	if strings.ContainsAny(host, "\r\n\x00") {
		return fmt.Errorf("remote_host contains control characters")
	}

	if user != "" {
		if strings.HasPrefix(user, "-") || !sshUserPattern.MatchString(user) {
			return fmt.Errorf("remote_user has invalid format")
		}
		if strings.ContainsAny(user, "\r\n\x00") {
			return fmt.Errorf("remote_user contains control characters")
		}
	}

	if keyPath != "" {
		if strings.HasPrefix(keyPath, "-") {
			return fmt.Errorf("remote_key_path cannot start with '-'")
		}
		if strings.ContainsAny(keyPath, "\r\n\x00") {
			return fmt.Errorf("remote_key_path contains control characters")
		}
	}

	if proxyJump != "" {
		if strings.HasPrefix(proxyJump, "-") {
			return fmt.Errorf("remote_proxy_jump cannot start with '-'")
		}
		if strings.ContainsAny(proxyJump, "\r\n\x00") {
			return fmt.Errorf("remote_proxy_jump contains control characters")
		}
	}

	return nil
}

func defaultSSHOptionArgs() []string {
	return []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-o", "ServerAliveInterval=15",
		"-o", "ServerAliveCountMax=2",
	}
}
