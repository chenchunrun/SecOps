package computer

import "github.com/chenchunrun/SecOps/internal/sandbox"

// NewLocalComputer creates a stable Computer backed by the existing local
// sandbox executor.
func NewLocalComputer(id ID) (Computer, error) {
	return newExecutorComputer(id, BackendLocal, sandbox.NewLocalExecutor())
}

// NewDockerComputer creates a stable Computer backed by the existing Docker
// sandbox executor.
func NewDockerComputer(id ID) (Computer, error) {
	return newExecutorComputer(id, BackendDocker, sandbox.NewDockerExecutor())
}

// NewSSHComputer creates a stable Computer backed by the existing SSH sandbox
// executor.
func NewSSHComputer(id ID, user, keyPath string) (Computer, error) {
	return newExecutorComputer(id, BackendSSH, sandbox.NewSSHExecutor(user, keyPath))
}
