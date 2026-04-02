package execution

import (
	"fmt"

	"github.com/chenchunrun/SecOps/internal/shell"
)

func formatExecutionOutput(stdout, stderr string, execErr error) string {
	interrupted := shell.IsInterrupt(execErr)
	exitCode := shell.ExitCode(execErr)

	errorMessage := stderr
	if errorMessage == "" && execErr != nil {
		errorMessage = execErr.Error()
	}

	hasBothOutputs := stdout != "" && stderr != ""
	if hasBothOutputs {
		stdout += "\n"
	}

	if interrupted {
		if errorMessage != "" {
			errorMessage += "\n"
		}
		errorMessage += "Command was aborted before completion"
	} else if exitCode != 0 {
		if errorMessage != "" {
			errorMessage += "\n"
		}
		errorMessage += fmt.Sprintf("Exit code %d", exitCode)
	}

	if errorMessage != "" {
		stdout += "\n" + errorMessage
	}

	return stdout
}
