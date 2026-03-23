package model

import (
	"testing"

	"github.com/chenchunrun/SecOps/internal/ui/dialog"
	"github.com/stretchr/testify/require"
)

func TestApplyRunModePrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mode    dialog.RunMode
		input   string
		output  string
	}{
		{
			name:   "auto mode keeps content",
			mode:   dialog.RunModeAuto,
			input:  "hello",
			output: "hello",
		},
		{
			name:   "fast mode injects prefix",
			mode:   dialog.RunModeFast,
			input:  "hello",
			output: "/fast hello",
		},
		{
			name:   "deep mode injects prefix",
			mode:   dialog.RunModeDeep,
			input:  "hello",
			output: "/deep hello",
		},
		{
			name:   "existing fast prefix is preserved",
			mode:   dialog.RunModeDeep,
			input:  "/fast check this",
			output: "/fast check this",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := applyRunModePrefix(tt.input, tt.mode)
			require.Equal(t, tt.output, got)
		})
	}
}

