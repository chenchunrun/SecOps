package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestElasticCheckRejectsInvalidCAFile(t *testing.T) {
	t.Parallel()
	for _, contents := range []string{"", "not a certificate"} {
		t.Run(contents, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			ca := filepath.Join(dir, "ca.pem")
			require.NoError(t, os.WriteFile(ca, []byte(contents), 0o600))
			cmd := newConnectorCmd()
			cmd.SetArgs([]string{"elastic-check", "--endpoint", "https://localhost:19200", "--index", "test", "--audit-file", filepath.Join(dir, "audit.jsonl"), "--ca-file", ca})
			require.ErrorContains(t, cmd.Execute(), "no valid certificates")
		})
	}
}
