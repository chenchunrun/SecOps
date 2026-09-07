package shell

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

type recordingLogger struct{ entries []string }

func (l *recordingLogger) InfoPersist(msg string, values ...any) {
	l.entries = append(l.entries, msg+fmt.Sprint(values...))
}

func TestCommandLogOmitsCommandAndError(t *testing.T) {
	t.Parallel()
	for _, command := range []string{"echo opaque-sensitive-value", "opaque-sensitive-value '"} {
		logger := &recordingLogger{}
		s := NewShell(&Options{WorkingDir: t.TempDir(), Logger: logger})
		_, _, _ = s.Exec(t.Context(), command)
		require.NotEmpty(t, logger.entries)
		for _, entry := range logger.entries {
			require.NotContains(t, entry, "opaque-sensitive-value")
			require.Contains(t, entry, "succeeded")
		}
	}
}
