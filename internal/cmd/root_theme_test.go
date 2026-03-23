package cmd

import (
	"os"
	"testing"

	"github.com/chenchunrun/SecOps/internal/ui/styles"
	"github.com/stretchr/testify/require"
)

func TestParseColorFGBG(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		want   int
		wantOK bool
	}{
		{name: "empty", input: "", wantOK: false},
		{name: "single value", input: "15", want: 15, wantOK: true},
		{name: "fg bg pair", input: "15;0", want: 0, wantOK: true},
		{name: "multiple values", input: "0;15;7", want: 7, wantOK: true},
		{name: "invalid value", input: "abc;def", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseColorFGBG(tt.input)
			require.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				require.Equal(t, tt.want, got)
			}
		})
	}
}

func TestDetectTerminalThemeFromEnvHints(t *testing.T) {
	t.Setenv("CRUSH_THEME", "dark")
	t.Setenv("TERM_BACKGROUND", "dark")
	t.Setenv("COLORFGBG", "15;0")
	require.Equal(t, styles.ThemeDark, detectTerminalTheme(os.Stdin, os.Stdout))

	t.Setenv("CRUSH_THEME", "")
	t.Setenv("TERM_BACKGROUND", "light")
	t.Setenv("COLORFGBG", "0;15")
	require.Equal(t, styles.ThemeLight, detectTerminalTheme(os.Stdin, os.Stdout))

	t.Setenv("CRUSH_THEME", "light")
	t.Setenv("TERM_BACKGROUND", "light")
	t.Setenv("COLORFGBG", "")
	require.Equal(t, styles.ThemeLight, detectTerminalTheme(os.Stdin, os.Stdout))

	t.Setenv("CRUSH_THEME", "")
	t.Setenv("TERM_BACKGROUND", "dark")
	require.Equal(t, styles.ThemeDark, detectTerminalTheme(os.Stdin, os.Stdout))

	t.Setenv("TERM_BACKGROUND", "")
	t.Setenv("COLORFGBG", "15;0")
	require.Equal(t, styles.ThemeDark, detectTerminalTheme(os.Stdin, os.Stdout))

	t.Setenv("COLORFGBG", "0;15")
	require.Equal(t, styles.ThemeLight, detectTerminalTheme(os.Stdin, os.Stdout))
}
