//go:build !windows

package e2e

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// terminalQueryResponder emulates the startup queries supported by a basic
// xterm. DA1 ends Lip Gloss's background probe; OSC 11 alone does not.
// Only a possible query prefix is retained between reads, not the transcript.
type terminalQueryResponder struct {
	background string
	pending    string
}

func (r *terminalQueryResponder) feed(chunk []byte) (string, int32) {
	queries := []struct{ query, response string }{
		{terminalBackgroundQuery + "\a", r.background},
		{terminalBackgroundQuery + "\x1b\\", r.background},
		{"\x1b[c", "\x1b[?1;2c"},
		{"\x1b[0c", "\x1b[?1;2c"},
	}
	var responses strings.Builder
	var backgrounds int32
	for _, b := range chunk {
		r.pending += string(b)
		for r.pending != "" {
			prefix := false
			for _, q := range queries {
				if r.pending == q.query {
					responses.WriteString(q.response)
					if strings.HasPrefix(q.query, terminalBackgroundQuery) {
						backgrounds++
					}
					r.pending = ""
					prefix = true
					break
				}
				prefix = prefix || strings.HasPrefix(q.query, r.pending)
			}
			if prefix {
				break
			}
			r.pending = r.pending[1:]
		}
	}
	return responses.String(), backgrounds
}

func TestTerminalQueryResponder(t *testing.T) {
	t.Parallel()
	input := "text\x1b[31m" + terminalBackgroundQuery + "\a\x1b[c" +
		terminalBackgroundQuery + "\x1b\\\x1b[0c"
	for split := 0; split <= len(input); split++ {
		r := terminalQueryResponder{background: lightBackgroundResponse}
		first, n1 := r.feed([]byte(input[:split]))
		second, n2 := r.feed([]byte(input[split:]))
		require.Equal(t, strings.Repeat(lightBackgroundResponse+"\x1b[?1;2c", 2), first+second)
		require.EqualValues(t, 2, n1+n2)
		require.Empty(t, r.pending)
	}
	r := terminalQueryResponder{background: darkBackgroundResponse}
	for _, b := range []byte(terminalBackgroundQuery) {
		response, count := r.feed([]byte{b})
		require.Empty(t, response, "must wait for the OSC terminator")
		require.Zero(t, count)
	}
	response, count := r.feed([]byte("\a"))
	require.Equal(t, darkBackgroundResponse, response)
	require.EqualValues(t, 1, count)
	response, count = r.feed([]byte(strings.Repeat("ordinary output", 10000)))
	require.Empty(t, response)
	require.Zero(t, count)
	require.Empty(t, r.pending)
}
