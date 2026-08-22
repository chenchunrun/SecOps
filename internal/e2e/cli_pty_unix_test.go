//go:build !windows

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/creack/pty"
	"github.com/stretchr/testify/require"
)

const (
	terminalBackgroundQuery = "\x1b]11;?"
	darkBackgroundResponse  = "\x1b]11;rgb:0000/0000/0000\x1b\\"
	lightBackgroundResponse = "\x1b]11;rgb:ffff/ffff/ffff\x1b\\"
)

var testBinary string

func TestMain(m *testing.M) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "resolve repository root: %v\n", err)
		os.Exit(1)
	}
	buildDir, err := os.MkdirTemp("", "secops-pty-")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "create PTY build directory: %v\n", err)
		os.Exit(1)
	}
	testBinary = filepath.Join(buildDir, "secops")
	build := exec.Command("go", "build", "-o", testBinary, ".")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, buildErr := build.CombinedOutput(); buildErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "build PTY test binary: %v\n%s", buildErr, output)
		_ = os.RemoveAll(buildDir)
		os.Exit(1)
	}

	code := m.Run()
	_ = os.RemoveAll(buildDir)
	os.Exit(code)
}

func TestCLIHelpAndVersionUnderPTY(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     []string
		expected []string
	}{
		{name: "help", args: []string{"--help"}, expected: []string{"USAGE", "SecOps", "--data-dir"}},
		{name: "version", args: []string{"--version"}, expected: []string{"SecOps version"}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output, err := runPTYCommand(t, test.args...)
			require.NoError(t, err, "PTY transcript:\n%s", output)
			plain := ansi.Strip(output)
			for _, expected := range test.expected {
				require.Contains(t, plain, expected)
			}
		})
	}
}

func TestTUIRespondsToTerminalBackgroundUnderPTY(t *testing.T) {
	tests := []struct {
		name     string
		response string
	}{
		{name: "dark", response: darkBackgroundResponse},
		{name: "light", response: lightBackgroundResponse},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			transcript, queries, err := runInteractivePTY(t, test.response)
			require.NoError(t, err, "PTY transcript:\n%s", transcript)
			require.Positive(t, queries, "terminal background was never queried")
			plain := ansi.Strip(transcript)
			require.Contains(t, plain, "SecOps")
			require.NotContains(t, strings.ToLower(plain), "crush crashed")
			require.NotContains(t, strings.ToLower(plain), "panic:")
		})
	}
}

func runPTYCommand(t *testing.T, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := isolatedCommand(t, ctx, args...)
	terminal, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 32, Cols: 120})
	if err != nil {
		return "", fmt.Errorf("start PTY command: %w", err)
	}
	var transcript lockedBuffer
	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(&transcript, terminal)
		close(copyDone)
	}()
	waitErr := cmd.Wait()
	_ = terminal.Close()
	<-copyDone
	if ctx.Err() != nil {
		return transcript.String(), fmt.Errorf("PTY command timed out: %w", ctx.Err())
	}
	return transcript.String(), waitErr
}

func runInteractivePTY(t *testing.T, backgroundResponse string) (string, int32, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := isolatedCommand(t, ctx, "--data-dir", filepath.Join(t.TempDir(), "data"))
	terminal, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 32, Cols: 120})
	if err != nil {
		return "", 0, fmt.Errorf("start interactive PTY: %w", err)
	}
	var transcript lockedBuffer
	var queryCount atomic.Int32
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buffer := make([]byte, 4096)
		stream := make([]byte, 0, 8192)
		searchFrom := 0
		for {
			n, readErr := terminal.Read(buffer)
			if n > 0 {
				chunk := append([]byte(nil), buffer[:n]...)
				_, _ = transcript.Write(chunk)
				stream = append(stream, chunk...)
				for {
					index := bytes.Index(stream[searchFrom:], []byte(terminalBackgroundQuery))
					if index < 0 {
						break
					}
					searchFrom += index + len(terminalBackgroundQuery)
					queryCount.Add(1)
					_, _ = terminal.Write([]byte(backgroundResponse))
				}
			}
			if readErr != nil {
				return
			}
		}
	}()

	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	ready := waitForPTY(15*time.Second, func() bool {
		return queryCount.Load() > 0 && strings.Contains(ansi.Strip(transcript.String()), "SecOps")
	})
	if !ready {
		_ = terminal.Close()
		<-readDone
		return transcript.String(), queryCount.Load(), errorsFromPTY(ctx, <-waitDone, "TUI did not become ready")
	}
	_, _ = terminal.Write([]byte{3})
	_, _ = terminal.Write([]byte("\x1b[D\r"))

	var waitErr error
	select {
	case waitErr = <-waitDone:
	case <-ctx.Done():
		waitErr = fmt.Errorf("interactive PTY timed out: %w", ctx.Err())
	}
	_ = terminal.Close()
	<-readDone
	if exitErr, ok := waitErr.(*exec.ExitError); ok && exitErr.ExitCode() == 130 {
		waitErr = nil
	}
	return transcript.String(), queryCount.Load(), waitErr
}

func isolatedCommand(t *testing.T, ctx context.Context, args ...string) *exec.Cmd {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	configDir := filepath.Join(root, "config")
	dataDir := filepath.Join(root, "data")
	require.NoError(t, os.MkdirAll(home, 0o700))
	require.NoError(t, os.MkdirAll(configDir, 0o700))
	require.NoError(t, os.MkdirAll(dataDir, 0o700))
	cmd := exec.CommandContext(ctx, testBinary, args...)
	cmd.Dir = root
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"USER=secops-pty",
		"LOGNAME=secops-pty",
		"TMPDIR=" + os.TempDir(),
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		"XDG_CONFIG_HOME=" + configDir,
		"XDG_DATA_HOME=" + dataDir,
		"CRUSH_GLOBAL_CONFIG=" + configDir,
		"CRUSH_GLOBAL_DATA=" + dataDir,
		"CRUSH_DISABLE_METRICS=true",
		"DO_NOT_TRACK=1",
	}
	return cmd
}

func waitForPTY(timeout time.Duration, ready func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ready() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func errorsFromPTY(ctx context.Context, processErr error, message string) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%s: %w", message, ctx.Err())
	}
	if processErr != nil {
		return fmt.Errorf("%s: %w", message, processErr)
	}
	return fmt.Errorf("%s", message)
}

type lockedBuffer struct {
	mu sync.RWMutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(data)
}

func (b *lockedBuffer) String() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.b.String()
}
