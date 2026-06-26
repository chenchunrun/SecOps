// Package shell provides cross-platform shell execution capabilities.
//
// This package provides Shell instances for executing commands with their own
// working directory and environment. Each shell execution is independent.
//
// WINDOWS COMPATIBILITY:
// This implementation provides POSIX shell emulation (mvdan.cc/sh/v3) even on
// Windows. Commands should use forward slashes (/) as path separators to work
// correctly on all platforms.
package shell

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/charmbracelet/x/exp/slice"
	"github.com/chenchunrun/SecOps/internal/security/redact"
	"mvdan.cc/sh/moreinterp/coreutils"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// ShellType represents the type of shell to use
type ShellType int

const (
	ShellTypePOSIX ShellType = iota
	ShellTypeCmd
	ShellTypePowerShell
)

// Logger interface for optional logging
type Logger interface {
	InfoPersist(msg string, keysAndValues ...any)
}

// noopLogger is a logger that does nothing
type noopLogger struct{}

func (noopLogger) InfoPersist(msg string, keysAndValues ...any) {}

// BlockFunc is a function that determines if a command should be blocked
type BlockFunc func(args []string) bool

// Shell provides cross-platform shell execution with optional state persistence
type Shell struct {
	env        []string
	cwd        string
	mu         sync.Mutex
	logger     Logger
	blockFuncs []BlockFunc
}

// Options for creating a new shell
type Options struct {
	WorkingDir string
	Env        []string
	Logger     Logger
	BlockFuncs []BlockFunc
}

// NewShell creates a new shell instance with the given options
func NewShell(opts *Options) *Shell {
	if opts == nil {
		opts = &Options{}
	}

	cwd := opts.WorkingDir
	if cwd == "" {
		cwd, _ = os.Getwd()
	}

	env := opts.Env
	if env == nil {
		env = os.Environ()
	}

	logger := opts.Logger
	if logger == nil {
		logger = noopLogger{}
	}

	return &Shell{
		cwd:        cwd,
		env:        env,
		logger:     logger,
		blockFuncs: opts.BlockFuncs,
	}
}

// Exec executes a command in the shell
func (s *Shell) Exec(ctx context.Context, command string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.exec(ctx, command)
}

// ExecStream executes a command in the shell with streaming output to provided writers
func (s *Shell) ExecStream(ctx context.Context, command string, stdout, stderr io.Writer) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.execStream(ctx, command, stdout, stderr)
}

// GetWorkingDir returns the current working directory
func (s *Shell) GetWorkingDir() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cwd
}

// SetWorkingDir sets the working directory
func (s *Shell) SetWorkingDir(dir string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Verify the directory exists
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("directory does not exist: %w", err)
	}

	s.cwd = dir
	return nil
}

// GetEnv returns a copy of the environment variables
func (s *Shell) GetEnv() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	env := make([]string, len(s.env))
	copy(env, s.env)
	return env
}

// SetEnv sets an environment variable
func (s *Shell) SetEnv(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Update or add the environment variable
	keyPrefix := key + "="
	for i, env := range s.env {
		if strings.HasPrefix(env, keyPrefix) {
			s.env[i] = keyPrefix + value
			return
		}
	}
	s.env = append(s.env, keyPrefix+value)
}

// SetBlockFuncs sets the command block functions for the shell
func (s *Shell) SetBlockFuncs(blockFuncs []BlockFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockFuncs = blockFuncs
}

// commandWrappers are programs that run another command supplied as their
// arguments. The blocker must look past them so that, e.g., "env curl ..." or
// "nohup wget ..." is still matched against the banned set.
var commandWrappers = map[string]struct{}{
	"env":     {},
	"command": {},
	"nohup":   {},
	"nice":    {},
	"ionice":  {},
	"stdbuf":  {},
	"setsid":  {},
	"timeout": {},
	"time":    {},
	"xargs":   {},
	"sudo":    {},
	"doas":    {},
}

// normalizeCommandName reduces an argv[0] to its bare program name so that
// absolute or relative paths (e.g. "/usr/bin/curl", "./curl") match the same
// banned entry as "curl". Matching on the basename closes the trivial bypass
// of invoking a banned binary by its full path.
func normalizeCommandName(arg string) string {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return ""
	}
	// Strip any path component; works for both / and \ separators.
	if idx := strings.LastIndexAny(arg, `/\`); idx >= 0 {
		arg = arg[idx+1:]
	}
	return arg
}

// effectiveCommandName walks past known wrapper programs (env, sudo, nohup,
// timeout, …) and skips their option flags / VAR=val assignments to find the
// actual program being invoked.
func effectiveCommandName(args []string) string {
	for i := 0; i < len(args); i++ {
		name := normalizeCommandName(args[i])
		if name == "" {
			continue
		}
		if _, isWrapper := commandWrappers[name]; !isWrapper {
			return name
		}
		// Skip the wrapper's own flags and (for env) VAR=value assignments so
		// the next bare token is treated as the wrapped command.
		for i+1 < len(args) {
			next := strings.TrimSpace(args[i+1])
			if strings.HasPrefix(next, "-") || strings.Contains(next, "=") {
				i++
				continue
			}
			break
		}
	}
	return ""
}

// CommandsBlocker creates a BlockFunc that blocks banned commands. Matching is
// performed on the normalized program basename and also looks past wrapper
// programs, so "/usr/bin/curl", "env curl", and "sudo wget" are all blocked.
func CommandsBlocker(cmds []string) BlockFunc {
	bannedSet := make(map[string]struct{})
	for _, cmd := range cmds {
		bannedSet[normalizeCommandName(cmd)] = struct{}{}
	}

	return func(args []string) bool {
		if len(args) == 0 {
			return false
		}
		if _, ok := bannedSet[normalizeCommandName(args[0])]; ok {
			return true
		}
		if effective := effectiveCommandName(args); effective != "" {
			if _, ok := bannedSet[effective]; ok {
				return true
			}
		}
		return false
	}
}

// ArgumentsBlocker creates a BlockFunc that blocks specific subcommand
func ArgumentsBlocker(cmd string, args []string, flags []string) BlockFunc {
	return func(parts []string) bool {
		if len(parts) == 0 || parts[0] != cmd {
			return false
		}

		argParts, flagParts := splitArgsFlags(parts[1:])
		if len(argParts) < len(args) || len(flagParts) < len(flags) {
			return false
		}

		argsMatch := slices.Equal(argParts[:len(args)], args)
		flagsMatch := slice.IsSubset(flags, flagParts)

		return argsMatch && flagsMatch
	}
}

// ScanBlockedCommand statically parses a command line and applies the provided
// block functions to every simple command it contains. It is used to enforce
// command blocklists on execution paths that do not run through the local
// interpreter (e.g. remote SSH execution), where the per-exec block handler
// never fires. It returns the offending command when a block func matches.
//
// Parsing failures are treated conservatively: if the command cannot be parsed
// it is reported as blocked so that malformed or obfuscated input is rejected
// rather than silently forwarded.
func ScanBlockedCommand(command string, blockFuncs []BlockFunc) (blocked bool, offending string) {
	command = strings.TrimSpace(command)
	if command == "" || len(blockFuncs) == 0 {
		return false, ""
	}

	parser := syntax.NewParser()
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return true, command
	}

	syntax.Walk(file, func(node syntax.Node) bool {
		if blocked {
			return false
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		args := make([]string, 0, len(call.Args))
		for _, w := range call.Args {
			args = append(args, wordLiteral(w))
		}
		for _, fn := range blockFuncs {
			if fn(args) {
				blocked = true
				offending = args[0]
				return false
			}
		}
		return true
	})
	return blocked, offending
}

// wordLiteral extracts a best-effort literal string from a shell word. Quoted
// and bare literal parts are concatenated; non-literal parts (expansions,
// command substitutions) are rendered as a placeholder so they never
// accidentally match a banned literal.
func wordLiteral(w *syntax.Word) string {
	var b strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, dp := range p.Parts {
				if lit, ok := dp.(*syntax.Lit); ok {
					b.WriteString(lit.Value)
				}
			}
		default:
			b.WriteString("\x00")
		}
	}
	return b.String()
}

func splitArgsFlags(parts []string) (args []string, flags []string) {
	args = make([]string, 0, len(parts))
	flags = make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.HasPrefix(part, "-") {
			// Extract flag name before '=' if present
			flag := part
			if before, _, ok := strings.Cut(part, "="); ok {
				flag = before
			}
			flags = append(flags, flag)
		} else {
			args = append(args, part)
		}
	}
	return args, flags
}

func (s *Shell) blockHandler() func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if len(args) == 0 {
				return next(ctx, args)
			}

			for _, blockFunc := range s.blockFuncs {
				if blockFunc(args) {
					return fmt.Errorf("command is not allowed for security reasons: %q", args[0])
				}
			}

			return next(ctx, args)
		}
	}
}

// newInterp creates a new interpreter with the current shell state
func (s *Shell) newInterp(stdout, stderr io.Writer) (*interp.Runner, error) {
	return interp.New(
		interp.StdIO(nil, stdout, stderr),
		interp.Interactive(false),
		interp.Env(expand.ListEnviron(s.env...)),
		interp.Dir(s.cwd),
		interp.ExecHandlers(s.execHandlers()...),
	)
}

// updateShellFromRunner updates the shell from the interpreter after execution.
func (s *Shell) updateShellFromRunner(runner *interp.Runner) {
	s.cwd = runner.Dir
	s.env = s.env[:0]
	for name, vr := range runner.Vars {
		if vr.Exported {
			s.env = append(s.env, name+"="+vr.Str)
		}
	}
}

// execCommon is the shared implementation for executing commands
func (s *Shell) execCommon(ctx context.Context, command string, stdout, stderr io.Writer) (err error) {
	var runner *interp.Runner
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("command execution panic: %v", r)
		}
		if runner != nil {
			s.updateShellFromRunner(runner)
		}
		// Redact embedded credentials before logging the command so secrets passed
		// inline (tokens, DSNs, keys) do not land in the persistent log.
		s.logger.InfoPersist("command finished", "command", redact.String(command), "err", err)
	}()

	line, err := syntax.NewParser().Parse(strings.NewReader(command), "")
	if err != nil {
		return fmt.Errorf("could not parse command: %w", err)
	}

	runner, err = s.newInterp(stdout, stderr)
	if err != nil {
		return fmt.Errorf("could not run command: %w", err)
	}

	err = runner.Run(ctx, line)
	return err
}

// exec executes commands using a cross-platform shell interpreter.
func (s *Shell) exec(ctx context.Context, command string) (string, string, error) {
	var stdout, stderr bytes.Buffer
	err := s.execCommon(ctx, command, &stdout, &stderr)
	return stdout.String(), stderr.String(), err
}

// execStream executes commands using POSIX shell emulation with streaming output
func (s *Shell) execStream(ctx context.Context, command string, stdout, stderr io.Writer) error {
	return s.execCommon(ctx, command, stdout, stderr)
}

func (s *Shell) execHandlers() []func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	handlers := []func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc{
		s.blockHandler(),
	}
	if useGoCoreUtils {
		handlers = append(handlers, coreutils.ExecHandler)
	}
	return handlers
}

// IsInterrupt checks if an error is due to interruption
func IsInterrupt(err error) bool {
	return errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded)
}

// ExitCode extracts the exit code from an error
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr interp.ExitStatus
	if errors.As(err, &exitErr) {
		return int(exitErr)
	}
	return 1
}
