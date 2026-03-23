package tools

import (
	"bytes"
	"cmp"
	"context"
	_ "embed"
	"fmt"
	"html/template"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"charm.land/fantasy"
	"github.com/chenchunrun/SecOps/internal/audit"
	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/fsext"
	"github.com/chenchunrun/SecOps/internal/permission"
	"github.com/chenchunrun/SecOps/internal/shell"
)

type BashParams struct {
	Description         string `json:"description" description:"A brief description of what the command does, try to keep it under 30 characters or so"`
	Command             string `json:"command" description:"The command to execute"`
	WorkingDir          string `json:"working_dir,omitempty" description:"The working directory to execute the command in (defaults to current directory)"`
	RemoteProfile       string `json:"remote_profile,omitempty" description:"Remote profile ID from config.remote.profiles"`
	RemoteHost          string `json:"remote_host,omitempty" description:"SSH host for remote execution, e.g. 10.0.1.12 or server.example.com"`
	RemoteUser          string `json:"remote_user,omitempty" description:"SSH user for remote execution"`
	RemotePort          int    `json:"remote_port,omitempty" description:"SSH port for remote execution (default 22)"`
	RemoteKeyPath       string `json:"remote_key_path,omitempty" description:"Path to SSH private key for remote execution"`
	RemoteProxyJump     string `json:"remote_proxy_jump,omitempty" description:"Optional SSH ProxyJump host"`
	RemoteWorkingDir    string `json:"remote_working_dir,omitempty" description:"Working directory on remote host"`
	RemoteEnv           string `json:"remote_env,omitempty" description:"Remote environment label (e.g. prod/staging)"`
	RunInBackground     bool   `json:"run_in_background,omitempty" description:"Set to true (boolean) to run this command in the background. Use job_output to read the output later."`
	AutoBackgroundAfter int    `json:"auto_background_after,omitempty" description:"Seconds to wait before automatically moving the command to a background job (default: 60)"`
}

// BashLocalParams keeps the legacy local-only schema for environments where
// remote execution is not configured, preserving VCR stability and reducing
// irrelevant tool arguments.
type BashLocalParams struct {
	Description         string `json:"description" description:"A brief description of what the command does, try to keep it under 30 characters or so"`
	Command             string `json:"command" description:"The command to execute"`
	WorkingDir          string `json:"working_dir,omitempty" description:"The working directory to execute the command in (defaults to current directory)"`
	RunInBackground     bool   `json:"run_in_background,omitempty" description:"Set to true (boolean) to run this command in the background. Use job_output to read the output later."`
	AutoBackgroundAfter int    `json:"auto_background_after,omitempty" description:"Seconds to wait before automatically moving the command to a background job (default: 60)"`
}

type BashPermissionsParams struct {
	Description         string `json:"description"`
	Command             string `json:"command"`
	WorkingDir          string `json:"working_dir"`
	RemoteProfile       string `json:"remote_profile,omitempty"`
	RemoteHost          string `json:"remote_host,omitempty"`
	RemoteUser          string `json:"remote_user,omitempty"`
	RemotePort          int    `json:"remote_port,omitempty"`
	RemoteKeyPath       string `json:"remote_key_path,omitempty"`
	RemoteProxyJump     string `json:"remote_proxy_jump,omitempty"`
	RemoteWorkingDir    string `json:"remote_working_dir,omitempty"`
	RemoteEnv           string `json:"remote_env,omitempty"`
	PolicyType          string `json:"policy_type,omitempty"`
	PolicyRule          string `json:"policy_rule,omitempty"`
	PolicyResult        string `json:"policy_result,omitempty"`
	RunInBackground     bool   `json:"run_in_background"`
	AutoBackgroundAfter int    `json:"auto_background_after"`
}

type BashResponseMetadata struct {
	StartTime        int64  `json:"start_time"`
	EndTime          int64  `json:"end_time"`
	Output           string `json:"output"`
	Description      string `json:"description"`
	WorkingDirectory string `json:"working_directory"`
	Remote           bool   `json:"remote,omitempty"`
	RemoteTarget     string `json:"remote_target,omitempty"`
	Background       bool   `json:"background,omitempty"`
	ShellID          string `json:"shell_id,omitempty"`
}

type remotePolicyDecision struct {
	Type   string
	Rule   string
	Result string
}

const (
	BashToolName = "bash"

	DefaultAutoBackgroundAfter = 60 // Commands taking longer automatically become background jobs
	MaxOutputLength            = 30000
	BashNoOutput               = "no output"
)

//go:embed bash.tpl
var bashDescriptionTmpl []byte

var bashDescriptionTpl = template.Must(
	template.New("bashDescription").
		Parse(string(bashDescriptionTmpl)),
)

type bashDescriptionData struct {
	BannedCommands  string
	MaxOutputLength int
	Attribution     config.Attribution
	ModelName       string
}

var bannedCommands = []string{
	// Network/Download tools
	"alias",
	"aria2c",
	"axel",
	"chrome",
	"curl",
	"curlie",
	"firefox",
	"http-prompt",
	"httpie",
	"links",
	"lynx",
	"nc",
	"safari",
	"scp",
	"ssh",
	"telnet",
	"w3m",
	"wget",
	"xh",

	// System administration
	"doas",
	"su",
	"sudo",

	// Package managers
	"apk",
	"apt",
	"apt-cache",
	"apt-get",
	"dnf",
	"dpkg",
	"emerge",
	"home-manager",
	"makepkg",
	"opkg",
	"pacman",
	"paru",
	"pkg",
	"pkg_add",
	"pkg_delete",
	"portage",
	"rpm",
	"yay",
	"yum",
	"zypper",

	// System modification
	"at",
	"batch",
	"chkconfig",
	"crontab",
	"fdisk",
	"mkfs",
	"mount",
	"parted",
	"service",
	"systemctl",
	"umount",

	// Network configuration
	"firewall-cmd",
	"ifconfig",
	"ip",
	"iptables",
	"netstat",
	"pfctl",
	"route",
	"ufw",
}

func bashDescription(attribution *config.Attribution, modelName string) string {
	bannedCommandsStr := strings.Join(bannedCommands, ", ")
	attr := config.Attribution{}
	if attribution != nil {
		attr = *attribution
	}
	var out bytes.Buffer
	if err := bashDescriptionTpl.Execute(&out, bashDescriptionData{
		BannedCommands:  bannedCommandsStr,
		MaxOutputLength: MaxOutputLength,
		Attribution:     attr,
		ModelName:       modelName,
	}); err != nil {
		// Avoid panics in tool construction; return a safe fallback description.
		return fmt.Sprintf(
			"Execute shell commands with safety guardrails. Banned commands: %s. Max output length: %d.",
			bannedCommandsStr,
			MaxOutputLength,
		)
	}
	return out.String()
}

func blockFuncs() []shell.BlockFunc {
	return []shell.BlockFunc{
		shell.CommandsBlocker(bannedCommands),

		// System package managers
		shell.ArgumentsBlocker("apk", []string{"add"}, nil),
		shell.ArgumentsBlocker("apt", []string{"install"}, nil),
		shell.ArgumentsBlocker("apt-get", []string{"install"}, nil),
		shell.ArgumentsBlocker("dnf", []string{"install"}, nil),
		shell.ArgumentsBlocker("pacman", nil, []string{"-S"}),
		shell.ArgumentsBlocker("pkg", []string{"install"}, nil),
		shell.ArgumentsBlocker("yum", []string{"install"}, nil),
		shell.ArgumentsBlocker("zypper", []string{"install"}, nil),

		// Language-specific package managers
		shell.ArgumentsBlocker("brew", []string{"install"}, nil),
		shell.ArgumentsBlocker("cargo", []string{"install"}, nil),
		shell.ArgumentsBlocker("gem", []string{"install"}, nil),
		shell.ArgumentsBlocker("go", []string{"install"}, nil),
		shell.ArgumentsBlocker("npm", []string{"install"}, []string{"--global"}),
		shell.ArgumentsBlocker("npm", []string{"install"}, []string{"-g"}),
		shell.ArgumentsBlocker("pip", []string{"install"}, []string{"--user"}),
		shell.ArgumentsBlocker("pip3", []string{"install"}, []string{"--user"}),
		shell.ArgumentsBlocker("pnpm", []string{"add"}, []string{"--global"}),
		shell.ArgumentsBlocker("pnpm", []string{"add"}, []string{"-g"}),
		shell.ArgumentsBlocker("yarn", []string{"global", "add"}, nil),

		// `go test -exec` can run arbitrary commands
		shell.ArgumentsBlocker("go", []string{"test"}, []string{"-exec"}),
	}
}

func NewBashTool(permissions permission.Service, workingDir string, attribution *config.Attribution, modelName string, remote ...*config.Remote) fantasy.AgentTool {
	var remoteCfg *config.Remote
	if len(remote) > 0 {
		remoteCfg = remote[0]
	}
	desc := string(bashDescription(attribution, modelName))

	runBash := func(ctx context.Context, params BashParams, call fantasy.ToolCall) (fantasy.ToolResponse, error) {
			if params.Command == "" {
				return fantasy.NewTextErrorResponse("missing command"), nil
			}
			sessionID := GetSessionFromContext(ctx)
			if sessionID == "" {
				return fantasy.ToolResponse{}, fmt.Errorf("session ID is required for executing shell command")
			}

			var remoteProfile *config.RemoteProfile
			if profile := strings.TrimSpace(params.RemoteProfile); profile != "" {
				var err error
				params, remoteProfile, err = applyRemoteProfile(params, remoteCfg)
				if err != nil {
					return fantasy.NewTextErrorResponse(err.Error()), nil
				}
			} else if shouldApplyDefaultRemoteProfile(params, remoteCfg) {
				var err error
				params, remoteProfile, err = applyDefaultRemoteProfile(params, remoteCfg)
				if err != nil {
					return fantasy.NewTextErrorResponse(err.Error()), nil
				}
			}

			// Determine working directory
			execWorkingDir := cmp.Or(params.WorkingDir, workingDir)
			remoteTarget := formatRemoteTarget(params.RemoteUser, params.RemoteHost)
			isRemoteExecution := strings.TrimSpace(params.RemoteHost) != ""
			policyDecision := remotePolicyDecision{Type: "none", Result: "allow"}
			if isRemoteExecution {
				var err error
				policyDecision, err = enforceRemoteCommandPolicy(remoteProfile, params.Command)
				if err != nil {
					recordRemotePolicyDeny(sessionID, remoteTarget, params, policyDecision, err)
					return fantasy.NewTextErrorResponse(err.Error()), nil
				}
			}

			isSafeReadOnly := false
			cmdLower := strings.ToLower(params.Command)

			for _, safe := range safeCommands {
				if strings.HasPrefix(cmdLower, safe) {
					if len(cmdLower) == len(safe) || cmdLower[len(safe)] == ' ' || cmdLower[len(safe)] == '-' {
						isSafeReadOnly = true
						break
					}
				}
			}

			permissionPath := execWorkingDir
			if isRemoteExecution {
				permissionPath = "ssh://" + remoteTarget
			}
			if !isSafeReadOnly || isRemoteExecution {
				p, err := permissions.Request(ctx,
					permission.CreatePermissionRequest{
						SessionID:   sessionID,
						Path:        permissionPath,
						ToolCallID:  call.ID,
						ToolName:    BashToolName,
						Action:      "execute",
						Description: fmt.Sprintf("Execute command: %s", params.Command),
						Params: BashPermissionsParams{
							Description:         params.Description,
							Command:             params.Command,
							WorkingDir:          params.WorkingDir,
							RemoteProfile:       params.RemoteProfile,
							RemoteHost:          params.RemoteHost,
							RemoteUser:          params.RemoteUser,
							RemotePort:          params.RemotePort,
							RemoteKeyPath:       params.RemoteKeyPath,
							RemoteProxyJump:     params.RemoteProxyJump,
							RemoteWorkingDir:    params.RemoteWorkingDir,
							RemoteEnv:           params.RemoteEnv,
							PolicyType:          policyDecision.Type,
							PolicyRule:          policyDecision.Rule,
							PolicyResult:        policyDecision.Result,
							RunInBackground:     params.RunInBackground,
							AutoBackgroundAfter: params.AutoBackgroundAfter,
						},
						Transport:   map[bool]string{true: "ssh", false: "local"}[isRemoteExecution],
						TargetHost:  remoteTarget,
						TargetEnv:   strings.TrimSpace(params.RemoteEnv),
						TargetID:    strings.TrimSpace(params.RemoteProfile),
					},
				)
				if err != nil {
					return fantasy.ToolResponse{}, err
				}
				if !p {
					return fantasy.ToolResponse{}, permission.ErrorPermissionDenied
				}
			}

			if isRemoteExecution {
				if params.RunInBackground {
					return fantasy.NewTextErrorResponse("remote background jobs are not supported yet"), nil
				}
				startTime := time.Now()
				output, remoteErr := runRemoteSSHCommand(ctx, params)
				metadata := BashResponseMetadata{
					StartTime:        startTime.UnixMilli(),
					EndTime:          time.Now().UnixMilli(),
					Output:           output,
					Description:      params.Description,
					WorkingDirectory: cmp.Or(params.RemoteWorkingDir, "~"),
					Remote:           true,
					RemoteTarget:     remoteTarget,
				}
				if remoteErr != nil {
					return fantasy.WithResponseMetadata(fantasy.NewTextErrorResponse(output), metadata), nil
				}
				if output == "" {
					return fantasy.WithResponseMetadata(fantasy.NewTextResponse(BashNoOutput), metadata), nil
				}
				output += fmt.Sprintf("\n\n<cwd>%s</cwd>", normalizeWorkingDir(cmp.Or(params.RemoteWorkingDir, "~")))
				return fantasy.WithResponseMetadata(fantasy.NewTextResponse(output), metadata), nil
			}

			// If explicitly requested as background, start immediately with detached context
			if params.RunInBackground {
				startTime := time.Now()
				bgManager := shell.GetBackgroundShellManager()
				bgManager.Cleanup()
				// Use background context so it continues after tool returns
				bgShell, err := bgManager.Start(context.Background(), execWorkingDir, blockFuncs(), params.Command, params.Description)
				if err != nil {
					return fantasy.ToolResponse{}, fmt.Errorf("error starting background shell: %w", err)
				}

				// Wait a short time to detect fast failures (blocked commands, syntax errors, etc.)
				time.Sleep(1 * time.Second)
				stdout, stderr, done, execErr := bgShell.GetOutput()

				if done {
					// Command failed or completed very quickly
					bgManager.Remove(bgShell.ID)

					interrupted := shell.IsInterrupt(execErr)
					exitCode := shell.ExitCode(execErr)
					if exitCode == 0 && !interrupted && execErr != nil {
						return fantasy.ToolResponse{}, fmt.Errorf("[Job %s] error executing command: %w", bgShell.ID, execErr)
					}

					stdout = formatOutput(stdout, stderr, execErr)

					metadata := BashResponseMetadata{
						StartTime:        startTime.UnixMilli(),
						EndTime:          time.Now().UnixMilli(),
						Output:           stdout,
						Description:      params.Description,
						Background:       params.RunInBackground,
						WorkingDirectory: bgShell.WorkingDir,
					}
					if stdout == "" {
						return fantasy.WithResponseMetadata(fantasy.NewTextResponse(BashNoOutput), metadata), nil
					}
					stdout += fmt.Sprintf("\n\n<cwd>%s</cwd>", normalizeWorkingDir(bgShell.WorkingDir))
					return fantasy.WithResponseMetadata(fantasy.NewTextResponse(stdout), metadata), nil
				}

				// Still running after fast-failure check - return as background job
				metadata := BashResponseMetadata{
					StartTime:        startTime.UnixMilli(),
					EndTime:          time.Now().UnixMilli(),
					Description:      params.Description,
					WorkingDirectory: bgShell.WorkingDir,
					Background:       true,
					ShellID:          bgShell.ID,
				}
				response := fmt.Sprintf("Background shell started with ID: %s\n\nUse job_output tool to view output or job_kill to terminate.", bgShell.ID)
				return fantasy.WithResponseMetadata(fantasy.NewTextResponse(response), metadata), nil
			}

			// Start synchronous execution with auto-background support
			startTime := time.Now()

			// Start with detached context so it can survive if moved to background
			bgManager := shell.GetBackgroundShellManager()
			bgManager.Cleanup()
			bgShell, err := bgManager.Start(context.Background(), execWorkingDir, blockFuncs(), params.Command, params.Description)
			if err != nil {
				return fantasy.ToolResponse{}, fmt.Errorf("error starting shell: %w", err)
			}

			// Wait for either completion, auto-background threshold, or context cancellation
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()

			autoBackgroundAfter := cmp.Or(params.AutoBackgroundAfter, DefaultAutoBackgroundAfter)
			autoBackgroundThreshold := time.Duration(autoBackgroundAfter) * time.Second
			timeout := time.After(autoBackgroundThreshold)

			var stdout, stderr string
			var done bool
			var execErr error

		waitLoop:
			for {
				select {
				case <-ticker.C:
					stdout, stderr, done, execErr = bgShell.GetOutput()
					if done {
						break waitLoop
					}
				case <-timeout:
					stdout, stderr, done, execErr = bgShell.GetOutput()
					break waitLoop
				case <-ctx.Done():
					// Incoming context was cancelled before we moved to background
					// Kill the shell and return error
					bgManager.Kill(bgShell.ID)
					return fantasy.ToolResponse{}, ctx.Err()
				}
			}

			if done {
				// Command completed within threshold - return synchronously
				// Remove from background manager since we're returning directly
				// Don't call Kill() as it cancels the context and corrupts the exit code
				bgManager.Remove(bgShell.ID)

				interrupted := shell.IsInterrupt(execErr)
				exitCode := shell.ExitCode(execErr)
				if exitCode == 0 && !interrupted && execErr != nil {
					return fantasy.ToolResponse{}, fmt.Errorf("[Job %s] error executing command: %w", bgShell.ID, execErr)
				}

				stdout = formatOutput(stdout, stderr, execErr)

				metadata := BashResponseMetadata{
					StartTime:        startTime.UnixMilli(),
					EndTime:          time.Now().UnixMilli(),
					Output:           stdout,
					Description:      params.Description,
					Background:       params.RunInBackground,
					WorkingDirectory: bgShell.WorkingDir,
				}
				if stdout == "" {
					return fantasy.WithResponseMetadata(fantasy.NewTextResponse(BashNoOutput), metadata), nil
				}
				stdout += fmt.Sprintf("\n\n<cwd>%s</cwd>", normalizeWorkingDir(bgShell.WorkingDir))
				return fantasy.WithResponseMetadata(fantasy.NewTextResponse(stdout), metadata), nil
			}

			// Still running - keep as background job
			metadata := BashResponseMetadata{
				StartTime:        startTime.UnixMilli(),
				EndTime:          time.Now().UnixMilli(),
				Description:      params.Description,
				WorkingDirectory: bgShell.WorkingDir,
				Background:       true,
				ShellID:          bgShell.ID,
			}
			response := fmt.Sprintf("Command is taking longer than expected and has been moved to background.\n\nBackground shell ID: %s\n\nUse job_output tool to view output or job_kill to terminate.", bgShell.ID)
			return fantasy.WithResponseMetadata(fantasy.NewTextResponse(response), metadata), nil
	}

	if remoteCfg == nil {
		return fantasy.NewAgentTool(
			BashToolName,
			desc,
			func(ctx context.Context, params BashLocalParams, call fantasy.ToolCall) (fantasy.ToolResponse, error) {
				return runBash(ctx, BashParams{
					Description:         params.Description,
					Command:             params.Command,
					WorkingDir:          params.WorkingDir,
					RunInBackground:     params.RunInBackground,
					AutoBackgroundAfter: params.AutoBackgroundAfter,
				}, call)
			},
		)
	}

	return fantasy.NewAgentTool(
		BashToolName,
		desc,
		runBash,
	)
}

// formatOutput formats the output of a completed command with error handling
func formatOutput(stdout, stderr string, execErr error) string {
	interrupted := shell.IsInterrupt(execErr)
	exitCode := shell.ExitCode(execErr)

	stdout = truncateOutput(stdout)
	stderr = truncateOutput(stderr)

	errorMessage := stderr
	if errorMessage == "" && execErr != nil {
		errorMessage = execErr.Error()
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

	hasBothOutputs := stdout != "" && stderr != ""

	if hasBothOutputs {
		stdout += "\n"
	}

	if errorMessage != "" {
		stdout += "\n" + errorMessage
	}

	return stdout
}

func truncateOutput(content string) string {
	if len(content) <= MaxOutputLength {
		return content
	}

	halfLength := MaxOutputLength / 2
	start := content[:halfLength]
	end := content[len(content)-halfLength:]

	truncatedLinesCount := countLines(content[halfLength : len(content)-halfLength])
	return fmt.Sprintf("%s\n\n... [%d lines truncated] ...\n\n%s", start, truncatedLinesCount, end)
}

func countLines(s string) int {
	if s == "" {
		return 0
	}
	return len(strings.Split(s, "\n"))
}

func normalizeWorkingDir(path string) string {
	if runtime.GOOS == "windows" {
		path = strings.ReplaceAll(path, fsext.WindowsWorkingDirDrive(), "")
	}
	return filepath.ToSlash(path)
}

func formatRemoteTarget(user, host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	user = strings.TrimSpace(user)
	if user == "" {
		return host
	}
	return user + "@" + host
}

func runRemoteSSHCommand(ctx context.Context, params BashParams) (string, error) {
	host := strings.TrimSpace(params.RemoteHost)
	if host == "" {
		return "", fmt.Errorf("remote_host is required for remote execution")
	}

	target := formatRemoteTarget(params.RemoteUser, host)
	args := []string{"-o", "BatchMode=yes"}
	if params.RemotePort > 0 {
		args = append(args, "-p", strconv.Itoa(params.RemotePort))
	}
	if key := strings.TrimSpace(params.RemoteKeyPath); key != "" {
		args = append(args, "-i", key)
	}
	if jump := strings.TrimSpace(params.RemoteProxyJump); jump != "" {
		args = append(args, "-J", jump)
	}

	remoteCommand := strings.TrimSpace(params.Command)
	if wd := strings.TrimSpace(params.RemoteWorkingDir); wd != "" {
		remoteCommand = "cd " + shellQuoteSingle(wd) + " && " + remoteCommand
	}

	args = append(args, target, "sh", "-lc", remoteCommand)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := formatOutput(stdout.String(), stderr.String(), err)
	return output, err
}

func shellQuoteSingle(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func recordRemotePolicyDeny(sessionID, remoteTarget string, params BashParams, decision remotePolicyDecision, denyErr error) {
	event := audit.NewAuditEventBuilder(audit.EventTypePermissionDenied).
		WithSession(sessionID).
		WithAction("remote_policy_deny").
		WithResource("command", BashToolName, "ssh://"+remoteTarget).
		WithResult(audit.ResultDenied).
		WithError(denyErr.Error()).
		WithRemoteTarget("ssh", remoteTarget, strings.TrimSpace(params.RemoteEnv), strings.TrimSpace(params.RemoteProfile)).
		WithDetail("command", params.Command).
		WithDetail("policy_type", decision.Type).
		WithDetail("policy_rule", decision.Rule).
		WithDetail("policy_result", decision.Result).
		Build()

	_ = audit.RecordGlobal(event)
}

func applyRemoteProfile(params BashParams, remote *config.Remote) (BashParams, *config.RemoteProfile, error) {
	if remote == nil {
		return params, nil, fmt.Errorf("remote profile requested but config.remote is not set")
	}
	profileID := strings.TrimSpace(params.RemoteProfile)
	if profileID == "" {
		return params, nil, nil
	}

	for _, p := range remote.Profiles {
		if strings.TrimSpace(p.ID) != profileID {
			continue
		}
		if strings.TrimSpace(params.RemoteHost) == "" {
			params.RemoteHost = p.Host
		}
		if strings.TrimSpace(params.RemoteUser) == "" {
			params.RemoteUser = p.User
		}
		if params.RemotePort == 0 {
			params.RemotePort = p.Port
		}
		if strings.TrimSpace(params.RemoteProxyJump) == "" {
			params.RemoteProxyJump = p.ProxyJump
		}
		if strings.TrimSpace(params.RemoteEnv) == "" {
			params.RemoteEnv = p.Env
		}
		if strings.TrimSpace(params.RemoteKeyPath) == "" {
			params.RemoteKeyPath = p.Auth.KeyPath
		}
		profileCopy := p
		return params, &profileCopy, nil
	}
	return params, nil, fmt.Errorf("remote profile not found: %s", profileID)
}

func shouldApplyDefaultRemoteProfile(params BashParams, remote *config.Remote) bool {
	if remote == nil || strings.TrimSpace(remote.DefaultProfile) == "" {
		return false
	}

	// Only apply a default profile when request is already marked as remote.
	return strings.TrimSpace(params.RemoteHost) != "" ||
		strings.TrimSpace(params.RemoteUser) != "" ||
		params.RemotePort != 0 ||
		strings.TrimSpace(params.RemoteKeyPath) != "" ||
		strings.TrimSpace(params.RemoteProxyJump) != "" ||
		strings.TrimSpace(params.RemoteWorkingDir) != "" ||
		strings.TrimSpace(params.RemoteEnv) != ""
}

func applyDefaultRemoteProfile(params BashParams, remote *config.Remote) (BashParams, *config.RemoteProfile, error) {
	if remote == nil {
		return params, nil, nil
	}
	defaultProfileID := strings.TrimSpace(remote.DefaultProfile)
	if defaultProfileID == "" {
		return params, nil, nil
	}
	params.RemoteProfile = defaultProfileID
	return applyRemoteProfile(params, remote)
}

func enforceRemoteCommandPolicy(profile *config.RemoteProfile, command string) (remotePolicyDecision, error) {
	if profile == nil {
		return remotePolicyDecision{Type: "none", Result: "allow"}, nil
	}
	cmd := strings.TrimSpace(command)
	if cmd == "" {
		return remotePolicyDecision{Type: "none", Result: "deny"}, fmt.Errorf("remote command is empty")
	}

	for _, deny := range profile.DenyCommands {
		if commandPatternMatch(deny, cmd) {
			rule := strings.TrimSpace(deny)
			return remotePolicyDecision{Type: "deny_list", Rule: rule, Result: "deny"},
				fmt.Errorf("remote command denied by profile deny rule: %q", rule)
		}
	}

	if len(profile.AllowedCommands) == 0 {
		return remotePolicyDecision{Type: "none", Result: "allow"}, nil
	}

	for _, allow := range profile.AllowedCommands {
		if commandPatternMatch(allow, cmd) {
			return remotePolicyDecision{Type: "allow_list", Rule: strings.TrimSpace(allow), Result: "allow"}, nil
		}
	}

	return remotePolicyDecision{Type: "allow_list", Rule: "<no allow rule matched>", Result: "deny"},
		fmt.Errorf("remote command denied: no allow rule matched in profile %q", profile.ID)
}

func commandPatternMatch(pattern, command string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	c := strings.ToLower(strings.TrimSpace(command))
	if p == "" || c == "" {
		return false
	}

	if strings.ContainsAny(p, "*?[") {
		return wildcardMatch(p, c)
	}
	return strings.Contains(c, p)
}

func wildcardMatch(pattern, value string) bool {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		switch ch {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(ch)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return false
	}
	return re.MatchString(value)
}
