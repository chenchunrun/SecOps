package secops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// makePathStub writes an executable stub named binName into a temp dir and
// returns that dir so the caller can prepend it to PATH. The stub's body is a
// POSIX sh script that prints stdoutBody and exits 0. This lets us exercise the
// real CLI-shelling-out code paths (getAWSAccessEntries / getGCPAccessEntries /
// runAccessCommand) without any cloud credentials or network access.
func makePathStub(t *testing.T, dir, binName, stdoutBody string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell CLI stubs are not supported on Windows")
	}
	script := "#!/bin/sh\ncat <<'EOF_STUB_OUT'\n" + stdoutBody + "\nEOF_STUB_OUT\n"
	stubPath := filepath.Join(dir, binName)
	if err := os.WriteFile(stubPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write stub %s failed: %v", binName, err)
	}
	return dir
}

// makeMissingStub returns dir without writing binName so LookPath fails; used
// to confirm the graceful-return branch of cloud helpers.
func makeMissingStub(t *testing.T, dir, binName string) string {
	t.Helper()
	_ = binName
	return dir
}

// prependToPATH mutates the process PATH; callers using this must NOT use
// t.Parallel() (matches sibling tests like TestInfrastructureQueryTool_getGCPCostsFromCLI).
func prependToPATH(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestAccessReviewTool_getAWSAccessEntries_ParsesIAMJSON injects an aws CLI stub
// that emits realistic iam list-users JSON, then asserts the parser maps age →
// risk correctly and fills LastUsed from PasswordLastUsed (or a fallback).
func TestAccessReviewTool_getAWSAccessEntries_ParsesIAMJSON(t *testing.T) {
	tool := NewAccessReviewTool(nil)

	tmp := t.TempDir()
	now := time.Now().UTC()
	oldUser := now.Add(-400 * 24 * time.Hour).Format(time.RFC3339) // >365d → high
	midUser := now.Add(-150 * 24 * time.Hour).Format(time.RFC3339) // >120d → medium
	newUser := now.Add(-10 * 24 * time.Hour).Format(time.RFC3339)  // → low
	body := fmt.Sprintf(`{
  "Users": [
    {"UserName":"admin","Arn":"arn:aws:iam::123:user/admin","CreateDate":"%s","PasswordLastUsed":"%s"},
    {"UserName":"devops","Arn":"arn:aws:iam::123:user/devops","CreateDate":"%s","PasswordLastUsed":"%s"},
    {"UserName":"newcomer","Arn":"arn:aws:iam::123:user/newcomer","CreateDate":"%s"}
  ]
}`, oldUser, oldUser, midUser, midUser, newUser)
	makePathStub(t, tmp, "aws", body)
	prependToPATH(t, tmp)

	entries := tool.getAWSAccessEntries(&AccessReviewParams{SystemType: "aws"})
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	wantRisk := map[string]string{"user:admin": "high", "user:devops": "medium", "user:newcomer": "low"}
	gotRisk := make(map[string]string, len(entries))
	for _, e := range entries {
		gotRisk[e.Principal] = e.Risk
		if e.Permission != "iam:user" {
			t.Errorf("expected permission iam:user for %s, got %s", e.Principal, e.Permission)
		}
		if e.LastUsed == "" {
			t.Errorf("expected non-empty LastUsed for %s", e.Principal)
		}
	}
	for principal, want := range wantRisk {
		if gotRisk[principal] != want {
			t.Errorf("expected risk %s for %s, got %s", want, principal, gotRisk[principal])
		}
	}

	// newcomer 没有 PasswordLastUsed → 回退到 ~180 天前的时间，LastUsed 应非空。
	var newcomer *AccessEntry
	for i := range entries {
		if entries[i].Principal == "user:newcomer" {
			newcomer = &entries[i]
		}
	}
	if newcomer == nil {
		t.Fatal("expected newcomer entry")
	}
	if newcomer.LastUsed == "" {
		t.Error("expected fallback LastUsed for user without PasswordLastUsed")
	}
}

// TestAccessReviewTool_getAWSAccessEntries_NoCLIGraceful confirms graceful nil
// return when aws CLI is not on PATH.
func TestAccessReviewTool_getAWSAccessEntries_NoCLIGraceful(t *testing.T) {
	tool := NewAccessReviewTool(nil)

	tmp := t.TempDir()
	makeMissingStub(t, tmp, "aws")
	prependToPATH(t, tmp)

	entries := tool.getAWSAccessEntries(&AccessReviewParams{SystemType: "aws"})
	if entries != nil {
		t.Fatalf("expected nil entries when aws CLI absent, got %v", entries)
	}
}

// TestAccessReviewTool_getAWSAccessEntries_GarbageOutput confirms graceful nil
// return when aws emits unparseable JSON.
func TestAccessReviewTool_getAWSAccessEntries_GarbageOutput(t *testing.T) {
	tool := NewAccessReviewTool(nil)

	tmp := t.TempDir()
	makePathStub(t, tmp, "aws", "not valid json at all")
	prependToPATH(t, tmp)

	entries := tool.getAWSAccessEntries(&AccessReviewParams{SystemType: "aws"})
	if entries != nil {
		t.Fatalf("expected nil on unparseable aws output, got %v", entries)
	}
}

// TestAccessReviewTool_getGCPAccessEntries_ParsesIamPolicy injects a gcloud stub
// emitting IAM policy JSON and asserts role → risk classification.
func TestAccessReviewTool_getGCPAccessEntries_ParsesIamPolicy(t *testing.T) {
	tool := NewAccessReviewTool(nil)

	tmp := t.TempDir()
	body := `{
  "bindings": [
    {"role":"roles/owner","members":["user:owner@example.com","serviceAccount:sa@example.iam.gserviceaccount.com"]},
    {"role":"roles/editor","members":["user:editor@example.com"]},
    {"role":"roles/viewer","members":["user:viewer@example.com"]}
  ]
}`
	makePathStub(t, tmp, "gcloud", body)
	prependToPATH(t, tmp)

	entries := tool.getGCPAccessEntries(&AccessReviewParams{
		SystemType: "gcp",
		Target:     "project-id",
	})
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(entries))
	}

	riskByPrincipal := make(map[string]string, len(entries))
	permByPrincipal := make(map[string]string, len(entries))
	for _, e := range entries {
		riskByPrincipal[e.Principal] = e.Risk
		permByPrincipal[e.Principal] = e.Permission
		if e.Resource != "projects/project-id" {
			t.Errorf("expected resource projects/project-id for %s, got %s", e.Principal, e.Resource)
		}
		if e.LastUsed == "" {
			t.Errorf("expected non-empty LastUsed for %s", e.Principal)
		}
	}
	if riskByPrincipal["user:owner@example.com"] != "high" {
		t.Errorf("expected high risk for owner, got %s", riskByPrincipal["user:owner@example.com"])
	}
	if riskByPrincipal["user:editor@example.com"] != "medium" {
		t.Errorf("expected medium risk for editor, got %s", riskByPrincipal["user:editor@example.com"])
	}
	if riskByPrincipal["user:viewer@example.com"] != "low" {
		t.Errorf("expected low risk for viewer, got %s", riskByPrincipal["user:viewer@example.com"])
	}
	if permByPrincipal["user:owner@example.com"] != "roles/owner" {
		t.Errorf("expected role roles/owner, got %s", permByPrincipal["user:owner@example.com"])
	}
}

// TestAccessReviewTool_getGCPAccessEntries_EmptyTarget confirms nil return
// without invoking gcloud when Target is empty.
func TestAccessReviewTool_getGCPAccessEntries_EmptyTarget(t *testing.T) {
	tool := NewAccessReviewTool(nil)

	tmp := t.TempDir()
	makePathStub(t, tmp, "gcloud", `{"bindings":[]}`)
	prependToPATH(t, tmp)

	entries := tool.getGCPAccessEntries(&AccessReviewParams{SystemType: "gcp"})
	if entries != nil {
		t.Fatalf("expected nil entries for empty target, got %v", entries)
	}
}

// TestAccessReviewTool_getGCPAccessEntries_NoCLIGraceful confirms graceful nil
// return when gcloud is not on PATH.
func TestAccessReviewTool_getGCPAccessEntries_NoCLIGraceful(t *testing.T) {
	tool := NewAccessReviewTool(nil)

	tmp := t.TempDir()
	makeMissingStub(t, tmp, "gcloud")
	prependToPATH(t, tmp)

	entries := tool.getGCPAccessEntries(&AccessReviewParams{
		SystemType: "gcp",
		Target:     "project-id",
	})
	if entries != nil {
		t.Fatalf("expected nil when gcloud absent, got %v", entries)
	}
}

// TestAccessReviewTool_Execute_LiveAWS exercises performReview's aws live path
// end-to-end (DataSource=live) by injecting an aws stub.
func TestAccessReviewTool_Execute_LiveAWS(t *testing.T) {
	tool := NewAccessReviewTool(nil)

	tmp := t.TempDir()
	now := time.Now().UTC().Format(time.RFC3339)
	body := fmt.Sprintf(`{"Users":[{"UserName":"live-admin","Arn":"arn:aws:iam::1:user/live-admin","CreateDate":"%s","PasswordLastUsed":"%s"}]}`, now, now)
	makePathStub(t, tmp, "aws", body)
	prependToPATH(t, tmp)

	result, err := tool.Execute(&AccessReviewParams{
		SystemType: "aws",
		ReviewType: "users",
		Target:     "prod-account",
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	ar := result.(*AccessReviewResult)
	if ar.DataSource != "live" {
		t.Fatalf("expected DataSource live, got %s", ar.DataSource)
	}
	if len(ar.Entries) != 1 {
		t.Fatalf("expected 1 live entry, got %d", len(ar.Entries))
	}
	if ar.Entries[0].Principal != "user:live-admin" {
		t.Fatalf("unexpected principal %s", ar.Entries[0].Principal)
	}
}

// TestAccessReviewTool_Execute_LiveGCP exercises performReview's gcp live path.
func TestAccessReviewTool_Execute_LiveGCP(t *testing.T) {
	tool := NewAccessReviewTool(nil)

	tmp := t.TempDir()
	body := `{"bindings":[{"role":"roles/owner","members":["user:owner@example.com"]}]}`
	makePathStub(t, tmp, "gcloud", body)
	prependToPATH(t, tmp)

	result, err := tool.Execute(&AccessReviewParams{
		SystemType: "gcp",
		ReviewType: "users",
		Target:     "live-project",
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	ar := result.(*AccessReviewResult)
	if ar.DataSource != "live" {
		t.Fatalf("expected DataSource live, got %s", ar.DataSource)
	}
	if len(ar.Entries) != 1 {
		t.Fatalf("expected 1 live entry, got %d", len(ar.Entries))
	}
	if ar.HighRiskCount != 1 {
		t.Fatalf("expected high risk count 1 for owner role, got %d", ar.HighRiskCount)
	}
}

// TestAccessReviewTool_runRemoteCommand covers both the happy path and the
// stderr/error fallback branches of (*AccessReviewTool).runRemoteCommand via a
// runCmd override (no real SSH).
func TestAccessReviewTool_runRemoteCommand(t *testing.T) {
	t.Run("成功返回stdout", func(t *testing.T) {
		tool := NewAccessReviewTool(nil)
		var gotName string
		var gotArgs []string
		tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
			gotName = name
			gotArgs = append([]string(nil), args...)
			return []byte("line-one\nline-two\n"), nil, nil
		}

		out, err := tool.runRemoteCommand(&AccessReviewParams{
			RemoteHost: "10.0.0.20",
			RemoteUser: "ops",
		}, "cat /etc/passwd")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "line-one") {
			t.Fatalf("expected stdout content, got %q", out)
		}
		if gotName != "ssh" {
			t.Fatalf("expected ssh command, got %s", gotName)
		}
		cmdline := strings.Join(gotArgs, " ")
		if !strings.Contains(cmdline, "ops@10.0.0.20") {
			t.Fatalf("unexpected ssh args: %q", cmdline)
		}
	})

	t.Run("失败时回退到stderr消息", func(t *testing.T) {
		tool := NewAccessReviewTool(nil)
		tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
			// stdout 为空 + error → 消息取自 stderr。
			return []byte(""), []byte("  permission denied (publickey)  \n"), fmt.Errorf("exit status 255")
		}
		_, err := tool.runRemoteCommand(&AccessReviewParams{
			RemoteHost: "10.0.0.20",
		}, "cat /etc/passwd")
		if err == nil {
			t.Fatal("expected error on empty stdout + failure")
		}
		if !strings.Contains(err.Error(), "permission denied (publickey)") {
			t.Fatalf("expected stderr message in error, got %v", err)
		}
	})

	t.Run("失败且stderr为空时回退到cmdErr消息", func(t *testing.T) {
		tool := NewAccessReviewTool(nil)
		tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
			return []byte(""), []byte(""), fmt.Errorf("connection reset")
		}
		_, err := tool.runRemoteCommand(&AccessReviewParams{
			RemoteHost: "10.0.0.20",
		}, "cat /etc/passwd")
		if err == nil {
			t.Fatal("expected error on empty stdout + empty stderr")
		}
		if !strings.Contains(err.Error(), "connection reset") {
			t.Fatalf("expected cmdErr message in error, got %v", err)
		}
	})

	t.Run("失败但stdout非空时仍返回stdout", func(t *testing.T) {
		tool := NewAccessReviewTool(nil)
		tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
			// stdout 非空即使有 error 也返回 stdout（不进 error 分支）。
			return []byte("partial-output\n"), []byte("warn"), fmt.Errorf("exit status 1")
		}
		out, err := tool.runRemoteCommand(&AccessReviewParams{
			RemoteHost: "10.0.0.20",
		}, "cat /etc/passwd")
		if err != nil {
			t.Fatalf("unexpected error when stdout non-empty: %v", err)
		}
		if !strings.Contains(out, "partial-output") {
			t.Fatalf("expected partial stdout, got %q", out)
		}
	})
}

// TestAccessReviewTool_runRemoteCommand_NilRunCmdRestoresDefault confirms the
// runRemoteCommand nil-runCmd self-heal branch assigns runAccessCommand. This
// test mutates PATH so it does NOT run in parallel.
func TestAccessReviewTool_runRemoteCommand_NilRunCmdRestoresDefault(t *testing.T) {
	tool := &AccessReviewTool{registry: nil, runCmd: nil}

	// 让 ssh 不可被 LookPath 找到，使 runAccessCommand 走到 exec 失败但不会真正
	// 发起网络连接；重点验证 runCmd nil 分支自愈为 runAccessCommand（非 nil）。
	tmp := t.TempDir()
	makeMissingStub(t, tmp, "ssh")
	prependToPATH(t, tmp)

	_, _ = tool.runRemoteCommand(&AccessReviewParams{RemoteHost: "10.0.0.20"}, "echo hi")
	if tool.runCmd == nil {
		t.Fatal("expected runCmd to be self-healed to runAccessCommand")
	}
}

// TestRunAccessCommand covers the package-level runAccessCommand directly with
// safe deterministic commands (echo / sh). No cloud tooling involved.
func TestRunAccessCommand(t *testing.T) {
	ctx := context.Background()

	t.Run("成功执行echo", func(t *testing.T) {
		out, stderr, err := runAccessCommand(ctx, "echo", "hello-access")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.TrimSpace(string(out)) != "hello-access" {
			t.Fatalf("expected 'hello-access', got %q", out)
		}
		if stderr != nil {
			t.Fatalf("expected nil stderr, got %q", stderr)
		}
	})

	t.Run("失败命令返回ExitError与stderr", func(t *testing.T) {
		// sh -c 'echo boom 1>&2; exit 7' 产生 ExitError 并捕获 stderr。
		out, stderr, err := runAccessCommand(ctx, "sh", "-c", "echo boom 1>&2; exit 7")
		if err == nil {
			t.Fatal("expected error from failing command")
		}
		_ = out
		if string(stderr) == "" {
			t.Fatalf("expected non-empty stderr from boom, got %q", stderr)
		}
	})

	t.Run("命令不存在返回error", func(t *testing.T) {
		_, _, err := runAccessCommand(ctx, "this-binary-does-not-exist-xyz")
		if err == nil {
			t.Fatal("expected error for missing binary")
		}
	})
}

// TestBuildAccessSSHArgs covers all option combinations and the two error
// branches (nil params, missing host).
func TestBuildAccessSSHArgs(t *testing.T) {
	baseArgs := defaultSSHOptionArgs()

	t.Run("完整参数含端口密钥跳板", func(t *testing.T) {
		args, err := buildAccessSSHArgs(&AccessReviewParams{
			RemoteHost:      "10.0.0.20",
			RemoteUser:      "ops",
			RemotePort:      2222,
			RemoteKeyPath:   "/tmp/id_ed25519",
			RemoteProxyJump: "bastion",
		}, "cat /etc/passwd")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cmdline := strings.Join(args, " ")
		for _, want := range []string{"ops@10.0.0.20", "-p 2222", "-i /tmp/id_ed25519", "-J bastion", "sh", "-lc", "cat /etc/passwd"} {
			if !strings.Contains(cmdline, want) {
				t.Errorf("expected args to contain %q, got %q", want, cmdline)
			}
		}
		// 默认选项（StrictHostKeyChecking 等）应出现在参数中。
		for _, a := range baseArgs {
			if !strings.Contains(cmdline, a) {
				t.Errorf("expected default ssh option %q present, got %q", a, cmdline)
			}
		}
	})

	t.Run("无用户仅host", func(t *testing.T) {
		args, err := buildAccessSSHArgs(&AccessReviewParams{
			RemoteHost: "10.0.0.20",
		}, "uptime")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cmdline := strings.Join(args, " ")
		if !strings.Contains(cmdline, "10.0.0.20") {
			t.Fatalf("expected host present, got %q", cmdline)
		}
		if strings.Contains(cmdline, "@") {
			t.Errorf("expected no user@ prefix, got %q", cmdline)
		}
		// 无端口/密钥/跳板时不加对应参数。
		if strings.Contains(cmdline, "-p ") || strings.Contains(cmdline, "-i ") || strings.Contains(cmdline, "-J ") {
			t.Errorf("expected no port/key/jump args, got %q", cmdline)
		}
	})

	t.Run("nil参数报错", func(t *testing.T) {
		_, err := buildAccessSSHArgs(nil, "uptime")
		if err == nil {
			t.Fatal("expected error for nil params")
		}
	})

	t.Run("空host报错", func(t *testing.T) {
		_, err := buildAccessSSHArgs(&AccessReviewParams{RemoteUser: "ops"}, "uptime")
		if err == nil {
			t.Fatal("expected error for empty host")
		}
	})
}

// TestFormatAccessRemoteTarget covers the with-user / without-user branches and
// whitespace trimming.
func TestFormatAccessRemoteTarget(t *testing.T) {
	tests := []struct {
		name string
		user string
		host string
		want string
	}{
		{"仅host", "", "10.0.0.20", "10.0.0.20"},
		{"用户加host", "ops", "10.0.0.20", "ops@10.0.0.20"},
		{"空白被裁剪", "  ops  ", "  10.0.0.20  ", "ops@10.0.0.20"},
		{"两者皆空", "   ", "  ", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatAccessRemoteTarget(tt.user, tt.host); got != tt.want {
				t.Errorf("formatAccessRemoteTarget(%q,%q) = %q, want %q", tt.user, tt.host, got, tt.want)
			}
		})
	}
}

// TestFormatRFC3339OrNow covers both the parseable-input and fallback branches.
func TestFormatRFC3339OrNow(t *testing.T) {
	t.Run("合法RFC3339", func(t *testing.T) {
		got := formatRFC3339OrNow("2025-06-01T08:30:00Z")
		if got != "2025-06-01 08:30" {
			t.Fatalf("expected '2025-06-01 08:30', got %q", got)
		}
	})

	t.Run("非法输入回退到当前时间", func(t *testing.T) {
		got := formatRFC3339OrNow("not-a-date")
		if got == "" {
			t.Fatal("expected non-empty fallback timestamp")
		}
		if len(got) != len("2006-01-02 15:04") {
			t.Fatalf("expected formatted timestamp, got %q", got)
		}
	})
}

// TestReadLinuxSudoers covers the override-file branch, the directory walk
// branch, and the case where nothing exists. These mutate env / read filesystem
// state so they do NOT run in parallel.
func TestReadLinuxSudoers(t *testing.T) {
	t.Run("覆盖路径读取单文件", func(t *testing.T) {
		tmp := t.TempDir()
		override := filepath.Join(tmp, "sudoers")
		if err := os.WriteFile(override, []byte("deploy ALL=(ALL) NOPASSWD: /bin/systemctl\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Setenv("SECOPS_LINUX_SUDOERS_PATH", override)

		got := readLinuxSudoers()
		if !strings.Contains(got, "deploy ALL=(ALL)") {
			t.Fatalf("expected override content in sudoers, got %q", got)
		}
	})

	t.Run("目录遍历读取多文件", func(t *testing.T) {
		tmp := t.TempDir()
		sudoersD := filepath.Join(tmp, "sudoers.d")
		if err := os.Mkdir(sudoersD, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sudoersD, "deploy"), []byte("deploy ALL=(ALL) NOPASSWD: ALL\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sudoersD, "contractor"), []byte("contractor ALL=(ALL) NOPASSWD: /usr/bin/su\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		// sub-dir should be skipped (IsDir branch inside WalkDir).
		if err := os.Mkdir(filepath.Join(sudoersD, "nested"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("SECOPS_LINUX_SUDOERS_PATH", sudoersD)

		got := readLinuxSudoers()
		if !strings.Contains(got, "deploy ALL=(ALL)") || !strings.Contains(got, "contractor ALL=(ALL)") {
			t.Fatalf("expected both sudoers.d entries, got %q", got)
		}
	})

	t.Run("无文件存在返回值", func(t *testing.T) {
		// 指向一个不存在路径；确保不 panic 即可（系统 /etc/sudoers 可读性因环境而异）。
		t.Setenv("SECOPS_LINUX_SUDOERS_PATH", "/this/path/does/not/exist/sudoers")
		_ = readLinuxSudoers()
	})
}

// TestAccessReviewTool_getLinuxAccessEntriesRemote_EdgeCases covers remote edge
// cases: empty passwd early return, malformed/comment/nologin lines skipped,
// sudoer-detected privilege escalation, runCmd error, and ssh:// resource prefix.
func TestAccessReviewTool_getLinuxAccessEntriesRemote_EdgeCases(t *testing.T) {
	t.Run("空passwd返回nil", func(t *testing.T) {
		tool := NewAccessReviewTool(nil)
		tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
			return []byte("   \n"), nil, nil
		}
		entries := tool.getLinuxAccessEntriesRemote(&AccessReviewParams{
			RemoteHost: "10.0.0.20",
		})
		if entries != nil {
			t.Fatalf("expected nil for empty remote passwd, got %v", entries)
		}
	})

	t.Run("注释与无效行被跳过且sudoers用户升级", func(t *testing.T) {
		tool := NewAccessReviewTool(nil)
		tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
			cmdline := strings.Join(args, " ")
			if strings.Contains(cmdline, "cat /etc/passwd") {
				return []byte(strings.Join([]string{
					"# comment line",
					"root:x:0:0:root:/root:/bin/bash",
					"deploy:x:1001:1001::/home/deploy:/bin/bash",
					"svc:x:1002:1002::/home/svc:/bin/bash",
					"nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin",
					"ftp:x:1003:1003::/home/ftp:/bin/false",
					"tooshort",
				}, "\n")), nil, nil
			}
			// sudoers 输出包含 deploy → 升级为 medium
			return []byte("deploy ALL=(ALL) NOPASSWD: /bin/systemctl\n"), nil, nil
		}

		entries := tool.getLinuxAccessEntriesRemote(&AccessReviewParams{
			RemoteHost: "10.0.0.20",
			RemoteUser: "ops",
		})
		// root + deploy + svc（nobody/ftp 被过滤，tooshort 字段不足被跳过）
		if len(entries) != 3 {
			t.Fatalf("expected 3 entries, got %d (%+v)", len(entries), entries)
		}

		perm := make(map[string]string, len(entries))
		risk := make(map[string]string, len(entries))
		res := make(map[string]string, len(entries))
		for _, e := range entries {
			perm[e.Principal] = e.Permission
			risk[e.Principal] = e.Risk
			res[e.Principal] = e.Resource
		}
		if risk["user:root"] != "high" || perm["user:root"] != "sudo ALL=(ALL) NOPASSWD: ALL" {
			t.Errorf("root should be high-risk sudo, got perm=%s risk=%s", perm["user:root"], risk["user:root"])
		}
		if risk["user:deploy"] != "medium" || perm["user:deploy"] != "sudo privilege" {
			t.Errorf("deploy (sudoer) should be medium sudo privilege, got perm=%s risk=%s", perm["user:deploy"], risk["user:deploy"])
		}
		if risk["user:svc"] != "low" || perm["user:svc"] != "shell:user" {
			t.Errorf("svc should be low shell:user, got perm=%s risk=%s", perm["user:svc"], risk["user:svc"])
		}
		// resource 应使用 ssh://ops@10.0.0.20 前缀。
		if !strings.HasPrefix(res["user:svc"], "ssh://ops@10.0.0.20/") {
			t.Errorf("expected ssh:// resource prefix, got %q", res["user:svc"])
		}
	})

	t.Run("runCmd错误返回nil", func(t *testing.T) {
		tool := NewAccessReviewTool(nil)
		tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
			return nil, []byte("ssh unreachable"), fmt.Errorf("ssh unreachable")
		}
		entries := tool.getLinuxAccessEntriesRemote(&AccessReviewParams{
			RemoteHost: "10.0.0.20",
		})
		if entries != nil {
			t.Fatalf("expected nil on runCmd error, got %v", entries)
		}
	})
}
