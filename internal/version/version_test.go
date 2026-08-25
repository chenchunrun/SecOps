package version

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLDFlagsVersionTakesPrecedenceOverEmbeddedBuildVersion(t *testing.T) {
	t.Parallel()

	root := filepath.Clean(filepath.Join("..", ".."))
	binary := filepath.Join(t.TempDir(), "SecOps")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	cmd := exec.CommandContext(
		t.Context(),
		"go",
		"build",
		"-ldflags",
		"-X github.com/chenchunrun/SecOps/internal/version.Version=v-test-release",
		"-o",
		binary,
		".",
	)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build release binary: %v\n%s", err, output)
	}

	versionCmd := exec.CommandContext(t.Context(), binary, "--version")
	output, err := versionCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run release binary: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "v-test-release") {
		t.Fatalf("expected ldflags version, got %q", output)
	}
}
