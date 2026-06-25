package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// repoRoot walks upward from this test file until go.mod is found.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(1)
	require.True(t, ok, "runtime.Caller")
	dir := filepath.Dir(file)
	for range 20 {
		st, err := os.Stat(filepath.Join(dir, "go.mod"))
		if err == nil && !st.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("go.mod not found above %s", file)
	return ""
}

// TestGenerateSchema_MatchesCommittedGolden asserts that reflecting the config
// type still produces exactly the schema committed at repo-root schema.json.
//
// This guards against silent schema regressions that go build/test cannot catch
// — e.g. changing a receiver on a type that participates in jsonschema aliasing
// (such as csync.Map.JSONSchemaAlias) can make the reflector emit an opaque
// Map[...] definition instead of the inlined map type. If this test fails,
// re-run `go run . schema` and verify the diff is intentional before updating
// schema.json.
func TestGenerateSchema_MatchesCommittedGolden(t *testing.T) {
	t.Parallel()

	got, err := GenerateSchema()
	require.NoError(t, err)

	goldenPath := filepath.Join(repoRoot(t), "schema.json")
	want, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "read committed schema.json")

	// Normalize a single trailing newline: GenerateSchema omits it, while the
	// schema command (and therefore schema.json on disk) adds one via Println.
	if !strings.HasSuffix(string(got), "\n") {
		got = append(got, '\n')
	}

	if string(got) != string(want) {
		// Write the actual output to aid debugging the diff.
		debugPath := filepath.Join(t.TempDir(), "schema.actual.json")
		require.NoError(t, os.WriteFile(debugPath, got, 0o644))
		t.Fatalf("generated schema drifts from committed schema.json;\n"+
			"  if intentional: regenerate with `go run . schema > schema.json`\n"+
			"  actual written to: %s", debugPath)
	}
}
