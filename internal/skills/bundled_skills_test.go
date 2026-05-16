package skills

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// requiredBundledSecuritySkillNames is the authoritative list from README § Security
// Skills — 28 defensive + 7 red team (35 total). Regression fails if any cannot be
// discovered and validated under skills/.
var requiredBundledSecuritySkillNames = []string{
	// Incident Response
	"linux-ir", "macos-ir", "windows-ir", "auth-log-analysis",
	// Threat Intelligence
	"ip-analysis", "domain-analysis", "url-analysis", "phishing-analysis",
	"email-osint", "traffic-analysis", "dns-cache-detection",
	// Asset & Attack Surface
	"asset-discovery", "asset-monitor", "cyberspace-search", "brand-impersonation",
	// Malware Detection
	"binary-reverse-engineering", "office-malware-analyzer", "pdf-analysis",
	"prompt-injection-detect", "ttp-extractor",
	// Code & Supply Chain
	"code-audit", "sca-analyzer",
	// Utilities
	"data-desensitize", "researching-vulnerabilities", "rga-knowledge-search",
	"mail-attachment-downloader",
	// Reporting
	"office-report", "pdf-report",
	// Red team (gated at runtime; files must still load cleanly)
	"redteam-recon-enterprise", "redteam-recon-person", "redteam-recon-nation",
	"redteam-recon-ngo", "redteam-intrusion-hunter", "redteam-intrusion-0day",
	"redteam-intrusion-social",
}

// repoRoot walks upward from this test file until go.mod is found.
func repoRoot(tb testing.TB) string {
	tb.Helper()
	_, file, _, ok := runtime.Caller(1)
	require.True(tb, ok, "runtime.Caller")
	dir := filepath.Dir(file)
	for range 20 {
		mod := filepath.Join(dir, "go.mod")
		st, err := os.Stat(mod)
		if err == nil && !st.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	tb.Fatalf("go.mod not found above %s", file)
	return ""
}

func pathUnderToolsDir(path string) bool {
	sep := string(filepath.Separator)
	p := filepath.Clean(path)
	parts := strings.Split(p, sep)
	for _, p := range parts {
		if p == "tools" {
			return true
		}
	}
	return false
}

// shouldLintBundledSkillScript limits syntax checks to first-generation bundles:
// skills/<bundle>/scripts/** where <bundle> is a direct child of skills/.
// Nested bundles (e.g. office-report/ooxml/scripts) are skipped. Scripts under
// skills/secops/** are skipped to keep crawl small. Paths containing a tools/
// segment stay excluded (vendor trees).
func shouldLintBundledSkillScript(skillsDir, absPath string) bool {
	if pathUnderToolsDir(absPath) {
		return false
	}
	rel, err := filepath.Rel(skillsDir, absPath)
	if err != nil || rel == "." {
		return false
	}
	sep := string(filepath.Separator)
	parts := strings.Split(rel, sep)
	if len(parts) < 3 {
		return false
	}
	if parts[0] == "secops" {
		return false
	}
	if parts[1] != "scripts" {
		return false
	}
	return true
}

func TestBundledSecuritySkillsDiscover(t *testing.T) {
	root := repoRoot(t)
	skillsDir := filepath.Join(root, "skills")
	st, err := os.Stat(skillsDir)
	if os.IsNotExist(err) {
		t.Skip("skills/ not present")
	}
	require.NoError(t, err)
	require.True(t, st.IsDir())

	got := Discover([]string{skillsDir})
	require.GreaterOrEqual(t, len(got), len(requiredBundledSecuritySkillNames),
		"expected at least the %d README security skills to load", len(requiredBundledSecuritySkillNames))

	byName := make(map[string]string, len(got))
	for _, s := range got {
		prev, dup := byName[s.Name]
		if dup {
			t.Fatalf("duplicate skill name %q:\n  %s\n  %s", s.Name, prev, s.SkillFilePath)
		}
		byName[s.Name] = s.SkillFilePath
		if s.Description == "" {
			t.Errorf("skill %q has empty description (%s)", s.Name, s.SkillFilePath)
		}
	}

	for _, name := range requiredBundledSecuritySkillNames {
		_, ok := byName[name]
		require.True(t, ok, "required bundled skill missing from Discover: %q", name)
	}

	xml := ToPromptXML(got)
	require.Contains(t, xml, "<available_skills>")
	for _, name := range []string{"linux-ir", "redteam-recon-ngo"} {
		require.Contains(t, xml, "<name>"+name+"</name>", name)
	}
}

// TestBundledSkillScriptSyntax runs static checks only (no network, no executing skill logic).
// Skipped under -short. Only crawls skills/<bundle>/scripts/** for top-level bundles (see
// shouldLintBundledSkillScript). Skips skills/secops/** scripts and paths under any tools/
// directory (vendor trees).
func TestBundledSkillScriptSyntax(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping script syntax crawl in -short")
	}
	root := repoRoot(t)
	skillsDir := filepath.Join(root, "skills")
	if _, err := os.Stat(skillsDir); os.IsNotExist(err) {
		t.Skip("skills/ not present")
	}

	py, _ := exec.LookPath("python3")
	if py == "" {
		py, _ = exec.LookPath("python")
	}
	bash, _ := exec.LookPath("bash")
	node, _ := exec.LookPath("node")
	if py == "" && bash == "" && node == "" {
		t.Skip("need at least one of python3/python, bash, or node for script syntax checks")
	}

	var paths []string
	err := filepath.WalkDir(skillsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			switch name {
			case "__pycache__", ".git", "node_modules", ".venv":
				return filepath.SkipDir
			default:
				return nil
			}
		}
		if !shouldLintBundledSkillScript(skillsDir, path) {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".py", ".sh", ".js":
			paths = append(paths, path)
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, paths, "expected some .py/.sh/.js under skills/<bundle>/scripts/ (first-gen bundles only; excludes secops/** and */tools/)")

	for _, scriptPath := range paths {
		scriptPath := scriptPath
		rel, err := filepath.Rel(root, scriptPath)
		require.NoError(t, err)
		label := filepath.ToSlash(rel)
		ext := strings.ToLower(filepath.Ext(scriptPath))

		t.Run(label, func(t *testing.T) {
			t.Parallel()
			switch ext {
			case ".py":
				if py == "" {
					t.Skip("no python3/python on PATH")
				}
				cmd := exec.Command(py, "-m", "py_compile", scriptPath)
				out, err := cmd.CombinedOutput()
				require.NoError(t, err, "%s\n%s", scriptPath, out)
			case ".sh":
				if bash == "" {
					t.Skip("no bash on PATH")
				}
				cmd := exec.Command(bash, "-n", scriptPath)
				out, err := cmd.CombinedOutput()
				require.NoError(t, err, "%s\n%s", scriptPath, out)
			case ".js":
				if node == "" {
					t.Skip("no node on PATH")
				}
				cmd := exec.Command(node, "--check", scriptPath)
				out, err := cmd.CombinedOutput()
				require.NoError(t, err, "%s\n%s", scriptPath, out)
			}
		})
	}
}
