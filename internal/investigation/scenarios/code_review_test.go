package scenarios

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/evidence"
)

func TestCodeReviewSeparatesReachableAndTheoreticalFindings(t *testing.T) {
	t.Parallel()
	store, err := evidence.NewFileStore(t.TempDir())
	require.NoError(t, err)
	workflow, err := NewCodeReviewWorkflow(store, &fakeCodeScanner{result: fixtureScan()}, nil, nil, &fakeScenarioAuditor{})
	require.NoError(t, err)
	report, err := workflow.Run(context.Background(), CodeReviewInput{TaskID: "code-read", Repository: "repo", MakerID: "maker", CheckerID: "checker"})
	require.NoError(t, err)
	require.Equal(t, []string{"reachable-cve"}, report.Reachable)
	require.Equal(t, []string{"theoretical-cve"}, report.Theoretical)
	require.Equal(t, evidence.VerdictPassed, report.Verification)
}

func TestCodeFixRequiresPassingTestsAndPreservesWorkspace(t *testing.T) {
	t.Parallel()
	input := CodeReviewInput{
		TaskID: "code-fix", Repository: "repo", MakerID: "maker", CheckerID: "checker",
		ApplyFix: true, FixApproved: true, WorkspaceBaseline: map[string]string{"go.mod": "before"},
	}
	store, err := evidence.NewFileStore(t.TempDir())
	require.NoError(t, err)
	workflow, err := NewCodeReviewWorkflow(store, &fakeCodeScanner{result: fixtureScan()}, &fakeCodeFixer{change: validChange()}, &fakeCodeTester{result: TestResult{Passed: false}}, &fakeScenarioAuditor{})
	require.NoError(t, err)
	_, err = workflow.Run(context.Background(), input)
	require.ErrorContains(t, err, "passing test evidence")

	input.TaskID = "code-unrelated"
	store, err = evidence.NewFileStore(t.TempDir())
	require.NoError(t, err)
	unrelated := validChange()
	unrelated.TouchedPaths = append(unrelated.TouchedPaths, "user-change.go")
	unrelated.BeforeHashes["user-change.go"] = "x"
	unrelated.AfterHashes["user-change.go"] = "y"
	workflow, err = NewCodeReviewWorkflow(store, &fakeCodeScanner{result: fixtureScan()}, &fakeCodeFixer{change: unrelated}, &fakeCodeTester{}, &fakeScenarioAuditor{})
	require.NoError(t, err)
	_, err = workflow.Run(context.Background(), input)
	require.ErrorContains(t, err, "unrelated path")
}

func TestCodeFixCompletesWithChangeAndTestEvidence(t *testing.T) {
	t.Parallel()
	store, err := evidence.NewFileStore(t.TempDir())
	require.NoError(t, err)
	workflow, err := NewCodeReviewWorkflow(store, &fakeCodeScanner{result: fixtureScan()}, &fakeCodeFixer{change: validChange()}, &fakeCodeTester{result: TestResult{Passed: true, Raw: []byte("PASS")}}, &fakeScenarioAuditor{})
	require.NoError(t, err)
	report, err := workflow.Run(context.Background(), CodeReviewInput{
		TaskID: "code-success", Repository: "repo", MakerID: "maker", CheckerID: "checker",
		ApplyFix: true, FixApproved: true, WorkspaceBaseline: map[string]string{"go.mod": "before"},
	})
	require.NoError(t, err)
	require.True(t, report.FixApplied)
	require.True(t, report.TestsPassed)
	require.Len(t, report.EvidenceIDs, 3)
	require.Equal(t, evidence.VerdictPassed, report.Verification)
}

func fixtureScan() ScanResult {
	return ScanResult{Findings: []DependencyFinding{
		{ID: "reachable-cve", Package: "module", Version: "v1.2.3", AdvisorySource: "OSV-1", Reachable: true, AllowedPaths: []string{"go.mod"}},
		{ID: "theoretical-cve", Package: "unused", Version: "v2.0.0", AdvisorySource: "OSV-2", Reachable: false},
	}, Raw: []byte("versioned scan fixture")}
}

func validChange() ChangeSet {
	return ChangeSet{TouchedPaths: []string{"go.mod"}, BeforeHashes: map[string]string{"go.mod": "before"}, AfterHashes: map[string]string{"go.mod": "after"}, Raw: []byte("minimal diff")}
}

type fakeCodeScanner struct{ result ScanResult }

func (f *fakeCodeScanner) Scan(context.Context, string) (ScanResult, error) { return f.result, nil }

type fakeCodeFixer struct{ change ChangeSet }

func (f *fakeCodeFixer) Apply(context.Context, DependencyFinding) (ChangeSet, error) {
	return f.change, nil
}

type fakeCodeTester struct{ result TestResult }

func (f *fakeCodeTester) Test(context.Context, []string) (TestResult, error) { return f.result, nil }
