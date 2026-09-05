package skills

import (
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/stretchr/testify/require"
)

func TestLocalScanContractRequiresAuthorization(t *testing.T) {
	t.Parallel()
	_, err := NewLocalScanContract(nil, nil)
	require.Error(t, err)
	schema := &jsonschema.Schema{Type: "object"}
	manifest, err := NewLocalScanContract(schema, schema)
	require.NoError(t, err)
	_, err = manifest.AuthorizeExecution(ExecutionRequest{Platform: "linux"})
	require.ErrorContains(t, err, "authorization")
	risk, err := manifest.AuthorizeExecution(ExecutionRequest{Platform: "linux", SignedScope: true})
	require.NoError(t, err)
	require.Equal(t, RiskMedium, risk)
	require.Equal(t, []string{"security:scan"}, manifest.Capabilities.Required)
}
