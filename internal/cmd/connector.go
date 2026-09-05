package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/chenchunrun/SecOps/internal/connectors"
	"github.com/spf13/cobra"
)

func newConnectorCmd() *cobra.Command {
	parent := &cobra.Command{Use: "connector", Short: "Validate read-only security platform connections"}
	var endpoint, index, auditPath, caPath string
	check := &cobra.Command{
		Use: "elastic-check", Short: "Check one Elasticsearch index using an expiring API key from the environment",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var caPEM []byte
			if caPath != "" {
				var err error
				caPEM, err = os.ReadFile(caPath)
				if err != nil {
					return fmt.Errorf("read connector CA file: %w", err)
				}
			}
			transport, err := connectors.NewHTTPTransportWithCA(endpoint, caPEM)
			if err != nil {
				return err
			}
			file, err := os.OpenFile(auditPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
			if err != nil {
				return fmt.Errorf("open connector audit: %w", err)
			}
			defer file.Close()
			client, err := connectors.NewElasticReadClient(index, elasticEnvironmentCredentials{}, transport, connectorFileAudit{file: file})
			if err != nil {
				return err
			}
			result, err := connectors.CheckElastic(cmd.Context(), client)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
		},
	}
	check.Flags().StringVar(&endpoint, "endpoint", "", "Elasticsearch HTTPS origin")
	check.Flags().StringVar(&caPath, "ca-file", "", "Optional PEM CA certificate for private HTTPS endpoints")
	check.Flags().StringVar(&index, "index", "", "One authorized index or alias")
	check.Flags().StringVar(&auditPath, "audit-file", "", "Local audit JSONL file (required)")
	_ = check.MarkFlagRequired("endpoint")
	_ = check.MarkFlagRequired("index")
	_ = check.MarkFlagRequired("audit-file")
	parent.AddCommand(check)
	return parent
}

type elasticEnvironmentCredentials struct{}

func (elasticEnvironmentCredentials) Credential(context.Context, connectors.Manifest) (connectors.Credential, error) {
	token := os.Getenv("SECOPS_ELASTIC_API_KEY")
	expires, err := time.Parse(time.RFC3339, os.Getenv("SECOPS_ELASTIC_API_KEY_EXPIRES_AT"))
	if token == "" || err != nil {
		return connectors.Credential{}, fmt.Errorf("configure SECOPS_ELASTIC_API_KEY and SECOPS_ELASTIC_API_KEY_EXPIRES_AT locally")
	}
	return connectors.Credential{Token: token, Scheme: "ApiKey", ExpiresAt: expires}, nil
}

type connectorFileAudit struct{ file *os.File }

func (a connectorFileAudit) Record(ctx context.Context, event connectors.AuditEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := json.NewEncoder(a.file).Encode(struct {
		At    time.Time             `json:"at"`
		Event connectors.AuditEvent `json:"event"`
	}{time.Now().UTC(), event}); err != nil {
		return err
	}
	return a.file.Sync()
}
