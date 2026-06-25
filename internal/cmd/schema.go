package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/invopop/jsonschema"
	"github.com/spf13/cobra"
)

var schemaCmd = &cobra.Command{
	Use:    "schema",
	Short:  "Generate JSON schema for configuration",
	Long:   "Generate JSON schema for the crush configuration file",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		bts, err := GenerateSchema()
		if err != nil {
			return err
		}
		fmt.Println(string(bts))
		return nil
	},
}

// GenerateSchema reflects the config type into a pretty-printed JSON schema.
// The returned bytes exclude the trailing newline; callers (the schema command
// and its golden-file test) add or normalize it as needed.
func GenerateSchema() ([]byte, error) {
	reflector := new(jsonschema.Reflector)
	bts, err := json.MarshalIndent(reflector.Reflect(&config.Config{}), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal schema: %w", err)
	}
	return bts, nil
}
