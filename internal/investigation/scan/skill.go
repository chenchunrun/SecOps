package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"math"

	"github.com/chenchunrun/SecOps/internal/agent/tools/secops"
	"github.com/chenchunrun/SecOps/internal/skills"
	"github.com/google/jsonschema-go/jsonschema"
)

type scanSkillInput struct {
	TaskID    string `json:"task_id"`
	Directory string `json:"directory"`
}

type scanSkillOutput struct {
	TaskID string             `json:"task_id"`
	Result *secops.ScanResult `json:"result"`
}

type scanSkillExecutor struct{ scanner Scanner }

func (s scanSkillExecutor) Execute(ctx context.Context, _ skills.SkillManifest, input skills.RuntimeInput) (map[string]interface{}, error) {
	directory, ok := input.Data["directory"].(string)
	if !ok || directory == "" {
		return nil, fmt.Errorf("scan directory is required")
	}
	output, err := s.scanner.ExecuteContext(ctx, &secops.SecurityScanParams{Scanner: secops.ScannerTrivy, Target: secops.TargetFilesystem, TargetPath: directory, ScanType: "vuln"})
	if err != nil {
		return nil, err
	}
	result, ok := output.(*secops.ScanResult)
	if !ok || result == nil {
		return nil, fmt.Errorf("scanner returned an invalid result")
	}
	if err := validateScanResult(result, directory); err != nil {
		return nil, err
	}
	return map[string]interface{}{"task_id": input.Data["task_id"], "result": result}, nil
}

func newScanSkill(scanner Scanner) (*skills.Runner, *skills.SkillManifest, error) {
	input, err := jsonschema.For[scanSkillInput](nil)
	if err != nil {
		return nil, nil, err
	}
	output, err := jsonschema.For[scanSkillOutput](nil)
	if err != nil {
		return nil, nil, err
	}
	manifest, err := skills.NewLocalScanContract(input, output)
	if err != nil {
		return nil, nil, err
	}
	runner, err := skills.NewRunner(scanSkillExecutor{scanner})
	return runner, manifest, err
}

func decodeScanOutput(output map[string]interface{}) (*secops.ScanResult, error) {
	data, err := json.Marshal(output["result"])
	if err != nil {
		return nil, err
	}
	var result secops.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func validateScanResult(result *secops.ScanResult, directory string) error {
	if result.Scanner != secops.ScannerTrivy || result.Target != directory || result.ScanTime.IsZero() || result.TotalVulnerabilities != len(result.Vulnerabilities) {
		return fmt.Errorf("invalid scan output: identity, timestamp or total mismatch")
	}
	counts := map[secops.VulnerabilityLevel]int{}
	for _, item := range result.Vulnerabilities {
		if item == nil || item.ID == "" || math.IsNaN(item.CVSS) || math.IsInf(item.CVSS, 0) || item.CVSS < 0 || item.CVSS > 10 {
			return fmt.Errorf("invalid scan output: malformed vulnerability")
		}
		switch item.Severity {
		case secops.VulnCritical, secops.VulnHigh, secops.VulnMedium, secops.VulnLow, "UNKNOWN":
		default:
			return fmt.Errorf("invalid scan output: unknown severity")
		}
		counts[item.Severity]++
	}
	if result.CriticalCount != counts[secops.VulnCritical] || result.HighCount != counts[secops.VulnHigh] || result.MediumCount != counts[secops.VulnMedium] || result.LowCount != counts[secops.VulnLow] {
		return fmt.Errorf("invalid scan output: severity counts mismatch")
	}
	return nil
}
