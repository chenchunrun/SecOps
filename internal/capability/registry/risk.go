package registry

import "slices"

// DescriptorBaseRisk derives deterministic base risk from descriptor metadata.
func DescriptorBaseRisk(metadata Metadata) int {
	base := 0
	switch {
	case slices.Contains(metadata.PolicyTags, "active_probe"):
		base = 40
	case slices.Contains(metadata.PolicyTags, "credential_access"):
		base = 30
	case slices.Contains(metadata.PolicyTags, "environment_inspection"):
		base = 10
	}
	if metadata.ExecutionProfile == ExecutionProfileRemoteCapable {
		base += 15
	}
	if base > 100 {
		return 100
	}
	return base
}
