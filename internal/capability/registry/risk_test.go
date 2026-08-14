package registry

import "testing"

func TestDescriptorBaseRiskUsesMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		meta Metadata
		want int
	}{
		{name: "active probe", meta: Metadata{PolicyTags: []string{"active_probe"}}, want: 40},
		{name: "inspection", meta: Metadata{PolicyTags: []string{"environment_inspection"}}, want: 10},
		{name: "remote active probe", meta: Metadata{PolicyTags: []string{"active_probe"}, ExecutionProfile: ExecutionProfileRemoteCapable}, want: 55},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DescriptorBaseRisk(tt.meta); got != tt.want {
				t.Fatalf("expected %d, got %d", tt.want, got)
			}
		})
	}
}
