package secops

import (
	"fmt"
	"time"
)

// AccessReviewParams for auditing user/group access
type AccessReviewParams struct {
	SystemType string `json:"system_type"` // "aws", "gcp", "linux", "database"
	ReviewType string `json:"review_type"` // "users", "permissions", "service_accounts"
	Target     string `json:"target"`
}

// AccessEntry 访问条目
type AccessEntry struct {
	Principal  string
	Permission string
	Resource   string
	AgeDays    int
	LastUsed   string
	Risk       string  // "low", "medium", "high"
}

// AccessReviewResult 访问审计结果
type AccessReviewResult struct {
	Entries       []AccessEntry
	HighRiskCount int
	StaleCount    int
	TotalCount    int
}

// AccessReviewTool 访问审计工具
type AccessReviewTool struct {
	registry *SecOpsToolRegistry
}

// NewAccessReviewTool 创建访问审计工具
func NewAccessReviewTool(registry *SecOpsToolRegistry) *AccessReviewTool {
	return &AccessReviewTool{registry: registry}
}

// Type 实现 Tool.Type
func (art *AccessReviewTool) Type() ToolType {
	return ToolTypeAccessReview
}

// Name 实现 Tool.Name
func (art *AccessReviewTool) Name() string {
	return "Access Review"
}

// Description 实现 Tool.Description
func (art *AccessReviewTool) Description() string {
	return "Audit user, group, and service account permissions across AWS, GCP, Linux, and databases"
}

// RequiredCapabilities 实现 Tool.RequiredCapabilities
func (art *AccessReviewTool) RequiredCapabilities() []string {
	return []string{"iam:read", "security:read"}
}

// ValidateParams 实现 Tool.ValidateParams
func (art *AccessReviewTool) ValidateParams(params interface{}) error {
	p, ok := params.(*AccessReviewParams)
	if !ok {
		return ErrInvalidParams
	}

	if p.SystemType == "" {
		return fmt.Errorf("system_type is required")
	}

	validSystems := map[string]bool{
		"aws":      true,
		"gcp":      true,
		"linux":    true,
		"database": true,
	}
	if !validSystems[p.SystemType] {
		return fmt.Errorf("unsupported system_type: %s", p.SystemType)
	}

	validReviewTypes := map[string]bool{
		"users":            true,
		"permissions":      true,
		"service_accounts": true,
	}
	if p.ReviewType != "" && !validReviewTypes[p.ReviewType] {
		return fmt.Errorf("unsupported review_type: %s", p.ReviewType)
	}

	return nil
}

// Execute 实现 Tool.Execute
func (art *AccessReviewTool) Execute(params interface{}) (interface{}, error) {
	p, ok := params.(*AccessReviewParams)
	if !ok {
		return nil, ErrInvalidParams
	}

	if err := art.ValidateParams(p); err != nil {
		return nil, err
	}

	return art.performReview(p), nil
}

// performReview 执行访问审计
func (art *AccessReviewTool) performReview(params *AccessReviewParams) *AccessReviewResult {
	result := &AccessReviewResult{
		Entries: make([]AccessEntry, 0),
	}

	switch params.SystemType {
	case "aws":
		result.Entries = []AccessEntry{
			{
				Principal:  "user:admin@example.com",
				Permission: "iam:*",
				Resource:   "*",
				AgeDays:    180,
				LastUsed:   time.Now().Add(-1 * time.Hour).Format("2006-01-02 15:04"),
				Risk:       "high",
			},
			{
				Principal:  "user:devops@example.com",
				Permission: "ec2:RunInstances",
				Resource:   "arn:aws:ec2:*:*:instance/*",
				AgeDays:    90,
				LastUsed:   time.Now().Add(-2 * time.Hour).Format("2006-01-02 15:04"),
				Risk:       "medium",
			},
			{
				Principal:  "role:prod-deployment",
				Permission: "eks:DescribeCluster",
				Resource:   "arn:aws:eks:*:*:cluster/prod-*",
				AgeDays:    30,
				LastUsed:   time.Now().Add(-1 * time.Hour).Format("2006-01-02 15:04"),
				Risk:       "low",
			},
			{
				Principal:  "user:former-employee@example.com",
				Permission: "s3:*",
				Resource:   "arn:aws:s3:::company-secrets/*",
				AgeDays:    365,
				LastUsed:   time.Now().Add(-60 * 24 * time.Hour).Format("2006-01-02 15:04"),
				Risk:       "high",
			},
			{
				Principal:  "service:lambda-processor",
				Permission: "sqs:ReceiveMessage",
				Resource:   "arn:aws:sqs:*:*:task-queue",
				AgeDays:    7,
				LastUsed:   time.Now().Add(-30 * time.Minute).Format("2006-01-02 15:04"),
				Risk:       "low",
			},
		}

	case "gcp":
		result.Entries = []AccessEntry{
			{
				Principal:  "user:admin@example.com",
				Permission: "roles/owner",
				Resource:   "projects/*",
				AgeDays:    180,
				LastUsed:   time.Now().Add(-3 * time.Hour).Format("2006-01-02 15:04"),
				Risk:       "high",
			},
			{
				Principal:  "serviceAccount:compute@project.iam.gserviceaccount.com",
				Permission: "roles/editor",
				Resource:   "projects/project-id",
				AgeDays:    60,
				LastUsed:   time.Now().Add(-1 * time.Hour).Format("2006-01-02 15:04"),
				Risk:       "medium",
			},
		}

	case "linux":
		result.Entries = []AccessEntry{
			{
				Principal:  "user:root",
				Permission: "sudo ALL=(ALL) NOPASSWD: ALL",
				Resource:   "/etc/sudoers",
				AgeDays:    730,
				LastUsed:   time.Now().Add(-10 * time.Minute).Format("2006-01-02 15:04"),
				Risk:       "low",
			},
			{
				Principal:  "user:deploy",
				Permission: "sudo systemctl restart nginx",
				Resource:   "/etc/sudoers.d/deploy",
				AgeDays:    90,
				LastUsed:   time.Now().Add(-2 * time.Hour).Format("2006-01-02 15:04"),
				Risk:       "medium",
			},
			{
				Principal:  "user:contractor-old",
				Permission: "sudo su -",
				Resource:   "/etc/sudoers.d/contractors",
				AgeDays:    400,
				LastUsed:   time.Now().Add(-120 * 24 * time.Hour).Format("2006-01-02 15:04"),
				Risk:       "high",
			},
		}

	case "database":
		result.Entries = []AccessEntry{
			{
				Principal:  "user:app_readonly",
				Permission: "SELECT",
				Resource:   "public.*",
				AgeDays:    30,
				LastUsed:   time.Now().Add(-1 * time.Minute).Format("2006-01-02 15:04"),
				Risk:       "low",
			},
			{
				Principal:  "user:app_writer",
				Permission: "SELECT, INSERT, UPDATE, DELETE",
				Resource:   "app_data.*",
				AgeDays:    60,
				LastUsed:   time.Now().Add(-5 * time.Minute).Format("2006-01-02 15:04"),
				Risk:       "medium",
			},
			{
				Principal:  "user:dba_admin",
				Permission: "ALL PRIVILEGES",
				Resource:   "*.*",
				AgeDays:    180,
				LastUsed:   time.Now().Add(-24 * time.Hour).Format("2006-01-02 15:04"),
				Risk:       "high",
			},
			{
				Principal:  "user:temp_user",
				Permission: "SELECT",
				Resource:   "analytics.*",
				AgeDays:    90,
				LastUsed:   time.Now().Add(-30 * 24 * time.Hour).Format("2006-01-02 15:04"),
				Risk:       "medium",
			},
		}
	}

	result.TotalCount = len(result.Entries)
	for _, e := range result.Entries {
		if e.Risk == "high" {
			result.HighRiskCount++
		}
		if e.AgeDays > 90 && e.LastUsed != "" {
			result.StaleCount++
		}
	}

	return result
}
