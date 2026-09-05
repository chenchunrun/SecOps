package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

var elasticIndexPattern = regexp.MustCompile(`^[a-z0-9.][a-z0-9._-]*$`)

// NewElasticReadClient restricts the adapter to a single index's search API.
func NewElasticReadClient(index string, credentials CredentialProvider, transport Transport, auditor Auditor) (*Client, error) {
	if !elasticIndexPattern.MatchString(index) || index == "." || index == ".." {
		return nil, errors.New("elastic check requires one concrete index or alias, without wildcards")
	}
	return NewClient(Manifest{
		APIVersion: "secops/connectors/v1", Name: "elastic", Version: "1.0.0", Provider: "Elastic Security",
		DataScopes: []string{"alerts:read"}, Credential: CredentialRequirement{Type: "api_key", Scopes: []string{"read"}, ShortLived: true},
		ProviderAPI: "v8", RateLimit: RateLimitPolicy{MaxRetries: 2, BackoffRaw: "1s"}, HealthPath: "/" + index + "/_search", EventSchema: "ecs-8",
		Operations: []OperationDescriptor{{Name: "query_alerts", Method: "POST", Path: "/" + index + "/_search", Risk: "low"}},
	}, credentials, transport, auditor)
}

type ElasticCheck struct {
	Healthy   bool      `json:"healthy"`
	CheckedAt time.Time `json:"checked_at"`
	Documents int64     `json:"documents"`
}

// CheckElastic verifies authorization and a complete search without retrieving documents.
func CheckElastic(ctx context.Context, client *Client) (ElasticCheck, error) {
	if err := client.auditor.Record(ctx, AuditEvent{Connector: "elastic", Operation: "query_alerts", Risk: "low"}); err != nil {
		return ElasticCheck{}, fmt.Errorf("audit elastic check: %w", err)
	}
	result, err := client.Execute(ctx, ExecuteRequest{Operation: "query_alerts", Payload: []byte(`{"size":0,"track_total_hits":true,"query":{"match_all":{}}}`)})
	if err != nil {
		return ElasticCheck{}, err
	}
	var response struct {
		TimedOut *bool `json:"timed_out"`
		Shards   *struct {
			Failed int `json:"failed"`
		} `json:"_shards"`
		Hits *struct {
			Total *struct {
				Value    int64  `json:"value"`
				Relation string `json:"relation"`
			} `json:"total"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(result.Body, &response); err != nil {
		return ElasticCheck{}, errors.New("invalid elastic search response")
	}
	if response.TimedOut == nil || *response.TimedOut || response.Shards == nil || response.Shards.Failed != 0 || response.Hits == nil || response.Hits.Total == nil || response.Hits.Total.Relation != "eq" || response.Hits.Total.Value < 0 {
		return ElasticCheck{}, errors.New("elastic search is incomplete or timed out")
	}
	return ElasticCheck{Healthy: true, CheckedAt: time.Now().UTC(), Documents: response.Hits.Total.Value}, nil
}
