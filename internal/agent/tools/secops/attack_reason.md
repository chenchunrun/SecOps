Rank MITRE ATT&CK techniques from normalized incident evidence and recommend next investigation steps.

## Usage

Provide normalized evidence events in `events`, or pass the output of other
SecOps tools directly:

- `incident_id` — optional incident identifier.
- `platform` — optional context such as `kubernetes`, `aws`, `gcp`.
- `events` — list of normalized evidence events.
- `alert_result` — optional output from `alert_check`.
- `log_analyze_result` — optional output from `log_analyze`.
- `timeline_result` — optional output from `incident_timeline`.
- `access_review_result` — optional output from `access_review`.

## Output

Returns a ranked list of ATT&CK technique matches, confidence scores,
evidence references, gaps, and recommended next actions.
