Combine alerts, logs, timelines, and access review into an ATT&CK-guided incident assessment with containment advice.

## Usage

Provide the outputs of earlier investigation tools:

- `incident_id` — optional incident identifier.
- `platform` — optional context such as `kubernetes`, `aws`, `gcp`.
- `alert_result` — optional output from `alert_check`.
- `log_analyze_result` — optional output from `log_analyze`.
- `timeline_result` — optional output from `incident_timeline`.
- `access_review_result` — optional output from `access_review`.
- `events` — optional normalized evidence events.

## Output

Returns an executive summary, evidence summary, ATT&CK-based attack
assessment, and prioritized containment advice.
