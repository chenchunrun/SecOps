# Reviewed local scanning

The interactive `/scan` workflow currently supports **local directories with
Trivy vulnerability scanning**. Install Trivy on the host first. The workflow
is unavailable when a non-local sandbox backend is configured.

1. Run `/scan new` (or open an existing session), then select `/sec`.
2. Run `/scan authorize /absolute/project/path` to grant that directory for
   30 minutes to the active role and session.
3. Run `/scan run /absolute/project/path`. Keep the returned scan ID, or use
   `/scan list` to find it again.
4. Run `/scan show <id>` to inspect the task and stored scanner evidence.
5. After inspecting package applicability and the evidence, run
   `/scan review <id> passed <review reason>` or
   `/scan review <id> rejected <review reason>`.
6. Use `/scan report <id>` to view a passed review's report.
7. Run `/scan revoke /absolute/project/path` when finished.

`/scan cancel <id>` cancels a pending or running scan. Expiry and revocation
are checked during execution. The scan ID is bound to its originating session;
open that session to inspect it after restarting. A process interrupted by an
application crash appears as interrupted and must be started as a new scan.
Completed evidence and recorded reviews remain available.

When typing `/`, the command palette opens. Continue typing `scan ...` and
press Enter; scan commands are routed directly rather than fuzzy-selected.
Reports wrap long lines and support arrow keys, Page Up/Down and Home/End.

Directory scopes use the canonical path, including symlink resolution. Scope
IDs displayed by `/capabilities` are hashes prefixed with `scan-`. Use `/scan
revoke` with the directory to revoke them conveniently. Directory authorization
does not authorize remediation or remote execution.

Evidence records contain normalized scanner output with a content hash. A
passed human review confirms the recorded review decision, not automatic proof
of exploitability. The checker identity is derived from the operating-system
UID of the local interactive operator;
this is not a federated multi-user identity system. Failed, canceled, rejected,
and unreviewed scans cannot produce a passed report.

The generic `security_scan` tool rejects `full=true` and `fix_vulns=true`.
All built-in SecOps tools support session cancellation; command and network
contexts inherit it, and local directory walks check it between entries.
An individual blocking filesystem operation may still need to return before
cancellation can be observed. For remote SSH
execution, closing the local SSH process does not guarantee termination of all
remote descendants.

The local scan workflow executes through the structured Skill Runner before
writing evidence. It validates the typed JSON contract, task binding, output
size, scan target, scanner identity, timestamp, vulnerability totals, and
severity counts. Invalid results never become completed evidence. This applies
to the built-in scan workflow; ordinary prompt-only `SKILL.md` instructions are
not automatically converted into structured runtime executions.

Unknown JSON tool parameter names, incorrect types, and null parameter objects
are rejected rather than silently ignored.

An opt-in real-scanner regression is available with Trivy on `PATH`:
`SECOPS_TEST_TRIVY=1 go test ./internal/agent/tools/secops -run TestRealTrivyCompatibility -count=1 -v`.
It scans an empty directory and a temporary dependency inventory, without
installing any vulnerable package. It requires access to the public Trivy DB;
if the default mirror is unreachable, set
`TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db:2`.

To exercise the TUI command lifecycle with the actual scanner, run:
`SECOPS_TEST_TRIVY=1 go test ./internal/ui/model -run TestRealTrivyScanCommandsEndToEnd -count=1 -v`.
This verifies the command callbacks, authorization, evidence and report flow;
it does not replace visual or human usability acceptance of a terminal build.

# Elastic read-only connection check

The first concrete connector checks one Elasticsearch index or alias using
`POST /<index>/_search`, with `size: 0`. It does not retrieve document contents
or update cases. HTTPS certificate validation is mandatory; redirects are not
followed. The check rejects timed-out or partially failed search responses.

Configure an expiring, read-only API key in your local environment:
`SECOPS_ELASTIC_API_KEY` and its RFC3339 expiry in
`SECOPS_ELASTIC_API_KEY_EXPIRES_AT`. Do not put the key in command arguments.
The supplied expiry is a local upper bound; Elasticsearch remains authoritative
for credential validity and index permissions.

```sh
SecOps connector elastic-check \
  --endpoint https://your-elasticsearch-host:9200 \
  --index your-authorized-alerts-alias \
  --audit-file /absolute/private/path/connector-audit.jsonl
```

The command records a local audit intent before querying and returns connection
health and a document count. This is a connection smoke test, not a full alert
ingestion or case-management integration. The other connector manifests remain
contracts pending provider-specific implementation and live acceptance.

For a private or local HTTPS endpoint, add `--ca-file /absolute/path/ca.crt`
to trust its PEM CA certificate for this connector only. System roots remain
trusted; certificate and hostname verification remain enabled. This does not
modify the operating system trust store. Empty or invalid CA files are rejected.

Protocol references: [Elastic API key authentication](https://www.elastic.co/docs/api/doc/elasticsearch/authentication)
and [search API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-search-2).
