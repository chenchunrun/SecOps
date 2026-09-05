# Reviewed local scanning

The interactive `/scan` workflow currently supports **local directories with
Trivy vulnerability scanning**. Install Trivy on the host first. The workflow
is unavailable when a non-local sandbox backend is configured.

1. Open a session and select `/sec`.
2. Run `/scan authorize /absolute/project/path` to grant that directory for
   30 minutes to the active role and session.
3. Run `/scan run /absolute/project/path`. Keep the returned scan ID, or use
   `/scan list` to find it again.
4. Run `/scan show <id>` to inspect the task and stored scanner evidence.
5. After inspecting package applicability and the evidence, run
   `/scan review <id> passed <review reason>` or
   `/scan review <id> rejected <review reason>`.
6. Use `/scan show <id>` again to view a passed review's report.
7. Run `/scan revoke /absolute/project/path` when finished.

`/scan cancel <id>` cancels a pending or running scan. Expiry and revocation
are checked during execution. The scan ID is bound to its originating session;
open that session to inspect it after restarting. A process interrupted by an
application crash appears as interrupted and must be started as a new scan.
Completed evidence and recorded reviews remain available.

Directory scopes use the canonical path, including symlink resolution. Scope
IDs displayed by `/capabilities` are hashes prefixed with `scan-`. Use `/scan
revoke` with the directory to revoke them conveniently. Directory authorization
does not authorize remediation or remote execution.

Evidence records contain normalized scanner output with a content hash. A
passed human review confirms the recorded review decision, not automatic proof
of exploitability. The checker identity is the local interactive operator;
this is not a federated multi-user identity system. Failed, canceled, rejected,
and unreviewed scans cannot produce a passed report.

The generic `security_scan` tool rejects `full=true` and `fix_vulns=true`.
Session cancellation is propagated to its scanner process. For remote SSH
execution, closing the local SSH process does not guarantee termination of all
remote descendants.

An opt-in real-scanner regression is available with Trivy on `PATH`:
`SECOPS_TEST_TRIVY=1 go test ./internal/agent/tools/secops -run TestRealTrivyCompatibility -count=1 -v`.
It scans an empty directory and a temporary dependency inventory, without
installing any vulnerable package. It requires access to the public Trivy DB;
if the default mirror is unreachable, set
`TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db:2`.

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

Protocol references: [Elastic API key authentication](https://www.elastic.co/docs/api/doc/elasticsearch/authentication)
and [search API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-search-2).
