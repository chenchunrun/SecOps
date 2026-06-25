Query infrastructure state for Terraform, AWS, GCP, Azure, and Kubernetes.

## Usage

- `system_type` — required: `terraform`, `aws`, `gcp`, `azure`, `kubernetes`.
- `query_type` — required: `state`, `resources`, `scaling`, `costs`.
- `target` — required workspace, cluster, project, or namespace.
- `filter` — optional filter expression for results.
- `region` — optional cloud region to scope the query.

## Remote execution

Set `remote_host` (and optionally `remote_user`, `remote_port`,
`remote_key_path`, `remote_proxy_jump`) to run the query from a remote machine
via SSH.

## Output

Returns resource lists, scaling information, cost estimates, Terraform state
summaries, or Kubernetes object status depending on the query type.
