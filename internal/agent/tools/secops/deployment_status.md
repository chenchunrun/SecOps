Check deployment health, rollout status, and canary analysis for Kubernetes and cloud platforms.

## Usage

- `platform` — required: `kubernetes`, `aws`, `gcp`, `azure`.
- `namespace` — Kubernetes namespace for the deployment.
- `deployment` — name of the deployment to check.
- `env` — environment: `production`, `staging`, `dev`.
- `target` — cluster or target identifier.

## Remote execution

Set `remote_host` (and optionally `remote_user`, `remote_port`,
`remote_key_path`, `remote_proxy_jump`) to check deployment status from a
remote machine via SSH.

## Output

Returns replica status, rollout progress, strategy, canary analysis, health
indicators, and any deployment issues.
