Evaluate system compliance against industry security frameworks.

Supported frameworks: **CIS Benchmark**, **Docker Bench**, **PCI-DSS**,
**SOC 2**, **HIPAA**, **GDPR**, **ISO 27001**.

## Usage

- `framework` — required: `cis`, `docker_bench`, `pci_dss`, `soc2`, `hipaa`,
  `gdpr`, or `iso27001`.
- `target_path` — optional: directory to audit (default: `/`).
- `category` — optional: limit checks to a specific category.
- `severity` — optional minimum severity filter.

## Remote execution

Set `remote_host` (and optionally `remote_user`, `remote_port`,
`remote_key_path`, `remote_proxy_jump`) to run compliance checks on a remote
machine via SSH.

## Output

Returns a compliance status (`pass`, `warning`, `fail`), individual check
results with pass/fail/skip counts, detailed findings per control, and
remediation recommendations.
