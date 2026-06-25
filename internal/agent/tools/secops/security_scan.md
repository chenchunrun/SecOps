Run vulnerability scans using industry-standard scanners.

Supported scanners: **Trivy**, **Grype**, **Nuclei**, **ClamAV**.

## Usage

- `scanner` — required: `trivy`, `grype`, `nuclei`, or `clamav`.
- `target` — required: `image`, `filesystem`, `git`, or `url`.
- `target_path` — required: the image name, directory, repo, or URL to scan.
- `scan_type` — optional: `vuln`, `config`, `secret`, or `all` (default).
- `severity` — optional minimum severity filter: `CRITICAL`, `HIGH`, `MEDIUM`,
  `LOW`.

## Remote execution

Set `remote_host` (and optionally `remote_user`, `remote_port`,
`remote_key_path`, `remote_proxy_jump`) to run the scanner on a remote machine
via SSH.

## Output

Returns total vulnerability counts by severity, a risk score (0–10), individual
vulnerability details (CVE, CVSS, fix availability), and prioritized
recommendations.
