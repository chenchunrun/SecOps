Audit system and service configurations including SSH, sudo, firewall, file permissions, kernel, and sysctl settings.

## Usage

- `targets` — required list: `ssh`, `sudo`, `firewall`, `file_permissions`,
  `kernel`, `sysctl`.
- `check_security` — enable security-related checks.
- `check_compliance` — enable compliance-related checks.
- `check_performance` — enable performance-related checks.
- `deep` — enable deep inspection of configuration files.
- `custom_rules` — optional custom rule IDs to include.

## Remote execution

Set `remote_host` (and optionally `remote_user`, `remote_port`,
`remote_key_path`, `remote_proxy_jump`) to run the audit on a remote machine
via SSH.

## Output

Returns a score (0–100), risk level, per-rule status (`pass`, `fail`,
`warning`, `info`), current/recommended values, and remediation recommendations.
