Audit TLS/SSL certificates for expiry, key strength, chain validity, and self-signed certs.

## Usage

- `paths` — optional certificate file paths to audit.
- `search_dirs` — optional directories to search for certificate files.
- `service_ports` — optional `host:port` pairs to probe for TLS certs.
- `check_expiry` — check expiration dates (default true).
- `check_key_strength` — check cryptographic key strength (default true).
- `check_chain` — validate the certificate chain (default true).
- `check_revocation` — check revocation status (default true).
- `verify_transport` — verify TLS endpoint identity during probe (default true).
- `expiry_warning_days` — days before expiry to trigger warning (default 30).
- `min_key_length` — minimum acceptable key length in bits (default 2048).

## Remote execution

Set `remote_host` (and optionally `remote_user`, `remote_port`,
`remote_key_path`, `remote_proxy_jump`) to audit certificates on a remote
machine via SSH.

## Output

Returns certificate details, days until expiry, key type/length, signature
algorithm, self-signed detection, chain status, and a list of issues with
remediation advice.
