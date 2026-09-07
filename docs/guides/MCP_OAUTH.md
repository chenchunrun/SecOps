# Browser OAuth for HTTP MCP servers

OAuth is opt-in for Streamable HTTP MCP servers. Configure an HTTPS MCP URL,
an explicitly trusted HTTPS issuer, and a preregistered **public** client ID:

```json
{
  "mcp": {
    "enterprise": {
      "type": "http",
      "url": "https://mcp.example.com/mcp",
      "oauth": {
        "issuer": "https://login.example.com",
        "client_id": "your-public-client-id",
        "scopes": ["read"]
      }
    }
  }
}
```

Obtain the client ID from your authorization-server administrator. Its native
application registration must allow `http://127.0.0.1:<ephemeral-port>/callback`
redirects and public-client authorization-code exchange with S256 PKCE. Client
secrets are not supported. The browser must run on the same computer as SecOps;
headless/SSH browser forwarding is not implemented.

On a 401, SecOps validates resource and issuer metadata, opens the browser, and
waits for consent. Approve only the permissions you intend to grant. A successful
callback retries the MCP request; this works for connections started by either
the CLI or TUI without an additional TUI dialog. Browser denial and cancellation
close the callback listener. A browser-launch failure is reported as an error.

The default connection timeout with OAuth is five minutes. An explicit `timeout`
still takes precedence, so remove a short legacy timeout if login is interrupted.

## Security and compatibility boundaries

- OAuth applies only to `type: "http"`, not stdio or legacy SSE. Existing header
  authentication is unchanged when OAuth is absent. Do not combine OAuth with an
  `Authorization` header.
- Resource metadata must identify the configured MCP URL exactly and advertise
  the configured issuer. It is obtained from the Bearer `resource_metadata`
  challenge, or the endpoint-specific protected-resource well-known path.
- Discovery and token HTTP traffic is restricted to the two configured HTTPS
  origins, with no HTTP redirects. Authorization and token endpoints must be
  on the issuer origin. This intentionally rejects some cross-origin deployments;
  it is not a complete network/SSRF policy for administrator-configured hosts.
- Metadata must advertise S256 PKCE. State and callback issuer are checked, and
  both authorization and token requests carry the configured `resource`.
- Scopes come only from your configuration. A 403 does not silently request more
  permissions. Change scopes deliberately and reconnect when necessary.
- Tokens are held only in memory for this connection. Refresh tokens are
  discarded. After expiry, the next unauthorized request requires browser login
  again. Reconnecting or restarting requires login again. Nothing is written to
  `crush.json`, the repository, or a credential file.
- Disconnecting drops local use of the connection; it does **not** revoke the
  remote OAuth grant. Revoke grants through your authorization platform.

Dynamic registration, credential persistence, automatic refresh, and a dedicated
TUI login/logout interface are not included. MCP authentication also does not
grant SecOps execution capabilities or bypass local approval policies.

The protocol checks follow the [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).
Local tests exercise a TLS authorization server and the real MCP SDK's
401 → callback → token exchange → initialize → list-tools flow. An actual
enterprise provider still needs a compatibility test with its registration.
