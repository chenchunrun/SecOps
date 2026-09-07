# Private model discovery

Custom OpenAI-compatible providers can opt into fetching `<base_url>/models`
each time configuration loads (including CLI `models` and TUI startup):

```json
{
  "providers": {
    "local-llm": {
      "type": "openai-compat",
      "base_url": "http://127.0.0.1:11434/v1",
      "model_discovery": {
        "context_window": 8192,
        "default_max_tokens": 1024
      }
    }
  }
}
```

Use a custom provider ID, not a built-in catalog ID. For authenticated servers,
add `"api_key": "$PRIVATE_API_KEY"` or the appropriate `extra_headers`.
HTTPS is required except for literal loopback HTTP addresses. Redirects are
rejected, including same-origin redirects; configure the final base URL.
The endpoint must return an object with a `data` array of objects containing
nonempty `id` strings. This is the model-list shape used by
[Ollama's OpenAI-compatible API](https://docs.ollama.com/api/openai-compatibility).
Other protocols and pagination are not implemented.

The limits in the example are user-selected values, not detected capabilities.
Check your server configuration and model documentation before using them.
Discovery does not infer vision, reasoning, tool-call support, or pricing. Zero
cost fields in the internal catalog mean no pricing was supplied, not a promise
of free inference. A listed model may be an embedding model or otherwise
unsuitable for an agent; select a suitable model explicitly in the TUI or config.

Handwritten `models` entries take precedence by ID and retain all their metadata.
New IDs are appended in sorted order. Existing model selections are not changed
by discovery. The existing first-model default applies if no selection was made.
For heterogeneous fleets, use handwritten entries to override per-model limits.

Requests have a five-second deadline per provider, a 1 MiB response limit, and
a 4096-entry limit. Invalid IDs and malformed responses reject the entire result.
Failures retain handwritten models; if none exist, configuration reports an
error. The catalog is not persisted, and there is no periodic refresh or offline
cache: restart/reload configuration to discover changes. Startup discovery uses
the existing context-free config loader and is bounded by its request deadline.

No model-list response or authentication material is written to disk. Requests
use only the configured provider endpoint; this does not replace a network
policy for administrator-configured hosts. Keep the option absent to preserve
the previous behavior with no private model-list request.
