# SecOps Agent

<p align="center">
    <a href="https://stuff.charm.sh/crush/charm-crush.png"><img width="450" alt="SecOps Agent" src="https://github.com/user-attachments/assets/cf8ca3ce-8b02-43f0-9d0f-5a331488da4b" /></a><br />
    <a href="https://github.com/chenchunrun/SecOps/releases"><img src="https://img.shields.io/github/release/chenchunrun/SecOps" alt="Latest Release"></a>
    <a href="https://github.com/chenchunrun/SecOps/actions"><img src="https://github.com/chenchunrun/SecOps/actions/workflows/build.yml/badge.svg" alt="Build Status"></a>
</p>

> Independent fork and SecOps extension maintained and released by
> **chenchunrun**.
> Built from the original Crush base, but extended into a security-operations
> runtime with policy, audit, and secure execution controls. Not affiliated
> with or endorsed by Charmbracelet.

Core contributor:

- `chenchunrun` `<chenchunrun@gmail.com>`

<p align="center">A terminal-native SecOps and engineering assistant with governed execution, auditability, and risk-aware automation.</p>
<p align="center">面向安全运营和工程协作的终端智能体，强调受控执行、风险感知和可审计自动化。</p>

<p align="center"><img width="800" alt="SecOps Agent Demo" src="https://github.com/user-attachments/assets/58280caf-851b-470a-b6f7-d5c4ea8a1968" /></p>

## What SecOps Adds

- **18 SecOps tools:** security scanning, monitoring, log analysis, certificate auditing, secret auditing, compliance checks, incident support, ATT&CK reasoning, incident assessment, deployment and infrastructure queries, and more.
- **35 security skills:** defensive skills (IR, threat intelligence, log analysis, malware analysis, compliance reporting) plus 7 red team skills with a mandatory authorization gate.
- **Risk-aware execution:** capability checks and permission decisions evaluate risk signals before sensitive tools or commands run.
- **Audit and SIEM pipeline:** every governed action can be recorded, reviewed, and exported to ELK, Splunk, Azure Sentinel, or generic JSON sinks with redaction.
- **Governed execution backends:** local, Docker, and SSH execution paths now carry policy validation, audit middleware, and remote-target checks.
- **Mode-specialized agents:** AUTO, OPS, SEC, and CODE flows expose explicit routing for operations and security work in the TUI.
- **SecOps-first runtime architecture:** capability registry, tool catalogs, fixed toolset datasets, and config/runtime wiring were generalized to reduce drift across the system.

## Security Skills

SecOps ships with 35 skills under `skills/`. Switch to the `sec` agent (`/sec`) to use them.

### Defensive Skills (28 — available by default)

| Category | Skills |
|----------|--------|
| Incident Response | `linux-ir`, `macos-ir`, `windows-ir`, `auth-log-analysis` |
| Threat Intelligence | `ip-analysis`, `domain-analysis`, `url-analysis`, `phishing-analysis`, `email-osint`, `traffic-analysis`, `dns-cache-detection` |
| Asset & Attack Surface | `asset-discovery`, `asset-monitor`, `cyberspace-search`, `brand-impersonation` |
| Malware Detection | `binary-reverse-engineering`, `office-malware-analyzer`, `pdf-analysis`, `prompt-injection-detect`, `ttp-extractor` |
| Code & Supply Chain | `code-audit`, `sca-analyzer` |
| Utilities | `data-desensitize`, `researching-vulnerabilities`, `rga-knowledge-search`, `mail-attachment-downloader` |
| Reporting | `office-report`, `pdf-report` |

### Red Team Skills (7 — require explicit authorization)

> ⚠️ Red team skills are part of the SecurityExpertAgent's professional toolkit.
> They are **gated behind a mandatory runtime authorization protocol** — the agent
> will not proceed without explicit user confirmation for each invocation.

| Skill | Purpose |
|-------|---------|
| `redteam-recon-enterprise` | Enterprise attack surface mapping |
| `redteam-recon-person` | Individual OSINT and social engineering profiling |
| `redteam-recon-nation` | APT and nation-state threat actor intelligence |
| `redteam-recon-ngo` | NGO/civil society attack surface reconnaissance |
| `redteam-intrusion-hunter` | Automated vulnerability scanning and PoC validation |
| `redteam-intrusion-0day` | Zero-day research and exploitability assessment |
| `redteam-intrusion-social` | Social engineering and phishing campaign planning |

#### How the Authorization Gate Works

When you invoke any red team skill, the SecurityExpertAgent will:

1. **Declare intent** — state which skill it is activating and what it will do.
2. **Request confirmation** — ask you to type `已授权` or `AUTHORIZED` along with the target scope and rules of engagement.
3. **Record and proceed** — only after confirmation does it execute. The invocation is logged as a `security_alert` audit event.

The agent will **refuse** if:
- You have not typed the authorization phrase.
- The target appears outside the stated scope.
- Any step is irreversible without a rollback plan.

#### Enabling Red Team Capabilities (optional hardening)

By default, red team skills rely on the behavioral gate in the agent prompt.
For stricter enforcement at the capability layer, add to your `crush.json`:

```json
{
  "permissions": {
    "secops_capability_grants": {
      "analyst": ["redteam:execute", "redteam:recon", "redteam:intrude"]
    }
  }
}
```

Without this config, the capability `redteam:execute` is never granted to any
role automatically, and the system will report capability-denied for tools that
check it explicitly.

## Base Capabilities

- **Multi-model:** works with OpenAI-compatible, Anthropic-compatible, and other provider integrations already present in the upstream base.
- **Session-based workflows:** keeps per-project conversational and tool context.
- **LSP and MCP integration:** supports code intelligence and external capability extension.
- **Cross-platform terminal UX:** runs on macOS, Linux, and Windows environments supported by the underlying project.

## Architecture Highlights

- **Capability registry generalization:** the SecOps capability layer was refactored into a reusable registry/spec model instead of one-off descriptor plumbing.
- **Toolset unification:** fixed built-in tools now use dataset-backed builders and catalog helpers instead of scattered ad hoc registration.
- **Execution middleware refactor:** policy and audit concerns were lifted into shared middleware around local and remote execution.
- **Security hardening:** SIEM exporters require real HTTPS endpoints, SSH targets enforce host/port allowlists, and dangerous path access is checked earlier in the execution path.
- **Public-docs split:** durable public guides stay under [`docs/README.md`](/Users/newmba/SecOpsCode/crush-main/docs/README.md), while process records stay local-only.

## Documentation

- Product and usage guide:
  [`docs/guides/secops_README.md`](/Users/newmba/SecOpsCode/crush-main/docs/guides/secops_README.md)
- Installation guide:
  [`docs/guides/INSTALL_ONECLICK_zh-CN.md`](/Users/newmba/SecOpsCode/crush-main/docs/guides/INSTALL_ONECLICK_zh-CN.md)
- Licensing and contributor records:
  [`docs/legal/MIXED_LICENSE_ASSESSMENT_2026-04-04.md`](/Users/newmba/SecOpsCode/crush-main/docs/legal/MIXED_LICENSE_ASSESSMENT_2026-04-04.md)
  [`docs/legal/CONTRIBUTORS.md`](/Users/newmba/SecOpsCode/crush-main/docs/legal/CONTRIBUTORS.md)
- Full documentation index:
  [`docs/README.md`](/Users/newmba/SecOpsCode/crush-main/docs/README.md)

## Validation

This fork includes SecOps runtime capabilities, risk-aware permissions,
auditing, and secure execution controls.

The cross-platform CI closure passed Build, Security, Lint, and Snapshot on
2026-07-14. The stabilization baseline is commit
[`86c91a3`](https://github.com/chenchunrun/SecOps/commit/86c91a3599e35fe36026bf9239dd2426b9e0bf0a);
the remaining release action is to tag that verified line and publish a GitHub
Release.

Recommended release verification commands:

```bash
GOCACHE=$(pwd)/.gocache go test ./internal/agent/tools/secops -count=1
GOCACHE=$(pwd)/.gocache go test ./internal/integration -count=1
GOCACHE=$(pwd)/.gocache go test ./internal/sandbox ./internal/audit -count=1
CGO_ENABLED=0 GOCACHE=$(pwd)/.gocache go test ./... -count=1
CGO_ENABLED=0 GOCACHE=$(pwd)/.gocache go build ./...
```

Public reference material:

- [`docs/guides/secops_README.md`](/Users/newmba/SecOpsCode/crush-main/docs/guides/secops_README.md)
- [`docs/legal/MIXED_LICENSE_ASSESSMENT_2026-04-04.md`](/Users/newmba/SecOpsCode/crush-main/docs/legal/MIXED_LICENSE_ASSESSMENT_2026-04-04.md)
- [`LICENSES/FILE_LICENSE_MAP.md`](/Users/newmba/SecOpsCode/crush-main/LICENSES/FILE_LICENSE_MAP.md)
- [`docs/README.md`](/Users/newmba/SecOpsCode/crush-main/docs/README.md)
- [`SECOPS_CLOSEOUT_GAP_PLAN_2026-07-10.md`](/Users/newmba/SecOpsCode/crush-main/SECOPS_CLOSEOUT_GAP_PLAN_2026-07-10.md)

## Installation

Published artifacts for this fork are distributed from the
[GitHub releases page](https://github.com/chenchunrun/SecOps/releases).

Recommended executable names:

- `SecOps`
- `secops-agent`

Build from source:

```bash
CGO_ENABLED=0 go build -o SecOps .
./SecOps --version
```

Install with Go:

```bash
go install github.com/chenchunrun/SecOps@latest
```

One-click packaging and Windows notes:

- [`docs/guides/INSTALL_ONECLICK_zh-CN.md`](/Users/newmba/SecOpsCode/crush-main/docs/guides/INSTALL_ONECLICK_zh-CN.md)

> [!WARNING]
> Productivity may increase when using SecOps and you may find yourself nerd
> sniped when first using the application. If the symptoms persist, join the
> [Discord][discord] and nerd snipe the rest of us.

## Getting Started

The quickest way to get started is to grab an API key for your preferred
provider such as Anthropic, OpenAI, Groq, OpenRouter, or Vercel AI Gateway and
start `SecOps`. You'll be prompted to enter your API key.

That said, you can also set environment variables for preferred providers.

| Environment Variable        | Provider                                           |
| --------------------------- | -------------------------------------------------- |
| `ANTHROPIC_API_KEY`         | Anthropic                                          |
| `OPENAI_API_KEY`            | OpenAI                                             |
| `VERCEL_API_KEY`            | Vercel AI Gateway                                  |
| `GEMINI_API_KEY`            | Google Gemini                                      |
| `SYNTHETIC_API_KEY`         | Synthetic                                          |
| `ZAI_API_KEY`               | Z.ai                                               |
| `MINIMAX_API_KEY`           | MiniMax                                            |
| `HF_TOKEN`                  | Hugging Face Inference                             |
| `CEREBRAS_API_KEY`          | Cerebras                                           |
| `OPENROUTER_API_KEY`        | OpenRouter                                         |
| `IONET_API_KEY`             | io.net                                             |
| `GROQ_API_KEY`              | Groq                                               |
| `VERTEXAI_PROJECT`          | Google Cloud VertexAI (Gemini)                     |
| `VERTEXAI_LOCATION`         | Google Cloud VertexAI (Gemini)                     |
| `AWS_ACCESS_KEY_ID`         | Amazon Bedrock (Claude)                            |
| `AWS_SECRET_ACCESS_KEY`     | Amazon Bedrock (Claude)                            |
| `AWS_REGION`                | Amazon Bedrock (Claude)                            |
| `AWS_PROFILE`               | Amazon Bedrock (Custom Profile)                    |
| `AWS_BEARER_TOKEN_BEDROCK`  | Amazon Bedrock                                     |
| `AZURE_OPENAI_API_ENDPOINT` | Azure OpenAI models                                |
| `AZURE_OPENAI_API_KEY`      | Azure OpenAI models (optional when using Entra ID) |
| `AZURE_OPENAI_API_VERSION`  | Azure OpenAI models                                |

### Subscriptions

If you prefer subscription-based usage, here are some plans that work well in
Crush:

- [Synthetic](https://synthetic.new/pricing)
- [GLM Coding Plan](https://z.ai/subscribe)
- [Kimi Code](https://www.kimi.com/membership/pricing)
- [MiniMax Coding Plan](https://platform.minimax.io/subscribe/coding-plan)

### By the Way

Is there a provider you’d like to see in Crush? Is there an existing model that needs an update?

Crush’s default model listing is managed in [Catwalk](https://github.com/charmbracelet/catwalk), a community-supported, open source repository of Crush-compatible models, and you’re welcome to contribute.

<a href="https://github.com/charmbracelet/catwalk"><img width="174" height="174" alt="Catwalk Badge" src="https://github.com/user-attachments/assets/95b49515-fe82-4409-b10d-5beb0873787d" /></a>

## Configuration

Crush runs great with no configuration. That said, if you do need or want to
customize Crush, configuration can be added either local to the project itself,
or globally, with the following priority:

1. `.crush.json`
2. `crush.json`
3. `$HOME/.config/crush/crush.json`

Configuration itself is stored as a JSON object:

```json
{
  "this-setting": { "this": "that" },
  "that-setting": ["ceci", "cela"]
}
```

As an additional note, Crush also stores ephemeral data, such as application state, in one additional location:

```bash
# Unix
$HOME/.local/share/crush/crush.json

# Windows
%LOCALAPPDATA%\crush\crush.json
```

> [!TIP]
> You can override the user and data config locations by setting:
> * `CRUSH_GLOBAL_CONFIG`
> * `CRUSH_GLOBAL_DATA`

### LSPs

Crush can use LSPs for additional context to help inform its decisions, just
like you would. LSPs can be added manually like so:

```json
{
  "$schema": "https://charm.land/crush.json",
  "lsp": {
    "go": {
      "command": "gopls",
      "env": {
        "GOTOOLCHAIN": "go1.24.5"
      }
    },
    "typescript": {
      "command": "typescript-language-server",
      "args": ["--stdio"]
    },
    "nix": {
      "command": "nil"
    }
  }
}
```

### MCPs

Crush also supports Model Context Protocol (MCP) servers through three
transport types: `stdio` for command-line servers, `http` for HTTP endpoints,
and `sse` for Server-Sent Events. Environment variable expansion is supported
using `$(echo $VAR)` syntax.

```json
{
  "$schema": "https://charm.land/crush.json",
  "mcp": {
    "filesystem": {
      "type": "stdio",
      "command": "node",
      "args": ["/path/to/mcp-server.js"],
      "timeout": 120,
      "disabled": false,
      "disabled_tools": ["some-tool-name"],
      "env": {
        "NODE_ENV": "production"
      }
    },
    "github": {
      "type": "http",
      "url": "https://api.githubcopilot.com/mcp/",
      "timeout": 120,
      "disabled": false,
      "disabled_tools": ["create_issue", "create_pull_request"],
      "headers": {
        "Authorization": "Bearer $GH_PAT"
      }
    },
    "streaming-service": {
      "type": "sse",
      "url": "https://example.com/mcp/sse",
      "timeout": 120,
      "disabled": false,
      "headers": {
        "API-Key": "$(echo $API_KEY)"
      }
    }
  }
}
```

### Ignoring Files

Crush respects `.gitignore` files by default, but you can also create a
`.crushignore` file to specify additional files and directories that Crush
should ignore. This is useful for excluding files that you want in version
control but don't want Crush to consider when providing context.

The `.crushignore` file uses the same syntax as `.gitignore` and can be placed
in the root of your project or in subdirectories.

### Allowing Tools

By default, Crush will ask you for permission before running tool calls. If
you'd like, you can allow tools to be executed without prompting you for
permissions. Use this with care.

```json
{
  "$schema": "https://charm.land/crush.json",
  "permissions": {
    "allowed_tools": [
      "view",
      "ls",
      "grep",
      "edit",
      "mcp_context7_get-library-doc"
    ]
  }
}
```

You can also skip all permission prompts entirely by running Crush with the
`--yolo` flag. Be very, very careful with this feature.

### Bypass-Intent Guardrail

To reduce prompt/skill injection risk, Crush performs bypass-intent checks in
the permission chain before applying `allowed_tools`, `--yolo`, or session
auto-approve.

- High/Critical risk requests are forced to interactive confirmation.
- Suspected bypass intent emits audit event:
  - `event_type: security_alert`
  - `action: permission_bypass_intent_detected`

You can customize marker rules in config:

```json
{
  "$schema": "https://charm.land/crush.json",
  "permissions": {
    "bypass_intent_markers": [
      "ignore all guardrails",
      "org-bypass-keyword"
    ],
    "extra_bypass_intent_markers": [
      "临时绕过审批"
    ]
  }
}
```

- `bypass_intent_markers`: override default marker set.
- `extra_bypass_intent_markers`: append organization-specific markers.

### Disabling Built-In Tools

If you'd like to prevent Crush from using certain built-in tools entirely, you
can disable them via the `options.disabled_tools` list. Disabled tools are
completely hidden from the agent.

```json
{
  "$schema": "https://charm.land/crush.json",
  "options": {
    "disabled_tools": [
      "bash",
      "sourcegraph"
    ]
  }
}
```

To disable tools from MCP servers, see the [MCP config section](#mcps).

### Agent Skills

Crush supports the [Agent Skills](https://agentskills.io) open standard for
extending agent capabilities with reusable skill packages. Skills are folders
containing a `SKILL.md` file with instructions that Crush can discover and
activate on demand.

Skills are discovered from:

- `~/.config/crush/skills/` on Unix (default, can be overridden with `CRUSH_SKILLS_DIR`)
- `%LOCALAPPDATA%\crush\skills\` on Windows (default, can be overridden with `CRUSH_SKILLS_DIR`)
- Additional paths configured via `options.skills_paths`

```jsonc
{
  "$schema": "https://charm.land/crush.json",
  "options": {
    "skills_paths": [
      "~/.config/crush/skills", // Windows: "%LOCALAPPDATA%\\crush\\skills",
      "./project-skills"
    ]
  }
}
```

You can get started with example skills from [anthropics/skills](https://github.com/anthropics/skills):

```bash
# Unix
mkdir -p ~/.config/crush/skills
cd ~/.config/crush/skills
git clone https://github.com/anthropics/skills.git _temp
mv _temp/skills/* . && rm -rf _temp
```

```powershell
# Windows (PowerShell)
mkdir -Force "$env:LOCALAPPDATA\crush\skills"
cd "$env:LOCALAPPDATA\crush\skills"
git clone https://github.com/anthropics/skills.git _temp
mv _temp/skills/* . ; rm -r -force _temp
```

### Desktop notifications

Crush sends desktop notifications when a tool call requires permission and when
the agent finishes its turn. They're only sent when the terminal window isn't
focused _and_ your terminal supports reporting the focus state.

```jsonc
{
  "$schema": "https://charm.land/crush.json",
  "options": {
    "disable_notifications": false // default
  }
}
```

To disable desktop notifications, set `disable_notifications` to `true` in your
configuration. On macOS, notifications currently lack icons due to platform
limitations.

### Initialization

When you initialize a project, Crush analyzes your codebase and creates
a context file that helps it work more effectively in future sessions.
By default, this file is named `AGENTS.md`, but you can customize the
name and location with the `initialize_as` option:

```json
{
  "$schema": "https://charm.land/crush.json",
  "options": {
    "initialize_as": "AGENTS.md"
  }
}
```

This is useful if you prefer a different naming convention or want to
place the file in a specific directory (e.g., `CRUSH.md` or
`docs/LLMs.md`). Crush will fill the file with project-specific context
like build commands, code patterns, and conventions it discovered during
initialization.

### Attribution Settings

By default, Crush adds attribution information to Git commits and pull requests
it creates. You can customize this behavior with the `attribution` option:

```json
{
  "$schema": "https://charm.land/crush.json",
  "options": {
    "attribution": {
      "trailer_style": "co-authored-by",
      "generated_with": true
    }
  }
}
```

- `trailer_style`: Controls the attribution trailer added to commit messages
  (default: `assisted-by`)
	- `assisted-by`: Adds `Assisted-by: [Model Name] via Crush <crush@charm.land>`
	  (includes the model name)
	- `co-authored-by`: Adds `Co-Authored-By: Crush <crush@charm.land>`
	- `none`: No attribution trailer
- `generated_with`: When true (default), adds `💘 Generated with Crush` line to
  commit messages and PR descriptions

### Custom Providers

Crush supports custom provider configurations for both OpenAI-compatible and
Anthropic-compatible APIs.

> [!NOTE]
> Note that we support two "types" for OpenAI. Make sure to choose the right one
> to ensure the best experience!
> * `openai` should be used when proxying or routing requests through OpenAI.
> * `openai-compat` should be used when using non-OpenAI providers that have OpenAI-compatible APIs.

#### OpenAI-Compatible APIs

Here’s an example configuration for Deepseek, which uses an OpenAI-compatible
API. Don't forget to set `DEEPSEEK_API_KEY` in your environment.

```json
{
  "$schema": "https://charm.land/crush.json",
  "providers": {
    "deepseek": {
      "type": "openai-compat",
      "base_url": "https://api.deepseek.com/v1",
      "api_key": "$DEEPSEEK_API_KEY",
      "models": [
        {
          "id": "deepseek-chat",
          "name": "Deepseek V3",
          "cost_per_1m_in": 0.27,
          "cost_per_1m_out": 1.1,
          "cost_per_1m_in_cached": 0.07,
          "cost_per_1m_out_cached": 1.1,
          "context_window": 64000,
          "default_max_tokens": 5000
        }
      ]
    }
  }
}
```

#### Anthropic-Compatible APIs

Custom Anthropic-compatible providers follow this format:

```json
{
  "$schema": "https://charm.land/crush.json",
  "providers": {
    "custom-anthropic": {
      "type": "anthropic",
      "base_url": "https://api.anthropic.com/v1",
      "api_key": "$ANTHROPIC_API_KEY",
      "extra_headers": {
        "anthropic-version": "2023-06-01"
      },
      "models": [
        {
          "id": "claude-sonnet-4-20250514",
          "name": "Claude Sonnet 4",
          "cost_per_1m_in": 3,
          "cost_per_1m_out": 15,
          "cost_per_1m_in_cached": 3.75,
          "cost_per_1m_out_cached": 0.3,
          "context_window": 200000,
          "default_max_tokens": 50000,
          "can_reason": true,
          "supports_attachments": true
        }
      ]
    }
  }
}
```

### Amazon Bedrock

Crush currently supports running Anthropic models through Bedrock, with caching disabled.

- A Bedrock provider will appear once you have AWS configured, i.e. `aws configure`
- Crush also expects the `AWS_REGION` or `AWS_DEFAULT_REGION` to be set
- To use a specific AWS profile set `AWS_PROFILE` in your environment, i.e. `AWS_PROFILE=myprofile crush`
- Alternatively to `aws configure`, you can also just set `AWS_BEARER_TOKEN_BEDROCK`

### Vertex AI Platform

Vertex AI will appear in the list of available providers when `VERTEXAI_PROJECT` and `VERTEXAI_LOCATION` are set. You will also need to be authenticated:

```bash
gcloud auth application-default login
```

To add specific models to the configuration, configure as such:

```json
{
  "$schema": "https://charm.land/crush.json",
  "providers": {
    "vertexai": {
      "models": [
        {
          "id": "claude-sonnet-4@20250514",
          "name": "VertexAI Sonnet 4",
          "cost_per_1m_in": 3,
          "cost_per_1m_out": 15,
          "cost_per_1m_in_cached": 3.75,
          "cost_per_1m_out_cached": 0.3,
          "context_window": 200000,
          "default_max_tokens": 50000,
          "can_reason": true,
          "supports_attachments": true
        }
      ]
    }
  }
}
```

### Local Models

Local models can also be configured via OpenAI-compatible API. Here are two common examples:

#### Ollama

```json
{
  "providers": {
    "ollama": {
      "name": "Ollama",
      "base_url": "http://localhost:11434/v1/",
      "type": "openai-compat",
      "models": [
        {
          "name": "Qwen 3 30B",
          "id": "qwen3:30b",
          "context_window": 256000,
          "default_max_tokens": 20000
        }
      ]
    }
  }
}
```

#### LM Studio

```json
{
  "providers": {
    "lmstudio": {
      "name": "LM Studio",
      "base_url": "http://localhost:1234/v1/",
      "type": "openai-compat",
      "models": [
        {
          "name": "Qwen 3 30B",
          "id": "qwen/qwen3-30b-a3b-2507",
          "context_window": 256000,
          "default_max_tokens": 20000
        }
      ]
    }
  }
}
```

## Logging

Sometimes you need to look at logs. Luckily, Crush logs all sorts of
stuff. Logs are stored in `./.crush/logs/crush.log` relative to the project.

The CLI also contains some helper commands to make perusing recent logs easier:

```bash
# Print the last 1000 lines
crush logs

# Print the last 500 lines
crush logs --tail 500

# Follow logs in real time
crush logs --follow
```

Want more logging? Run `crush` with the `--debug` flag, or enable it in the
config:

```json
{
  "$schema": "https://charm.land/crush.json",
  "options": {
    "debug": true,
    "debug_lsp": true
  }
}
```

## Provider Auto-Updates

By default, Crush automatically checks for the latest and greatest list of
providers and models from [Catwalk](https://github.com/charmbracelet/catwalk),
the open source Crush provider database. This means that when new providers and
models are available, or when model metadata changes, Crush automatically
updates your local configuration.

### Disabling automatic provider updates

For those with restricted internet access, or those who prefer to work in
air-gapped environments, this might not be want you want, and this feature can
be disabled.

To disable automatic provider updates, set `disable_provider_auto_update` into
your `crush.json` config:

```json
{
  "$schema": "https://charm.land/crush.json",
  "options": {
    "disable_provider_auto_update": true
  }
}
```

Or set the `CRUSH_DISABLE_PROVIDER_AUTO_UPDATE` environment variable:

```bash
export CRUSH_DISABLE_PROVIDER_AUTO_UPDATE=1
```

### Manually updating providers

Manually updating providers is possible with the `crush update-providers`
command:

```bash
# Update providers remotely from Catwalk.
crush update-providers

# Update providers from a custom Catwalk base URL.
crush update-providers https://example.com/

# Update providers from a local file.
crush update-providers /path/to/local-providers.json

# Reset providers to the embedded version, embedded at crush at build time.
crush update-providers embedded

# For more info:
crush update-providers --help
```

## Metrics

Crush records pseudonymous usage metrics (tied to a device-specific hash),
which maintainers rely on to inform development and support priorities. The
metrics include solely usage metadata; prompts and responses are NEVER
collected.

Details on exactly what’s collected are in the source code ([here](https://github.com/chenchunrun/SecOps/tree/main/internal/event)
and [here](https://github.com/chenchunrun/SecOps/blob/main/internal/llm/agent/event.go)).

You can opt out of metrics collection at any time by setting the environment
variable by setting the following in your environment:

```bash
export CRUSH_DISABLE_METRICS=1
```

Or by setting the following in your config:

```json
{
  "options": {
    "disable_metrics": true
  }
}
```

Crush also respects the `DO_NOT_TRACK` convention which can be enabled via
`export DO_NOT_TRACK=1`.

## Contributing

See the [contributing guide](https://github.com/chenchunrun/SecOps?tab=contributing-ov-file#contributing).

## Whatcha think?

We’d love to hear your thoughts on this project. Need help? We gotchu. You can find us on:

- [Twitter](https://twitter.com/charmcli)
- [Slack](https://charm.land/slack)
- [Discord][discord]
- [The Fediverse](https://mastodon.social/@charmcli)
- [Bluesky](https://bsky.app/profile/charm.land)

[discord]: https://charm.land/discord

## License

This repository is a mixed-license fork.

- The inherited and derivative Crush codebase remains governed by
  [`LICENSE.md`](/Users/newmba/SecOpsCode/crush-main/LICENSE.md), which
  contains the upstream `FSL-1.1-MIT` terms.
- Selected independent fork additions may be published under
  [`LICENSES/MIT-CHENCHUNRUN.txt`](/Users/newmba/SecOpsCode/crush-main/LICENSES/MIT-CHENCHUNRUN.txt).
- The current file-level designation is recorded in
  [`LICENSES/FILE_LICENSE_MAP.md`](/Users/newmba/SecOpsCode/crush-main/LICENSES/FILE_LICENSE_MAP.md).

This repository should not currently be represented as a single-license MIT
project or as wholly OSI-open-source.

---

Part of [Charm](https://charm.land).

<a href="https://charm.land/"><img alt="The Charm logo" width="400" src="https://stuff.charm.sh/charm-banner-next.jpg" /></a>

<!--prettier-ignore-->
Charm热爱开源 • Charm loves open source
