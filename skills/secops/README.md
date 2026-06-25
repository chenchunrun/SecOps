# SecOps Skills Pack

This folder provides workflow-level SecOps skills.

## Boundary with built-in tools
- Built-in tools (20 SecOps tools) are execution primitives.
- Skills here are orchestration playbooks.
- Skills do not replace or disable built-in tools.

## How to enable
Add `skills_paths` in your Crush config:

```json
{
  "options": {
    "skills_paths": ["/path/to/crush-main/skills/secops"]
  }
}
```

## How to trigger
- Automatic: describe your task normally; the model matches skill descriptions.
- Explicit: ask to use a specific skill name (for example, `use incident-triage skill`).

## Defensive red lines (applies to all skills)
- Defensive operations only.
- No high-risk destructive operations without explicit approval.
- Keep evidence and audit trail complete.
- Do not fabricate findings, status, or evidence.
