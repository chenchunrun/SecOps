<!-- SPDX-License-Identifier: MIT -->

# Mixed License Assessment (2026-04-04)

This document records a conservative file-level licensing assessment for the
current `SecOps` fork.

It is not legal advice. Its purpose is to separate:

- code and documents that are clearly inherited from or derived from upstream
  `crush`, and therefore should continue to follow the upstream
  [`FSL-1.1-MIT`](https://spdx.org/licenses/FSL-1.1-MIT.html) terms, and
- files that appear to be independently added in this fork and are reasonable
  candidates for separate licensing treatment if the repository owner chooses
  to do so.

## Current Overall Status

- The repository as a whole should still be treated as an
  `FSL-1.1-MIT`-governed fork.
- The repository does **not** currently qualify as a single-license,
  standard-OSI-open-source project.
- A mixed-license layout is now documented in
  [`LICENSES/FILE_LICENSE_MAP.md`](/Users/newmba/SecOpsCode/crush-main/LICENSES/FILE_LICENSE_MAP.md)
  and
  [`LICENSES/MIT-CHENCHUNRUN.txt`](/Users/newmba/SecOpsCode/crush-main/LICENSES/MIT-CHENCHUNRUN.txt),
  but only for files that are genuinely independent additions and do not embed
  protected upstream expression.

## Category A: Keep Under Upstream FSL Terms

These files are inherited upstream files or are clearly modifications of
upstream/distributed fork code and should remain under the upstream license
regime unless relicensing authority is separately established.

Representative examples:

- [`README.md`](/Users/newmba/SecOpsCode/crush-main/README.md)
- [`AGENTS.md`](/Users/newmba/SecOpsCode/crush-main/AGENTS.md)
- [`internal/config/config.go`](/Users/newmba/SecOpsCode/crush-main/internal/config/config.go)
- [`internal/agent/coordinator.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/coordinator.go)
- [`internal/agent/secops_adapter.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/secops_adapter.go)
- [`internal/sandbox/executor.go`](/Users/newmba/SecOpsCode/crush-main/internal/sandbox/executor.go)
- [`internal/audit/siem_export.go`](/Users/newmba/SecOpsCode/crush-main/internal/audit/siem_export.go)

Assessment basis:

- These files either originate from the initial imported `Crush` codebase or
  are tightly coupled modifications to core fork/runtime files.
- Even when heavily modified in this fork, they remain part of the same
  derivative codebase and should not be re-declared as standalone MIT files
  without separate relicensing authority.

## Category B: Reasonable MIT-Candidate Additions

These files appear to have been introduced in this fork as independent new
files and are better candidates for separate permissive licensing treatment,
subject to owner review.

Examples from the recent closeout stream:

- [`internal/capability/registry/spec.go`](/Users/newmba/SecOpsCode/crush-main/internal/capability/registry/spec.go)
- [`internal/capability/registry/doc.go`](/Users/newmba/SecOpsCode/crush-main/internal/capability/registry/doc.go)
- [`internal/capability/registry/registry_test.go`](/Users/newmba/SecOpsCode/crush-main/internal/capability/registry/registry_test.go)
- [`internal/capability/registry/test_helpers_test.go`](/Users/newmba/SecOpsCode/crush-main/internal/capability/registry/test_helpers_test.go)
- [`internal/agent/tools/catalog.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/tools/catalog.go)
- [`internal/agent/tools/catalog_test.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/tools/catalog_test.go)
- [`internal/agent/tools/bash_toolset.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/tools/bash_toolset.go)
- [`internal/agent/tools/search_toolset.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/tools/search_toolset.go)
- [`internal/agent/tools/edit_toolset.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/tools/edit_toolset.go)
- [`internal/agent/tools/job_toolset.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/tools/job_toolset.go)
- [`internal/agent/tools/lsp_toolset.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/tools/lsp_toolset.go)
- [`internal/agent/tools/mcp_toolset.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/tools/mcp_toolset.go)
- [`internal/agent/tools/remote_toolset.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/tools/remote_toolset.go)
- [`internal/agent/tools/runtime_toolset.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/tools/runtime_toolset.go)
- [`CONTRIBUTORS.md`](/Users/newmba/SecOpsCode/crush-main/docs/legal/CONTRIBUTORS.md)
- [`PROJECT_ANALYSIS_MAPPING_2026-04-04.md`](/Users/newmba/SecOpsCode/crush-main/docs/project/PROJECT_ANALYSIS_MAPPING_2026-04-04.md)
- [`SECURITY_AUDIT_2026-04-04.md`](/Users/newmba/SecOpsCode/crush-main/docs/security/SECURITY_AUDIT_2026-04-04.md)

Assessment basis:

- These files were added as new files in fork history rather than edited in
  place from upstream.
- They are more plausibly separable as original additions by the fork
  maintainer.
- This is still a conservative technical assessment, not a legal opinion.

## Category C: Local/Release Materials That Should Be Deliberately Classified

These are not licensing blockers by themselves, but they need explicit policy:

- [`POST_RELEASE_CHECKLIST.md`](/Users/newmba/SecOpsCode/crush-main/docs/release/POST_RELEASE_CHECKLIST.md)
- [`MANUAL_TUI_ACCEPTANCE_2026-04-04.md`](/Users/newmba/SecOpsCode/crush-main/docs/release/MANUAL_TUI_ACCEPTANCE_2026-04-04.md)
- [`WINDOWS_PACKAGING_VERIFICATION_2026-04-04.md`](/Users/newmba/SecOpsCode/crush-main/docs/release/WINDOWS_PACKAGING_VERIFICATION_2026-04-04.md)
- [`CURRENT_MAINLINE_STATUS_2026-03-28.md`](/Users/newmba/SecOpsCode/crush-main/docs/project/CURRENT_MAINLINE_STATUS_2026-03-28.md)

These should either:

1. remain tracked public project records, or
2. be moved back to ignored local-only documentation.

Right now the repository still mixes both ideas, which is a governance clarity
issue even if it is not a code-license defect.

## Implemented Mixed-License Controls

The repository now includes:

1. A dedicated MIT text for selected independent additions:
   [`LICENSES/MIT-CHENCHUNRUN.txt`](/Users/newmba/SecOpsCode/crush-main/LICENSES/MIT-CHENCHUNRUN.txt).
2. A file-level mapping for the additions intentionally designated under MIT:
   [`LICENSES/FILE_LICENSE_MAP.md`](/Users/newmba/SecOpsCode/crush-main/LICENSES/FILE_LICENSE_MAP.md).
3. Updated project notices in
   [`README.md`](/Users/newmba/SecOpsCode/crush-main/README.md),
   [`secops_README.md`](/Users/newmba/SecOpsCode/crush-main/secops_README.md),
   and [`NOTICE`](/Users/newmba/SecOpsCode/crush-main/NOTICE).

What remains intentionally not done:

1. No relicensing of modified upstream files or derivative core files.
2. No claim that the repository as a whole is MIT-licensed.
3. No claim that the repository as a whole is standard OSI open source.

## Bottom Line

- Yes, a file-level distinction is possible.
- No, the current repository cannot honestly be presented as wholly MIT or
  wholly standard open source.
- A limited mixed-license approach is plausible for clearly independent new
  files added by the fork maintainer.
