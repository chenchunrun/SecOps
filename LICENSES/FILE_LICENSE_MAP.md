<!-- SPDX-License-Identifier: MIT -->

# File License Map

This repository is a mixed-license fork.

- The repository-level inherited and derivative codebase remains governed by
  [`LICENSE.md`](/Users/newmba/SecOpsCode/crush-main/LICENSE.md), which
  contains the upstream `FSL-1.1-MIT` terms.
- Selected independent additions created in this fork may be published under
  the MIT terms in
  [`LICENSES/MIT-CHENCHUNRUN.txt`](/Users/newmba/SecOpsCode/crush-main/LICENSES/MIT-CHENCHUNRUN.txt).
- This file is a conservative technical mapping, not legal advice.

## Files Intentionally Published Under MIT

The following files are designated as fork-maintainer additions and may be
distributed under
[`LICENSES/MIT-CHENCHUNRUN.txt`](/Users/newmba/SecOpsCode/crush-main/LICENSES/MIT-CHENCHUNRUN.txt):

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
- [`internal/agent/tools/bash_toolset_test.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/tools/bash_toolset_test.go)
- [`internal/agent/tools/search_toolset_test.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/tools/search_toolset_test.go)
- [`internal/agent/tools/edit_toolset_test.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/tools/edit_toolset_test.go)
- [`internal/agent/tools/job_toolset_test.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/tools/job_toolset_test.go)
- [`internal/agent/tools/lsp_toolset_test.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/tools/lsp_toolset_test.go)
- [`internal/agent/tools/mcp_toolset_test.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/tools/mcp_toolset_test.go)
- [`internal/agent/tools/remote_toolset_test.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/tools/remote_toolset_test.go)
- [`internal/agent/tools/runtime_toolset_test.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/tools/runtime_toolset_test.go)
- [`CONTRIBUTORS.md`](/Users/newmba/SecOpsCode/crush-main/CONTRIBUTORS.md)
- [`PROJECT_ANALYSIS_MAPPING_2026-04-04.md`](/Users/newmba/SecOpsCode/crush-main/PROJECT_ANALYSIS_MAPPING_2026-04-04.md)
- [`SECURITY_AUDIT_2026-04-04.md`](/Users/newmba/SecOpsCode/crush-main/SECURITY_AUDIT_2026-04-04.md)
- [`MIXED_LICENSE_ASSESSMENT_2026-04-04.md`](/Users/newmba/SecOpsCode/crush-main/MIXED_LICENSE_ASSESSMENT_2026-04-04.md)
- [`LICENSES/MIT-CHENCHUNRUN.txt`](/Users/newmba/SecOpsCode/crush-main/LICENSES/MIT-CHENCHUNRUN.txt)
- [`LICENSES/FILE_LICENSE_MAP.md`](/Users/newmba/SecOpsCode/crush-main/LICENSES/FILE_LICENSE_MAP.md)

## Files That Remain Under Repository-Level FSL Terms

Unless this file explicitly says otherwise, repository files should be treated
as governed by [`LICENSE.md`](/Users/newmba/SecOpsCode/crush-main/LICENSE.md).
That includes inherited upstream files and modified derivative core files such
as the main runtime, config, coordinator, sandbox, audit, and UI layers.

Representative examples:

- [`README.md`](/Users/newmba/SecOpsCode/crush-main/README.md)
- [`AGENTS.md`](/Users/newmba/SecOpsCode/crush-main/AGENTS.md)
- [`internal/config/config.go`](/Users/newmba/SecOpsCode/crush-main/internal/config/config.go)
- [`internal/agent/coordinator.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/coordinator.go)
- [`internal/agent/secops_adapter.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/secops_adapter.go)
- [`internal/sandbox/executor.go`](/Users/newmba/SecOpsCode/crush-main/internal/sandbox/executor.go)
- [`internal/audit/siem_export.go`](/Users/newmba/SecOpsCode/crush-main/internal/audit/siem_export.go)

## Scope Boundary

This mapping does not mean the repository as a whole is MIT-licensed or OSI
open source. It only identifies specific fork-added files that the fork
maintainer may publish separately under MIT while the inherited codebase
remains under the upstream FSL-derived licensing regime.
