## Plan: KubeVirt Best-Practices CLI

Build a Go-based CNCF-aligned CLI that audits any conformant Kubernetes cluster with KubeVirt enabled, using a hybrid policy architecture from v1 (Go-native checks + OPA/Rego), with human-readable output first and machine output (JSON) for automation. The implementation will focus on a resilient fetch-evaluate-report pipeline, policy modularity, and compatibility across current Kubernetes minus two minor versions.

**Steps**
1. Phase 0: Project bootstrap and guardrails.
2. Create module and CLI scaffolding with Cobra root command and `scan` subcommand.
3. Add foundational engineering guardrails: `golangci-lint`, `make` targets, CI skeleton, semantic versioning policy, and contribution docs.
4. Define compatibility constraints and feature gates for Kubernetes version window (current, current-1, current-2) and KubeVirt API discovery behavior.
5. Phase 1: Cluster access and discovery foundation. *depends on 1-4*
6. Implement kubeconfig/in-cluster auth loading and context resolution.
7. Implement API discovery layer to detect available group/versions (core, policy, networking, kubevirt.io) and capture capability matrix.
8. Implement permission probe to preflight read access for required resources and return best-effort scan mode when RBAC is limited.
9. Add request timeout, retry/backoff, and bounded concurrency controls for scale safety.
10. Phase 2: Check framework and shared data model. *depends on 6-9*
11. Define core check contracts: metadata (ID/category/severity/version), inputs, result schema, and remediation guidance fields.
12. Build check registry with category/tag filtering, include/exclude by ID, and stable ordering.
13. Build normalized finding model and run summary model (pass/fail/warn/error/unknown, skipped reason taxonomy).
14. Implement explicit exit-code contract for CLI runs (success with findings, policy violation, partial data, fatal runtime error).
15. Phase 3: Hybrid policy engine (Go + OPA/Rego) from day one. *depends on 11-14*
16. Implement Go evaluator runtime for built-in checks (fast path, typed logic).
17. Implement OPA/Rego evaluator runtime for policy bundle execution (declarative path).
18. Implement result unification layer so both evaluators emit identical finding schema.
19. Define policy packaging/distribution model: embedded baseline bundle + optional external bundle path/URL + signature/checksum validation.
20. Add versioned policy metadata contract and compatibility checks between binary version and policy bundle version.
21. Phase 4: Baseline checks for v1 domains. *depends on 16-20*
22. Production Readiness checks: KubeVirt API availability, operator deployment health/replicas, storage class/binding requirements for VM workloads, quotas and limits coverage, and migration prerequisites.
23. Security checks: namespace default-deny network policies, pod security posture alignment, RBAC over-privilege patterns affecting VM lifecycle, webhook/admission hardening for KubeVirt resources, and VM template security context risks.
24. Availability checks: anti-affinity/topology spread for VM workloads, PodDisruptionBudget presence for supporting components, control-plane HA signal checks, and live-migration readiness controls.
25. Add skip/waiver mechanism with mandatory justification metadata and report visibility.
26. Phase 5: Reporting and UX (human-first, automation-ready). *depends on 11-14, parallel with 22-25 after schema freeze*
27. Implement default human-readable table output with category rollups, severity counts, and actionable remediation text.
28. Implement JSON output with stable schema versioning for CI integration.
29. Add filtering flags: `--category`, `--severity`, `--check`, `--exclude-check`, `--namespace`, `--output`.
30. Add deterministic run metadata in reports (cluster context hash, discovery capabilities, policy bundle version, runtime duration).
31. Phase 6: Testing, compatibility matrix, and release pipeline. *depends on 22-30*
32. Unit tests for registry, evaluators, result normalization, and formatter contracts.
33. Fixture-based tests for checks using manifest sets (pass/fail/edge/false-positive regression cases).
34. Integration tests against kind-based clusters for supported Kubernetes version matrix and KubeVirt installed path.
35. Add non-KubeVirt negative test path to ensure graceful degradation and clear messaging.
36. Add performance tests for medium/large resource counts and enforce latency budget thresholds.
37. Wire CI pipeline: lint, unit, integration (matrix), artifact build, SBOM generation, and release signing.
38. Phase 7: Documentation and adoption packaging. *depends on 27-37*
39. Publish check catalog docs with IDs, rationale, severity, and remediation mapping.
40. Provide policy authoring guide for Rego and equivalent Go-check development guide.
41. Provide operations guide for RBAC prerequisites, best-effort mode semantics, and troubleshooting.
42. Provide example workflows for local audits and CI gating with JSON outputs.

**Relevant files**
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/go.mod — module declaration and dependency baselines.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/cmd/kvirtbp/main.go — CLI entrypoint and root command wiring.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/internal/cli/root.go — persistent flags and command bootstrap.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/internal/cli/scan.go — scan command orchestration and flag handling.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/internal/kube/client.go — client-go initialization and kube context handling.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/internal/kube/discovery.go — API discovery and capability matrix generation.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/internal/kube/rbac_preflight.go — permission probes and degraded mode handling.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/internal/checks/types.go — check metadata/result interfaces and contracts.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/internal/checks/registry.go — check registration, filtering, execution order.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/internal/eval/goeval/engine.go — Go-native check evaluator.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/internal/eval/rego/engine.go — OPA/Rego evaluator integration.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/internal/eval/merge/normalize.go — unified findings normalization.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/internal/checks/production/* — production-readiness checks.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/internal/checks/security/* — security checks.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/internal/checks/availability/* — availability checks.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/policy/baseline/*.rego — baseline Rego policy bundle.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/internal/report/table.go — human-readable report rendering.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/internal/report/json.go — stable JSON schema output.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/internal/report/schema.go — report schema versioning.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/test/fixtures/** — test manifests and expected outcomes.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/test/integration/** — kind + KubeVirt integration tests.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/.github/workflows/ci.yml — lint/test/matrix/release verification.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/README.md — usage, examples, and scope statement.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/docs/check-catalog.md — check taxonomy and remediation mapping.
- /Users/phenix/Documents/CODE/github.com/phenixblue/kvirtbp/docs/policy-authoring.md — Rego/Go extension model.

**Verification**
1. Validate CLI behavior: run `scan` against a cluster with KubeVirt and confirm table output includes category/severity summaries and non-zero violation exit code behavior.
2. Validate machine output: run with JSON output and verify schema version field, deterministic ordering, and parser compatibility in a CI-style script.
3. Validate hybrid evaluation: run same check IDs through Go evaluator and Rego evaluator and assert normalized-equivalent findings for canonical fixtures.
4. Validate RBAC degradation: run with restricted ServiceAccount and confirm partial-scan report explicitly marks skipped/unknown resources without hard crash.
5. Validate compatibility matrix: execute integration tests for supported Kubernetes minor versions and verify capability gating when API groups differ.
6. Validate non-KubeVirt handling: run against cluster without KubeVirt CRDs and confirm clear informational message and proper skip semantics.
7. Validate scale/performance: run synthetic large-manifest test and verify scan completes within defined timeout and bounded memory target.
8. Validate supply-chain quality: ensure CI produces signed binaries, SBOM, and passing lint/test gates before release tagging.

**Decisions**
- Policy architecture: include Go-native and OPA/Rego evaluators in v1 with a unified finding model.
- UX priority: default to human-readable table reports; JSON included in v1 for automation.
- Output scope v1: table + JSON only; SARIF/JUnit deferred.
- Compatibility target: support current Kubernetes minor and previous two minors.
- Cluster portability: design to avoid distribution-specific assumptions and require only conformant API behavior.

**Further Considerations**
1. Compliance profile packaging: start with a single baseline profile in v1, then add profile sets (e.g., strict, regulated, edge) in v1.1.
2. Waiver governance: store waivers in a versioned YAML file with expiration and owner fields to reduce permanent exceptions.
3. Data collection mode: optionally add `--snapshot` in later release to export fetched objects for offline policy replay and audit reproducibility.