# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-04

Initial public release — the framework-neutral offensive core of the Agent
Assurance Layer.

### Added

- **Capability Manifest** (`src/manifest/`) — a versioned, zod-validated description
  of what an agent can touch (tools + side-effect class, data scopes, untrusted
  ingress, identity, declared mitigations).
- **Target Adapter** (`src/adapter/`) — the seam to run any agent; an exec adapter
  that round-trips a `{text, toolCalls}` JSON envelope over a subprocess (HTTP/SDK
  adapters stubbed).
- **Toxic-flow graph** (`src/graph/`) — static analysis over the manifest detecting
  the **lethal trifecta** (parity with the Agentic Product Standard's
  `lethal_trifecta_check.py`) and untrusted-content → code-execution paths.
- **Attack library** (`src/attacks/`, `attacks/`) — YAML corpus mapped to OWASP
  Agentic (ASI01–ASI10) and MITRE ATLAS, with machine-checkable success conditions
  (EN + RU).
- **Dynamic runner** (`src/runner/`) — a process-jail sandbox with canary
  interception (no real side effects), a pluggable success oracle, an
  execution-layer side-effect detector (refuse-in-text-but-fire = critical), and
  N-run stability scoring.
- **Reporting** (`src/report/`, `src/cli.ts`) — a severity-ranked findings model,
  SARIF 2.1.0, a Markdown report with a coverage ratio, structured JSON, and the
  `aal scan` CLI that gates CI (non-zero exit on any critical finding).
- **Cycle-of-Trust policy pack** (`policy-pack/`, `src/policy/`) — layered runtime
  enforcement that blocks an agent from editing its own tools, permissions, or
  hooks, with a hash-not-text audit event per attempt.

### Security invariants

- Fail-closed: inconclusive/errored is reported as `not_verified`, never `safe`.
- Hash-not-text: attack payloads and agent output are referenced by sha256 — never
  written raw to a log, report, or committed artifact.
- No engine dependency: the core imports no AgenticMind code.

[0.1.0]: https://github.com/Moai-Team-LLC/agent-assurance/releases/tag/v0.1.0
