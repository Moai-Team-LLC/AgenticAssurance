# AAL Core (`agent-assurance`) — contract for Claude Code

Guidance for AI coding agents working in this repository.

## What this is
The **framework-neutral offensive core** of the Agent Assurance Layer (AAL). Given a
**Capability Manifest** and a **runner adapter**, it red-teams any agent: runs an
attack library against an isolated copy, builds a **toxic-flow graph** over the agent's
declared tools, and detects **execution-layer side-effect divergences** (the agent
refuses in text but a side-effecting tool still fires). Output: reproducible findings,
**SARIF**, and a human report. It is *not* a runtime guardrail and *not* a code scanner.

## Part of a suite — read the canon
- **Agentic Product Standard** (doctrine): https://github.com/Moai-Team-LLC/agentic-product-standard
  — Principle 6 "Security is structural", Harness Layer 8, the OWASP Agentic Top 10 anchor,
  and the `templates/security/` kit this repo productizes.
- **AgenticMind** (engine): the auditable memory substrate. **This repo must NOT import it.**
  AAL Core is framework-neutral; the AgenticMind-native evidence layer is a separate repo.

## Hard invariants (never violate)
- **No AgenticMind dependency.** `grep -rn agenticmind src/` must be empty.
- **Fail-closed.** Inconclusive/errored = `not_verified`, never `safe`.
- **Hash-not-text.** Never write a raw secret or offending attack payload to a log,
  report, or committed file. Reference payloads by sha256 (the `guard_events` contract).
- **Cycle of Trust.** This core is read/report-only. It never remediates and never
  triggers a side-effecting tool for real — all side effects are intercepted in the sandbox.

## Commands
```bash
bun run check     # lint + tsc + tests (the full gate)
bun test          # unit tests
bun run tsc       # typecheck
```
Lint (`oxlint`) needs Node >= 22.18 (`.nvmrc`); the rest run under Bun.

## Conventions (honor)
- **Conventional Commits**, enforced by commitlint + a husky `commit-msg` hook and CI.
- Strict TypeScript, functional style, `neverthrow` `Result` types (don't throw for control flow).
- `zod` on every external boundary (manifest, attack files, adapter I/O, report emit).
- **Every new failure mode becomes a permanent test.** Don't add a CLI command without a
  snapshot test of its output contract.
- No secrets/PII/real payloads in code, tests, or fixtures. `dotenvx` for runtime secrets.

## Where things live
```text
src/manifest/     <- Capability Manifest zod schema + loader (FR-1)
src/adapter/      <- Target adapter interface + exec/http/sdk impls (FR-1)
src/graph/        <- Toxic-flow graph + lethal-trifecta query (FR-3)
src/attacks/      <- Attack library format + loader; YAML corpus in attacks/ (FR-2)
src/runner/       <- Sandbox, attack runner, side-effect detector (FR-4/5)
src/report/       <- Findings model, SARIF emitter, human report (FR-6)
src/cli.ts        <- `aal` CLI entry (FR-12)
fixtures/         <- reference vulnerable agent + manifests for tests
```

## How to verify a change works
Run `bun run check`. A change to red-team logic must add or update a fixture-backed test
that proves the new detection (or non-detection) is correct. SARIF output must validate
against the SARIF 2.1.0 schema.
