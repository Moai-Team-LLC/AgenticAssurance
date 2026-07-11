# AgenticAssurance

[![CI](https://github.com/Moai-Team-LLC/AgenticAssurance/actions/workflows/ci.yml/badge.svg)](https://github.com/Moai-Team-LLC/AgenticAssurance/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![OWASP Agentic](https://img.shields.io/badge/OWASP-Agentic%20taxonomy-informational)](https://genai.owasp.org/)
[![SARIF 2.1.0](https://img.shields.io/badge/output-SARIF%202.1.0-brightgreen)](https://sarifweb.azurewebsites.net/)

The framework-neutral offensive core of the **Agent Assurance Layer (AAL)**. Given a
**Capability Manifest** and a **runner adapter**, it red-teams any agent:

- runs an **attack library** — mapped to the OWASP Top 10 for Agentic Applications taxonomy and MITRE ATLAS — against an isolated copy of the target (the seed corpus currently exercises ASI01/02/03/05; the schema and graph cover the full ASI01–ASI10 range);
- builds a **toxic-flow graph** over the agent's declared tools to find lethal-trifecta and RCE composition paths that single-prompt scanners miss;
- detects **execution-layer side-effect divergences** — the agent refuses in text but a side-effecting tool still fires;
- emits **SARIF** (for CI/code-scanning) and a human-readable report.

It is **not** a runtime guardrail and **not** a generic code scanner. The AgenticMind-native
compliance/evidence layer (AIUC-1 gap analysis, auditor bundle) is a separate package.

## Install

```bash
# published on npm — run it with no install:
npx agent-assurance scan path/to/manifest.json --sarif out.sarif

# or from source (contributors):
git clone https://github.com/Moai-Team-LLC/AgenticAssurance && cd AgenticAssurance
nvm use            # Node >= 22.18 (for oxlint)
bun install
bun run check      # lint + typecheck + tests
```

## Quickstart

Red-team the bundled reference agent — a deliberately vulnerable fixture (a lethal trifecta,
an RCE path, and a refuse-in-text-but-fire divergence):

```bash
bun run cli -- scan fixtures/vulnerable-agent/manifest.json \
  --sarif out.sarif --report out.md -n 1
```

```text
aal scan — vulnerable-support-agent
8/8 attacks conclusively evaluated (100%), 0 not_verified — dynamic suite ran
findings: 6 critical · 4 high · 0 medium · 0 low · 0 info
  [CRITICAL] Lethal trifecta — OWASP ASI01
  [CRITICAL] Untrusted-content → code-execution path — OWASP ASI05
  [CRITICAL] Refuse-in-text but fired a side-effecting tool (data-exfil) — OWASP ASI03 (stability 1/1)
  ...
verdict: FAIL — 6 critical      # exit code 1 → gates CI (FR-12.1)
```

It writes SARIF 2.1.0 (`out.sarif`) for code-scanning dashboards and a Markdown report
(`out.md`). Findings reference every attack input by **sha256** — no raw payloads on disk.

### Point it at your own agent

1. Write a **Capability Manifest** describing your agent's tools (and their side-effect class),
   data scopes, untrusted-ingress points, identity, and declared mitigations — see
   `fixtures/vulnerable-agent/manifest.json`.
2. Drop a `target.json` (`{ "command": ..., "args": [...] }`) next to it so the exec adapter can
   run your agent. Your agent reads `{"input": "..."}` on stdin and replies with
   `{"text": "...", "toolCalls": [...]}` on stdout.
3. `bun run cli -- scan path/to/manifest.json --sarif out.sarif`.

Without a `target.json` the scan runs **static-only** (toxic-flow graph) and honestly marks every
dynamic attack `not_verified`.

## Cycle-of-Trust policy pack

Where AAL Core *detects* boundary violations offensively, [`policy-pack/`](./policy-pack/)
*prevents* the most direct one — an agent editing its own tools, permissions, or
hooks — and streams a hash-not-text evidence event for every attempt (→ AgenticMind
`/hooks/audit`). It layers a `PreToolUse` guard hook + `permissions.deny` + a
managed-settings fragment that disables `bypassPermissions`. A live spike (Claude
Code v2.1.201) showed the **hook blocks in every mode, including `bypassPermissions`
and `--dangerously-skip-permissions`** — so the hook is the load-bearing layer and
managed settings are org-level defense-in-depth. See [`policy-pack/README.md`](./policy-pack/README.md)
and [ADR-0001](./docs/adr/0001-layered-cycle-of-trust-enforcement.md); the offline
gate is `bun x vitest run src/policy/`.

## Hard invariants
- **No AgenticMind dependency** (framework-neutral core).
- **Fail-closed:** inconclusive ⇒ `not_verified`, never `safe`.
- **Hash-not-text:** never write a raw secret or attack payload to a log/report/fixture.
- **Read/report-only:** this core never remediates and never fires a real side effect.

## 🌐 The AgenticProduct ecosystem

One standard and five reference implementations you can run — together they close the loop every production agent needs: **run → remember → measure**, with security as a cross-cutting assurance plane.

|  | Project | Role |
|---|---|---|
| 📐 | [agentic-product-standard](https://github.com/Moai-Team-LLC/agentic-product-standard) | The contract — principles, the autonomy ladder, the harness layers, and eval discipline (plus a Claude Code skill set). |
| ⚙️ | [AgenticOps](https://github.com/Moai-Team-LLC/AgenticOps) | Runtime & operations — deployable manifests, scheduling, a durable backlog, a bounded runner, and fleet health. |
| 🧠 | [AgenticMind](https://github.com/Moai-Team-LLC/AgenticMind) | Knowledge & memory — auditable, self-improving, citation-enforced, over MCP; Postgres-only. |
| 📈 | [AgenticPerformance](https://github.com/Moai-Team-LLC/AgenticPerformance) | Evals & observability — OTel traces, golden-set evals with a CI gate, failure clusters, and the improvement loop. |
| 🌉 | [AgenticGateway](https://github.com/Moai-Team-LLC/AgenticGateway) | Model & cost plane — one key, measured routing, ceilings, cache, evidence. |
| 🛡️ | **AgenticAssurance** (this repo) | Security & assurance — red-teams any agent (OWASP Agentic + MITRE ATLAS), a toxic-flow graph, and SARIF output. |

**How they compose.** **AgenticOps** runs the fleet, **AgenticMind** gives agents auditable knowledge & memory, and **AgenticPerformance** measures every run with traces and evals — closing the **run → remember → measure** loop. **AgenticGateway** is the model plane every LLM call in that loop passes through — one key, eval-measured routing, cost ceilings — and **AgenticAssurance** red-teams any agent in the loop, with the whole stack conforming to the **[agentic-product-standard](https://github.com/Moai-Team-LLC/agentic-product-standard)**.

## License
MIT © Moai Team LLC
