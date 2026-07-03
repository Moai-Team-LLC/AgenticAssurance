# AAL Core (`agent-assurance`)

The framework-neutral offensive core of the **Agent Assurance Layer (AAL)**. Given a
**Capability Manifest** and a **runner adapter**, it red-teams any agent:

- runs an **attack library** (mapped to OWASP Top 10 for Agentic Applications, ASI01–ASI10, and MITRE ATLAS) against an isolated copy of the target;
- builds a **toxic-flow graph** over the agent's declared tools to find lethal-trifecta and RCE composition paths that single-prompt scanners miss;
- detects **execution-layer side-effect divergences** — the agent refuses in text but a side-effecting tool still fires;
- emits **SARIF** (for CI/code-scanning) and a human-readable report.

It is **not** a runtime guardrail and **not** a generic code scanner. The AgenticMind-native
compliance/evidence layer (AIUC-1 gap analysis, auditor bundle) is a separate package.

> Status: **scaffold (Step 0)**. See the build blueprint for the step sequence. The `aal scan`
> command is stubbed until the static (Step 2) and dynamic (Step 4) engines land.

## Quickstart

```bash
nvm use            # Node >= 22.18 (for oxlint)
bun install
bun run check      # lint + typecheck + tests
bun run cli -- --help
```

## Hard invariants
- **No AgenticMind dependency** (framework-neutral core).
- **Fail-closed:** inconclusive ⇒ `not_verified`, never `safe`.
- **Hash-not-text:** never write a raw secret or attack payload to a log/report/fixture.
- **Read/report-only:** this core never remediates and never fires a real side effect.

## License
MIT © Moai Team LLC
