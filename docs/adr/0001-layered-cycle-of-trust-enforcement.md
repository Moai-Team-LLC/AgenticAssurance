# ADR-0001: Layered Cycle-of-Trust enforcement pack (not hooks alone)

- **Status:** Proposed
- **Date:** 2026-07-04

## Context

WS1 ships a reference policy pack that mechanically enforces the Cycle of Trust
boundary: autonomous remediation may touch prompts, context, and manifests only —
never tools, permission grants, permission modes, or hook policies. The brief's
verification criterion (ADOPTION-BRIEF §WS1) demands that an agent instructed to
modify its own permissions/hooks be **blocked in every permission mode**.

The load-bearing finding is matrix delta **D1** (ADOPTION-MATRIX §1, verified
against the live `permission-modes` docs, v2.1.199+): a `PreToolUse` deny hook
does **not** block in `bypassPermissions`. Hooks run *after* permission rules and
cannot tighten `bypassPermissions`. What actually survives bypass mode is a short
list: `permissions.deny` rules (a higher layer than hooks), explicit `ask` rules,
the fs-root/home deletion circuit breaker, and MCP `requiresUserInteraction`. A
naive hooks-only pack would therefore advertise a guarantee it cannot keep — a
direct violation of the standard's Canon 5 ("permissions enforced by code, never
by prompt").

Secondary finding **D2**: the `ConfigChange` event exists, but its input schema
and *block* capability are undocumented — so blocking config/skill changes cannot
be committed to without an empirical spike.

Repo state: `agent-assurance` has zero Claude Code artifacts today, but a mature
vitest harness with `fixtures/` and `attacks/*.yaml` adversarial patterns ready to
extend.

## Decision

Ship the enforcement pack as **four layers**, ordered by the layer that actually
holds the guarantee, not by convenience:

1. **`permissions.deny` rules** (top layer) for tool-definition paths, permission
   settings, and hook-config paths. These sit above hooks and hold in normal
   modes.
2. **A managed-settings fragment** that disables `bypassPermissions` availability
   (`disableBypassPermissionsMode`) — the *only* mechanism that makes the WS1
   guarantee hold in **every** mode.
3. **`PreToolUse` deny hooks** as a second enforcement layer plus **evidence
   emitters**: every blocked attempt emits an event.
4. **`ConfigChange`** wired to evidence **always**; wired to *block* protected
   paths **only if** the D2 spike confirms block capability.

The pack ships under `policy-pack/` with a single source of truth
(`protected-paths.json`) that the deny rules, the guard hook, and the tests all
read, so they cannot drift. The README documents guarantees **per permission
mode** — no overclaiming.

The adversarial suite is `src/policy/protected-paths.test.ts`: it proves the guard
blocks every self-modification attempt (Write/Edit/Bash), proves the pack denies
every protected glob in both the settings and managed layers, and asserts the
honest per-mode guarantee matrix (`GUARANTEES_BY_MODE`) — in `bypassPermissions`
only the managed layer holds. The live empirical confirmation of D1/D2 is
`policy-pack/spike-bypass.sh`, run by an operator against the real `claude` CLI
(this repo's build env ships no CLI). A dynamic `attacks/hook-bypass.yaml` corpus
entry is a follow-up: it needs a fixture agent exposing config-write tools before
it can be executed rather than merely described.

## Consequences

- The pack's promise is honest and mechanically true: with the managed-settings
  fragment applied, self-modification of tools/permissions/hooks is blocked in
  every mode; without it, the README states exactly which modes are covered.
- Blocking `ConfigChange` is gated behind the D2 spike (~½ day). Until the spike
  resolves, `ConfigChange` is evidence-only — no false blocking guarantee.
- More surface to maintain (settings fragment + deny rules + hooks) than a single
  hook file, and installers must apply the managed-settings fragment for the full
  guarantee — this is a documented install step, not an optional nicety.
- The `disableBypassPermissionsMode` key and the hook matcher grammar are flagged
  in the README as "verify against current docs" — the pack should not be trusted
  in production until those are confirmed for the target CLI version.
- Revisit trigger: if a future Claude Code version lets hooks tighten
  `bypassPermissions` (reversing D1), layers 1–2 can be simplified.

## Alternatives considered

- **Hooks-only pack** (the brief's original WS1 shape) — simplest to author, but
  advertises a guarantee that D1 proves false in `bypassPermissions`. Rejected as
  dishonest and Canon-5-violating.
- **Block `ConfigChange` now** — attractive but rests on undocumented D2
  semantics. Deferred behind a spike rather than shipped on faith.
