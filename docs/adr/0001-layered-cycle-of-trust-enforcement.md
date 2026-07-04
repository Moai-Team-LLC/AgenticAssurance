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
4. **`ConfigChange`** wired to evidence **always**, and — now that the D2 spike has
   confirmed the block contract — to *block* protected settings/skill changes from
   taking effect (except `policy_settings`) via `hooks/guard-config-change.mjs`.

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
- `ConfigChange` blocking is now enabled (D2 resolved): it freezes protected
  settings/skill changes from taking effect while installed, so in a hardened
  deployment the boundary is changed only through managed (`policy_settings`).
  Deployments that need settings live-editable remove `guard-config-change.mjs`
  and keep the evidence hook.
- More surface to maintain (settings fragment + deny rules + hooks) than a single
  hook file, and installers must apply the managed-settings fragment for the full
  guarantee — this is a documented install step, not an optional nicety.
- The `disableBypassPermissionsMode` key and the hook matcher grammar are flagged
  in the README as "verify against current docs" — the pack should not be trusted
  in production until those are confirmed for the target CLI version.
- Revisit trigger: if a future Claude Code version lets `bypassPermissions` skip
  hooks (reversing the spike result below), the managed layer becomes the only
  thing holding under bypass — re-run the spike after upgrades.

## Empirical results (spike, Claude Code v2.1.201 — 2026-07-04)

The D1 premise in the Context was **refuted by the live spike**
(`policy-pack/spike-bypass.sh`, run once a `claude` CLI was installed). Controlled
result:

- **Control — no hook, `bypassPermissions`:** the Write **succeeded** (a write that
  default mode denies), proving bypass genuinely skips permission checks.
- **Hook + `bypassPermissions`:** the `PreToolUse` exit-2 deny **blocked** the Write.
- **Hook + `--dangerously-skip-permissions`:** also **blocked**.

So a PreToolUse deny hook **holds in every mode, including bypass** — the opposite
of the doc-based D1 reading. The reconciliation: permission *rules*
(`permissions.deny`/`allow`) are skipped under bypass, but *hooks* are not
("hooks can only tighten, never loosen" is consistent with this); the doc-verify
pass appears to have conflated the two. The captured event JSON also confirmed the
hook payload shape (`session_id`, `transcript_path`, `cwd`, `tool_name`,
`tool_input`), which validates the WS2 ingestion parser.

**Effect on this decision:** the layered design stands, but the *reason* shifts.
The **hook is the load-bearing layer** and holds unconditionally; `permissions.deny`
is normal-mode redundancy; managed-settings is **org-level defense-in-depth**
(removes the mode entirely, non-overridable by the agent) rather than the only
layer that holds under bypass. `GUARANTEES_BY_MODE`, the pack README, and the
settings comments were updated to match. The finding is version-specific (v2.1.201)
and must be re-confirmed on CLI upgrades.

**D2 — resolved.** A second spike triggered a real `ConfigChange` (an agent editing
`.claude/settings.local.json` under bypass). It fired headlessly and carried a
richer schema than the docs list: `hook_event_name`, `source` (`local_settings`),
`file_path`, plus the common fields. Docs confirm exit 2 blocks the change from
taking effect for every source except `policy_settings` (managed). The pack now
ships `hooks/guard-config-change.mjs`, wired into `ConfigChange`: it blocks (exit 2)
a change whose `source` is `skills` or whose `file_path` is a protected control
path, and never blocks `policy_settings` (the admin channel). The captured live
event was replayed through the guard and correctly returned exit 2. The
block-*effect* (config not reloaded) is not observable in a one-shot headless run —
the file bytes are not reverted — but the fire + decision path is verified.

## Alternatives considered

- **Hooks-only pack** (the brief's original WS1 shape) — simplest to author, but
  advertises a guarantee that D1 proves false in `bypassPermissions`. Rejected as
  dishonest and Canon-5-violating.
- **Block `ConfigChange` now** — attractive but rests on undocumented D2
  semantics. Deferred behind a spike rather than shipped on faith.
