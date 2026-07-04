# Cycle-of-Trust Policy Pack (reference)

A drop-in Claude Code configuration that **mechanically enforces the Cycle of Trust
boundary**: an autonomous agent may modify its **prompts, context, and manifests**,
but never its own **tools, permission grants, permission modes, or hook policies**.

This is the productized companion to AAL Core. AAL Core *detects* boundary
violations offensively; this pack *prevents* the most direct one — an agent
editing its own guardrails — and streams an evidence event for every attempt.

## Why layered (and what the spike found)

The boundary is enforced by three controls. The load-bearing one turned out to be
the **hook**: an empirical spike (Claude Code **v2.1.201**, 2026-07-04 — see
[ADR-0001](../docs/adr/0001-layered-cycle-of-trust-enforcement.md)) showed a
`PreToolUse` exit-2 deny blocks the tool call in **every** mode tested, including
`bypassPermissions` **and** `--dangerously-skip-permissions`. A no-hook control run
confirmed bypass genuinely skips permission checks — so the block is the hook's,
not a permission rule's. This **reverses** the earlier doc-based reading (matrix
delta D1, which had claimed hooks don't hold under bypass).

| Layer | File | default / plan / acceptEdits | **bypassPermissions** |
|---|---|:---:|:---:|
| `permissions.deny` rules | `settings.json` | ✅ | ❌ (permission rules are skipped under bypass) |
| **`PreToolUse` guard hook** | `settings.json` → `hooks/guard-protected-paths.mjs` | ✅ | ✅ **(verified v2.1.201)** |
| Managed settings (`disableBypassPermissionsMode` + deny) | `managed-settings.json` | ✅ | ✅ (also removes the mode) |

**Take-away:** the **hook alone holds the boundary in every mode**, so the pack's
core guarantee does not depend on managed settings. Install `managed-settings.json`
anyway for **org-level defense-in-depth** — it removes `bypassPermissions` as an
option entirely and its deny rules cannot be edited away by the agent. This matrix
is asserted in `src/policy/protected-paths.test.ts` (`GUARANTEES_BY_MODE`); the
live re-run is [`spike-bypass.sh`](./spike-bypass.sh).

## What is protected

The single source of truth is [`protected-paths.json`](./protected-paths.json).
Every consumer (deny rules, the guard hook, the tests) reads it, so they cannot
drift:

| Protected path (glob) | Invariant it defends |
|---|---|
| `**/.claude/settings.json`, `**/.claude/settings.local.json` | permission grants, permission modes, hook policies |
| `**/.claude/hooks/**` | hook policies (the enforcement code itself) |
| `**/.claude/agents/**` | subagent / tool definitions |
| `**/.mcp.json` | MCP tool/server definitions (tools) |

`shellMarkers` mirror these for `Bash` (substring match), so `echo … > .claude/settings.json`
is caught too.

## Install

1. **Project or user settings** — merge [`settings.json`](./settings.json) into
   `.claude/settings.json`. Copy `policy-pack/` into the repo (the hook command
   references `$CLAUDE_PROJECT_DIR/policy-pack/hooks/guard-protected-paths.mjs`).
2. **Managed settings (required for the bypass guarantee)** — install
   [`managed-settings.json`](./managed-settings.json) at the OS managed path:
   - macOS: `/Library/Application Support/ClaudeCode/managed-settings.json`
   - Linux: `/etc/claude-code/managed-settings.json`
   - Windows: `C:\ProgramData\ClaudeCode\managed-settings.json`
3. **Evidence stream (optional, → WS2)** — export `AAL_AUDIT_URL` (the AgenticMind
   `POST /hooks/audit` URL) and `AAL_AUDIT_TOKEN` (a bearer carrying the
   `audit:write` scope). The `PostToolUse` and `ConfigChange` HTTP hooks then
   record every mutating tool call and config change as a hash-not-text evidence
   row. Secrets come from the environment only — never hardcode them.

## Open items — verify before rollout

- **`disableBypassPermissionsMode`** (`managed-settings.json`) drives the
  org-level defense-in-depth (removing bypass as an option). The hook already
  holds the boundary in every mode, so this key is not the sole guarantee — but
  confirm its exact name/values against the current managed-settings docs before
  relying on the org-level control.
- **Re-run the spike per CLI version.** The v2.1.201 result (hook blocks in every
  mode) is version-specific evidence, not a doc guarantee. If a future version
  lets `bypassPermissions` skip hooks, the managed layer becomes load-bearing
  again — re-run `spike-bypass.sh` after upgrades.
- **`ConfigChange` blocking (delta D2 — resolved).** A spike confirmed the event
  fires headlessly with `source` + `file_path`, and exit 2 blocks the change from
  taking effect (except `policy_settings`). The pack now ships
  `hooks/guard-config-change.mjs`, which blocks protected settings/skill changes
  and lets `policy_settings` (managed) through. ⚠ This **freezes** ordinary edits
  to `.claude/settings.json` / `settings.local.json` and any skills change from
  taking effect — admins change the boundary via **managed** settings. Remove this
  hook (keep the evidence hook) if settings must stay live-editable.
- **HTTP-hook runtime semantics (delta D3).** sync/async, timeout, and retry
  behavior of `http` hooks are undocumented. The evidence stream is best-effort;
  do not assume it is synchronous or that a failed POST is retried.
- **Hook matcher / `ConfigChange` matcher syntax.** Confirm the matcher grammar
  against the hooks reference for your CLI version.

## Verify it works

- **Offline (CI gate):** `bun run tsc && bun x vitest run src/policy/` — proves the
  pack denies every protected glob in both layers, that managed settings disable
  bypass, that the guard blocks self-modification attempts, and that the
  guarantee matrix is honest about bypass.
- **Live (the D1/D2 spike):** run [`spike-bypass.sh`](./spike-bypass.sh) with the
  real `claude` CLI. It drives an agent to modify its own `settings.json` under
  each permission mode and records what actually happened. Result on **v2.1.201**:
  the `PreToolUse` hook blocked the write in every mode — default, plan,
  acceptEdits, `bypassPermissions`, and `--dangerously-skip-permissions` — while a
  no-hook control confirmed bypass really does skip permission checks. Re-run this
  on your target CLI version; the hook's cross-mode enforcement is the property to
  re-confirm.
