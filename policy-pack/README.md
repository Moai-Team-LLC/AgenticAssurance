# Cycle-of-Trust Policy Pack (reference)

A drop-in Claude Code configuration that **mechanically enforces the Cycle of Trust
boundary**: an autonomous agent may modify its **prompts, context, and manifests**,
but never its own **tools, permission grants, permission modes, or hook policies**.

This is the productized companion to AAL Core. AAL Core *detects* boundary
violations offensively; this pack *prevents* the most direct one — an agent
editing its own guardrails — and streams an evidence event for every attempt.

## Why three layers (and the one that actually holds)

Per the live Claude Code docs (`permission-modes`, v2.1.199+), **a `PreToolUse`
deny hook does NOT block in `bypassPermissions` mode** — hooks run *after*
permission rules and cannot tighten `bypassPermissions`. So a hook-only pack would
advertise a guarantee it does not have. This pack layers three controls and is
explicit about which holds in which mode:

| Layer | File | Holds in default / plan / acceptEdits | Holds in **bypassPermissions** |
|---|---|:---:|:---:|
| `permissions.deny` rules | `settings.json` | ✅ | ❌ |
| `PreToolUse` guard hook | `settings.json` → `hooks/guard-protected-paths.mjs` | ✅ (defense-in-depth) | ❌ |
| **Managed settings** (`disableBypassPermissionsMode` + deny) | `managed-settings.json` | ✅ | ✅ |

**Take-away:** only `managed-settings.json` makes the boundary hold in *every*
mode, because it both denies the paths **and removes `bypassPermissions` as an
option**. Install it if you need the guarantee unconditionally. The other two
layers are the everyday enforcement + the evidence trigger. This matrix is
asserted in `src/policy/protected-paths.test.ts` (`GUARANTEES_BY_MODE`).

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

- **`disableBypassPermissionsMode`** (`managed-settings.json`) is the load-bearing
  key for the bypass guarantee. Confirm its exact name/values against the current
  managed-settings docs before you rely on it.
- **`ConfigChange` blocking (delta D2).** The event exists, but the docs do not
  specify its input schema or whether a hook can *block* (vs only observe) a
  config change. This pack uses `ConfigChange` for **evidence only**; add a deny
  once the block contract is confirmed by the spike.
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
  each permission mode and records what actually happened — the empirical proof
  the docs leave open. Expected: blocked in default/plan/acceptEdits by any layer;
  blocked in bypassPermissions **only** when `managed-settings.json` is installed.
