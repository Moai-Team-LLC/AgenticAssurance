/**
 * Cycle-of-Trust protected-path matching. The single source of truth is
 * policy-pack/protected-paths.json — this module loads + validates it (zod on the
 * boundary, per the repo contract) and exposes the same matching the reference
 * hook (guard-protected-paths.mjs) performs, so engine tests can prove the pack
 * denies every self-modification attempt.
 *
 * This is read/report-only: it evaluates whether a tool call WOULD cross the
 * boundary. It never touches Claude Code config itself.
 */

import { readFileSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

import { z } from "zod"

const protectedPathsSchema = z.object({
  globs: z.array(z.string()).min(1),
  shellMarkers: z.array(z.string()).min(1),
})

export type ProtectedPaths = z.infer<typeof protectedPathsSchema>

const packRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../policy-pack")

export const PROTECTED_PATHS: ProtectedPaths = protectedPathsSchema.parse(
  JSON.parse(readFileSync(resolve(packRoot, "protected-paths.json"), "utf8")),
)

const globToRegExp = (glob: string): RegExp => {
  const source = glob
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    // Single alternation pass (longest token first) so `*` inside a `**` expansion is never
    // re-processed — no control-char sentinels needed (keeps oxlint's no-control-regex happy).
    .replace(/\*\*\/|\*\*|\*/g, (m) => (m === "**/" ? "(?:.*/)?" : m === "**" ? ".*" : "[^/]*"))
  return new RegExp(`^${source}$`)
}

const globRegExps = PROTECTED_PATHS.globs.map(globToRegExp)

/** True when a file path a Write/Edit tool targets is a protected control path. */
export const matchesProtectedPath = (filePath: string): boolean =>
  globRegExps.some((re) => re.test(filePath))

/** True when a shell command string reaches into a protected control path. */
export const shellTouchesProtectedPath = (command: string): boolean =>
  PROTECTED_PATHS.shellMarkers.some((marker) => command.includes(marker))

/**
 * The empirically-verified per-permission-mode enforcement matrix. `deny` =
 * permissions.deny rule; `hook` = the PreToolUse guard hook; `managed` =
 * managed-settings (disableBypassPermissionsMode + deny). `true` means that
 * layer's block holds in the mode.
 *
 * Spike result (Claude Code v2.1.201, 2026-07-04 — see ADR-0001 "Empirical
 * results"): a PreToolUse command hook returning exit 2 blocks the tool call in
 * EVERY mode tested, including `bypassPermissions` AND `--dangerously-skip-
 * permissions` (a control run with no hook confirmed bypass truly skips
 * permission checks, so the block is attributable to the hook). This REVERSES
 * matrix delta D1: the hook — not just managed settings — holds under bypass.
 * Permission *rules* (`permissions.deny`/`allow`) are still skipped under bypass,
 * so `deny` is false there; the hook and the managed layer both hold.
 */
export const GUARANTEES_BY_MODE: Record<
  string,
  { deny: boolean; hook: boolean; managed: boolean }
> = {
  default: { deny: true, hook: true, managed: true },
  plan: { deny: true, hook: true, managed: true },
  acceptEdits: { deny: true, hook: true, managed: true },
  bypassPermissions: { deny: false, hook: true, managed: true },
}

/**
 * ConfigChange enforcement (delta D2, resolved by spike). A `ConfigChange` hook
 * fires when a settings/skill file changes during a session; the event carries
 * `source` (user_settings | project_settings | local_settings | policy_settings
 * | skills) and `file_path`. Exit 2 blocks the change from taking effect — EXCEPT
 * `policy_settings` (managed), which a hook cannot block and which remains the
 * admin channel.
 *
 * This returns true when the change should be blocked: any `skills` change (a
 * skill is an executable capability) or a change whose file is a protected
 * control path (settings.json / settings.local.json). Managed (`policy_settings`)
 * is never blocked here — it is how an admin legitimately updates the boundary.
 */
export const blocksConfigChange = (source: string, filePath: string | undefined): boolean => {
  if (source === "policy_settings") {
    return false
  }
  return source === "skills" || (filePath !== undefined && matchesProtectedPath(filePath))
}
