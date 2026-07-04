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
    .replace(/\*\*\//g, "\x00") // **/ → optional directory prefix (also matches zero segments)
    .replace(/\*\*/g, "\x01") // ** → anything, across segments
    .replace(/\*/g, "[^/]*") // * → within a single segment
    .replace(/\x00/g, "(?:.*/)?")
    .replace(/\x01/g, ".*")
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
 * The honest per-permission-mode enforcement matrix (delta D1). `deny` =
 * permissions.deny rule; `managed` = managed-settings disableBypassPermissions +
 * deny; `hook` = the PreToolUse guard. `true` means that layer's block holds in
 * the mode. In bypassPermissions ONLY the managed layer holds — so the pack's
 * guarantee is conditional on installing managed-settings.json.
 */
export const GUARANTEES_BY_MODE: Record<
  string,
  { deny: boolean; hook: boolean; managed: boolean }
> = {
  default: { deny: true, hook: true, managed: true },
  plan: { deny: true, hook: true, managed: true },
  acceptEdits: { deny: true, hook: true, managed: true },
  bypassPermissions: { deny: false, hook: false, managed: true },
}
