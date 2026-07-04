#!/usr/bin/env node
/**
 * ConfigChange guard hook — blocks a settings/skill change to a protected control
 * path from taking effect (exit 2). Second net behind the PreToolUse guard: even
 * if a protected-config change lands on disk, ConfigChange refuses to apply it.
 *
 * The event carries `source` (user_settings | project_settings | local_settings |
 * policy_settings | skills) and `file_path`. `policy_settings` (managed) cannot be
 * blocked by a hook and is the admin channel — we never block it. Verified against
 * a live ConfigChange event on Claude Code v2.1.201 (delta D2, resolved).
 *
 * ⚠ This freezes protected-config changes for hardened deployments: ordinary edits
 * to .claude/settings.json / settings.local.json and any skills change won't take
 * effect while installed. Admins change the boundary via MANAGED (policy) settings.
 * Remove this hook (keep the PreToolUse guard + evidence) if settings must stay
 * live-editable.
 */

import { readFileSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const here = dirname(fileURLToPath(import.meta.url))
const { globs } = JSON.parse(readFileSync(resolve(here, "../protected-paths.json"), "utf8"))

const globToRe = (g) => {
  // Convert a glob to a regex in a single alternation pass (longest token first) so `*` inside a
  // `**` expansion is never re-processed — no placeholder sentinels needed.
  const re = g
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*\/|\*\*|\*/g, (m) => (m === "**/" ? "(?:.*/)?" : m === "**" ? ".*" : "[^/]*"))
  return new RegExp("^" + re + "$")
}
const globRes = globs.map(globToRe)
const matchesPath = (p) => typeof p === "string" && globRes.some((re) => re.test(p))

let raw = ""
process.stdin.setEncoding("utf8")
process.stdin.on("data", (c) => (raw += c))
process.stdin.on("end", () => {
  let ev = {}
  try {
    ev = JSON.parse(raw || "{}")
  } catch {
    process.exit(0)
  }
  const source = ev.source ?? ""
  if (source === "policy_settings") {
    process.exit(0) // managed settings are the admin channel — never blocked
  }
  const block = source === "skills" || matchesPath(ev.file_path)
  if (block) {
    process.stderr.write(
      `Cycle of Trust: blocked a ${source} change to a protected control path from ` +
        `taking effect (${ev.file_path ?? "skill"}). Change the boundary via managed ` +
        `(policy) settings, not from inside a session.\n`,
    )
    process.exit(2)
  }
  process.exit(0)
})
