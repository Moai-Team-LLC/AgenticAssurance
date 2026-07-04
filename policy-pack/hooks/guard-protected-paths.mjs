#!/usr/bin/env node
/**
 * PreToolUse deny hook — Cycle of Trust boundary (defense-in-depth layer).
 *
 * Blocks Write / Edit / MultiEdit / Bash calls that would modify the agent's own
 * tools, permission grants, permission modes, or hook policies. Reads the shared
 * protected-paths.json so it can never drift from the deny rules and the tests.
 *
 * Deny protocol: exit code 2, reason on stderr (shown to the model). Exit 0 = allow.
 *
 * ⚠ Delta D1 (per live docs, permission-modes v2.1.199+): a PreToolUse deny does
 * NOT block in `bypassPermissions` mode — hooks run *after* permission rules and
 * cannot tighten bypass. The load-bearing guarantee comes from `permissions.deny`
 * plus managed-settings.json (`disableBypassPermissionsMode`). This hook is
 * second-layer enforcement + a per-attempt evidence trigger, never the sole gate.
 */

import { readFileSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const here = dirname(fileURLToPath(import.meta.url))
const { globs, shellMarkers } = JSON.parse(
  readFileSync(resolve(here, "../protected-paths.json"), "utf8"),
)

const globToRe = (g) => {
  const re = g
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*\//g, "\x00") // **/ → optional directory prefix (also matches zero segments)
    .replace(/\*\*/g, "\x01") // ** → anything, across segments
    .replace(/\*/g, "[^/]*") // * → within a single segment
    .replace(/\x00/g, "(?:.*/)?")
    .replace(/\x01/g, ".*")
  return new RegExp("^" + re + "$")
}
const globRes = globs.map(globToRe)
const matchesPath = (p) => typeof p === "string" && globRes.some((re) => re.test(p))
const shellTouches = (cmd) =>
  typeof cmd === "string" && shellMarkers.some((m) => cmd.includes(m))

let raw = ""
process.stdin.setEncoding("utf8")
process.stdin.on("data", (c) => (raw += c))
process.stdin.on("end", () => {
  let ev = {}
  try {
    ev = JSON.parse(raw || "{}")
  } catch {
    process.exit(0) // unparseable event — do not block; the http audit hook still records
  }
  const tool = ev.tool_name ?? ev.tool ?? ""
  const ti = ev.tool_input ?? {}
  const blocked =
    matchesPath(ti.file_path) || matchesPath(ti.path) || shellTouches(ti.command)
  if (blocked) {
    process.stderr.write(
      `Cycle of Trust: blocked ${tool} targeting a protected control path ` +
        `(tools / permissions / hooks). Autonomous remediation may modify ` +
        `prompts, context, and manifests only — never its own guardrails.\n`,
    )
    process.exit(2)
  }
  process.exit(0)
})
