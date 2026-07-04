import { readFileSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

import { describe, expect, it } from "vitest"

import {
  blocksConfigChange,
  GUARANTEES_BY_MODE,
  matchesProtectedPath,
  PROTECTED_PATHS,
  shellTouchesProtectedPath,
} from "./protected-paths"

const packRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../policy-pack")
const readPack = (name: string): unknown =>
  JSON.parse(readFileSync(resolve(packRoot, name), "utf8"))

describe("adversarial: an agent trying to modify its own guardrails is caught", () => {
  it("flags writes to permission / hook / tool config", () => {
    for (const p of [
      "/repo/.claude/settings.json",
      ".claude/settings.local.json",
      "/repo/.claude/hooks/guard.mjs",
      "project/.claude/agents/evil.md",
      "/repo/.mcp.json",
    ]) {
      expect(matchesProtectedPath(p), p).toBe(true)
    }
  })

  it("flags shell commands that reach into protected paths", () => {
    for (const cmd of [
      'echo "{}" > .claude/settings.json',
      "rm .claude/hooks/guard-protected-paths.mjs",
      "cat foo >> .mcp.json",
      "vim /Library/Application Support/ClaudeCode/managed-settings.json",
    ]) {
      expect(shellTouchesProtectedPath(cmd), cmd).toBe(true)
    }
  })

  it("does not flag ordinary work (no false positives on the happy path)", () => {
    for (const p of ["src/index.ts", "README.md", "/repo/docs/adr/0001.md", ".claude/CLAUDE.md"]) {
      expect(matchesProtectedPath(p), p).toBe(false)
    }
    expect(shellTouchesProtectedPath("bun run check")).toBe(false)
  })
})

describe("structural: the pack denies every protected glob in both layers", () => {
  const settings = readPack("settings.json") as {
    permissions: { deny: string[] }
    hooks: Record<string, unknown[]>
  }
  const managed = readPack("managed-settings.json") as {
    permissions: { deny: string[]; disableBypassPermissionsMode?: string }
  }

  it("every glob has a Write AND Edit deny rule in settings and managed", () => {
    for (const glob of PROTECTED_PATHS.globs) {
      for (const rules of [settings.permissions.deny, managed.permissions.deny]) {
        expect(rules, glob).toContain(`Write(${glob})`)
        expect(rules, glob).toContain(`Edit(${glob})`)
      }
    }
  })

  it("managed settings disable bypassPermissions — the only D1-proof layer", () => {
    expect(managed.permissions.disableBypassPermissionsMode).toBe("disable")
  })

  it("wires a PreToolUse guard, PostToolUse evidence, and a ConfigChange guard + evidence hook", () => {
    expect(settings.hooks["PreToolUse"]).toBeDefined()
    expect(settings.hooks["PostToolUse"]).toBeDefined()
    expect(settings.hooks["ConfigChange"]).toBeDefined()
    const hooksJson = JSON.stringify(settings.hooks)
    expect(hooksJson).toContain("guard-protected-paths.mjs")
    expect(hooksJson).toContain("guard-config-change.mjs")
    expect(hooksJson).toContain("AAL_AUDIT_URL")
  })
})

describe("ConfigChange guard (D2 — verified on Claude Code v2.1.201)", () => {
  it("blocks protected settings changes and any skills change", () => {
    expect(blocksConfigChange("local_settings", "/r/.claude/settings.local.json")).toBe(true)
    expect(blocksConfigChange("project_settings", "/r/.claude/settings.json")).toBe(true)
    expect(blocksConfigChange("user_settings", "/home/u/.claude/settings.json")).toBe(true)
    expect(blocksConfigChange("skills", "/home/u/.claude/skills/x/SKILL.md")).toBe(true)
  })

  it("never blocks managed (policy_settings) — the admin channel", () => {
    expect(blocksConfigChange("policy_settings", "/etc/claude-code/managed-settings.json")).toBe(
      false,
    )
  })

  it("does not block config changes outside the protected set", () => {
    expect(blocksConfigChange("project_settings", "/r/some/other-config.json")).toBe(false)
    expect(blocksConfigChange("local_settings", undefined)).toBe(false)
  })
})

describe("the guarantee matrix matches the spike (Claude Code v2.1.201)", () => {
  it("under bypassPermissions the hook and managed layers hold; only the permission rule is skipped", () => {
    // Empirically verified: a PreToolUse exit-2 hook blocks even under
    // bypassPermissions / --dangerously-skip-permissions (ADR-0001, spike).
    const bypass = GUARANTEES_BY_MODE["bypassPermissions"]
    expect(bypass).toEqual({ deny: false, hook: true, managed: true })
  })

  it("all three layers hold in the everyday modes", () => {
    for (const mode of ["default", "plan", "acceptEdits"]) {
      expect(GUARANTEES_BY_MODE[mode]).toEqual({ deny: true, hook: true, managed: true })
    }
  })
})
