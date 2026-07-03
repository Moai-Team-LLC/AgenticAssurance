/**
 * Attack Library schema (FR-2).
 *
 * Attacks are *data, not code* — contributors extend coverage by editing YAML, never engine
 * internals (this productizes the Standard's injection_cases.yaml). Every attack maps to the
 * OWASP Top 10 for Agentic Applications (ASI01–ASI10) and a MITRE ATLAS technique, and declares
 * a machine-checkable success condition (assert predicates and/or an LLM rubric).
 *
 * Payload hygiene: corpus `input`s use synthetic, reserved indicators only (example/.test/.invalid
 * domains, obviously-demonstrative markers) — never real secrets, targets, or weaponized
 * jailbreaks. Findings never echo them back: they store the sha256 (hash-not-text, NFR-3).
 */
import { z } from "zod";
import { SideEffectClass } from "../manifest/schema";

export const AttackClass = z.enum([
  "prompt-injection",
  "indirect-injection",
  "tool-poisoning",
  "tool-shadowing",
  "mcp-rug-pull",
  "data-exfil",
  "trifecta-exploit",
  "config-rce",
]);
export type AttackClass = z.infer<typeof AttackClass>;

/** OWASP Top 10 for Agentic Applications (2026). */
export const OwaspAsi = z.enum([
  "ASI01",
  "ASI02",
  "ASI03",
  "ASI04",
  "ASI05",
  "ASI06",
  "ASI07",
  "ASI08",
  "ASI09",
  "ASI10",
]);
export type OwaspAsi = z.infer<typeof OwaspAsi>;

/** A MITRE ATLAS id, e.g. `AML.T0051` (LLM prompt injection) or a tactic `AML.TA0000`. */
export const AtlasId = z.string().regex(/^AML\.[A-Z]{1,3}\d{4}(\.\d+)?$/, "not a MITRE ATLAS id");

/**
 * One success predicate. Each evaluates to *did the attack succeed* (i.e. the unsafe condition
 * holds) — TRUE means the target is vulnerable. Composed with OR across the `assert` array.
 */
export const Assertion = z.discriminatedUnion("type", [
  z.object({ type: z.literal("text-contains"), value: z.string().min(1) }),
  z.object({ type: z.literal("text-matches"), pattern: z.string().min(1), flags: z.string().optional() }),
  z.object({ type: z.literal("tool-called"), tool: z.string().min(1) }),
  z.object({ type: z.literal("side-effect-fired"), sideEffect: SideEffectClass }),
]);
export type Assertion = z.infer<typeof Assertion>;

/** The attack's machine-checkable success condition. At least one of assert/llmRubric required. */
export const SuccessCondition = z
  .object({
    assert: z.array(Assertion).default([]),
    llmRubric: z.string().min(1).optional(),
  })
  .refine((s) => s.assert.length > 0 || s.llmRubric !== undefined, {
    message: "success needs at least one `assert` predicate or an `llmRubric`",
  });
export type SuccessCondition = z.infer<typeof SuccessCondition>;

export const Attack = z.object({
  id: z.string().min(1),
  class: AttackClass,
  owasp: OwaspAsi,
  atlas: AtlasId,
  description: z.string().optional(),
  lang: z.enum(["en", "ru"]).default("en"),
  input: z.string().min(1),
  vars: z.record(z.string(), z.string()).optional(),
  success: SuccessCondition,
});
export type Attack = z.infer<typeof Attack>;

/** One corpus YAML file: a versioned list of attacks. */
export const AttackFile = z.object({
  version: z.string().optional(),
  attacks: z.array(Attack).min(1),
});
export type AttackFile = z.infer<typeof AttackFile>;

/** Render an attack's input, substituting `{{var}}` placeholders from its `vars` map. */
export function renderAttackInput(attack: Attack): string {
  const vars = attack.vars ?? {};
  return attack.input.replace(/\{\{(\w+)\}\}/g, (match, key: string) =>
    Object.prototype.hasOwnProperty.call(vars, key) ? vars[key] ?? match : match,
  );
}
