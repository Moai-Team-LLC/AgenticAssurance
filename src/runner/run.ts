/**
 * Attack runner / orchestrator (FR-4, FR-6.2).
 *
 * For each attack: render its input, run the target N times through the sandbox, judge each run
 * with the oracle, detect side-effect divergence, and compute a stability score (n_pass/n_total)
 * so model nondeterminism is *measured*, not hidden. Fail-closed: any inconclusive run (adapter
 * error, or an llmRubric with no provider) prevents a "contained" verdict → `not_verified`.
 *
 * Results carry only the input's sha256 and payload-free summaries — never the raw attack input,
 * the raw agent text, or tool arguments (NFR-3).
 */
/* oxlint-disable no-await-in-loop -- runs and attacks execute strictly sequentially by design:
   reproducibility under a fixed seed (FR-6.2) and avoiding subprocess/resource storms. Do not
   "optimize" these into Promise.all — parallelism would make results non-reproducible. */
import { createHash } from "node:crypto";
import type { CapabilityManifest } from "../manifest/schema";
import { renderAttackInput, type Attack, type OwaspAsi } from "../attacks/schema";
import { evaluateSuccess, type OracleProvider } from "./oracle";
import type { Sandbox, InterceptedSideEffect } from "./sandbox";
import { detectSideEffectDivergence, type SideEffectFinding } from "./side-effect";

export type AttackOutcome = "succeeded" | "contained" | "not_verified";

export interface AttackResult {
  attackId: string;
  attackClass: Attack["class"];
  owasp: OwaspAsi;
  atlas: string;
  inputHash: string;
  outcome: AttackOutcome;
  stability: { pass: number; total: number };
  sideEffect: SideEffectFinding;
  intercepted: InterceptedSideEffect[];
  observed: string;
  note?: string;
}

export interface RunOptions {
  runs?: number;
  provider?: OracleProvider;
  seed?: number;
}

const DEFAULT_RUNS = 5;
const EMPTY_SIDE_EFFECT: SideEffectFinding = {
  refusedInText: false,
  firedSideEffects: [],
  refuseButFire: false,
};

/** sha256 of the rendered attack input — the only representation of a payload we persist. */
export function hashInput(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

/** Run one attack N times against a sandboxed target and score it. */
export async function runAttack(
  attack: Attack,
  sandbox: Sandbox,
  manifest: CapabilityManifest,
  options: RunOptions = {},
): Promise<AttackResult> {
  const total = Math.max(1, options.runs ?? DEFAULT_RUNS);
  const input = renderAttackInput(attack);
  const inputHash = hashInput(input);

  let pass = 0;
  let inconclusive = 0;
  let lastSideEffect: SideEffectFinding = EMPTY_SIDE_EFFECT;
  let lastIntercepted: InterceptedSideEffect[] = [];
  let note: string | undefined;

  for (let i = 0; i < total; i++) {
    const sandboxed = await sandbox.run(input);
    if (sandboxed.isErr()) {
      inconclusive++;
      note = `adapter ${sandboxed.error.kind}: ${sandboxed.error.message}`;
      continue;
    }
    const { run, intercepted } = sandboxed.value;
    lastIntercepted = intercepted;
    lastSideEffect = detectSideEffectDivergence(run, manifest);

    const judged = await evaluateSuccess(attack.success, run, manifest, options.provider);
    if (judged.isErr()) {
      inconclusive++;
      note = `oracle ${judged.error.kind}: ${judged.error.message}`;
      continue;
    }
    if (judged.value) pass++;
  }

  const outcome: AttackOutcome =
    pass > 0 ? "succeeded" : inconclusive > 0 ? "not_verified" : "contained";

  return {
    attackId: attack.id,
    attackClass: attack.class,
    owasp: attack.owasp,
    atlas: attack.atlas,
    inputHash,
    outcome,
    stability: { pass, total },
    sideEffect: lastSideEffect,
    intercepted: lastIntercepted,
    observed: describeObserved(outcome, lastSideEffect, total),
    ...(note !== undefined && outcome === "not_verified" ? { note } : {}),
  };
}

/** Run a whole attack suite sequentially (reproducible; avoids subprocess storms). */
export async function runSuite(
  attacks: Attack[],
  sandbox: Sandbox,
  manifest: CapabilityManifest,
  options: RunOptions = {},
): Promise<AttackResult[]> {
  const results: AttackResult[] = [];
  for (const attack of attacks) {
    results.push(await runAttack(attack, sandbox, manifest, options));
  }
  return results;
}

function describeObserved(
  outcome: AttackOutcome,
  sideEffect: SideEffectFinding,
  total: number,
): string {
  if (outcome === "not_verified") return "inconclusive — reported not_verified (fail-closed)";
  if (outcome === "contained") return `attack contained across ${total} run(s)`;
  const tools = sideEffect.firedSideEffects.map((f) => `${f.tool} (${f.sideEffect})`).join(", ");
  if (sideEffect.refuseButFire) {
    return `CRITICAL: agent refused in text but fired side-effecting tool(s): ${tools}`;
  }
  if (sideEffect.firedSideEffects.length > 0) return `fired side-effecting tool(s): ${tools}`;
  return "agent output satisfied the attack's success condition";
}
