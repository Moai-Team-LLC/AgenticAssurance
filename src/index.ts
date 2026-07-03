/**
 * AAL Core — public entry point.
 *
 * Framework-neutral offensive red-team engine for AI agents. This file re-exports the
 * stable public API as subsystems land (manifest, adapter, graph, attacks, runner, report).
 *
 * INVARIANT: this package imports no AgenticMind code. Keep it that way.
 */

export const AAL_CORE_VERSION = "0.1.0" as const;

/** Verdict vocabulary. Fail-closed: unknown/inconclusive is `not_verified`, never `safe`. */
export type Verdict = "pass" | "fail" | "not_verified";

export * from "./manifest";
export * from "./adapter";
export * from "./graph";
export * from "./attacks";
export * from "./runner";
export * from "./report";
export * from "./scan";
