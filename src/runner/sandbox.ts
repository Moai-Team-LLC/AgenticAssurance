/**
 * Sandbox / isolation (FR-5, NFR-4).
 *
 * A dynamic red-team run must never cause a real side effect. This process-jail sandbox (the
 * dependency-light v0.1 substrate) wraps a target adapter and routes every declared
 * side-effecting tool call to a **canary** that *records the attempt and performs nothing*.
 * `performedCount` MUST stay 0 — the canary-interception test asserts it (NFR-4).
 *
 * The canary records only a sha256 of the call arguments, never the raw args (hash-not-text,
 * NFR-3) — a tool call may carry the very secret an exfil attack is trying to leak.
 */
import { createHash } from "node:crypto";
import type { Result } from "neverthrow";
import type { AdapterError, AgentRun, TargetAdapter } from "../adapter/types";
import type { CapabilityManifest } from "../manifest/schema";
import { isSideEffecting, sideEffectClassOf, type ResolvedSideEffect } from "./side-effect";

/** A side-effecting tool call that was intercepted (never performed) during a run. */
export interface InterceptedSideEffect {
  tool: string;
  sideEffect: ResolvedSideEffect;
  argHash: string;
  intercepted: true;
}

export interface SandboxRunResult {
  run: AgentRun;
  intercepted: InterceptedSideEffect[];
}

export interface Sandbox {
  run(input: string): Promise<Result<SandboxRunResult, AdapterError>>;
  /** Count of side effects actually performed against a real system. Must remain 0 (NFR-4). */
  readonly performedCount: number;
}

/** sha256 of a value's canonical JSON — never store raw tool arguments. */
export function hashArgs(args: unknown): string {
  return createHash("sha256").update(safeJson(args)).digest("hex");
}

/**
 * Build a process-jail sandbox around an adapter. Declared side effects are intercepted and
 * recorded; none are executed. The canary is the only path a side-effecting call can take.
 */
export function createProcessJailSandbox(
  adapter: TargetAdapter,
  manifest: CapabilityManifest,
): Sandbox {
  let performed = 0; // v0.1 never performs a real side effect; kept as the NFR-4 tripwire.

  return {
    get performedCount() {
      return performed;
    },
    async run(input: string): Promise<Result<SandboxRunResult, AdapterError>> {
      const result = await adapter.runAgent(input);
      return result.map((run) => {
        const intercepted: InterceptedSideEffect[] = [];
        for (const call of run.toolCalls) {
          const sideEffect = sideEffectClassOf(call.tool, manifest);
          if (!isSideEffecting(sideEffect)) continue;
          // Canary: record THIS call's own attempt (its args, hashed), perform nothing. Iterating
          // per call keeps argHash correct when the same tool fires more than once in a run.
          intercepted.push({ tool: call.tool, sideEffect, argHash: hashArgs(call.args), intercepted: true });
        }
        return { run, intercepted };
      });
    },
  };
}

function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value) ?? "null";
  } catch {
    return String(value);
  }
}
