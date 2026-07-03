/**
 * SDK Target Adapter — interface stub (FR-1.1).
 *
 * Placeholder for an in-process adapter that wraps a target exposed as a JS/TS function or SDK
 * client. Ships when a real SDK target exists; kept as a typed seam so the CLI's `--adapter sdk`
 * path compiles today.
 */
import { err, ok, type Result } from "neverthrow";
import type { AdapterError, AgentRun, TargetAdapter } from "./types";

/** A caller-supplied function that runs the target in-process and returns its observed run. */
export type SdkRunner = (input: string) => Promise<AgentRun> | AgentRun;

export interface SdkAdapterConfig {
  run?: SdkRunner;
}

export function createSdkAdapter(config: SdkAdapterConfig): TargetAdapter {
  const { run } = config;
  return {
    async runAgent(input: string): Promise<Result<AgentRun, AdapterError>> {
      if (!run) {
        return err({ kind: "unsupported", message: "sdk adapter requires a `run` function" });
      }
      try {
        return ok(await run(input));
      } catch (cause) {
        return err({
          kind: "protocol",
          message: cause instanceof Error ? cause.message : String(cause),
        });
      }
    },
  };
}
