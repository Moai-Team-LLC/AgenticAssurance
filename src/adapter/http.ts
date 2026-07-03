/**
 * HTTP Target Adapter — interface stub (FR-1.1).
 *
 * Placeholder for an adapter that POSTs the attack input to a target's HTTP endpoint and reads
 * back the `{text, toolCalls}` envelope. The exec adapter ships first (Step 1); this lands when
 * a real HTTP target exists. Kept as a typed seam so the CLI's `--adapter http` path compiles.
 */
import { err, type Result } from "neverthrow";
import type { AdapterError, AgentRun, TargetAdapter } from "./types";

export interface HttpAdapterConfig {
  url: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
}

export function createHttpAdapter(_config: HttpAdapterConfig): TargetAdapter {
  return {
    runAgent(): Promise<Result<AgentRun, AdapterError>> {
      return Promise.resolve(
        err({ kind: "unsupported", message: "http adapter is not implemented yet" }),
      );
    },
  };
}
