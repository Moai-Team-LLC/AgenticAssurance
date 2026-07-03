/**
 * Target Adapter interface (FR-1.1).
 *
 * The adapter is the single seam AAL Core uses to *run* a target agent — it knows nothing
 * about the agent's framework. Every concrete adapter (exec/http/sdk) returns the same shape:
 * the agent's text AND its structured tool calls. Capturing `toolCalls` (not just `text`) is
 * what makes execution-layer side-effect detection possible (FR-4).
 */
import type { Result } from "neverthrow";

/** A single tool invocation the target agent emitted during a run. */
export interface ToolCall {
  tool: string;
  args: unknown;
}

/** The observable result of one agent run: its prose and every tool it invoked. */
export interface AgentRun {
  text: string;
  toolCalls: ToolCall[];
}

/** A typed adapter failure. Fail-closed: any of these ⇒ the attack result is `not_verified`. */
export type AdapterError =
  | { kind: "spawn"; message: string }
  | { kind: "timeout"; message: string }
  | { kind: "protocol"; message: string }
  | { kind: "exit"; code: number | null; message: string }
  | { kind: "unsupported"; message: string };

/** How AAL Core runs a target agent. One input in, one observed run out. */
export interface TargetAdapter {
  runAgent(input: string): Promise<Result<AgentRun, AdapterError>>;
}
