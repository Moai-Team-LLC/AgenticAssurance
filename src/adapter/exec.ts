/**
 * CLI-exec Target Adapter (FR-1.1).
 *
 * Runs a target agent as a subprocess, mirroring the APS `run_agent.sh` provider shape. The
 * protocol is a single JSON round-trip so it is language-agnostic and zod-checkable on both
 * sides:
 *   - AAL writes `{"input": "<attack text>"}` to the agent's stdin, then closes it.
 *   - The agent writes `{"text": "...", "toolCalls": [{"tool","args"}...]}` to stdout.
 *
 * The adapter itself performs no side effect — the agent merely *declares* the tool calls it
 * would make; interception of those calls is the sandbox's job (FR-5).
 *
 * Hash-not-text (NFR-3): a crashing or misbehaving agent may echo an attack payload or leaked
 * secret to stdout/stderr. Error messages therefore NEVER embed raw agent output — they reference
 * it by byte count and sha256, and validation errors use zod issue paths/codes, not received values.
 */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { err, ok, type Result } from "neverthrow";
import { z } from "zod";
import type { AdapterError, AgentRun, TargetAdapter } from "./types";

/** Configuration for one exec-adapter target. */
export interface ExecAdapterConfig {
  command: string;
  args?: string[];
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 15_000;

/** The envelope an exec target must emit on stdout. Validated before we trust it. */
const AgentRunEnvelope = z.object({
  text: z.string(),
  toolCalls: z
    .array(z.object({ tool: z.string().min(1), args: z.unknown() }))
    .default([]),
});

export function createExecAdapter(config: ExecAdapterConfig): TargetAdapter {
  return {
    runAgent(input: string): Promise<Result<AgentRun, AdapterError>> {
      return runOnce(config, input);
    },
  };
}

function runOnce(
  config: ExecAdapterConfig,
  input: string,
): Promise<Result<AgentRun, AdapterError>> {
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(config.command, config.args ?? [], {
        cwd: config.cwd,
        env: { ...process.env, ...config.env },
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (cause) {
      resolve(err({ kind: "spawn", message: messageOf(cause) }));
      return;
    }

    let stdout = "";
    let stderr = "";
    let settled = false;
    const finish = (result: Result<AgentRun, AdapterError>): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(err({ kind: "timeout", message: `agent exceeded ${timeoutMs}ms` }));
    }, timeoutMs);

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => (stdout += chunk));
    child.stderr.on("data", (chunk: string) => (stderr += chunk));

    child.on("error", (cause) => finish(err({ kind: "spawn", message: messageOf(cause) })));
    // A child that exits before reading stdin makes our write raise EPIPE; fail closed, don't crash.
    child.stdin.on("error", (cause) => finish(err({ kind: "spawn", message: messageOf(cause) })));

    child.on("close", (code) => {
      const parsed = parseEnvelope(stdout);
      if (parsed.isErr()) {
        // No usable envelope. Distinguish a crash (non-zero exit) from a protocol violation.
        // stderr is referenced by hash only — it may carry an echoed payload/secret.
        if (code !== 0) {
          finish(err({ kind: "exit", code, message: `agent exited ${code}; ${digest("stderr", stderr)}` }));
          return;
        }
        finish(err({ kind: "protocol", message: parsed.error }));
        return;
      }
      finish(ok(parsed.value));
    });

    child.stdin.end(JSON.stringify({ input }));
  });
}

function parseEnvelope(stdout: string): Result<AgentRun, string> {
  const trimmed = stdout.trim();
  if (trimmed === "") return err("agent produced no stdout");
  let json: unknown;
  try {
    json = JSON.parse(trimmed);
  } catch {
    // The JSON parser's message echoes the offending bytes — reference stdout by hash instead.
    return err(`agent stdout is not valid JSON; ${digest("stdout", trimmed)}`);
  }
  const validated = AgentRunEnvelope.safeParse(json);
  if (!validated.success) {
    // Use the issue path + code (structural), never the received value (which is agent-controlled).
    const issue = validated.error.issues[0];
    const at = issue ? `${issue.path.join(".") || "<root>"}: ${issue.code}` : "unknown";
    return err(`agent envelope failed validation (${at})`);
  }
  return ok(validated.data);
}

function messageOf(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}

/** A payload-free reference to some agent output: byte length + a short sha256. */
function digest(label: string, text: string): string {
  const trimmed = text.trim();
  if (trimmed === "") return `${label} empty`;
  const hash = createHash("sha256").update(trimmed).digest("hex").slice(0, 16);
  return `${label} ${trimmed.length}b sha256:${hash}`;
}
