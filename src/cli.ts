#!/usr/bin/env node
/**
 * `aal` CLI (FR-12.1) — the primary interface and the CI gate.
 *
 * `aal scan <manifest>` runs the static toxic-flow graph plus the dynamic attack suite (when a
 * target is configured), writes SARIF and/or a Markdown report, prints a deterministic summary,
 * and exits non-zero on any critical finding.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { Command } from "commander";
import { z } from "zod";
import { AAL_CORE_VERSION } from "./index";
import { createExecAdapter, type TargetAdapter } from "./adapter";
import { runScan } from "./scan";
import { toSarif } from "./report/sarif";
import { renderCliSummary, toMarkdown } from "./report/human";
import { createAnthropicProvider, type OracleProvider } from "./runner/oracle";

const TargetConfig = z.object({
  command: z.string().min(1),
  args: z.array(z.string()).optional(),
  timeoutMs: z.number().optional(),
});

const program = new Command();

program
  .name("aal")
  .description("Agent Assurance Layer — offensive core (red-team any agent)")
  .version(AAL_CORE_VERSION);

program
  .command("scan")
  .description("Red-team an agent from its Capability Manifest")
  .argument("<manifest>", "path to the agent Capability Manifest (JSON/YAML)")
  .option("--attacks <dir>", "attack corpus directory (defaults to the packaged corpus)")
  .option("--adapter <kind>", "target adapter: exec | http | sdk", "exec")
  .option("--target <path>", "target config JSON (exec); defaults to target.json next to the manifest")
  .option("--sarif <path>", "write SARIF 2.1.0 output")
  .option("--report <path>", "write a Markdown report")
  .option("-n, --runs <n>", "stability runs per dynamic attack", "5")
  .option("--seed <n>", "seed for reproducible runs")
  .action(async (manifest: string, opts: ScanOpts) => {
    const adapter = resolveAdapter(manifest, opts);
    const provider = resolveProvider();

    const result = await runScan({
      manifestPath: manifest,
      ...(opts.attacks ? { attacksDir: opts.attacks } : {}),
      runs: Number.parseInt(opts.runs, 10),
      ...(opts.seed !== undefined ? { seed: Number.parseInt(opts.seed, 10) } : {}),
      ...(adapter ? { adapter } : {}),
      ...(provider ? { provider } : {}),
    });

    if (result.isErr()) {
      process.stderr.write(`aal scan: ${result.error.kind} error — ${result.error.message}\n`);
      process.exitCode = 2;
      return;
    }

    const report = result.value;
    if (opts.sarif) writeFileSync(opts.sarif, `${JSON.stringify(toSarif(report), null, 2)}\n`);
    if (opts.report) writeFileSync(opts.report, toMarkdown(report));

    process.stdout.write(`${renderCliSummary(report)}\n`);
    // FR-12.1: non-zero exit on any critical finding, so CI can gate on it.
    process.exitCode = report.criticalCount > 0 ? 1 : 0;
  });

program.parse();

interface ScanOpts {
  attacks?: string;
  adapter: string;
  target?: string;
  sarif?: string;
  report?: string;
  runs: string;
  seed?: string;
}

/** Resolve an exec adapter from a target config; return undefined for a static-only scan. */
function resolveAdapter(manifest: string, opts: ScanOpts): TargetAdapter | undefined {
  if (opts.adapter !== "exec") {
    process.stderr.write(`aal scan: adapter '${opts.adapter}' is not implemented yet — running static-only.\n`);
    return undefined;
  }
  const targetPath = opts.target ?? join(dirname(manifest), "target.json");
  if (!existsSync(targetPath)) {
    process.stderr.write(`aal scan: no target config at ${targetPath} — running static-only.\n`);
    return undefined;
  }
  let parsed;
  try {
    parsed = TargetConfig.safeParse(JSON.parse(readFileSync(targetPath, "utf8")));
  } catch (cause) {
    process.stderr.write(`aal scan: cannot read target config: ${cause instanceof Error ? cause.message : String(cause)}\n`);
    return undefined;
  }
  if (!parsed.success) {
    process.stderr.write(`aal scan: invalid target config at ${targetPath}\n`);
    return undefined;
  }
  return createExecAdapter({
    command: parsed.data.command,
    ...(parsed.data.args ? { args: parsed.data.args } : {}),
    cwd: dirname(targetPath),
    ...(parsed.data.timeoutMs !== undefined ? { timeoutMs: parsed.data.timeoutMs } : {}),
  });
}

/** Build the oracle provider only when a key is present; otherwise rubric attacks stay not_verified. */
function resolveProvider(): OracleProvider | undefined {
  return process.env.ANTHROPIC_API_KEY ? createAnthropicProvider() : undefined;
}
