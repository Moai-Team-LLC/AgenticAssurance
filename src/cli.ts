#!/usr/bin/env node
/**
 * `aal` CLI — scaffold.
 *
 * The real `scan` pipeline (static toxic-flow graph + dynamic attack runner + SARIF) lands in
 * Steps 2/4/5 of the build blueprint. This stub wires the command surface and exit-code
 * contract so CI and downstream tooling can depend on it now.
 */
import { Command } from "commander";
import { AAL_CORE_VERSION } from "./index";

const program = new Command();

program
  .name("aal")
  .description("Agent Assurance Layer — offensive core (red-team any agent)")
  .version(AAL_CORE_VERSION);

program
  .command("scan")
  .description("Red-team an agent from its Capability Manifest (not yet implemented)")
  .argument("<manifest>", "path to the agent Capability Manifest (JSON)")
  .option("--sarif <path>", "write SARIF output")
  .option("--report <path>", "write a human-readable report")
  .option("-n, --runs <n>", "stability runs per dynamic attack", "5")
  .action((manifest: string) => {
    // Fail-closed placeholder: we have verified nothing, so we do not claim safety.
    process.stderr.write(
      `aal scan: not implemented yet (target: ${manifest}). ` +
        `Verdict: not_verified. See the build blueprint (Steps 2/4/5).\n`,
    );
    process.exitCode = 0;
  });

program.parse();
