/**
 * Scan orchestration — the one call the CLI (and tests) drive.
 *
 * Runs the static toxic-flow graph over the manifest and, when a target adapter is supplied, the
 * dynamic attack suite in a sandbox; then normalizes both into a single ranked findings list with
 * an honest coverage ratio. Deterministic and timestamp-free so results are reproducible (FR-6.2)
 * and snapshot-testable.
 */
import { err, ok, type Result } from "neverthrow";
import { fileURLToPath } from "node:url";
import type { TargetAdapter } from "./adapter/types";
import { loadManifest, type CapabilityManifest } from "./manifest";
import { loadAttackCorpus, renderAttackInput, type Attack } from "./attacks";
import { analyzeToxicFlows, type ToxicFlow } from "./graph";
import { createProcessJailSandbox } from "./runner/sandbox";
import { hashInput, normalizeRuns, runSuite, type AttackResult } from "./runner/run";
import type { OracleProvider } from "./runner/oracle";
import {
  computeCoverage,
  findingsFromFlows,
  findingsFromResults,
  rankFindings,
  type Coverage,
  type Finding,
} from "./report/findings";

/** Default corpus shipped with the package (resolves from both src/ and dist/). */
export const DEFAULT_ATTACKS_DIR = fileURLToPath(new URL("../attacks", import.meta.url));

export interface ScanInput {
  manifestPath: string;
  attacksDir?: string;
  runs?: number;
  seed?: number;
  adapter?: TargetAdapter;
  provider?: OracleProvider;
}

export interface ScanReport {
  target: string;
  manifestPath: string;
  seed?: number;
  runs: number;
  findings: Finding[];
  coverage: Coverage;
  toxicFlows: ToxicFlow[];
  attackResults: AttackResult[];
  criticalCount: number;
}

export type ScanError =
  | { kind: "manifest"; message: string }
  | { kind: "attacks"; message: string };

export async function runScan(input: ScanInput): Promise<Result<ScanReport, ScanError>> {
  const manifestResult = loadManifest(input.manifestPath);
  if (manifestResult.isErr()) {
    return err({ kind: "manifest", message: manifestResult.error.message });
  }
  const manifest = manifestResult.value;

  const corpus = loadAttackCorpus(input.attacksDir ?? DEFAULT_ATTACKS_DIR);
  if (corpus.isErr()) {
    return err({ kind: "attacks", message: corpus.error.message });
  }
  const attacks = corpus.value;

  const toxicFlows = analyzeToxicFlows(manifest);
  const runs = normalizeRuns(input.runs);

  let attackResults: AttackResult[];
  let dynamicRan: boolean;
  if (input.adapter) {
    const sandbox = createProcessJailSandbox(input.adapter, manifest);
    attackResults = await runSuite(attacks, sandbox, manifest, {
      runs,
      ...(input.seed !== undefined ? { seed: input.seed } : {}),
      ...(input.provider ? { provider: input.provider } : {}),
    });
    dynamicRan = true;
  } else {
    // No runnable target: static analysis still runs; every attack is honestly not_verified.
    attackResults = attacks.map((a) => notVerified(a, manifest, runs));
    dynamicRan = false;
  }

  const findings = rankFindings([
    ...findingsFromFlows(toxicFlows),
    ...findingsFromResults(attackResults),
  ]);
  const criticalCount = findings.filter((f) => f.severity === "critical").length;

  return ok({
    target: manifest.name,
    manifestPath: input.manifestPath,
    ...(input.seed !== undefined ? { seed: input.seed } : {}),
    runs,
    findings,
    coverage: computeCoverage(attackResults, dynamicRan),
    toxicFlows,
    attackResults,
    criticalCount,
  });
}

function notVerified(attack: Attack, _manifest: CapabilityManifest, runs: number): AttackResult {
  return {
    attackId: attack.id,
    attackClass: attack.class,
    owasp: attack.owasp,
    atlas: attack.atlas,
    inputHash: hashInput(renderAttackInput(attack)),
    outcome: "not_verified",
    stability: { pass: 0, total: runs },
    sideEffect: { refusedInText: false, firedSideEffects: [], refuseButFire: false },
    intercepted: [],
    observed: "skipped — no target configured (static-only scan)",
    note: "no target configured",
  };
}
