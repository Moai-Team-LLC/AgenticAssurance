/**
 * Structured JSON report (FR-6.3 / FR-10.3).
 *
 * A downstream-ingestible, versioned view of a scan — consumed by the AAL Evidence layer to score
 * controls. Payload-free (findings and attacks reference inputs by sha256 only). Deterministic and
 * timestamp-free so it stays reproducible.
 */
import type { ScanReport } from "../scan";
import type { Finding } from "./findings";

export interface AssuranceJson {
  schemaVersion: "aal-core-report/0.1";
  target: string;
  criticalCount: number;
  coverage: ScanReport["coverage"];
  findings: Finding[];
  attacks: AssuranceAttack[];
  flows: AssuranceFlow[];
}

export interface AssuranceAttack {
  attackId: string;
  attackClass: string;
  owasp: string;
  atlas: string;
  outcome: "succeeded" | "contained" | "not_verified";
  stability: { pass: number; total: number };
  inputHash: string;
  refuseButFire: boolean;
}

export interface AssuranceFlow {
  id: string;
  kind: string;
  mitigated: boolean;
  legs: string[];
}

/** Shape a scan report as the stable JSON the Evidence layer ingests. */
export function toAssuranceJson(report: ScanReport): AssuranceJson {
  return {
    schemaVersion: "aal-core-report/0.1",
    target: report.target,
    criticalCount: report.criticalCount,
    coverage: report.coverage,
    findings: report.findings,
    attacks: report.attackResults.map((r) => ({
      attackId: r.attackId,
      attackClass: r.attackClass,
      owasp: r.owasp,
      atlas: r.atlas,
      outcome: r.outcome,
      stability: r.stability,
      inputHash: r.inputHash,
      refuseButFire: r.sideEffect.refuseButFire,
    })),
    flows: report.toxicFlows.map((f) => ({ id: f.id, kind: f.kind, mitigated: f.mitigated, legs: f.legs })),
  };
}
