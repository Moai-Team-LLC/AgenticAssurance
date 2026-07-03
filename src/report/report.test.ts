import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { createExecAdapter } from "../adapter";
import { runScan, type ScanReport } from "../scan";
import { toMarkdown } from "./human";
import { toAssuranceJson } from "./json";
import { toSarif, validateSarif } from "./sarif";

const url = (p: string): string => fileURLToPath(new URL(p, import.meta.url));
const manifestPath = url("../../fixtures/vulnerable-agent/manifest.json");
const agentPath = url("../../fixtures/vulnerable-agent/agent.mjs");

async function scan(): Promise<ScanReport> {
  const adapter = createExecAdapter({ command: "node", args: [agentPath] });
  const result = await runScan({ manifestPath, adapter, runs: 1, seed: 7 });
  if (result.isErr()) throw new Error(`scan failed: ${result.error.message}`);
  return result.value;
}

describe("scan report", () => {
  it("flags the static lethal trifecta and the dynamic refuse-but-fire, both critical", async () => {
    const report = await scan();
    const trifecta = report.findings.find((f) => f.ruleId === "toxic-flow/lethal-trifecta");
    expect(trifecta?.severity).toBe("critical");
    const refuseButFire = report.findings.find((f) => f.title.startsWith("Refuse-in-text"));
    expect(refuseButFire?.severity).toBe("critical");
    expect(report.criticalCount).toBeGreaterThanOrEqual(2);
  });

  it("ranks findings most-severe first", async () => {
    const report = await scan();
    const order = ["critical", "high", "medium", "low", "info"];
    const idx = report.findings.map((f) => order.indexOf(f.severity));
    expect(idx).toEqual(idx.toSorted((a, b) => a - b));
  });

  it("emits SARIF that conforms to 2.1.0", async () => {
    const sarif = toSarif(await scan());
    const { valid, issues } = validateSarif(sarif);
    expect(issues).toEqual([]);
    expect(valid).toBe(true);
    expect(sarif.version).toBe("2.1.0");
  });

  it("states an honest coverage ratio (NFR-8)", async () => {
    const report = await scan();
    expect(report.coverage.dynamicRan).toBe(true);
    expect(report.coverage.attacksTotal).toBeGreaterThanOrEqual(8);
    // The seed corpus is all assert-based → every attack is conclusive with no provider.
    expect(report.coverage.attacksNotVerified).toBe(0);
    expect(report.coverage.ratio).toBe(1);
    expect(toMarkdown(report)).toContain("conclusively evaluated");
  });

  it("never writes a raw payload or secret into SARIF or the report (NFR-3)", async () => {
    const report = await scan();
    const sarif = JSON.stringify(toSarif(report));
    const md = toMarkdown(report);
    for (const secret of ["attacker.example", "alice@corp.test", "evil.test"]) {
      expect(sarif).not.toContain(secret);
      expect(md).not.toContain(secret);
    }
  });

  it("emits a structured JSON report for the Evidence layer (payload-free)", async () => {
    const json = toAssuranceJson(await scan());
    expect(json.schemaVersion).toBe("aal-core-report/0.1");
    expect(json.attacks.length).toBeGreaterThanOrEqual(8);
    expect(json.attacks.every((a) => ["succeeded", "contained", "not_verified"].includes(a.outcome))).toBe(true);
    expect(json.flows.some((f) => f.kind === "lethal-trifecta")).toBe(true);
    expect(JSON.stringify(json)).not.toContain("attacker.example");
  });

  it("is reproducible: two scans produce identical findings", async () => {
    const a = await scan();
    const b = await scan();
    expect(b.findings).toEqual(a.findings);
    expect(b.coverage).toEqual(a.coverage);
  });
});
