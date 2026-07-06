/**
 * SARIF 2.1.0 emitter (FR-6.3).
 *
 * Renders a scan report as SARIF for CI code-scanning dashboards. Result messages carry the
 * payload-free `observed` summary and the input's sha256 (never the raw payload, NFR-3), plus a
 * `security-severity` so GitHub code scanning ranks findings correctly.
 */
import { AAL_CORE_VERSION } from "../index";
import type { ScanReport } from "../scan";
import type { Finding, Severity } from "./findings";

export type SarifLevel = "error" | "warning" | "note" | "none";

export interface SarifLog {
  version: "2.1.0";
  $schema: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: { driver: SarifDriver };
  results: SarifResult[];
}

interface SarifDriver {
  name: string;
  informationUri: string;
  version: string;
  rules: SarifReportingDescriptor[];
}

interface SarifReportingDescriptor {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: SarifLevel };
  properties: Record<string, unknown>;
}

interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: { text: string };
  locations: SarifLocation[];
  properties: Record<string, unknown>;
}

interface SarifLocation {
  physicalLocation: { artifactLocation: { uri: string } };
  logicalLocations?: { fullyQualifiedName: string; kind: string }[];
}

const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";

const SEVERITY_TO_LEVEL: Record<Severity, SarifLevel> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.0",
  low: "3.0",
  info: "0.0",
};

export function toSarif(report: ScanReport): SarifLog {
  const uri = report.manifestPath;
  const rules = buildRules(report.findings);
  const results = report.findings.map((f) => toResult(f, uri));
  return {
    version: "2.1.0",
    $schema: SARIF_SCHEMA,
    runs: [
      {
        tool: {
          driver: {
            name: "AAL Core",
            informationUri: "https://github.com/Moai-Team-LLC/AgenticAssurance",
            version: AAL_CORE_VERSION,
            rules,
          },
        },
        results,
      },
    ],
  };
}

function buildRules(findings: Finding[]): SarifReportingDescriptor[] {
  const byId = new Map<string, SarifReportingDescriptor>();
  for (const f of findings) {
    if (byId.has(f.ruleId)) continue;
    byId.set(f.ruleId, {
      id: f.ruleId,
      name: f.ruleId.replace(/[^A-Za-z0-9]+/g, ""),
      shortDescription: { text: f.title },
      defaultConfiguration: { level: SEVERITY_TO_LEVEL[f.severity] },
      properties: {
        tags: ["security", ...(f.owasp ? [f.owasp] : []), ...(f.atlas ? [f.atlas] : [])],
        ...(f.owasp ? { owasp: f.owasp } : {}),
        ...(f.atlas ? { atlas: f.atlas } : {}),
      },
    });
  }
  return [...byId.values()];
}

function toResult(f: Finding, uri: string): SarifResult {
  const location: SarifLocation = {
    physicalLocation: { artifactLocation: { uri } },
    ...(f.locations.length > 0
      ? { logicalLocations: f.locations.map((id) => ({ fullyQualifiedName: id, kind: "member" })) }
      : {}),
  };
  return {
    ruleId: f.ruleId,
    level: SEVERITY_TO_LEVEL[f.severity],
    message: { text: f.observed },
    locations: [location],
    properties: {
      severity: f.severity,
      "security-severity": SECURITY_SEVERITY[f.severity],
      ...(f.owasp ? { owasp: f.owasp } : {}),
      ...(f.atlas ? { atlas: f.atlas } : {}),
      ...(f.attackId ? { attackId: f.attackId } : {}),
      ...(f.flowId ? { flowId: f.flowId } : {}),
      ...(f.inputHash ? { inputHash: f.inputHash } : {}),
      ...(f.stability ? { stability: `${f.stability.pass}/${f.stability.total}` } : {}),
    },
  };
}

/** Structural conformance check for SARIF 2.1.0 (offline substitute for schema validation). */
export function validateSarif(log: unknown): { valid: boolean; issues: string[] } {
  const issues: string[] = [];
  const levels = new Set<SarifLevel>(["error", "warning", "note", "none"]);
  const obj = log as SarifLog;

  if (obj?.version !== "2.1.0") issues.push("version must be '2.1.0'");
  if (typeof obj?.$schema !== "string") issues.push("$schema must be a string");
  if (!Array.isArray(obj?.runs) || obj.runs.length === 0) issues.push("runs must be a non-empty array");

  for (const run of obj?.runs ?? []) {
    if (typeof run.tool?.driver?.name !== "string") issues.push("run.tool.driver.name required");
    if (!Array.isArray(run.tool?.driver?.rules)) issues.push("run.tool.driver.rules must be an array");
    if (!Array.isArray(run.results)) {
      issues.push("run.results must be an array");
      continue;
    }
    for (const r of run.results) {
      if (typeof r.ruleId !== "string") issues.push("result.ruleId required");
      if (!levels.has(r.level)) issues.push(`result.level invalid: ${String(r.level)}`);
      if (typeof r.message?.text !== "string") issues.push("result.message.text required");
      if (!Array.isArray(r.locations)) issues.push("result.locations must be an array");
    }
  }
  return { valid: issues.length === 0, issues };
}
