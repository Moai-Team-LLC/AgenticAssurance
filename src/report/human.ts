/**
 * Human-readable report (FR-6.3).
 *
 * Renders a scan report as Markdown: a verdict line, findings ranked most-severe first with their
 * OWASP/ATLAS mapping and a prioritized fix, and — mandatory — the coverage ratio so results are
 * never over-claimed (NFR-8). Deterministic (no timestamps) so it is reproducible and snapshottable.
 */
import type { ScanReport } from "../scan";
import type { Finding, Severity } from "./findings";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

/** Count findings by severity. */
export function severityCounts(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

/** One-line coverage statement (NFR-8). */
export function coverageLine(report: ScanReport): string {
  const c = report.coverage;
  const pct = Math.round(c.ratio * 100);
  const suite = c.dynamicRan ? "ran" : "skipped (no target configured)";
  return `${c.attacksConclusive}/${c.attacksTotal} attacks conclusively evaluated (${pct}%), ${c.attacksNotVerified} not_verified — dynamic suite ${suite}`;
}

export function toMarkdown(report: ScanReport): string {
  const counts = severityCounts(report.findings);
  const verdict =
    counts.critical > 0
      ? `❌ ${counts.critical} critical finding(s)`
      : counts.high > 0
        ? `⚠️ ${counts.high} high finding(s), no critical`
        : "✅ no critical or high findings";

  const lines: string[] = [
    "# AAL Core — Assurance Report",
    "",
    `**Target:** ${report.target}`,
    `**Manifest:** ${report.manifestPath}`,
    `**Verdict:** ${verdict}`,
    `**Severity:** ${SEVERITIES.map((s) => `${counts[s]} ${s}`).join(" · ")}`,
    `**Coverage:** ${coverageLine(report)}`,
    report.seed !== undefined ? `**Seed:** ${report.seed} · **Runs:** ${report.runs}` : `**Runs:** ${report.runs}`,
    "",
    "## Findings (ranked)",
    "",
  ];

  if (report.findings.length === 0) {
    lines.push("_No findings._", "");
  } else {
    for (const f of report.findings) lines.push(...renderFinding(f));
  }

  lines.push(
    "## Coverage",
    "",
    `- ${coverageLine(report)}`,
    "- Static toxic-flow analysis runs on 100% of the manifest (no execution required).",
    "",
    "## Notes",
    "",
    "- No raw attack payloads or secrets are written to this report — inputs are referenced by sha256 (hash-not-text).",
    "- Inconclusive checks are reported as `not_verified`, never as safe (fail-closed).",
    "",
  );
  return lines.join("\n");
}

/**
 * Compact, deterministic CLI summary (the stdout output contract). Machine-independent: keyed on
 * the target name and findings, not absolute paths, so it is snapshot-stable.
 */
export function renderCliSummary(report: ScanReport): string {
  const counts = severityCounts(report.findings);
  const lines = [
    `aal scan — ${report.target}`,
    coverageLine(report),
    `findings: ${SEVERITIES.map((s) => `${counts[s]} ${s}`).join(" · ")}`,
  ];
  for (const f of report.findings) {
    if (f.severity !== "critical" && f.severity !== "high") continue;
    const map = f.owasp ? ` — OWASP ${f.owasp}` : "";
    const stab = f.stability ? ` (stability ${f.stability.pass}/${f.stability.total})` : "";
    lines.push(`  [${f.severity.toUpperCase()}] ${f.title}${map}${stab}`);
  }
  lines.push(counts.critical > 0 ? `verdict: FAIL — ${counts.critical} critical` : "verdict: PASS — no critical");
  return lines.join("\n");
}

function renderFinding(f: Finding): string[] {
  const meta: string[] = [];
  if (f.owasp) meta.push(`OWASP ${f.owasp}`);
  if (f.atlas) meta.push(`ATLAS ${f.atlas}`);
  if (f.attackId) meta.push(`attack \`${f.attackId}\``);
  if (f.flowId) meta.push(`flow \`${f.flowId}\``);
  if (f.stability) meta.push(`stability ${f.stability.pass}/${f.stability.total}`);

  const out = [
    `### [${f.severity.toUpperCase()}] ${f.title}`,
    "",
    `- **Rule:** \`${f.ruleId}\``,
    meta.length > 0 ? `- **Mapping:** ${meta.join(" · ")}` : "",
    f.inputHash ? `- **Input hash:** \`${f.inputHash.slice(0, 16)}…\`` : "",
    `- **Observed:** ${f.observed}`,
    f.locations.length > 0 ? `- **Locations:** ${f.locations.map((l) => `\`${l}\``).join(", ")}` : "",
    `- **Fix:** ${f.fix}`,
    "",
  ];
  return out.filter((line) => line !== "");
}
