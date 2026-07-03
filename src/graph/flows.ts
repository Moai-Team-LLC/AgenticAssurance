/**
 * General transitive-composition detection (FR-3.1).
 *
 * The lethal trifecta is the flagship (trifecta.ts). This adds the other canonical composition
 * risk — `read_untrusted -> code_exec` — where untrusted content reaching the agent can drive a
 * code-execution tool (config-injection RCE). Returns every detected flow, mitigated or not, so
 * the report can show controlled flows as YELLOW and unmitigated ones as critical.
 */
import type { CapabilityManifest, MitigationLeg } from "../manifest/schema";
import {
  AGENT_ID,
  brokenLegs,
  buildCapabilityGraph,
  reachableFrom,
  sourceViaLeg,
  type CapabilityGraph,
  type GraphNode,
  type ToxicFlow,
} from "./build";
import { findLethalTrifecta } from "./trifecta";

const RCE_LEGS: MitigationLeg[] = ["untrusted-ingress", "code-exec"];

function rceWitness(
  graph: CapabilityGraph,
  cut: ReadonlySet<MitigationLeg>,
): { ingress: GraphNode; exec: GraphNode } | null {
  const ingress = sourceViaLeg(graph, "untrusted-ingress", cut);
  if (!ingress) return null;
  const reach = reachableFrom(graph, AGENT_ID, cut);
  let exec: GraphNode | undefined;
  for (const id of reach) {
    const node = graph.nodes.get(id);
    if (node?.kind === "tool" && node.sideEffect === "code-exec") {
      exec = node;
      break;
    }
  }
  return exec ? { ingress, exec } : null;
}

/** Detect the untrusted-content -> code-execution path, or null when absent. */
export function findUntrustedToCodeExec(manifest: CapabilityManifest): ToxicFlow | null {
  const graph = buildCapabilityGraph(manifest);
  const raw = rceWitness(graph, new Set());
  if (!raw) return null;

  const cut = brokenLegs(manifest);
  const mitigated = rceWitness(graph, cut) === null;
  const broken = RCE_LEGS.filter((leg) => cut.has(leg));

  return {
    id: `untrusted-to-code-exec:${raw.ingress.id}->${AGENT_ID}->${raw.exec.id}`,
    kind: "untrusted-to-code-exec",
    legs: RCE_LEGS,
    nodes: [raw.ingress.id, AGENT_ID, raw.exec.id],
    mitigated,
    brokenLegs: broken,
    rationale: mitigated
      ? `Untrusted ingress (${raw.ingress.label}) can reach code-exec tool ${raw.exec.label}, ` +
        `but a declared mitigation breaks: ${broken.join(", ")}. Verify it holds.`
      : `Untrusted content from ${raw.ingress.label} can drive ${raw.exec.label} into executing ` +
        `attacker-controlled code (config-injection RCE). Quarantine the ingress or sandbox exec.`,
  };
}

/** All toxic flows on a manifest: the lethal trifecta plus transitive RCE paths (FR-3.1/3.2). */
export function analyzeToxicFlows(manifest: CapabilityManifest): ToxicFlow[] {
  const flows: ToxicFlow[] = [];
  const trifecta = findLethalTrifecta(manifest);
  if (trifecta) flows.push(trifecta);
  const rce = findUntrustedToCodeExec(manifest);
  if (rce) flows.push(rce);
  return flows;
}
