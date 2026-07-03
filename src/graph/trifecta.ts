/**
 * Lethal-trifecta query (FR-3.2) — the flagship toxic-flow rule.
 *
 * Flags any composition where private data reaches the agent AND untrusted content reaches the
 * agent (the injection enabler) AND the agent can reach an external-egress sink — with no
 * declared mitigation breaking a leg. This is the runtime, graph-discoverable equivalent of the
 * Agentic Product Standard's `lethal_trifecta_check.py`, and returns the same verdict on the
 * same inputs (see graph.test.ts for the parity assertion).
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

const TRIFECTA_LEGS: MitigationLeg[] = ["private-data", "untrusted-ingress", "external-egress"];

interface TrifectaWitness {
  privateSource: GraphNode;
  ingress: GraphNode;
  egress: GraphNode;
}

/** Return the concrete nodes forming a trifecta under the given leg cuts, or null if broken. */
function witness(graph: CapabilityGraph, cut: ReadonlySet<MitigationLeg>): TrifectaWitness | null {
  const privateSource = sourceViaLeg(graph, "private-data", cut);
  const ingress = sourceViaLeg(graph, "untrusted-ingress", cut);
  if (!privateSource || !ingress) return null;

  const reach = reachableFrom(graph, AGENT_ID, cut);
  let egress: GraphNode | undefined;
  for (const id of reach) {
    const node = graph.nodes.get(id);
    if (node?.kind === "tool" && node.sideEffect === "external-egress") {
      egress = node;
      break;
    }
  }
  if (!egress) return null;
  return { privateSource, ingress, egress };
}

/** Detect the lethal trifecta on a manifest. Null when fewer than three legs are present. */
export function findLethalTrifecta(manifest: CapabilityManifest): ToxicFlow | null {
  const graph = buildCapabilityGraph(manifest);

  const raw = witness(graph, new Set());
  if (!raw) return null; // structurally absent — fewer than three legs.

  const cut = brokenLegs(manifest);
  const survives = witness(graph, cut);
  const mitigated = survives === null;
  const broken = TRIFECTA_LEGS.filter((leg) => cut.has(leg));

  return {
    id: `lethal-trifecta:${raw.privateSource.id}->${AGENT_ID}->${raw.egress.id}`,
    kind: "lethal-trifecta",
    legs: TRIFECTA_LEGS,
    nodes: [raw.privateSource.id, raw.ingress.id, AGENT_ID, raw.egress.id],
    mitigated,
    brokenLegs: broken,
    rationale: mitigated
      ? `Private data (${raw.privateSource.label}) + untrusted ingress (${raw.ingress.label}) + ` +
        `external egress (${raw.egress.label}) compose a lethal trifecta, but a declared ` +
        `mitigation breaks: ${broken.join(", ")}. Verify the mitigation actually holds.`
      : `Lethal trifecta with no broken leg: private data (${raw.privateSource.label}) can be ` +
        `exfiltrated via ${raw.egress.label} under injection from ${raw.ingress.label}. Break a ` +
        `leg (gate egress, quarantine untrusted input, or scope the data) and declare it.`,
  };
}
