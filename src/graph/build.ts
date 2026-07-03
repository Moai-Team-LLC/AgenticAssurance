/**
 * Toxic-flow graph builder (FR-3.1).
 *
 * Turns a Capability Manifest into a directed graph over which we detect *transitive* attack
 * paths that single-prompt scanners miss. Nodes are the agent core, its tools, its untrusted
 * ingress points, and the data scopes it can reach; edges are the data-flow reachability the
 * manifest implies. Every dangerous edge is tagged with the trifecta/RCE *leg* it belongs to,
 * so a declared mitigation can cut exactly that leg.
 *
 * Pure and in-memory — no agent execution — so it is fast (NFR-6, < 60s) and CI-safe (FR-3.4).
 */
import type { CapabilityManifest, MitigationLeg, SideEffectClass } from "../manifest/schema";

export type NodeKind = "agent" | "untrusted-ingress" | "data-scope" | "tool";

export interface GraphNode {
  id: string;
  kind: NodeKind;
  label: string;
  sideEffect?: SideEffectClass;
  sensitivity?: "public" | "private";
}

/** A directed data-flow edge. `leg` names the trifecta/RCE leg a mitigation can cut here. */
export interface GraphEdge {
  from: string;
  to: string;
  leg?: MitigationLeg;
}

export interface CapabilityGraph {
  nodes: Map<string, GraphNode>;
  edges: GraphEdge[];
}

/**
 * A detected composition risk over the manifest. `mitigated` is true when a declared mitigation
 * breaks at least one leg (the flow is structurally present but claimed-controlled → YELLOW);
 * an unmitigated flow is a critical finding (FR-3.2). `nodes` are the exact manifest-derived
 * node ids that form the flow, so remediation is unambiguous (FR-3.3).
 */
export interface ToxicFlow {
  id: string;
  kind: "lethal-trifecta" | "untrusted-to-code-exec";
  legs: MitigationLeg[];
  nodes: string[];
  mitigated: boolean;
  brokenLegs: MitigationLeg[];
  rationale: string;
}

export const AGENT_ID = "agent";

/** The mitigation leg a side-effecting sink tool contributes, if any. */
function sinkLeg(sideEffect: SideEffectClass): MitigationLeg | undefined {
  if (sideEffect === "external-egress") return "external-egress";
  if (sideEffect === "code-exec") return "code-exec";
  return undefined;
}

/** Build the capability graph from a validated manifest. */
export function buildCapabilityGraph(manifest: CapabilityManifest): CapabilityGraph {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  const add = (node: GraphNode): void => void nodes.set(node.id, node);

  add({ id: AGENT_ID, kind: "agent", label: manifest.name });

  // Untrusted content enters the agent's context — the injection surface.
  for (const ingress of manifest.untrustedIngress) {
    const id = `ingress:${ingress.id}`;
    add({ id, kind: "untrusted-ingress", label: `${ingress.id} (${ingress.kind})` });
    edges.push({ from: id, to: AGENT_ID, leg: "untrusted-ingress" });
  }

  // Data scopes, and the read tools that pull them into the agent's context.
  const scopeNode = (scopeId: string, sensitivity: "public" | "private"): string => {
    const id = `data:${scopeId}`;
    if (!nodes.has(id)) {
      add({ id, kind: "data-scope", label: scopeId, sensitivity });
    }
    return id;
  };

  for (const tool of manifest.tools) {
    const toolId = `tool:${tool.name}`;
    add({ id: toolId, kind: "tool", label: tool.name, sideEffect: tool.sideEffect });

    // The agent can invoke any declared tool. For side-effecting sinks the invoke edge carries
    // the trifecta/RCE leg, so a declared mitigation cuts exactly this reachability and nothing
    // else — there is only ever one edge agent -> tool, never a leg-less shadow of it.
    const invokeLeg = sinkLeg(tool.sideEffect);
    edges.push({ from: AGENT_ID, to: toolId, ...(invokeLeg ? { leg: invokeLeg } : {}) });

    for (const scope of tool.dataScopes) {
      const dataId = scopeNode(scope.id, scope.sensitivity);
      if (tool.sideEffect === "read") {
        // A read pulls this scope into the agent's context; private reads are the trifecta leg.
        edges.push({
          from: dataId,
          to: AGENT_ID,
          ...(scope.sensitivity === "private" ? { leg: "private-data" as const } : {}),
        });
      } else {
        edges.push({ from: toolId, to: dataId });
      }
    }
  }

  return { nodes, edges };
}

/** The legs a manifest's declared mitigations break (a mitigation counts only with a control). */
export function brokenLegs(manifest: CapabilityManifest): Set<MitigationLeg> {
  const broken = new Set<MitigationLeg>();
  for (const m of manifest.declaredMitigations) {
    if (m.control.trim() !== "") broken.add(m.breaks);
  }
  return broken;
}

/** Direct predecessors of a node, skipping edges whose leg is in `cut`. */
export function predecessors(
  graph: CapabilityGraph,
  target: string,
  cut: ReadonlySet<MitigationLeg>,
): GraphNode[] {
  const out: GraphNode[] = [];
  for (const edge of graph.edges) {
    if (edge.to !== target) continue;
    if (edge.leg && cut.has(edge.leg)) continue;
    const node = graph.nodes.get(edge.from);
    if (node) out.push(node);
  }
  return out;
}

/** Node ids reachable forward from `start` (BFS), skipping edges whose leg is in `cut`. */
export function reachableFrom(
  graph: CapabilityGraph,
  start: string,
  cut: ReadonlySet<MitigationLeg>,
): Set<string> {
  const seen = new Set<string>([start]);
  const queue = [start];
  while (queue.length > 0) {
    const current = queue.shift() as string;
    for (const edge of graph.edges) {
      if (edge.from !== current) continue;
      if (edge.leg && cut.has(edge.leg)) continue;
      if (!seen.has(edge.to)) {
        seen.add(edge.to);
        queue.push(edge.to);
      }
    }
  }
  return seen;
}
