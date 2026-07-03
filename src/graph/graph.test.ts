import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { loadManifest, type CapabilityManifest, type MitigationLeg } from "../manifest";
import { analyzeToxicFlows, findLethalTrifecta, findUntrustedToCodeExec } from "./index";

/** Replica of the APS lethal_trifecta_check.py verdict: all three legs present, none broken. */
const pyGateFails = (p: boolean, u: boolean, e: boolean, mitigated: boolean): boolean =>
  p && u && e && !mitigated;

const fixture = (name: string): CapabilityManifest => {
  const r = loadManifest(fileURLToPath(new URL(`../../fixtures/vulnerable-agent/${name}`, import.meta.url)));
  if (r.isErr()) throw new Error(`fixture ${name} failed to load: ${r.error.message}`);
  return r.value;
};

describe("toxic-flow graph", () => {
  it("flags the seeded lethal trifecta with the exact offending nodes", () => {
    const flow = findLethalTrifecta(fixture("manifest.json"));
    expect(flow).not.toBeNull();
    expect(flow?.mitigated).toBe(false);
    expect(flow?.nodes).toContain("data:customer-pii");
    expect(flow?.nodes).toContain("tool:send_email");
    expect(flow?.nodes).toContain("agent");
    expect(flow?.nodes.some((n) => n.startsWith("ingress:"))).toBe(true);
  });

  it("flags the seeded read_untrusted -> code_exec (RCE) path", () => {
    const flow = findUntrustedToCodeExec(fixture("manifest.json"));
    expect(flow).not.toBeNull();
    expect(flow?.mitigated).toBe(false);
    expect(flow?.nodes).toContain("tool:run_shell");
  });

  it("does NOT flag an unmitigated trifecta on the mitigated variant", () => {
    const flows = analyzeToxicFlows(fixture("manifest.mitigated.json"));
    // Both flows are structurally present but every one is broken by a declared mitigation.
    expect(flows.length).toBeGreaterThan(0);
    expect(flows.every((f) => f.mitigated)).toBe(true);
    const trifecta = flows.find((f) => f.kind === "lethal-trifecta");
    expect(trifecta?.brokenLegs).toContain("external-egress");
  });

  it("returns null when fewer than three trifecta legs are present", () => {
    expect(findLethalTrifecta(gen({ priv: true, untrusted: true, egress: false }))).toBeNull();
  });

  it("a code-exec mitigation does not falsely mitigate the trifecta", () => {
    const flow = findLethalTrifecta(
      gen({ priv: true, untrusted: true, egress: true, mitigate: ["code-exec"] }),
    );
    expect(flow?.mitigated).toBe(false);
  });

  // Parity with the Agentic Product Standard's lethal_trifecta_check.py across the truth table.
  it("matches the APS Python trifecta gate on every leg combination", () => {
    for (const priv of [false, true]) {
      for (const untrusted of [false, true]) {
        for (const egress of [false, true]) {
          for (const mitigate of [[] as MitigationLeg[], ["external-egress"] as MitigationLeg[]]) {
            const m = gen({ priv, untrusted, egress, mitigate });
            const flow = findLethalTrifecta(m);
            const aalFlagsUnmitigated = flow !== null && !flow.mitigated;
            const mitigatedLeg = mitigate.length > 0;
            expect(aalFlagsUnmitigated).toBe(pyGateFails(priv, untrusted, egress, mitigatedLeg));
          }
        }
      }
    }
  });
});

function gen(opts: {
  priv: boolean;
  untrusted: boolean;
  egress: boolean;
  codeExec?: boolean;
  mitigate?: MitigationLeg[];
}): CapabilityManifest {
  const tools: CapabilityManifest["tools"] = [];
  if (opts.priv) {
    tools.push({
      name: "read_priv",
      sideEffect: "read",
      dataScopes: [{ id: "secret", sensitivity: "private" }],
    });
  }
  if (opts.egress) tools.push({ name: "egress", sideEffect: "external-egress", dataScopes: [] });
  if (opts.codeExec) tools.push({ name: "exec", sideEffect: "code-exec", dataScopes: [] });
  if (tools.length === 0) tools.push({ name: "noop", sideEffect: "read", dataScopes: [] });

  return {
    manifestVersion: "0.1",
    name: "generated",
    identity: { delegated: false, scoped: true },
    tools,
    untrustedIngress: opts.untrusted ? [{ id: "web", kind: "web" }] : [],
    declaredMitigations: (opts.mitigate ?? []).map((breaks) => ({ breaks, control: "declared control" })),
  };
}
