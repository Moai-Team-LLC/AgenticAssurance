import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { loadManifest, parseManifest } from "./load";

const fixture = (name: string): string =>
  fileURLToPath(new URL(`../../fixtures/vulnerable-agent/${name}`, import.meta.url));

describe("manifest loader", () => {
  it("loads and validates the vulnerable reference manifest", () => {
    const result = loadManifest(fixture("manifest.json"));
    expect(result.isOk()).toBe(true);
    if (result.isOk()) {
      const m = result.value;
      expect(m.name).toBe("vulnerable-support-agent");
      expect(m.tools.map((t) => t.sideEffect)).toContain("external-egress");
      expect(m.untrustedIngress.length).toBeGreaterThan(0);
    }
  });

  it("loads the mitigated variant with declared mitigations", () => {
    const result = loadManifest(fixture("manifest.mitigated.json"));
    expect(result.isOk()).toBe(true);
    if (result.isOk()) {
      expect(result.value.declaredMitigations.map((m) => m.breaks)).toContain("external-egress");
    }
  });

  it("returns a typed validation error for a malformed manifest", () => {
    const result = parseManifest({ manifestVersion: "0.1", name: "", tools: [] });
    expect(result.isErr()).toBe(true);
    if (result.isErr()) {
      expect(result.error.kind).toBe("validation");
      if (result.error.kind === "validation") {
        expect(result.error.issues.length).toBeGreaterThan(0);
      }
    }
  });

  it("returns a read error for a missing file (fail-closed, no throw)", () => {
    const result = loadManifest(fixture("does-not-exist.json"));
    expect(result.isErr()).toBe(true);
    if (result.isErr()) expect(result.error.kind).toBe("read");
  });

  it("rejects an unknown side-effect class", () => {
    const result = parseManifest({
      manifestVersion: "0.1",
      name: "x",
      identity: { delegated: false, scoped: true },
      tools: [{ name: "t", sideEffect: "teleport" }],
    });
    expect(result.isErr()).toBe(true);
  });
});
