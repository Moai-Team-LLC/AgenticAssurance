import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AttackFile, loadAttackCorpus, renderAttackInput, type Attack } from "./index";

const corpusDir = fileURLToPath(new URL("../../attacks", import.meta.url));

describe("attack corpus", () => {
  it("loads and validates the seed corpus", () => {
    const result = loadAttackCorpus(corpusDir);
    expect(result.isOk()).toBe(true);
    if (result.isOk()) expect(result.value.length).toBeGreaterThanOrEqual(8);
  });

  it("every seeded attack is OWASP + ATLAS mapped with a checkable success condition", () => {
    const result = loadAttackCorpus(corpusDir);
    expect(result.isOk()).toBe(true);
    if (!result.isOk()) return;
    for (const attack of result.value) {
      expect(attack.owasp).toMatch(/^ASI\d\d$/);
      expect(attack.atlas).toMatch(/^AML\./);
      const hasCondition = attack.success.assert.length > 0 || attack.success.llmRubric !== undefined;
      expect(hasCondition, `attack ${attack.id} has no success condition`).toBe(true);
    }
  });

  it("covers the core attack classes and includes a Russian variant (FR-2.5)", () => {
    const result = loadAttackCorpus(corpusDir);
    if (!result.isOk()) throw new Error("corpus failed to load");
    const classes = new Set(result.value.map((a) => a.class));
    for (const required of ["prompt-injection", "indirect-injection", "data-exfil", "config-rce", "tool-poisoning"]) {
      expect(classes.has(required as Attack["class"]), `missing class ${required}`).toBe(true);
    }
    expect(result.value.some((a) => a.lang === "ru")).toBe(true);
  });

  it("substitutes {{vars}} in an attack input", () => {
    const parsed = AttackFile.parse({
      attacks: [
        {
          id: "t",
          class: "data-exfil",
          owasp: "ASI01",
          atlas: "AML.T0051",
          input: "leak {{secret}} now",
          vars: { secret: "TOKEN-XYZ" },
          success: { assert: [{ type: "text-contains", value: "x" }] },
        },
      ],
    });
    expect(renderAttackInput(parsed.attacks[0]!)).toBe("leak TOKEN-XYZ now");
  });

  it("rejects an unknown OWASP id (fail-closed validation)", () => {
    const parsed = AttackFile.safeParse({
      attacks: [
        { id: "x", class: "data-exfil", owasp: "ASI99", atlas: "AML.T0051", input: "hi", success: { assert: [{ type: "text-contains", value: "x" }] } },
      ],
    });
    expect(parsed.success).toBe(false);
  });

  it("rejects an attack with no success condition", () => {
    const parsed = AttackFile.safeParse({
      attacks: [{ id: "x", class: "data-exfil", owasp: "ASI01", atlas: "AML.T0051", input: "hi", success: {} }],
    });
    expect(parsed.success).toBe(false);
  });

  it("rejects a text-matches assertion whose regex does not compile (fail-closed at load)", () => {
    const parsed = AttackFile.safeParse({
      attacks: [
        {
          id: "x",
          class: "data-exfil",
          owasp: "ASI01",
          atlas: "AML.T0051",
          input: "hi",
          success: { assert: [{ type: "text-matches", pattern: "([unclosed" }] },
        },
      ],
    });
    expect(parsed.success).toBe(false);
  });
});

describe("corpus loader errors", () => {
  let dir: string;
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "aal-attacks-"));
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("returns a typed error for a malformed file", () => {
    writeFileSync(join(dir, "bad.yaml"), "attacks:\n  - id: nope\n"); // missing required fields
    const result = loadAttackCorpus(dir);
    expect(result.isErr()).toBe(true);
    if (result.isErr()) expect(result.error.kind).toBe("validation");
    rmSync(join(dir, "bad.yaml"));
  });

  it("rejects duplicate attack ids across files", () => {
    const one = 'attacks:\n  - { id: dup, class: data-exfil, owasp: ASI01, atlas: AML.T0051, input: "a", success: { assert: [{ type: text-contains, value: x }] } }\n';
    writeFileSync(join(dir, "a.yaml"), one);
    writeFileSync(join(dir, "b.yaml"), one);
    const result = loadAttackCorpus(dir);
    expect(result.isErr()).toBe(true);
    if (result.isErr()) expect(result.error.kind).toBe("duplicate");
    rmSync(join(dir, "a.yaml"));
    rmSync(join(dir, "b.yaml"));
  });

  it("returns an empty error for a directory with no attack files", () => {
    const result = loadAttackCorpus(dir);
    expect(result.isErr()).toBe(true);
    if (result.isErr()) expect(result.error.kind).toBe("empty");
  });
});
