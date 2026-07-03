import { describe, expect, it } from "vitest";
import { AAL_CORE_VERSION, type Verdict } from "../src/index";

describe("scaffold smoke", () => {
  it("exposes a version", () => {
    expect(AAL_CORE_VERSION).toBe("0.1.0");
  });

  it("defaults to fail-closed vocabulary", () => {
    // The unverified state must exist and be distinct from a pass.
    const v: Verdict = "not_verified";
    expect(v).not.toBe("pass");
  });
});
