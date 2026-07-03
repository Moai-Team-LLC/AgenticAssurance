/**
 * Capability Manifest loader (FR-1.2, FR-1.4).
 *
 * Loads a manifest from disk (JSON or YAML) and validates it against the zod schema.
 * Returns a typed `Result` — we never throw for control flow, and a malformed manifest is a
 * value the caller handles, not an exception (fail-closed: no manifest ⇒ no scan).
 */
import { readFileSync } from "node:fs";
import { extname } from "node:path";
import { err, ok, type Result } from "neverthrow";
import { parse as parseYaml } from "yaml";
import { CapabilityManifest } from "./schema";

/** A typed manifest-loading failure. `issues` carries zod's per-field detail when relevant. */
export type ManifestError =
  | { kind: "read"; path: string; message: string }
  | { kind: "parse"; path: string; message: string }
  | { kind: "validation"; path: string; message: string; issues: readonly ManifestIssue[] };

export interface ManifestIssue {
  path: string;
  message: string;
}

/** Parse + validate an already-in-memory manifest value (source-agnostic). */
export function parseManifest(
  raw: unknown,
  path = "<memory>",
): Result<CapabilityManifest, ManifestError> {
  const parsed = CapabilityManifest.safeParse(raw);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((issue) => ({
      path: issue.path.join("."),
      message: issue.message,
    }));
    return err({
      kind: "validation",
      path,
      message: `manifest failed validation (${issues.length} issue(s))`,
      issues,
    });
  }
  return ok(parsed.data);
}

/** Load, parse (JSON or YAML by extension), and validate a manifest file. */
export function loadManifest(path: string): Result<CapabilityManifest, ManifestError> {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (cause) {
    return err({ kind: "read", path, message: messageOf(cause) });
  }

  let data: unknown;
  try {
    data = extname(path).toLowerCase() === ".json" ? JSON.parse(text) : parseYaml(text);
  } catch (cause) {
    return err({ kind: "parse", path, message: messageOf(cause) });
  }

  return parseManifest(data, path);
}

function messageOf(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}
