/**
 * Attack corpus loader (FR-2.3).
 *
 * Loads and validates every `.yaml`/`.yml` file in a corpus directory, flattens their attacks
 * into one list, and rejects duplicate ids. Fail-closed: a malformed or empty corpus is a typed
 * error the caller handles, never a partial silent pass.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { err, ok, type Result } from "neverthrow";
import { parse as parseYaml } from "yaml";
import { AttackFile, type Attack } from "./schema";

export type AttackError =
  | { kind: "read"; path: string; message: string }
  | { kind: "parse"; path: string; message: string }
  | { kind: "validation"; path: string; message: string; issues: readonly AttackIssue[] }
  | { kind: "empty"; path: string; message: string }
  | { kind: "duplicate"; path: string; message: string; ids: readonly string[] };

export interface AttackIssue {
  path: string;
  message: string;
}

/** Load + validate one corpus file's attacks. */
export function loadAttackFile(path: string): Result<Attack[], AttackError> {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (cause) {
    return err({ kind: "read", path, message: messageOf(cause) });
  }

  let data: unknown;
  try {
    data = parseYaml(text);
  } catch (cause) {
    return err({ kind: "parse", path, message: messageOf(cause) });
  }

  const parsed = AttackFile.safeParse(data);
  if (!parsed.success) {
    return err({
      kind: "validation",
      path,
      message: `attack file failed validation (${parsed.error.issues.length} issue(s))`,
      issues: parsed.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })),
    });
  }
  return ok(parsed.data.attacks);
}

/** Load every attack file in a directory, flatten, and enforce id uniqueness. */
export function loadAttackCorpus(dir: string): Result<Attack[], AttackError> {
  let files: string[];
  try {
    files = readdirSync(dir)
      .filter((f) => f.endsWith(".yaml") || f.endsWith(".yml"))
      .toSorted();
  } catch (cause) {
    return err({ kind: "read", path: dir, message: messageOf(cause) });
  }

  if (files.length === 0) {
    return err({ kind: "empty", path: dir, message: "no .yaml/.yml attack files found" });
  }

  const all: Attack[] = [];
  const seen = new Set<string>();
  const duplicates: string[] = [];
  for (const file of files) {
    const loaded = loadAttackFile(join(dir, file));
    if (loaded.isErr()) return err(loaded.error);
    for (const attack of loaded.value) {
      if (seen.has(attack.id)) duplicates.push(attack.id);
      seen.add(attack.id);
      all.push(attack);
    }
  }

  if (duplicates.length > 0) {
    return err({
      kind: "duplicate",
      path: dir,
      message: `duplicate attack id(s): ${duplicates.join(", ")}`,
      ids: duplicates,
    });
  }

  return ok(all);
}

function messageOf(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}
