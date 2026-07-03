# Contributing

## Ground rules
- **Conventional Commits** (enforced by commitlint + a husky `commit-msg` hook and CI).
  Header <= 72 chars.
- Run `bun run check` before pushing (format + lint + tsc + tests). CI runs the same gate.
- Strict TypeScript, functional style, `neverthrow` `Result` types, `zod` on all boundaries.
- **No AgenticMind imports** — AAL Core is framework-neutral.
- **No secrets/PII/real payloads** in code, tests, or fixtures. Hash, don't store.
- Every new failure mode becomes a permanent test; every CLI command gets an output snapshot test.

## Adding an attack
Attacks are data (YAML) under `attacks/`. Each entry maps to an OWASP ASI id and a MITRE ATLAS
technique, and declares a machine-checkable success condition. Extend the corpus without
touching engine code.

## Formatting
Formatting aligns to the AgenticMind `oxlint-config` when this package is folded into the
monorepo. Until then, keep diffs clean and let `oxlint` catch correctness issues.
