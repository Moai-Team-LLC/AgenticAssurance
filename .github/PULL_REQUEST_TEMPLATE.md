<!-- Thanks for contributing to agent-assurance! -->

## What & why

<!-- What does this change do, and why? Link any issue: Closes #123 -->

## Type

- [ ] `feat` — new capability
- [ ] `fix` — bug fix
- [ ] `docs` / `test` / `refactor` / `chore`

## Checklist

- [ ] `bun run check` is green (lint + tsc + tests).
- [ ] Every new failure mode or detection has a **fixture-backed test**.
- [ ] No raw secrets, PII, or weaponized attack payloads added to code, tests, or
      the corpus (payloads are synthetic / reserved-domain; findings hash inputs).
- [ ] The core adds **no AgenticMind dependency** (`grep -rn agenticmind src/` empty).
- [ ] Commits follow [Conventional Commits](https://www.conventionalcommits.org/).
- [ ] SARIF output still validates against 2.1.0 (if reporting changed).
