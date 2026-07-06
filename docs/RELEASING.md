# Releasing `agent-assurance`

This project publishes to npm as **`agent-assurance`** and cuts a GitHub Release on every
`v*` tag, driven by [`.github/workflows/release.yml`](../.github/workflows/release.yml).

## One-time setup

0. **Commit a lockfile** (required — CI and release run `bun install --frozen-lockfile`):
   ```bash
   bun install          # generates bun.lock from package.json
   git add bun.lock && git commit -m "build: add bun lockfile"
   ```
   Without a committed `bun.lock`, the frozen install in CI/release fails.
1. **Create the GitHub repo** (public) and push:
   ```bash
   gh repo create Moai-Team-LLC/AgenticAssurance --public --source . --remote origin --push
   ```
2. **npm access:** the publishing account must be able to publish `agent-assurance`
   (unscoped, public). Create an **automation** npm token and add it to the repo:
   ```bash
   gh secret set NPM_TOKEN --body "<npm-automation-token>"
   ```
   Provenance (`--provenance`) is emitted by the workflow via GitHub OIDC — no extra secret.
3. Confirm branch protection + required CI on `main` (optional but recommended).

## Cut a release

The version is the single source of truth in `package.json`. **Run every command from the repo
root** (`cd` into it first) — not from your home directory.

### First release (0.1.0)

`package.json` is already at `0.1.0`, so do **not** run `npm version` — just tag it:

```bash
git checkout main
git tag v0.1.0
git push origin v0.1.0        # triggers release.yml → publishes to npm
```

### Subsequent releases

```bash
# 1. bump version (choose one) — follows SemVer; Conventional Commits guide the bump
npm version patch   # or: minor | major  (this also creates the git tag)

# 2. update CHANGELOG.md (move Unreleased → the new version + date)

# 3. push the commit and the tag
git push origin main --follow-tags
```

The tag push triggers `release.yml`, which runs `bun run check`, builds, then
`npm publish --provenance --access public` and creates a GitHub Release with generated notes.

## Verify a release

```bash
npm view agent-assurance version          # the published version
npx agent-assurance@latest --version      # runs the published CLI
npx agent-assurance@latest scan <manifest> --sarif out.sarif
```

## Manual publish (fallback, if the workflow is unavailable)

```bash
bun install
bun run check          # must be green
bun run build          # produces dist/cli.js
npm publish --access public   # runs prepublishOnly (build) again; requires npm login
```

## What ships

`npm pack --dry-run` shows the exact tarball. It includes `dist/` (the bundled CLI),
`src/` (library source, minus tests), `attacks/` (the default corpus the CLI resolves at
runtime), `policy-pack/`, and the docs an auditor reads. It excludes tests, fixtures, CI
config, and dev tooling (see [`.npmignore`](../.npmignore)). Re-run the dry-run before any
manual publish and confirm **no secrets, `.env`, or `node_modules`** are listed.
