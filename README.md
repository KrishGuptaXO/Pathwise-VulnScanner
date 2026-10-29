# Pathwise (CLI: `todoku`)

Reachability-based vulnerability prioritization for JavaScript/TypeScript projects.
`npm audit` tells you which dependencies have known CVEs; Pathwise also tells you whether your
application can actually reach the vulnerable code, so you know what to fix first.

Every finding gets one of three verdicts:

| Verdict | Meaning |
|---|---|
| **Reachable** | A static import/call path from an application entry point reaches the vulnerable package (or the named vulnerable function). Fix first. |
| **Present but unreachable** | Nothing the analyzer could follow leads there, **and** nothing it could not follow (dynamic `import()`, `eval`, unresolved modules, ...) could be hiding a path. |
| **Undetermined** | The analysis hit something it cannot see through, was skipped, or failed. Never silently treated as safe. |

## How it works

```
repo path/URL -> lockfile -> dependency graph -> OSV.dev matching -> static call graph -> verdicts -> report
                 pipeline/resolver   pipeline/vuln      analyzer/ (TypeScript Compiler API)   pipeline/reachability
```

- `pipeline/` - dependency resolution (lockfile v2/v3, physical-path identity), OSV.dev client and
  matcher, lazy tarball source acquisition, adapter to the analyzer, entry-point detection,
  reachability classifier, report. (Krish)
- `analyzer/` - static call-graph analyzer. See [`analyzer/README.md`](analyzer/README.md). (Rakshit)
- `cli/` - the `todoku` command.
- `src/` - the web UI scaffold (React/Vite), not wired to the pipeline yet.

## Usage

```bash
npm ci
npm run build:cli
node dist/cli/index.js analyze <path-or-github-url>
# options: -e/--entry <files...>  -o/--output table|json  --out-file <path>  --skip-reachability
```

Requires Node 20+, a `package-lock.json` (v2/v3) in the target repo, and network access to
`api.osv.dev` and the npm registry. Dependencies are never installed: only the tarballs of the
vulnerable packages and their ancestors are fetched, lazily.

### Offline-OSV demo

```bash
node --import ./test/helpers/fake-osv-preload.mjs dist/cli/index.js analyze test/fixtures/demo-app
```

Uses **canned** OSV responses (`test/helpers/fake-osv.mjs`); lockfile parsing, registry downloads and
analysis are real. Expected: lodash and (transitive) ms reachable; both minimist versions unreachable.

## Tests

`npm test` builds the CLI and runs all `node:test` suites (analyzer + pipeline). The end-to-end test
needs the npm registry and skips itself if unreachable. OSV is always mocked in tests.

## Honest limitations

- Static analysis is approximate; a missing edge is not proof of safety, which is why "unreachable"
  is only issued when the analyzer reported no blocking gaps.
- OSV rarely names a vulnerable function, so most verdicts are package-level.
- npm lockfile v2/v3 only; no yarn/pnpm. Entry points are detected (package.json, conventions) or given with `--entry`.
- Live `api.osv.dev` responses have not been verified end-to-end in development (blocked in the build sandbox).
