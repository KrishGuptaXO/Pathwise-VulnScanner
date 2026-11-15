# DEVELOPMENT SUMMARY - merge of Krish's pipeline and Rakshit's analyzer

1. **Goal**: one repo where `todoku analyze <repo>` goes lockfile -> OSV -> static call graph -> reachability verdicts -> report.

2. **Base**: official `Pathwise-VulnScanner` repo; `analyzer/` kept unchanged.

3. **Ported (CommonJS -> ESM/NodeNext)** into `pipeline/`: resolver, OSV client/matcher, lazy source acquisition.

4. **New glue**: `adapter.ts` (DependencyGraph -> analyzer manifest, physical-path ids kept), `entryPoints.ts`, `reachability/classifier.ts`, `report.ts`, `run.ts`, `cli/index.ts`.

5. **Contract**: DependencyGraph unchanged. New `ReachabilityResult` (status, granularity, reason, callPath, caveats).

6. **Honesty rules**: "unreachable" only when no blocking diagnostics (dynamic import/eval, unresolved module, missing source, parse error...); skipped/failed analysis => undetermined; vulnerableFunction never invented.

7. **Tests**: node:test, 33 passing (11 analyzer + 22 pipeline incl. e2e on `test/fixtures/demo-app`). Vitest dropped.

8. **Tooling**: oxlint clean, `tsc` clean, `npm run build` (tsc -b, vite, CLI) succeeds.

9. **Demo**: `node --import ./test/helpers/fake-osv-preload.mjs dist/cli/index.js analyze test/fixtures/demo-app` -> 2 reachable (lodash direct, ms transitive via debug), 2 unreachable (minimist 1.2.0 never imported; minimist 0.0.8 only used by mkdirp's bin/cmd.js).

10. **Dependencies**: added `tar`; removed none beyond vitest/undici from Krish's version.

11. **Known gaps**: live api.osv.dev not verified (sandbox blocked; tests/demo use canned data); npm lockfile v2/v3 only; mostly package-level verdicts; classifier detects asset imports by parsing the analyzer's message text (a structured `specifier` field in diagnostics would be better - for Rakshit); `src/` web UI not wired up.

12. **Next**: run on 2-3 real open-source repos with live OSV; Rakshit review of adapter + classifier; evaluation numbers vs `npm audit` for the report.

13. **Where things are**: `README.md` (usage), `analyzer/README.md` (analyzer contract), `pipeline/`, `cli/`, `test/`.

## SHOWCASE STATUS
- **Working end-to-end**: CLI on a local repo with lockfile (OSV mocked in tests/demo).
- **Partially working**: live OSV path (code complete, unverified from sandbox); GitHub URL acquisition.
- **Not implemented**: yarn/pnpm lockfiles, web UI integration, function-level data from OSV.
- **Demo-ready**: yes, via the offline-OSV demo; run live OSV on your own network before presenting.