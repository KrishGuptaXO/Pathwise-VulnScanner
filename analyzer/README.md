# Pathwise / Todoku

The Node analysis module implements **static source analysis and call-graph construction only**. The existing React starter is unchanged.

## Run

```sh
npm install
npm test
npm run build:analyzer
```

`npm run build` builds both the existing app and the analyzer. The analyzer is emitted to `dist/analyzer/` with TypeScript declarations and uses the TypeScript compiler API at runtime. Node 22.12+ is recommended by the existing Vite setup.

## Module contract

```ts
import { analyzeProject } from "./dist/analyzer/index.js";

const graph = await analyzeProject({
  repositoryPath: "/absolute/path/to/application",
  entryPoints: ["src/index.ts"],
  manifest: {
    packages: [
      {
        name: "example-package",
        version: "1.2.3",
        path: "node_modules/example-package",
        isDirect: true,
        resolved: "https://registry.npmjs.org/example-package/-/example-package-1.2.3.tgz",
        integrity: "sha512-...",
        dependents: ["root"],
        vulnerabilities: [
          {
            id: "EXAMPLE-ADVISORY",
            severity: "high",
            vulnerableFunction: null,
          },
        ],
      },
    ],
  },
  getPackageSource: async (name, version) => {
    // Delegate to the separate source-acquisition module.
    // Return the absolute extracted package root containing package.json.
    return sourceProvider.getPackageSource(name, version);
  },
});
```

`sourceProvider` in this example is supplied by the caller. No source-acquisition implementation is included. A synchronous resolver is accepted too. The analyzer does not parse lockfiles, query OSV, install target dependencies, execute target code, or fetch tarballs.

The full input/output types live in `analyzer/types.ts`. This accepts the agreed `{ packages: [...] }` manifest. The upstream resolver is responsible for the npm lockfile v2/v3 and no-workspaces restrictions.

- Each package identity defaults to `name@version:path`; an explicit unique `id` is also accepted. Physical package paths must be normalized repository-relative npm paths.
- `dependents` identifies parent instances using their `id`, physical path, or the agreed `name@version` labels. Prefer IDs/paths: ambiguous legacy labels conservatively include every matching parent in the source eligibility set. `root` denotes the application.
- All manifest metadata, including vulnerabilities, remains in `graph.packages`. No vulnerability-function matching or reachability verdict is performed here.
- Only vulnerable instances and their transitive ancestors are eligible for dependency source loading. Eligible source is requested when an import/require is encountered during traversal from the supplied entry files, including imports inside function bodies. There is no upfront fetch of the eligible set.
- Resolution follows the importing instance's nested npm paths and then hoisted ancestors. A shared `name@version` source fetch is cached for one analysis, while graph identities remain distinct for each physical instance. Persistent download/extraction caching belongs to the provider.

## Graph output

`nodes` contains module-initialization nodes and function nodes with stable logical file/offset IDs, package IDs, names, and 1-based source locations. `entryPointIds` identifies the supplied entry modules. `edges` contains `call`, `construct`, and `module-load` edges, each attributed to its containing module/function and call-site location.

`diagnostics` carries `undetermined`, `external` (Node built-ins), or `out-of-scope` (excluded packages) status with a code, message, location, and caller ID where available. Missing imports/source, syntax errors, computed require/import, eval, and unresolved calls are retained as diagnostics. Missing entry files and invalid/duplicate manifest identities reject the request.

## Supported analysis and limits

The analyzer parses JS, JSX, TS, TSX, MJS/CJS and MTS/CTS. It follows relative files, directory indexes, package `main`, and string-valued package exports. It supports ESM imports/reexports/aliases, local declarations, constant function aliases, direct functions/arrows/IIFEs, recursion, common literal CommonJS require/exports patterns, and declared constructor/member candidates. Lexical scope prevents parameter shadowing and same-named functions in different Node files from being conflated. Explicit type-only imports are skipped.

This is a **partial, syntactic candidate graph**, not a sound whole-program graph or evidence that a call executes. Calls inside all loaded function bodies are recorded without evaluating branches. A missing edge must never be interpreted as proof that vulnerable code is unreachable. Consumers must preserve diagnostics and scope exclusions when implementing the later reachability stage.

Runtime property mutation/overrides, callbacks, higher-order return values, accessors, decorators, class initialization timing, JSX/framework dispatch, tagged templates, and dynamic code are not fully modeled; diagnostics mark encountered limitations. Member edges are declared candidates and carry a dispatch diagnostic. Reassignable local aliases are unresolved. General data-flow/points-to analysis, bundler aliases, tsconfig path mappings, conditional/wildcard package exports, workspace resolution, and mixed browser-script global scopes are unsupported. Conditional/unexported package entries produce diagnostics instead of guessing a target. For app aliases, supply source using supported relative/package imports in this version.

Analysis operates only on the supplied entries and their imported source. It does not infer framework entry points. Source imports cannot escape the repository/package root through relative traversal or symlinks.

## Checks

```sh
npm test                 # Analyzer integration fixtures; no network or target installs
npm run lint
npm run build
npx oxfmt --check analyzer test tsconfig.analyzer.json package.json README.md
```

Reachability classification, risk scoring, reporting, CLI wiring, dependency resolution, and source acquisition are intentionally left for separate modules.
