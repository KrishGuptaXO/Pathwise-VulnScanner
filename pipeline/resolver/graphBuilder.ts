import {
  RawLockfilePackageEntry,
  readLockfile,
  readRootPackageJson,
} from "./lockfileParser.js";
import { resolveDependencyPath } from "./moduleResolution.js";
import {
  DependencyEdge,
  DependencyGraph,
  DependencyKind,
  PackageInstance,
  PackageInstanceId,
  RepositoryMetadata,
} from "../types/graph.js";

export interface BuildGraphOptions {
  /** Absolute or relative path to the repository root */
  repoRoot: string;
  /** The original input string the user gave (path or URL) — stored for
   *  report context, distinct from the resolved local filesystem root. */
  sourceInput: string;
  acquisitionMethod: "local" | "github-clone";
}

/**
 * The root project itself is not a real installable package instance —
 * it's keyed by "" in the lockfile. We never emit it as a PackageInstance;
 * its declared dependencies become the seed for determining which
 * node_modules/* entries are "direct".
 */
const ROOT_KEY = "";

/**
 * Builds the canonical DependencyGraph from a repository's package.json +
 * package-lock.json.
 *
 * This is the single entry point for Phase 1 (Dependency Resolution).
 * Throws LockfileError (from lockfileParser) if validation fails.
 */
export function buildDependencyGraph(options: BuildGraphOptions): DependencyGraph {
  const lockfile = readLockfile(options.repoRoot);
  const rootPkg = readRootPackageJson(options.repoRoot);

  const rootEntry = lockfile.packages[ROOT_KEY];
  if (!rootEntry) {
    throw new Error(
      'package-lock.json is missing the root entry (packages[""]). ' +
        "This lockfile may be corrupted or from an unsupported npm version."
    );
  }

  // Determine direct dependency names -> which declaration block they came from.
  const directDependencyKind = new Map<string, DependencyKind>();
  for (const name of Object.keys(rootPkg.dependencies)) {
    directDependencyKind.set(name, "dependencies");
  }
  for (const name of Object.keys(rootPkg.devDependencies)) {
    // dependencies block takes precedence if somehow listed in both
    if (!directDependencyKind.has(name)) directDependencyKind.set(name, "devDependencies");
  }
  for (const name of Object.keys(rootPkg.peerDependencies)) {
    if (!directDependencyKind.has(name)) directDependencyKind.set(name, "peerDependencies");
  }
  for (const name of Object.keys(rootPkg.optionalDependencies)) {
    if (!directDependencyKind.has(name)) directDependencyKind.set(name, "optionalDependencies");
  }

  // Pass 1: build a PackageInstance for every non-root entry in the lockfile.
  const packages: PackageInstance[] = [];
  const pathToEntry = new Map<string, RawLockfilePackageEntry>();

  for (const [pkgPath, entry] of Object.entries(lockfile.packages)) {
    if (pkgPath === ROOT_KEY) continue;
    // Skip "link" entries (symlinked local packages, e.g. workspaces) —
    // explicitly out of scope for v1 (monorepo/workspace support).
    if (entry.link) continue;
    if (!entry.version) continue; // malformed/unexpected entry, skip defensively

    pathToEntry.set(pkgPath, entry);

    const name = packageNameFromPath(pkgPath);
    // Top-level means exactly one "node_modules" segment in the path,
    // i.e. not nested inside another package's node_modules.
    const segments = pkgPath.split("/");
    const isTopLevel =
      segments[0] === "node_modules" &&
      segments.filter((s) => s === "node_modules").length === 1;

    const relation = isTopLevel && directDependencyKind.has(name) ? "direct" : "transitive";
    const kind: DependencyKind = relation === "direct"
      ? (directDependencyKind.get(name) as DependencyKind)
      : "transitive";

    packages.push({
      id: pkgPath,
      name,
      version: entry.version,
      path: pkgPath,
      relation,
      kind,
      resolvedUrl: entry.resolved ?? null,
      integrity: entry.integrity ?? null,
      isDuplicateVersion: false, // computed in pass 3
    });
  }

  // Pass 2: build edges by resolving each entry's declared dependency
  // ranges to physical instances via Node resolution semantics.
  const edges: DependencyEdge[] = [];

  const resolveAndEmit = (
    fromPath: string,
    depNames: string[] | undefined
  ): void => {
    if (!depNames) return;
    for (const depName of depNames) {
      const resolvedPath = resolveDependencyPath(fromPath, depName, lockfile);
      if (resolvedPath) {
        edges.push({ from: fromPath, to: resolvedPath });
      }
      // If null: dependency couldn't be resolved (e.g. unmet optional/peer
      // dependency never installed). This is expected in real-world repos
      // and is silently omitted from edges rather than treated as an error.
    }
  };

  // Root project's own direct dependencies become edges from a virtual
  // "root" node — we use the empty string ROOT_KEY as the synthetic
  // from-id, matching DependencyEdge's PackageInstanceId type (string).
  resolveAndEmit(ROOT_KEY, Object.keys(rootPkg.dependencies));
  resolveAndEmit(ROOT_KEY, Object.keys(rootPkg.devDependencies));

  for (const [pkgPath, entry] of pathToEntry.entries()) {
    resolveAndEmit(pkgPath, entry.dependencies ? Object.keys(entry.dependencies) : undefined);
  }

  // Pass 3: mark duplicate versions — same name+version appearing at
  // more than one physical path.
  const nameVersionCounts = new Map<string, number>();
  for (const pkg of packages) {
    const key = `${pkg.name}@${pkg.version}`;
    nameVersionCounts.set(key, (nameVersionCounts.get(key) ?? 0) + 1);
  }
  for (const pkg of packages) {
    const key = `${pkg.name}@${pkg.version}`;
    pkg.isDuplicateVersion = (nameVersionCounts.get(key) ?? 0) > 1;
  }

  const repository: RepositoryMetadata = {
    rootPath: options.repoRoot,
    name: rootPkg.name ?? lockfile.name,
    sourceInput: options.sourceInput,
    acquisitionMethod: options.acquisitionMethod,
    lockfileFormat: lockfile.lockfileVersion === 3 ? "npm-v3" : "npm-v2",
    resolvedAt: new Date().toISOString(),
  };

  return { repository, packages, edges };
}

/**
 * Extracts a package name from its lockfile path key.
 * "node_modules/axios" -> "axios"
 * "node_modules/axios/node_modules/follow-redirects" -> "follow-redirects"
 * "node_modules/@babel/core" -> "@babel/core" (scoped packages keep their scope,
 *   since the scope and package name are two separate path segments)
 */
function packageNameFromPath(pkgPath: string): string {
  const segments = pkgPath.split("/");
  const lastNodeModulesIndex = segments.lastIndexOf("node_modules");
  return segments.slice(lastNodeModulesIndex + 1).join("/");
}

/** Builds an id -> instance lookup map from a graph's package list. */
export function buildPackageIndex(graph: DependencyGraph): Map<PackageInstanceId, PackageInstance> {
  const index = new Map<PackageInstanceId, PackageInstance>();
  for (const pkg of graph.packages) {
    index.set(pkg.id, pkg);
  }
  return index;
}
