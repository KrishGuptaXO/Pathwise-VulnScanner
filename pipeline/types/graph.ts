/**
 * DependencyGraph — the canonical, stable data contract produced by the
 * dependency-resolution module and consumed by the static-analysis /
 * reachability module (owned by a different team member).
 *
 * STABILITY NOTE:
 * This file defines a public contract between two independently developed
 * modules. If you change a shape here, you MUST document the change
 * (see rule #15 in project conventions) because the consumer depends on it.
 */

/**
 * A stable, unique identifier for one physical package instance on disk.
 *
 * A package instance is NOT identified by name alone — the same package
 * name can appear multiple times in a tree at different versions and at
 * different nesting paths (e.g. npm's non-deduped nested node_modules).
 *
 * We use the physical install path as the identity, since it is guaranteed
 * unique per instance and is exactly what static analysis needs to resolve
 * an `import`/`require` to a real file on disk.
 *
 * Example: "node_modules/axios/node_modules/follow-redirects"
 */
export type PackageInstanceId = string;

/**
 * Where this package instance sits relative to the root project.
 * - "direct": explicitly declared in the root package.json
 *   (dependencies OR devDependencies — see DependencyKind)
 * - "transitive": pulled in indirectly via another package
 */
export type DependencyRelation = "direct" | "transitive";

/**
 * Which declaration block a *direct* dependency came from in the root
 * package.json. Only meaningful when relation === "direct".
 * Undetermined/not applicable for transitive packages.
 */
export type DependencyKind =
  | "dependencies"
  | "devDependencies"
  | "peerDependencies"
  | "optionalDependencies"
  | "transitive"; // used when relation === "transitive"

export interface PackageInstance {
  /** Stable unique ID — see PackageInstanceId doc above. Use this to
   *  reference this exact instance anywhere else in the graph. */
  id: PackageInstanceId;

  /** Package name as it appears in the npm registry, e.g. "axios" */
  name: string;

  /** Exact resolved semver version, e.g. "0.21.1" (never a range) */
  version: string;

  /** Physical path relative to repository root,
   *  e.g. "node_modules/axios/node_modules/follow-redirects" */
  path: string;

  relation: DependencyRelation;
  kind: DependencyKind;

  /** The exact tarball URL from package-lock.json's `resolved` field.
   *  This is what the source-acquisition module fetches from.
   *  Null if the lockfile entry had no resolved URL (e.g. a git/local
   *  dependency — rare, but must not crash the resolver). */
  resolvedUrl: string | null;

  /** Subresource integrity hash from the lockfile, if present.
   *  Used to verify tarball downloads match what was actually installed. */
  integrity: string | null;

  /** True if this exact {name, version} pair appears more than once in
   *  the graph at different physical paths (non-deduped tree). Useful
   *  for the report to explain "why do I see lodash twice?" */
  isDuplicateVersion: boolean;
}

/**
 * A directed edge: `from` package depends on `to` package.
 * Reverse/consumer relationships (`to` is depended on by `from`) are
 * intentionally NOT stored redundantly — derive them from edges if needed.
 */
export interface DependencyEdge {
  from: PackageInstanceId;
  to: PackageInstanceId;
}

export interface RepositoryMetadata {
  /** Absolute or repo-relative path analysis was run against */
  rootPath: string;

  /** Name from the root package.json, if present */
  name: string | null;

  /** Original input as given by the user: a local path or a GitHub URL */
  sourceInput: string;

  /** How the repo was acquired */
  acquisitionMethod: "local" | "github-clone";

  /** Package manager lockfile format detected */
  lockfileFormat: "npm-v2" | "npm-v3";

  /** ISO 8601 timestamp of when resolution was performed */
  resolvedAt: string;
}

/**
 * The full, canonical output of the dependency-resolution module.
 * This is the object handed to vulnerability matching, source acquisition,
 * and ultimately the static-analysis / reachability engine.
 */
export interface DependencyGraph {
  repository: RepositoryMetadata;
  packages: PackageInstance[];
  edges: DependencyEdge[];
}

/** Convenience helper type: a lookup map from id -> instance.
 *  Build this once with buildPackageIndex() rather than linear-scanning
 *  `packages` repeatedly. */
export type PackageIndex = Map<PackageInstanceId, PackageInstance>;
