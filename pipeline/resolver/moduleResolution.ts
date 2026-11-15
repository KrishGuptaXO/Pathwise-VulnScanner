import { RawLockfile } from "./lockfileParser.js";

/**
 * Replicates Node.js's module resolution algorithm for the purpose of
 * turning a lockfile's declared dependency *ranges* (e.g. "follow-redirects
 * depends on debug: ^4.0.0") into a resolved *physical instance* (an exact
 * key in the lockfile's `packages` map).
 *
 * WHY THIS IS NECESSARY:
 * The lockfile's `packages` map is flat — keyed by physical path — but each
 * entry's own `dependencies` field just lists name -> semver range, the
 * same way package.json does. It does NOT tell you which physical instance
 * that range resolved to. npm/Node resolve that at require()-time by
 * walking up the directory tree: check node_modules nested under the
 * current package first, then the parent directory's node_modules, and so
 * on up to the repo root. This module replicates exactly that walk so we
 * can build real dependency edges between physical instances.
 *
 * Example:
 *   fromPath = "node_modules/axios"
 *   dependencyName = "follow-redirects"
 *   Checks in order:
 *     1. node_modules/axios/node_modules/follow-redirects
 *     2. node_modules/follow-redirects
 *   Returns the first one that exists in the lockfile's packages map.
 */
export function resolveDependencyPath(
  fromPath: string,
  dependencyName: string,
  lockfile: RawLockfile
): string | null {
  // Build the chain of node_modules directories to check, innermost first.
  // fromPath looks like "node_modules/a/node_modules/b" or "node_modules/a".
  const segments = fromPath.split("/").filter((s) => s.length > 0);

  // Find every prefix of `segments` that itself is a valid package path
  // ending point — we walk by progressively trimming trailing path
  // components and checking for a node_modules/<dependencyName> entry.
  const candidatePrefixes: string[] = [];
  for (let i = segments.length; i >= 0; i--) {
    candidatePrefixes.push(segments.slice(0, i).join("/"));
  }

  for (const prefix of candidatePrefixes) {
    const candidate = prefix.length > 0
      ? `${prefix}/node_modules/${dependencyName}`
      : `node_modules/${dependencyName}`;

    if (lockfile.packages[candidate]) {
      return candidate;
    }
  }

  // Not found anywhere up the chain — this can legitimately happen for
  // optional peerDependencies that were never installed, or dependencies
  // the lockfile omitted for other valid reasons. Caller should treat
  // this as "could not resolve", not throw.
  return null;
}
