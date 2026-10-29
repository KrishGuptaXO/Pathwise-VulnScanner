import type { Manifest, PackageInstance as AnalyzerPackage } from "../analyzer/types.js";
import type { SourceAcquirer } from "./source/sourceAcquisition.js";
import type { DependencyGraph, PackageInstance } from "./types/graph.js";
import type { VulnerabilityMatchResult } from "./types/vulnerability.js";

/**
 * Translates the pipeline's DependencyGraph + vulnerability matches into the analyzer's Manifest.
 *
 *   pipeline                         analyzer
 *   --------                         --------
 *   id (physical path)          ->   id            (explicit, so identities match end to end)
 *   relation === "direct"       ->   isDirect
 *   resolvedUrl / integrity     ->   resolved / integrity
 *   edges (from -> to)          ->   dependents[]  ("" = the application = "root")
 *   VulnerabilityMatchResult    ->   vulnerabilities[] inline on each instance
 */

/** The analyzer only accepts top-level `node_modules/...` paths (workspaces/monorepos are out of scope). */
const isAnalyzablePath = (p: string): boolean =>
  p.startsWith("node_modules/") && !p.includes("\\") && !p.includes("/../");

export interface ManifestBuild {
  manifest: Manifest;
  /** Instance ids left out because the analyzer cannot represent them. */
  excluded: string[];
}

export function buildAnalyzerManifest(
  graph: DependencyGraph,
  vulns: VulnerabilityMatchResult,
): ManifestBuild {
  const dependents = new Map<string, string[]>();
  for (const edge of graph.edges) {
    const parent = edge.from === "" ? "root" : edge.from;
    const list = dependents.get(edge.to);
    if (list) {
      if (!list.includes(parent)) list.push(parent);
    } else {
      dependents.set(edge.to, [parent]);
    }
  }

  const vulnsByInstance = new Map(vulns.vulnerableInstances.map((v) => [v.packageInstanceId, v]));
  const packages: AnalyzerPackage[] = [];
  const excluded: string[] = [];

  for (const pkg of graph.packages) {
    if (!isAnalyzablePath(pkg.path)) {
      excluded.push(pkg.id);
      continue;
    }
    const entry: AnalyzerPackage = {
      id: pkg.id,
      name: pkg.name,
      version: pkg.version,
      path: pkg.path,
      isDirect: pkg.relation === "direct",
      dependents: dependents.get(pkg.id) ?? [],
    };
    if (pkg.resolvedUrl) entry.resolved = pkg.resolvedUrl;
    if (pkg.integrity) entry.integrity = pkg.integrity;
    const found = vulnsByInstance.get(pkg.id);
    if (found) {
      entry.vulnerabilities = found.findings.map((f) => ({
        id: f.id,
        severity: f.severity,
        vulnerableFunction: f.vulnerableFunction,
      }));
    }
    packages.push(entry);
  }

  return { manifest: { packages }, excluded };
}

/**
 * Adapts SourceAcquirer.getPackageSource(instance) to the analyzer's
 * getPackageSource(name, version). The analyzer shares one fetch per name@version, so any instance
 * with that name and version yields the same tarball.
 */
export function createSourceProvider(
  graph: DependencyGraph,
  acquirer: Pick<SourceAcquirer, "getPackageSource">,
): (name: string, version: string) => Promise<string> {
  const byNameVersion = new Map<string, PackageInstance>();
  for (const pkg of graph.packages) {
    const key = `${pkg.name}@${pkg.version}`;
    const existing = byNameVersion.get(key);
    // Prefer an instance that has a lockfile tarball URL.
    if (!existing || (!existing.resolvedUrl && pkg.resolvedUrl)) byNameVersion.set(key, pkg);
  }
  return async (name, version) => {
    const pkg = byNameVersion.get(`${name}@${version}`);
    if (!pkg) throw new Error(`${name}@${version} is not in the dependency graph`);
    return acquirer.getPackageSource(pkg);
  };
}
