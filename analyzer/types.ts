/** Input owned by dependency resolution and vulnerability matching. */
export interface PackageInstance {
  id?: string;
  name: string;
  version: string;
  path: string;
  isDirect: boolean;
  resolved?: string;
  integrity?: string;
  dependents: string[];
  vulnerabilities?: { id: string; severity: string; vulnerableFunction: string | null }[];
}

export interface Manifest {
  packages: PackageInstance[];
}

export interface AnalysisInput {
  repositoryPath: string;
  /** Repository-relative source files whose imports should be analyzed. */
  entryPoints: string[];
  manifest: Manifest;
  /** The analyzer never installs or downloads target dependencies itself. */
  getPackageSource: (name: string, version: string) => string | Promise<string>;
}

export interface Location {
  /** Repository-relative logical path, retaining nested node_modules locations. */
  file: string;
  line: number;
  column: number;
}

export interface GraphNode {
  id: string;
  name: string;
  kind: "module" | "function";
  location: Location;
  packageId: string | null;
}

export interface GraphEdge {
  from: string;
  to: string;
  kind: "call" | "construct" | "module-load";
  location: Location;
}

export interface AnalysisDiagnostic {
  status: "undetermined" | "external" | "out-of-scope";
  code: string;
  message: string;
  location: Location;
  callerId?: string;
}

export interface CallGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  entryPointIds: string[];
  diagnostics: AnalysisDiagnostic[];
  /** Original vulnerability metadata stays attached to exact package instances. */
  packages: (PackageInstance & { id: string })[];
}

export const packageId = (pkg: PackageInstance): string =>
  pkg.id ?? `${pkg.name}@${pkg.version}:${pkg.path}`;
