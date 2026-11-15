import type { CallGraph, GraphEdge, GraphNode } from "../../analyzer/types.js";
import type { DependencyGraph } from "../types/graph.js";
import type { VulnerablePackageInstance } from "../types/vulnerability.js";
import {
  reachabilityKey,
  undeterminedResult,
  type ReachabilityResult,
} from "../types/reachability.js";

/**
 * Turns the analyzer's candidate call graph into Reachable / Present-but-Unreachable /
 * Undetermined verdicts.
 *
 * The analyzer deliberately builds a PARTIAL graph ("a missing edge must never be interpreted as
 * proof that vulnerable code is unreachable"). So this classifier only says "unreachable" when
 * nothing the analyzer reported could be hiding a path. Everything it could not resolve is either
 * a BLOCKER (the verdict becomes "undetermined") or a CAVEAT (the verdict stands but is annotated).
 */

/** Diagnostics that could hide a way of loading a package -> a "no path" result is untrustworthy. */
const BLOCKING_CODES = new Set([
  "dynamic-import", // require(variable) / import(variable)
  "dynamic-eval", // eval / new Function
  "unresolved-module", // an import we could not resolve to a file
  "missing-package", // import of something not in the dependency manifest (aliases, workspaces)
  "source-unavailable", // a dependency's source could not be fetched
  "unsupported-exports", // conditional / wildcard package.json "exports" we cannot follow
  "invalid-package-json",
  "parse-error", // a file that failed to parse is a hole in the graph
]);

/** Diagnostics about calls/values we could not follow. They matter only for function-level verdicts. */
const DISPATCH_CODES = new Set([
  "member-dispatch",
  "unresolved-call",
  "callback-flow",
  "accessor-flow",
  "class-initializer-flow",
  "decorator-flow",
  "mutation-flow",
  "jsx-dispatch",
  "tagged-template",
  "dynamic-import-value",
]);

/** Relative imports of these files cannot contain code paths (CSS, images, data...). */
const NON_CODE_ASSET = /\.(css|scss|sass|less|svg|png|jpe?g|gif|webp|avif|ico|bmp|woff2?|ttf|otf|eot|mp[34]|webm|ogg|wav|json|md|txt|html)$/i;

/** True for "Cannot resolve ./logo.svg" - an unresolvable import that cannot hide code. */
function isHarmlessAssetImport(code: string, message: string): boolean {
  if (code !== "unresolved-module") return false;
  const match = /^Cannot resolve (\.\S*)$/.exec(message);
  return match !== null && NON_CODE_ASSET.test(match[1] ?? "");
}

interface Reached {
  distance: Map<string, number>;
  /** For path reconstruction: node id -> the node it was reached from. */
  parent: Map<string, string>;
}

function search(entryIds: string[], edges: GraphEdge[]): Reached {
  const outgoing = new Map<string, string[]>();
  for (const edge of edges) {
    const list = outgoing.get(edge.from);
    if (list) list.push(edge.to);
    else outgoing.set(edge.from, [edge.to]);
  }
  const distance = new Map<string, number>();
  const parent = new Map<string, string>();
  const queue: string[] = [];
  for (const id of entryIds) {
    distance.set(id, 0);
    queue.push(id);
  }
  for (let head = 0; head < queue.length; head++) {
    const current = queue[head] as string;
    const next = (distance.get(current) ?? 0) + 1;
    for (const target of outgoing.get(current) ?? []) {
      if (distance.has(target)) continue;
      distance.set(target, next);
      parent.set(target, current);
      queue.push(target);
    }
  }
  return { distance, parent };
}

function describeNode(node: GraphNode): string {
  const { file, line } = node.location;
  return node.kind === "module" ? `${file} (module)` : `${node.name}()  ${file}:${line}`;
}

function buildPath(targetId: string, reached: Reached, nodes: Map<string, GraphNode>): string[] {
  const ids: string[] = [];
  let cursor: string | undefined = targetId;
  while (cursor !== undefined) {
    ids.push(cursor);
    cursor = reached.parent.get(cursor);
  }
  return ids.reverse().map((id) => {
    const node = nodes.get(id);
    return node ? describeNode(node) : id;
  });
}

function summarizeBlockers(blockers: CallGraph["diagnostics"]): string {
  const byCode = new Map<string, number>();
  for (const d of blockers) byCode.set(d.code, (byCode.get(d.code) ?? 0) + 1);
  const counts = [...byCode].map(([code, n]) => `${code} x${n}`).join(", ");
  const samples = blockers
    .slice(0, 3)
    .map((d) => `${d.location.file}:${d.location.line} (${d.code})`)
    .join("; ");
  return `${counts}. e.g. ${samples}`;
}

export interface ClassifyInput {
  callGraph: CallGraph;
  graph: DependencyGraph;
  vulnerable: VulnerablePackageInstance[];
}

/** Returns one verdict per vulnerability on each vulnerable instance, keyed by reachabilityKey(). */
export function classifyReachability(input: ClassifyInput): Map<string, ReachabilityResult> {
  const { callGraph, graph, vulnerable } = input;
  const results = new Map<string, ReachabilityResult>();

  const nodesById = new Map(callGraph.nodes.map((n) => [n.id, n] as const));
  const reached = search(callGraph.entryPointIds, callGraph.edges);
  const analyzedInstances = new Set(callGraph.packages.map((p) => p.id));
  const instanceById = new Map(graph.packages.map((p) => [p.id, p] as const));

  const diagnostics = callGraph.diagnostics.filter((d) => d.status === "undetermined");
  const blockers = diagnostics.filter(
    (d) => BLOCKING_CODES.has(d.code) && !isHarmlessAssetImport(d.code, d.message),
  );
  const dispatchCount = diagnostics.filter((d) => DISPATCH_CODES.has(d.code)).length;

  for (const item of vulnerable) {
    const instance = instanceById.get(item.packageInstanceId);
    const modulesOfPackage = callGraph.nodes.filter(
      (n) => n.packageId === item.packageInstanceId && n.kind === "module",
    );
    const functionsOfPackage = callGraph.nodes.filter(
      (n) => n.packageId === item.packageInstanceId && n.kind === "function",
    );

    // Only finding-specific caveats live here; the general "static analysis is approximate"
    // limitation is stated once in the report footer.
    const caveats: string[] = [];
    if (instance?.kind === "devDependencies") {
      caveats.push(
        "devDependency: only the application's runtime import graph is analyzed; build-time and tooling use is not modelled.",
      );
    }

    for (const finding of item.findings) {
      const key = reachabilityKey(item.packageInstanceId, finding.id);

      if (!analyzedInstances.has(item.packageInstanceId)) {
        results.set(
          key,
          undeterminedResult(
            "This package instance was not part of the analyzed manifest (for example it sits outside a top-level node_modules path, as in monorepo/workspace layouts).",
          ),
        );
        continue;
      }

      const fn = finding.vulnerableFunction;
      const targetFunctions = fn ? functionsOfPackage.filter((n) => n.name === fn) : [];
      const functionLevel = fn !== null && targetFunctions.length > 0;
      const targets = functionLevel ? targetFunctions : modulesOfPackage;

      let best: GraphNode | undefined;
      for (const target of targets) {
        const d = reached.distance.get(target.id);
        if (d === undefined) continue;
        if (best === undefined || d < (reached.distance.get(best.id) ?? Infinity)) best = target;
      }

      // 1) A static path exists.
      if (best) {
        results.set(key, {
          status: "reachable",
          granularity: functionLevel ? "function" : "package",
          reason: functionLevel
            ? `A static call path leads from an application entry point to ${fn}(), the vulnerable function named by the advisory.`
            : fn
              ? `The package is loaded by the application, but the advisory's vulnerable function ${fn}() could not be matched in the call graph, so this is a package-level result. Treat as reachable.`
              : "The package's code is loaded by the application (static import path found). The advisory does not name a vulnerable function, so this is a package-level result. Treat as reachable.",
          callPath: buildPath(best.id, reached, nodesById),
          caveats,
        });
        continue;
      }

      // 2) Nothing found, but something the analyzer could not see may hide a path.
      if (blockers.length > 0) {
        results.set(
          key,
          undeterminedResult(
            `No static path was found, but the analysis has gaps that could hide one: ${summarizeBlockers(blockers)}.`,
            caveats,
          ),
        );
        continue;
      }

      // 3) Function named and its package is loaded, but the function is never reached.
      if (fn !== null && modulesOfPackage.some((m) => reached.distance.has(m.id))) {
        if (dispatchCount > 0) {
          results.set(
            key,
            undeterminedResult(
              `The package is loaded and no static call path reaches ${fn}(), but ${dispatchCount} call(s) could not be followed (dynamic dispatch/callbacks), so a call cannot be ruled out.`,
              caveats,
            ),
          );
        } else {
          results.set(key, {
            status: "unreachable",
            granularity: "function",
            reason: `The package is loaded, but no static call path reaches the vulnerable function ${fn}(), and no calls were left unresolved.`,
            callPath: [],
            caveats,
          });
        }
        continue;
      }

      // 4) The package is never imported, and every import was resolvable.
      results.set(key, {
        status: "unreachable",
        granularity: "package",
        reason:
          "No static import path leads from the application's entry points to this package, and every import in the analyzed code could be resolved.",
        callPath: [],
        caveats,
      });
    }
  }

  return results;
}
