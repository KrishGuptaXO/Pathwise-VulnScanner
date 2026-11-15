import type { PackageInstanceId } from "./graph.js";

/**
 * Reachability classification contract (output of the classifier, input of the report).
 *
 * - reachable:    a static path exists from an application entry point to the vulnerable
 *                 code. This means "exploitable in principle - fix first", NOT "being exploited".
 * - unreachable:  no static path exists AND nothing the analyzer could not see (dynamic
 *                 require/import, eval, unresolvable imports...) could be hiding one.
 * - undetermined: the analysis cannot answer reliably. The reason says why.
 */
export type ReachabilityStatus = "reachable" | "unreachable" | "undetermined";

/**
 * What the verdict is about.
 * - function: a specific vulnerable function named by the advisory was matched in the call graph.
 * - package:  the advisory names no function (the common case), so the verdict is about whether
 *             the package's code is loaded by the application at all.
 * - none:     no verdict could be made (undetermined).
 */
export type ReachabilityGranularity = "function" | "package" | "none";

export interface ReachabilityResult {
  status: ReachabilityStatus;
  granularity: ReachabilityGranularity;
  /** Human-readable evidence / explanation. Always present, especially for "undetermined". */
  reason: string;
  /** Steps from the entry point to the vulnerable code. Only filled when status is "reachable". */
  callPath: string[];
  /** Known limits of the verdict that do not change it but a reader should know about. */
  caveats: string[];
}

export interface ReachabilityFinding {
  packageInstanceId: PackageInstanceId;
  vulnerabilityId: string;
  reachability: ReachabilityResult;
}

/** Stable lookup key for one vulnerability on one package instance. */
export const reachabilityKey = (
  packageInstanceId: PackageInstanceId,
  vulnerabilityId: string,
): string => `${packageInstanceId}|${vulnerabilityId}`;

/** An honest "we could not tell" result - never used to fake a verdict. */
export function undeterminedResult(reason: string, caveats: string[] = []): ReachabilityResult {
  return { status: "undetermined", granularity: "none", reason, callPath: [], caveats };
}
