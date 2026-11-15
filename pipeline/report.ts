import type { DependencyGraph } from "./types/graph.js";
import type { VulnerabilityMatchResult } from "./types/vulnerability.js";
import {
  reachabilityKey,
  undeterminedResult,
  type ReachabilityGranularity,
  type ReachabilityResult,
  type ReachabilityStatus,
} from "./types/reachability.js";

export const GENERAL_LIMITATION =
  "Static analysis is approximate: it follows literal imports and direct calls, and cannot see " +
  "config/framework-driven loading. 'Reachable' means exploitable in principle (fix first), not " +
  "that an attacker can supply the input. 'Present but Unreachable' is only reported when nothing " +
  "the analyzer could not follow could be hiding a path.";

export interface ReportRow {
  packageName: string;
  packageVersion: string;
  packageInstanceId: string;
  relation: "direct" | "transitive";
  dependencyKind: string;
  vulnerabilityId: string;
  aliases: string[];
  severity: string;
  summary: string;
  vulnerableFunction: string | null;
  reachability: ReachabilityStatus;
  granularity: ReachabilityGranularity;
  evidence: string;
  callPath: string[];
  caveats: string[];
}

export interface AnalysisSummary {
  /** Did the static analyzer actually run? */
  ran: boolean;
  /** Why it did not run / what happened. */
  note: string;
  entryPoints: string[];
  entrySource: string;
  modulesAnalyzed: number;
  diagnosticCount: number;
}

export interface Report {
  generatedAt: string;
  repositoryName: string | null;
  totalPackagesScanned: number;
  totalVulnerablePackages: number;
  totalFindings: number;
  queryFailureCount: number;
  counts: Record<ReachabilityStatus, number>;
  analysis: AnalysisSummary;
  rows: ReportRow[];
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
const STATUS_ORDER: Record<ReachabilityStatus, number> = { reachable: 0, undetermined: 1, unreachable: 2 };

/**
 * Joins graph + vulnerability matches + reachability verdicts into a flat, report-friendly shape.
 * A finding with no verdict is reported "undetermined" - never silently dropped or assumed safe.
 */
export function buildReport(
  graph: DependencyGraph,
  vulns: VulnerabilityMatchResult,
  reachability: Map<string, ReachabilityResult>,
  analysis: AnalysisSummary,
): Report {
  const pkgIndex = new Map(graph.packages.map((p) => [p.id, p] as const));
  const rows: ReportRow[] = [];

  for (const instance of vulns.vulnerableInstances) {
    const pkg = pkgIndex.get(instance.packageInstanceId);
    if (!pkg) continue;
    for (const finding of instance.findings) {
      const verdict =
        reachability.get(reachabilityKey(pkg.id, finding.id)) ??
        undeterminedResult("No reachability verdict was produced for this finding.");
      rows.push({
        packageName: pkg.name,
        packageVersion: pkg.version,
        packageInstanceId: pkg.id,
        relation: pkg.relation,
        dependencyKind: pkg.kind,
        vulnerabilityId: finding.id,
        aliases: finding.aliases,
        severity: finding.severity,
        summary: finding.summary,
        vulnerableFunction: finding.vulnerableFunction,
        reachability: verdict.status,
        granularity: verdict.granularity,
        evidence: verdict.reason,
        callPath: verdict.callPath,
        caveats: verdict.caveats,
      });
    }
  }

  rows.sort(
    (a, b) =>
      STATUS_ORDER[a.reachability] - STATUS_ORDER[b.reachability] ||
      (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5) ||
      (a.relation === b.relation ? 0 : a.relation === "direct" ? -1 : 1),
  );

  const counts: Record<ReachabilityStatus, number> = { reachable: 0, unreachable: 0, undetermined: 0 };
  for (const row of rows) counts[row.reachability]++;

  return {
    generatedAt: new Date().toISOString(),
    repositoryName: graph.repository.name,
    totalPackagesScanned: graph.packages.length,
    totalVulnerablePackages: vulns.vulnerableInstances.length,
    totalFindings: rows.length,
    queryFailureCount: vulns.queryFailures.length,
    counts,
    analysis,
    rows,
  };
}

const VERDICT_LABEL: Record<ReachabilityStatus, string> = {
  reachable: "REACHABLE - fix first",
  unreachable: "PRESENT BUT UNREACHABLE",
  undetermined: "UNDETERMINED",
};

/** Renders the report for a terminal. */
export function formatReportAsTable(report: Report): string {
  const out: string[] = [];
  out.push("");
  out.push("Pathwise (Todoku) - Vulnerability Reachability Report");
  out.push(`Repository: ${report.repositoryName ?? "(unnamed)"}`);
  out.push(`Generated:  ${report.generatedAt}`);
  out.push(
    `Scanned ${report.totalPackagesScanned} package instance(s); ` +
      `${report.totalVulnerablePackages} vulnerable, ${report.totalFindings} finding(s).`,
  );
  if (report.queryFailureCount > 0) {
    out.push(
      `WARNING: ${report.queryFailureCount} package(s) could not be fully checked against OSV.dev ` +
        `(network/API errors) - results for those are incomplete.`,
    );
  }
  out.push("");

  if (report.analysis.ran) {
    out.push(
      `Entry points: ${report.analysis.entryPoints.join(", ")} (${report.analysis.entrySource}); ` +
        `${report.analysis.modulesAnalyzed} module(s) analyzed.`,
    );
  } else {
    out.push(`Reachability analysis: ${report.analysis.note}`);
  }

  if (report.rows.length === 0) {
    out.push("");
    out.push("No known vulnerabilities found in resolved dependencies.");
  } else {
    const c = report.counts;
    out.push(
      `Verdicts: ${c.reachable} reachable (fix first), ${c.unreachable} present but unreachable, ` +
        `${c.undetermined} undetermined.`,
    );
    out.push("");
    for (const row of report.rows) {
      out.push(
        `[${row.severity.toUpperCase()}] ${row.packageName}@${row.packageVersion} ` +
          `(${row.relation}${row.dependencyKind === "devDependencies" ? ", dev" : ""}) - ${row.vulnerabilityId}`,
      );
      out.push(
        `  Verdict:  ${VERDICT_LABEL[row.reachability]}` +
          (row.granularity !== "none" ? ` (${row.granularity}-level)` : ""),
      );
      out.push(`  Advisory: ${row.summary}`);
      out.push(`  Evidence: ${row.evidence}`);
      if (row.callPath.length > 0) {
        out.push("  Path:");
        row.callPath.forEach((step, i) => out.push(`    ${i === 0 ? "  " : "-> "}${step}`));
      }
      for (const caveat of row.caveats) out.push(`  Note:     ${caveat}`);
      out.push("");
    }
  }

  out.push(`Limitations: ${GENERAL_LIMITATION}`);
  return out.join("\n");
}

export function formatReportAsJson(report: Report): string {
  return JSON.stringify(report, null, 2);
}
