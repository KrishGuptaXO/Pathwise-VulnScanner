import fs from "node:fs";
import { analyzeProject } from "../analyzer/index.js";
import { buildAnalyzerManifest, createSourceProvider } from "./adapter.js";
import { detectEntryPoints } from "./entryPoints.js";
import { classifyReachability } from "./reachability/classifier.js";
import { buildReport, type AnalysisSummary, type Report } from "./report.js";
import { buildDependencyGraph } from "./resolver/graphBuilder.js";
import { acquireRepository } from "./resolver/repositoryAcquisition.js";
import { SourceAcquirer } from "./source/sourceAcquisition.js";
import { reachabilityKey, undeterminedResult, type ReachabilityResult } from "./types/reachability.js";
import type { VulnerabilityMatchResult } from "./types/vulnerability.js";
import { matchVulnerabilities } from "./vuln/vulnerabilityMatcher.js";

export interface PipelineOptions {
  /** Local directory path or GitHub URL. */
  repoInput: string;
  /** Repo-relative entry files; detected from package.json / conventions when omitted. */
  entryPoints?: string[];
  /** Report vulnerabilities without running the (slower) static analysis. */
  skipReachability?: boolean;
  /** Progress messages (the CLI sends these to stderr). */
  log?: (message: string) => void;
}

/** Collaborators, injectable so the whole pipeline can be tested without network access. */
export interface PipelineDeps {
  matchVulnerabilities?: typeof matchVulnerabilities;
  analyzeProject?: typeof analyzeProject;
  createAcquirer?: () => Pick<SourceAcquirer, "getPackageSource" | "cleanup">;
}

function markAllUndetermined(
  vulns: VulnerabilityMatchResult,
  reason: string,
  into: Map<string, ReachabilityResult>,
): void {
  for (const instance of vulns.vulnerableInstances) {
    for (const finding of instance.findings) {
      into.set(reachabilityKey(instance.packageInstanceId, finding.id), undeterminedResult(reason));
    }
  }
}

/**
 * Repository -> dependency graph -> vulnerability matching -> static analysis -> reachability
 * verdicts -> report. User-facing problems (bad path, missing lockfile, bad --entry) throw typed
 * errors for the CLI to print; analysis problems degrade to honest "undetermined" verdicts.
 */
export async function runPipeline(
  options: PipelineOptions,
  deps: PipelineDeps = {},
): Promise<Report> {
  const log = options.log ?? (() => {});
  const match = deps.matchVulnerabilities ?? matchVulnerabilities;
  const analyze = deps.analyzeProject ?? analyzeProject;
  const makeAcquirer = deps.createAcquirer ?? (() => new SourceAcquirer());

  log(`Acquiring repository: ${options.repoInput} ...`);
  const acquired = await acquireRepository(options.repoInput);

  try {
    log("Resolving dependency graph ...");
    const graph = buildDependencyGraph({
      repoRoot: acquired.localPath,
      sourceInput: options.repoInput,
      acquisitionMethod: acquired.acquisitionMethod,
    });
    log(`  ${graph.packages.length} package instance(s), ${graph.edges.length} edge(s).`);

    log("Querying OSV.dev for known vulnerabilities ...");
    const vulns = await match(graph);
    log(`  ${vulns.vulnerableInstances.length} vulnerable package instance(s).`);
    if (vulns.queryFailures.length > 0) {
      log(`  WARNING: ${vulns.queryFailures.length} package(s) could not be checked.`);
    }

    const verdicts = new Map<string, ReachabilityResult>();
    let analysis: AnalysisSummary = {
      ran: false,
      note: "",
      entryPoints: [],
      entrySource: "none",
      modulesAnalyzed: 0,
      diagnosticCount: 0,
    };

    if (vulns.vulnerableInstances.length === 0) {
      analysis.note = "skipped - no vulnerable packages, so there is nothing to analyze.";
    } else if (options.skipReachability) {
      analysis.note = "skipped (--skip-reachability); every finding is undetermined.";
      markAllUndetermined(vulns, "Reachability analysis was skipped by request.", verdicts);
    } else {
      // Throws EntryPointError for a bad explicit --entry (a user mistake worth surfacing).
      const detection = detectEntryPoints(acquired.localPath, options.entryPoints);
      analysis.entryPoints = detection.entries;
      analysis.entrySource = detection.source;

      if (detection.entries.length === 0) {
        analysis.note = detection.notes.join(" ");
        markAllUndetermined(vulns, `Reachability could not run: ${analysis.note}`, verdicts);
      } else {
        log(`Analyzing call graph from ${detection.entries.join(", ")} ...`);
        const { manifest } = buildAnalyzerManifest(graph, vulns);
        const acquirer = makeAcquirer();
        try {
          const callGraph = await analyze({
            repositoryPath: acquired.localPath,
            entryPoints: detection.entries,
            manifest,
            getPackageSource: createSourceProvider(graph, acquirer),
          });
          for (const [key, verdict] of classifyReachability({
            callGraph,
            graph,
            vulnerable: vulns.vulnerableInstances,
          })) {
            verdicts.set(key, verdict);
          }
          analysis = {
            ...analysis,
            ran: true,
            note: "ok",
            modulesAnalyzed: callGraph.nodes.filter((n) => n.kind === "module").length,
            diagnosticCount: callGraph.diagnostics.length,
          };
        } catch (error) {
          const reason = `Static analysis failed: ${(error as Error).message}`;
          analysis.note = reason;
          markAllUndetermined(vulns, reason, verdicts);
        } finally {
          acquirer.cleanup();
        }
      }
    }

    return buildReport(graph, vulns, verdicts, analysis);
  } finally {
    if (acquired.tempDirToCleanup) {
      fs.rmSync(acquired.tempDirToCleanup, { recursive: true, force: true });
    }
  }
}
