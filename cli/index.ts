#!/usr/bin/env node
import fs from "node:fs";
import { Command } from "commander";
import { EntryPointError } from "../pipeline/entryPoints.js";
import { formatReportAsJson, formatReportAsTable } from "../pipeline/report.js";
import { LockfileError } from "../pipeline/resolver/lockfileParser.js";
import { RepositoryAcquisitionError } from "../pipeline/resolver/repositoryAcquisition.js";
import { runPipeline } from "../pipeline/run.js";

const program = new Command();

program
  .name("todoku")
  .description("Pathwise (Todoku): reachability-based vulnerability prioritization for JS/TS projects")
  .version("0.1.0");

program
  .command("analyze")
  .description("Find known vulnerabilities in a repository and decide whether their code is reachable")
  .argument("<repo-path-or-url>", "Local directory path or GitHub repository URL")
  .option("-e, --entry <files...>", "Application entry file(s), relative to the repo (default: detected)")
  .option("-o, --output <format>", "Output format: table or json", "table")
  .option("--out-file <path>", "Write the report to a file instead of stdout")
  .option("--skip-reachability", "List vulnerabilities only; skip the static analysis")
  .action(
    async (
      repoInput: string,
      opts: { entry?: string[]; output: string; outFile?: string; skipReachability?: boolean },
    ) => {
      try {
        const report = await runPipeline(
          {
            repoInput,
            ...(opts.entry ? { entryPoints: opts.entry } : {}),
            ...(opts.skipReachability ? { skipReachability: true } : {}),
            log: (message) => console.error(message),
          },
        );
        const text =
          opts.output === "json" ? formatReportAsJson(report) : formatReportAsTable(report);
        if (opts.outFile) {
          fs.writeFileSync(opts.outFile, text, "utf-8");
          console.error(`Report written to ${opts.outFile}`);
        } else {
          console.log(text);
        }
      } catch (error) {
        if (
          error instanceof LockfileError ||
          error instanceof RepositoryAcquisitionError ||
          error instanceof EntryPointError
        ) {
          console.error(`\nError: ${error.message}`);
        } else {
          console.error(`\nUnexpected error: ${(error as Error).message}`);
          console.error((error as Error).stack);
        }
        process.exitCode = 1;
      }
    },
  );

await program.parseAsync(process.argv);
