import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { runPipeline } from "../dist/pipeline/run.js";
import { formatReportAsTable } from "../dist/pipeline/report.js";
import { installFakeOsv } from "./helpers/fake-osv.mjs";

const demo = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "demo-app");
const logs = [];
const opts = (extra = {}) => ({ repoInput: demo, log: (m) => logs.push(m), ...extra });

// Uses canned OSV data but REAL lockfile parsing, REAL tarball downloads from the npm registry
// and the REAL static analyzer. Needs registry access; skipped when it is unreachable.
async function registryReachable() {
  try { return (await fetch("https://registry.npmjs.org/ms", { method: "HEAD" })).ok; } catch { return false; }
}

test("e2e on demo-app: reachable direct, reachable transitive, two unreachable", async (t) => {
  if (!(await registryReachable())) return t.skip("npm registry not reachable");
  const restore = installFakeOsv();
  try {
    const report = await runPipeline(opts());
    const verdict = (name, version) =>
      report.rows.find((r) => r.packageName === name && r.packageVersion === version)?.reachability;
    assert.equal(verdict("lodash", "4.17.20"), "reachable");
    assert.equal(verdict("ms", "0.7.1"), "reachable");
    assert.equal(verdict("minimist", "1.2.0"), "unreachable");
    assert.equal(verdict("minimist", "0.0.8"), "unreachable");
    assert.deepEqual(report.counts, { reachable: 2, unreachable: 2, undetermined: 0 });
    const ms = report.rows.find((r) => r.packageName === "ms");
    assert.ok(ms.callPath.length >= 3, "transitive path goes through debug");
    assert.match(formatReportAsTable(report), /Limitations:/);
    assert.equal(report.rows[0].reachability, "reachable", "reachable findings sort first");
  } finally {
    restore();
  }
});

test("--skip-reachability reports everything as undetermined, honestly", async () => {
  const restore = installFakeOsv();
  try {
    const report = await runPipeline(opts({ skipReachability: true }));
    assert.equal(report.analysis.ran, false);
    assert.equal(report.counts.undetermined, report.totalFindings);
    assert.ok(report.totalFindings > 0);
  } finally {
    restore();
  }
});

test("analyzer crash degrades to undetermined instead of failing the run", async () => {
  const restore = installFakeOsv();
  try {
    const report = await runPipeline(opts(), { analyzeProject: async () => { throw new Error("boom"); } });
    assert.equal(report.counts.reachable + report.counts.unreachable, 0);
    assert.match(report.analysis.note, /boom/);
  } finally {
    restore();
  }
});
