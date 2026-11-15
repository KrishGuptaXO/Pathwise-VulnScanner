import assert from "node:assert/strict";
import test from "node:test";
import { matchVulnerabilities } from "../dist/pipeline/vuln/vulnerabilityMatcher.js";

const graphOf = (pkgs) => ({
  repository: { rootPath: "/x", name: "x", sourceInput: "/x", acquisitionMethod: "local", lockfileFormat: "npm-v3", resolvedAt: "" },
  packages: pkgs.map(([name, version]) => ({
    id: `node_modules/${name}`, name, version, path: `node_modules/${name}`, relation: "direct",
    kind: "dependencies", resolvedUrl: null, integrity: null, isDuplicateVersion: false,
  })),
  edges: [],
});
const jsonRes = (b, status = 200) => new Response(JSON.stringify(b), { status });

test("clean result when OSV reports nothing", async (t) => {
  t.mock.method(globalThis, "fetch", async () => jsonRes({ results: [{ vulns: [] }] }));
  const r = await matchVulnerabilities(graphOf([["left-pad", "1.3.0"]]));
  assert.equal(r.vulnerableInstances.length, 0);
  assert.equal(r.queryFailures.length, 0);
});

test("batch results map back to the right instance by position", async (t) => {
  t.mock.method(globalThis, "fetch", async (url) => {
    if (String(url).endsWith("/querybatch"))
      return jsonRes({ results: [{ vulns: [] }, { vulns: [{ id: "GHSA-1" }] }] });
    return jsonRes({
      id: "GHSA-1", summary: "bad", database_specific: { severity: "HIGH" },
      affected: [{ package: { name: "b", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }] }],
    });
  });
  const r = await matchVulnerabilities(graphOf([["a", "1.0.0"], ["b", "1.0.0"]]));
  assert.equal(r.vulnerableInstances.length, 1);
  assert.equal(r.vulnerableInstances[0].packageInstanceId, "node_modules/b");
  const f = r.vulnerableInstances[0].findings[0];
  assert.equal(f.severity, "high");
  assert.equal(f.vulnerableFunction, null, "never fabricated when OSV gives none");
});

test("OSV outage is reported as a query failure, not as 'no vulnerabilities'", async (t) => {
  t.mock.method(globalThis, "fetch", async () => jsonRes({ error: "down" }, 500));
  const r = await matchVulnerabilities(graphOf([["a", "1.0.0"]]));
  assert.equal(r.vulnerableInstances.length, 0);
  assert.ok(r.queryFailures.length > 0);
});
