import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { buildAnalyzerManifest } from "../dist/pipeline/adapter.js";
import { EntryPointError, detectEntryPoints } from "../dist/pipeline/entryPoints.js";

const pkg = (id, name, relation = "direct") => ({ id, name, version: "1.0.0", path: id, relation, kind: "dependencies", resolvedUrl: `https://r/${name}.tgz`, integrity: "sha512-x", isDuplicateVersion: false });
const graph = {
  repository: {},
  packages: [pkg("node_modules/a", "a"), pkg("node_modules/a/node_modules/b", "b", "transitive")],
  edges: [
    { from: "", to: "node_modules/a" },
    { from: "node_modules/a", to: "node_modules/a/node_modules/b" },
  ],
};
const vulns = {
  vulnerableInstances: [{ packageInstanceId: "node_modules/a/node_modules/b", packageName: "b", packageVersion: "1.0.0", findings: [{ id: "V", severity: "high", vulnerableFunction: null }] }],
  queryFailures: [],
};

test("manifest keeps physical-path ids and maps root edges to 'root'", () => {
  const { manifest, excluded } = buildAnalyzerManifest(graph, vulns);
  assert.deepEqual(excluded, []);
  const ids = manifest.packages.map((p) => p.id);
  assert.deepEqual(ids.sort(), ["node_modules/a", "node_modules/a/node_modules/b"]);
  const a = manifest.packages.find((p) => p.id === "node_modules/a");
  assert.deepEqual(a.dependents, ["root"]);
  const b = manifest.packages.find((p) => p.id.endsWith("/b"));
  assert.deepEqual(b.dependents, ["node_modules/a"]);
  assert.equal(b.vulnerabilities[0].vulnerableFunction, null);
});

function repo(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pw-entry-"));
  for (const [f, c] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
    fs.writeFileSync(path.join(dir, f), c);
  }
  return dir;
}

test("entry detection: package.json main", () => {
  const dir = repo({ "package.json": '{"main":"lib/app.js"}', "lib/app.js": "" });
  const r = detectEntryPoints(dir);
  assert.deepEqual(r.entries, ["lib/app.js"]);
  assert.equal(r.source, "package.json");
});

test("entry detection: built main maps back to src/", () => {
  const dir = repo({ "package.json": '{"main":"dist/index.js"}', "src/index.ts": "" });
  assert.deepEqual(detectEntryPoints(dir).entries, ["src/index.ts"]);
});

test("entry detection: convention fallback, then none", () => {
  assert.equal(detectEntryPoints(repo({ "package.json": "{}", "server.js": "" })).source, "convention");
  const none = detectEntryPoints(repo({ "package.json": "{}" }));
  assert.equal(none.source, "none");
  assert.deepEqual(none.entries, []);
});

test("explicit --entry that does not exist is a user error", () => {
  const dir = repo({ "package.json": "{}" });
  assert.throws(() => detectEntryPoints(dir, ["nope.js"]), EntryPointError);
});
