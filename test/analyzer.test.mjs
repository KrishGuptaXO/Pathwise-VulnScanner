import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { analyzeProject } from "../dist/analyzer/index.js";

async function fixture(t, files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "todoku-analysis-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  for (const [name, text] of Object.entries(files)) {
    await fs.mkdir(path.dirname(path.join(root, name)), { recursive: true });
    await fs.writeFile(path.join(root, name), text);
  }
  return root;
}
function calls(graph) {
  const names = new Map(graph.nodes.map((node) => [node.id, node.name]));
  return graph.edges
    .filter((edge) => edge.kind === "call")
    .map((edge) => [names.get(edge.from), names.get(edge.to)]);
}
const pkg = (name, version, physicalPath, dependents, vulnerable = false) => ({
  name,
  version,
  path: physicalPath,
  isDirect: dependents.includes("root"),
  dependents,
  vulnerabilities: vulnerable
    ? [{ id: "TEST-1", severity: "high", vulnerableFunction: "danger" }]
    : [],
});

test("ESM aliases, reexports, recursion, lexical shadowing, IIFEs, and source locations", async (t) => {
  const root = await fixture(t, {
    "main.ts": `import { renamed as invoke } from './barrel.js';
function start() { invoke(); const local = () => invoke(); local(); }
function other(invoke: () => void) { invoke(); }
start(); (() => start())();`,
    "barrel.ts": `export { danger as renamed } from './danger.js';`,
    "danger.ts": `export function danger() { danger(); }`,
  });
  const graph = await analyzeProject({
    repositoryPath: root,
    entryPoints: ["main.ts"],
    manifest: { packages: [] },
    getPackageSource() {
      throw new Error("must not fetch");
    },
  });
  assert.ok(calls(graph).some(([from, to]) => from === "start" && to === "danger"));
  assert.ok(calls(graph).some(([from, to]) => from === "danger" && to === "danger"));
  assert.ok(calls(graph).some(([from, to]) => from === "start" && to === "local"));
  assert.ok(!calls(graph).some(([from]) => from === "other"));
  assert.ok(graph.diagnostics.some((d) => d.code === "unresolved-call" && d.location.line === 3));
  assert.equal(graph.entryPointIds[0], "main.ts#module");
  assert.ok(graph.edges.every((edge) => edge.location.line > 0 && edge.location.column > 0));
  assert.equal(graph.edges.filter((edge) => edge.kind === "module-load").length, 2);
});

test("lazy ancestor loading, exact nested versions, and no fetch for unrelated packages", async (t) => {
  const root = await fixture(t, {
    "main.js": `import { wrap } from 'wrapper'; import { danger } from 'vulnerable'; import 'unrelated'; wrap(); danger();`,
    "sources/wrapper/package.json": `{"main":"index.js"}`,
    "sources/wrapper/index.js": `import { danger } from 'vulnerable'; export function wrap() { danger(); }`,
    "sources/v1/index.js": `export function danger() {}`,
    "sources/v2/index.js": `export function danger() {}`,
  });
  const packages = [
    pkg("wrapper", "1", "node_modules/wrapper", ["root"]),
    pkg("vulnerable", "1", "node_modules/wrapper/node_modules/vulnerable", ["wrapper@1"], true),
    pkg("vulnerable", "2", "node_modules/vulnerable", ["root"], true),
    pkg("unrelated", "1", "node_modules/unrelated", ["root"]),
  ];
  const requests = [];
  const graph = await analyzeProject({
    repositoryPath: root,
    entryPoints: ["main.js"],
    manifest: { packages },
    getPackageSource(name, version) {
      requests.push(`${name}@${version}`);
      return path.join(root, "sources", name === "wrapper" ? "wrapper" : `v${version}`);
    },
  });
  assert.deepEqual(requests.sort(), ["vulnerable@1", "vulnerable@2", "wrapper@1"]);
  const dangerous = graph.nodes.filter((node) => node.name === "danger");
  assert.equal(dangerous.length, 2);
  assert.notEqual(dangerous[0].packageId, dangerous[1].packageId);
  const wrapper = graph.nodes.find((node) => node.name === "wrap");
  const target = graph.nodes.find(
    (node) =>
      node.id === graph.edges.find((edge) => edge.from === wrapper.id && edge.kind === "call").to,
  );
  assert.equal(target.packageId, "vulnerable@1:node_modules/wrapper/node_modules/vulnerable");
  assert.ok(graph.diagnostics.some((d) => d.code === "excluded-package"));
  assert.deepEqual(graph.packages[1].vulnerabilities, packages[1].vulnerabilities);
});

test("CommonJS default, destructured, namespace, and local calls", async (t) => {
  const root = await fixture(t, {
    "main.cjs": `const run = require('./default.cjs'); const ns = require('./named.cjs'); const { danger: alias } = require('./named.cjs'); run(); ns.danger(); alias();`,
    "default.cjs": `function run() {} module.exports = run;`,
    "named.cjs": `function danger() {} module.exports = { danger };`,
  });
  const graph = await analyzeProject({
    repositoryPath: root,
    entryPoints: ["main.cjs"],
    manifest: { packages: [] },
    getPackageSource() {
      throw new Error("must not fetch");
    },
  });
  assert.equal(calls(graph).filter(([, to]) => to === "danger").length, 2);
  assert.equal(calls(graph).filter(([, to]) => to === "run").length, 1);
});

test("cycles terminate and repeated physical instances share source fetch, not graph identities", async (t) => {
  const root = await fixture(t, {
    "main.js": `import 'a'; import 'b';`,
    "sources/a/index.js": `import { danger } from 'v'; danger();`,
    "sources/b/index.js": `import { danger } from 'v'; danger();`,
    "sources/v/index.js": `import './cycle.js'; export function danger() {}`,
    "sources/v/cycle.js": `import './index.js';`,
  });
  const packages = [
    pkg("a", "1", "node_modules/a", ["root"]),
    pkg("b", "1", "node_modules/b", ["root"]),
    pkg("v", "1", "node_modules/a/node_modules/v", ["a@1"], true),
    pkg("v", "1", "node_modules/b/node_modules/v", ["b@1"], true),
  ];
  const requests = [];
  const graph = await analyzeProject({
    repositoryPath: root,
    entryPoints: ["main.js"],
    manifest: { packages },
    getPackageSource(name) {
      requests.push(name);
      return path.join(root, "sources", name);
    },
  });
  assert.deepEqual(requests.sort(), ["a", "b", "v"]);
  assert.equal(graph.nodes.filter((node) => node.name === "danger").length, 2);
});

test("dynamic code, callbacks, mutable aliases, JSX and missing files remain undetermined", async (t) => {
  const root = await fixture(t, {
    "main.tsx": `import './missing'; function f() {} let alias = f; alias(); require(name); eval(code); import(name); setTimeout(f, 0); const view = <Widget />;`,
  });
  const graph = await analyzeProject({
    repositoryPath: root,
    entryPoints: ["main.tsx"],
    manifest: { packages: [] },
    getPackageSource() {
      throw new Error("must not fetch");
    },
  });
  const codes = new Set(graph.diagnostics.map((d) => d.code));
  for (const code of [
    "dynamic-import",
    "dynamic-eval",
    "callback-flow",
    "unresolved-call",
    "unresolved-module",
    "jsx-dispatch",
  ])
    assert.ok(codes.has(code), code);
  assert.equal(calls(graph).length, 0);
});

test("source-provider failures are diagnostics and malformed source does not disappear", async (t) => {
  const root = await fixture(t, { "main.js": `import 'v'; function broken( {` });
  const graph = await analyzeProject({
    repositoryPath: root,
    entryPoints: ["main.js"],
    manifest: { packages: [pkg("v", "1", "node_modules/v", ["root"], true)] },
    getPackageSource() {
      throw new Error("offline");
    },
  });
  assert.ok(graph.diagnostics.some((d) => d.code === "source-unavailable"));
  assert.ok(graph.diagnostics.some((d) => d.code === "parse-error"));
});

test("package exports and source boundary are respected", async (t) => {
  const root = await fixture(t, {
    "main.js": `import 'v'; import 'v/private';`,
    "sources/v/package.json": `{"exports": {".": "./lib/start.js"}}`,
    "sources/v/lib/start.js": `import '../../outside.js'; export function danger() {}`,
    "sources/outside.js": `function outside() {}`,
  });
  const graph = await analyzeProject({
    repositoryPath: root,
    entryPoints: ["main.js"],
    manifest: { packages: [pkg("v", "1", "node_modules/v", ["root"], true)] },
    getPackageSource() {
      return path.join(root, "sources/v");
    },
  });
  assert.ok(graph.nodes.some((n) => n.name === "danger"));
  assert.ok(!graph.nodes.some((n) => n.name === "outside"));
  assert.ok(graph.diagnostics.some((d) => d.code === "unsupported-exports"));
  assert.ok(graph.diagnostics.some((d) => d.code === "unresolved-module"));
});

test("entry traversal and duplicate manifest instances are rejected", async (t) => {
  const root = await fixture(t, { "main.js": "" });
  const base = {
    repositoryPath: root,
    entryPoints: ["../outside.js"],
    manifest: { packages: [] },
    getPackageSource() {},
  };
  await assert.rejects(analyzeProject(base), /outside the repository/);
  const instance = pkg("v", "1", "node_modules/v", ["root"]);
  await assert.rejects(
    analyzeProject({
      ...base,
      entryPoints: ["main.js"],
      manifest: { packages: [instance, instance] },
    }),
    /Duplicate package/,
  );
});

test("shadowed require is a local call and does not acquire package source", async (t) => {
  const root = await fixture(t, { "main.js": `function require(name) {} require('v');` });
  const requests = [];
  const graph = await analyzeProject({
    repositoryPath: root,
    entryPoints: ["main.js"],
    manifest: { packages: [pkg("v", "1", "node_modules/v", ["root"], true)] },
    getPackageSource(name) {
      requests.push(name);
      throw new Error("must not fetch");
    },
  });
  assert.deepEqual(requests, []);
  assert.ok(calls(graph).some(([, to]) => to === "require"));
});

test("Node modules cannot accidentally share same-named local functions", async (t) => {
  const root = await fixture(t, {
    "main.js": `require('./a.js'); require('./b.js');`,
    "a.js": `function local() {} local();`,
    "b.js": `function local() {} local();`,
  });
  const graph = await analyzeProject({
    repositoryPath: root,
    entryPoints: ["main.js"],
    manifest: { packages: [] },
    getPackageSource() {
      throw new Error("must not fetch");
    },
  });
  const localCalls = graph.edges.filter((edge) => edge.kind === "call");
  assert.equal(localCalls.length, 2);
  for (const edge of localCalls) assert.equal(edge.from.split("#")[0], edge.to.split("#")[0]);
});

test("constructors and method candidates are recorded with dispatch limitations", async (t) => {
  const root = await fixture(t, {
    "main.ts": `function sink() {} class Worker { constructor() { sink(); } run() { sink(); } } const worker = new Worker(); worker.run();`,
  });
  const graph = await analyzeProject({
    repositoryPath: root,
    entryPoints: ["main.ts"],
    manifest: { packages: [] },
    getPackageSource() {
      throw new Error("must not fetch");
    },
  });
  assert.equal(graph.edges.filter((edge) => edge.kind === "construct").length, 1);
  assert.ok(calls(graph).some(([from, to]) => from === "<module>" && to === "run"));
  assert.ok(graph.diagnostics.some((d) => d.code === "member-dispatch"));
});
