import assert from "node:assert/strict";
import test from "node:test";
import { classifyReachability } from "../dist/pipeline/reachability/classifier.js";
import { reachabilityKey } from "../dist/pipeline/types/reachability.js";

const PKG = "node_modules/vuln";
const graph = {
  repository: { name: "t" },
  packages: [{ id: PKG, name: "vuln", version: "1.0.0", relation: "direct", kind: "dependencies" }],
  edges: [],
};
const finding = (fn = null) => ({ id: "V-1", aliases: [], summary: "", severity: "high", cvssScore: null, vulnerableFunction: fn, affectedRange: "" });
const vulnerable = (fn) => [{ packageInstanceId: PKG, packageName: "vuln", packageVersion: "1.0.0", findings: [finding(fn)] }];
const loc = { file: "f.js", line: 1, column: 1 };
const mod = (id, pkg) => ({ id, kind: "module", name: id, packageId: pkg, location: loc });
const fnNode = (id, name, pkg) => ({ id, kind: "function", name, packageId: pkg, location: loc });

function cg({ nodes, edges = [], diagnostics = [], packages = [{ id: PKG }] }) {
  return { nodes, edges, entryPointIds: ["app"], diagnostics, packages };
}
const base = [mod("app", "root"), mod("vmod", PKG)];
const verdict = (callGraph, fn) =>
  classifyReachability({ callGraph, graph, vulnerable: vulnerable(fn) }).get(reachabilityKey(PKG, "V-1"));

test("path to the package's module => reachable (package-level)", () => {
  const v = verdict(cg({ nodes: base, edges: [{ from: "app", to: "vmod" }] }), null);
  assert.equal(v.status, "reachable");
  assert.equal(v.granularity, "package");
  assert.ok(v.callPath.length >= 2);
});

test("no path and a clean analysis => unreachable", () => {
  assert.equal(verdict(cg({ nodes: base }), null).status, "unreachable");
});

test("no path but a blocking diagnostic => undetermined, never unreachable", () => {
  const diagnostics = [{ status: "undetermined", code: "dynamic-import", message: "dynamic import", nodeId: "app", location: loc }];
  assert.equal(verdict(cg({ nodes: base, diagnostics }), null).status, "undetermined");
});

test("asset imports that cannot resolve (css) do not block an unreachable verdict", () => {
  const diagnostics = [{ status: "undetermined", code: "unresolved-module", message: "Cannot resolve ./style.css", nodeId: "app", location: loc }];
  assert.equal(verdict(cg({ nodes: base, diagnostics }), null).status, "unreachable");
});

test("function-level: reaching the named function => reachable (function)", () => {
  const nodes = [...base, fnNode("f", "template", PKG)];
  const v = verdict(cg({ nodes, edges: [{ from: "app", to: "vmod" }, { from: "app", to: "f" }] }), "template");
  assert.equal(v.status, "reachable");
  assert.equal(v.granularity, "function");
});

test("function-level: package loaded, function not reached, dispatch gaps => undetermined", () => {
  const nodes = [...base, fnNode("f", "template", PKG)];
  const diagnostics = [{ status: "undetermined", code: "member-dispatch", message: "x", nodeId: "app", location: loc }];
  const v = verdict(cg({ nodes, edges: [{ from: "app", to: "vmod" }], diagnostics }), "template");
  assert.equal(v.status, "undetermined");
});

test("package never loaded by the analyzer and nothing blocks => unreachable, but a missing analysis never invents reachability", () => {
  const v = verdict(cg({ nodes: [mod("app", "root")], packages: [] }), null);
  assert.notEqual(v.status, "reachable");
});
