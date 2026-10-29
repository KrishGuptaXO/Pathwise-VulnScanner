import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { buildDependencyGraph } from "../dist/pipeline/resolver/graphBuilder.js";
import { LockfileError } from "../dist/pipeline/resolver/lockfileParser.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const build = (name) => {
  const root = path.join(here, "fixtures", name);
  return buildDependencyGraph({ repoRoot: root, sourceInput: root, acquisitionMethod: "local" });
};

test("sample-repo-1: direct, dev and transitive packages are classified", () => {
  const g = build("sample-repo-1");
  assert.equal(g.repository.lockfileFormat, "npm-v3");
  const axios = g.packages.find((p) => p.name === "axios");
  assert.equal(axios.relation, "direct");
  assert.equal(axios.kind, "dependencies");
  assert.equal(g.packages.find((p) => p.name === "typescript").kind, "devDependencies");
  const fr = g.packages.find((p) => p.name === "follow-redirects");
  assert.equal(fr.relation, "transitive");
  assert.ok(g.edges.some((e) => e.from === axios.id && e.to === fr.id));
});

test("sample-repo-2: a package installed twice stays separate physical instances", () => {
  const g = build("sample-repo-2");
  const ids = g.packages.map((p) => p.id);
  assert.equal(new Set(ids).size, ids.length);
  const byName = Map.groupBy(g.packages, (p) => p.name);
  assert.ok([...byName.values()].some((list) => list.length > 1), "fixture has a name installed twice");
});

test("demo-app: nested minimist@0.0.8 is a distinct instance reached only through mkdirp", () => {
  const g = build("demo-app");
  const nested = g.packages.find((p) => p.id === "node_modules/mkdirp/node_modules/minimist");
  assert.equal(nested.version, "0.0.8");
  assert.equal(nested.relation, "transitive");
  const parents = g.edges.filter((e) => e.to === nested.id).map((e) => e.from);
  assert.deepEqual(parents, ["node_modules/mkdirp"]);
});

test("a repo without a lockfile fails with a LockfileError", () => {
  assert.throws(() => build("."), LockfileError);
});
