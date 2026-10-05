import fs from "node:fs";
import path from "node:path";
import { builtinModules } from "node:module";
import ts from "typescript";
import { packageId } from "./types.js";
import type { AnalysisInput, AnalysisDiagnostic, Location, PackageInstance } from "./types.js";

export const slash = (value: string): string => value.split(path.sep).join("/");
export const inside = (root: string, file: string): boolean => {
  const relative = path.relative(root, file);
  return (
    relative === "" ||
    (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative))
  );
};
const extensions = [".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs"];
const builtins = new Set(builtinModules.map((name) => name.replace(/^node:/, "")));

export interface LoadedModule {
  file: string;
  source: ts.SourceFile;
  pkg?: PackageInstance;
  imports: Map<string, string>;
}

export function location(root: string, node: ts.Node): Location {
  const source = node.getSourceFile();
  const position = source.getLineAndCharacterOfPosition(node.getStart(source));
  return {
    file: slash(path.relative(root, source.fileName)),
    line: position.line + 1,
    column: position.character + 1,
  };
}

/** Resolve physical npm instances by walking the importing instance's ancestor directories. */
export function resolvePackage(
  packages: PackageInstance[],
  importer: string,
  name: string,
): PackageInstance | undefined {
  let directory = path.posix.dirname(importer);
  while (true) {
    if (path.posix.basename(directory) !== "node_modules") {
      const candidate = path.posix.normalize(path.posix.join(directory, "node_modules", name));
      const found = packages.find((pkg) => pkg.path === candidate);
      if (found) return found;
    }
    const parent = path.posix.dirname(directory);
    if (parent === directory) return undefined;
    directory = parent;
  }
}

function relevantPackages(packages: PackageInstance[]): Set<string> {
  const selected = new Set(packages.filter((pkg) => pkg.vulnerabilities?.length).map(packageId));
  let changed = true;
  while (changed) {
    changed = false;
    for (const child of packages) {
      if (!selected.has(packageId(child))) continue;
      for (const parent of packages) {
        if (selected.has(packageId(parent))) continue;
        const identifiers = [packageId(parent), parent.path, `${parent.name}@${parent.version}`];
        // Legacy name@version labels can be ambiguous: include every matching ancestor.
        if (child.dependents.some((dependent) => identifiers.includes(dependent))) {
          selected.add(packageId(parent));
          changed = true;
        }
      }
    }
  }
  return selected;
}

export async function loadModules(input: AnalysisInput): Promise<{
  root: string;
  modules: Map<string, LoadedModule>;
  entries: string[];
  diagnostics: AnalysisDiagnostic[];
}> {
  const root = fs.realpathSync(input.repositoryPath);
  const modules = new Map<string, LoadedModule>();
  const diagnostics: AnalysisDiagnostic[] = [];
  const selected = relevantPackages(input.manifest.packages);
  const sourceCache = new Map<string, string | Error>();
  const entries: string[] = [];
  const paths = new Set<string>();
  const ids = new Set<string>();
  for (const pkg of input.manifest.packages) {
    if (
      !pkg.path.startsWith("node_modules/") ||
      path.posix.normalize(pkg.path) !== pkg.path ||
      pkg.path.includes("\\") ||
      pkg.path.includes("/../")
    ) {
      throw new Error(`Invalid package instance path: ${pkg.path}`);
    }
    if (paths.has(pkg.path) || ids.has(packageId(pkg)))
      throw new Error(`Duplicate package instance: ${pkg.path}`);
    paths.add(pkg.path);
    ids.add(packageId(pkg));
  }

  function diagnostic(
    code: string,
    message: string,
    node: ts.Node,
    status: AnalysisDiagnostic["status"] = "undetermined",
  ) {
    diagnostics.push({ code, message, location: location(root, node), status });
  }

  function read(file: string, boundary: string): string | undefined {
    if (!inside(boundary, file)) return undefined;
    try {
      if (!inside(boundary, fs.realpathSync(file)) || !fs.statSync(file).isFile()) return undefined;
      return fs.readFileSync(file, "utf8");
    } catch {
      return undefined;
    }
  }

  function resolveFile(
    candidate: string,
    boundary: string,
    seen = new Set<string>(),
  ): string | undefined {
    if (!inside(boundary, candidate) || seen.has(candidate)) return undefined;
    seen.add(candidate);
    const alternatives = [candidate];
    if (/\.[cm]?jsx?$/.test(candidate))
      alternatives.push(
        candidate.replace(/\.[cm]?jsx?$/, ".ts"),
        candidate.replace(/\.jsx?$/, ".tsx"),
      );
    alternatives.push(...extensions.map((extension) => candidate + extension));
    for (const file of alternatives) {
      if (extensions.includes(path.extname(file)) && read(file, boundary) !== undefined)
        return file;
    }
    const metadata = read(path.join(candidate, "package.json"), boundary);
    if (metadata) {
      try {
        const json = JSON.parse(metadata);
        if (typeof json.main === "string") {
          const found = resolveFile(path.resolve(candidate, json.main), boundary, seen);
          if (found) return found;
        }
      } catch {
        /* Invalid metadata is handled as an unresolved module by the caller. */
      }
    }
    for (const extension of extensions) {
      const file = path.join(candidate, "index" + extension);
      if (read(file, boundary) !== undefined) return file;
    }
    return undefined;
  }

  async function visit(
    file: string,
    actual: string,
    boundary: string,
    pkg?: PackageInstance,
  ): Promise<void> {
    if (modules.has(file)) return;
    const text = read(actual, boundary);
    if (text === undefined) return;
    // Use the compiler host so moduleDetection isolates Node files without ESM syntax.
    const parseOptions: ts.CompilerOptions = {
      allowJs: true,
      noLib: true,
      types: [],
      moduleDetection: ts.ModuleDetectionKind.Force,
      target: ts.ScriptTarget.Latest,
    };
    const parseHost = ts.createCompilerHost(parseOptions, true);
    parseHost.readFile = (candidate) => (candidate === file ? text : undefined);
    parseHost.fileExists = (candidate) => candidate === file;
    const scopeProgram = ts.createProgram([file], parseOptions, parseHost);
    const source = scopeProgram.getSourceFile(file)!;
    const scopeChecker = scopeProgram.getTypeChecker();
    const shadowedRequires = new Set<number>();
    function findShadowed(node: ts.Node) {
      if (
        ts.isIdentifier(node) &&
        node.text === "require" &&
        scopeChecker.getSymbolAtLocation(node)?.declarations?.length
      )
        shadowedRequires.add(node.getStart());
      ts.forEachChild(node, findShadowed);
    }
    findShadowed(source);
    const loaded: LoadedModule = { file, source, pkg, imports: new Map() };
    modules.set(file, loaded);
    const requests: { specifier: string; node: ts.Node }[] = [];
    function scan(node: ts.Node) {
      if (
        (ts.isImportDeclaration(node) && !node.importClause?.isTypeOnly) ||
        (ts.isExportDeclaration(node) && !node.isTypeOnly)
      ) {
        if (node.moduleSpecifier && ts.isStringLiteralLike(node.moduleSpecifier))
          requests.push({ specifier: node.moduleSpecifier.text, node });
      }
      if (
        ts.isImportEqualsDeclaration(node) &&
        !node.isTypeOnly &&
        ts.isExternalModuleReference(node.moduleReference)
      ) {
        const expression = node.moduleReference.expression;
        if (expression && ts.isStringLiteralLike(expression))
          requests.push({ specifier: expression.text, node });
      }
      if (
        ts.isCallExpression(node) &&
        (node.expression.kind === ts.SyntaxKind.ImportKeyword ||
          (ts.isIdentifier(node.expression) &&
            node.expression.text === "require" &&
            !shadowedRequires.has(node.expression.getStart())))
      ) {
        const argument = node.arguments[0];
        if (node.arguments.length === 1 && argument && ts.isStringLiteralLike(argument))
          requests.push({ specifier: argument.text, node });
        else
          diagnostic(
            "dynamic-import",
            "Non-literal require/import cannot be resolved statically.",
            node,
          );
      }
      ts.forEachChild(node, scan);
    }
    scan(source);
    for (const { specifier, node } of requests) {
      if (loaded.imports.has(specifier)) continue;
      if (specifier.startsWith("node:") || builtins.has(specifier)) {
        diagnostic("builtin-module", `Runtime-provided module: ${specifier}`, node, "external");
        continue;
      }
      if (specifier.startsWith(".")) {
        const resolved = resolveFile(path.resolve(path.dirname(actual), specifier), boundary);
        if (!resolved) {
          diagnostic("unresolved-module", `Cannot resolve ${specifier}`, node);
          continue;
        }
        const logical = path.resolve(
          path.dirname(file),
          path.relative(path.dirname(actual), resolved),
        );
        loaded.imports.set(specifier, logical);
        await visit(logical, resolved, boundary, pkg);
        continue;
      }
      const name = specifier.startsWith("@")
        ? specifier.split("/").slice(0, 2).join("/")
        : specifier.split("/")[0]!;
      const dependency = resolvePackage(
        input.manifest.packages,
        slash(path.relative(root, file)),
        name,
      );
      if (!dependency) {
        diagnostic("missing-package", `No manifest instance resolves ${specifier}`, node);
        continue;
      }
      if (!selected.has(packageId(dependency))) {
        diagnostic(
          "excluded-package",
          `Package is outside the vulnerable-package ancestor set: ${dependency.path}`,
          node,
          "out-of-scope",
        );
        continue;
      }
      const cacheKey = `${dependency.name}@${dependency.version}`;
      if (!sourceCache.has(cacheKey)) {
        try {
          sourceCache.set(
            cacheKey,
            fs.realpathSync(await input.getPackageSource(dependency.name, dependency.version)),
          );
        } catch (error) {
          sourceCache.set(cacheKey, new Error(String(error)));
        }
      }
      const packageRoot = sourceCache.get(cacheKey)!;
      if (packageRoot instanceof Error) {
        diagnostic(
          "source-unavailable",
          `Source unavailable for ${cacheKey}: ${packageRoot.message}`,
          node,
        );
        continue;
      }
      const subpath = specifier.slice(name.length).replace(/^\//, "");
      const metadata = read(path.join(packageRoot, "package.json"), packageRoot);
      let candidate = path.resolve(packageRoot, subpath || ".");
      if (metadata) {
        try {
          const json = JSON.parse(metadata);
          if (json.exports !== undefined) {
            const key = subpath ? `./${subpath}` : ".";
            const target =
              typeof json.exports === "string" && !subpath ? json.exports : json.exports?.[key];
            if (typeof target !== "string" || !target.startsWith("./")) {
              diagnostic(
                "unsupported-exports",
                `Conditional, wildcard, or unexported package entry: ${specifier}`,
                node,
              );
              continue;
            }
            candidate = path.resolve(packageRoot, target);
          }
        } catch {
          diagnostic("invalid-package-json", `Invalid package.json for ${cacheKey}`, node);
          continue;
        }
      }
      const resolved = resolveFile(candidate, packageRoot);
      if (!resolved) {
        diagnostic("unresolved-module", `Cannot resolve source entry for ${specifier}`, node);
        continue;
      }
      const logical = path.resolve(root, dependency.path, path.relative(packageRoot, resolved));
      loaded.imports.set(specifier, logical);
      await visit(logical, resolved, packageRoot, dependency);
    }
  }

  for (const entry of input.entryPoints) {
    const file = path.resolve(root, entry);
    const resolved = resolveFile(file, root);
    if (!resolved || !inside(root, file))
      throw new Error(`Entry point is missing or outside the repository: ${entry}`);
    entries.push(resolved);
    await visit(resolved, resolved, root);
  }
  return { root, modules, entries, diagnostics };
}
