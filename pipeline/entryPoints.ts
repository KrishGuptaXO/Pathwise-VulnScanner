import fs from "node:fs";
import path from "node:path";

/**
 * Finds the application entry files the static analyzer starts from.
 *
 * Priority: explicit --entry flags > package.json (main / bin / exports) > common conventions.
 * We never guess silently: `source` and `notes` explain where the answer came from, and when
 * nothing is found the caller reports "undetermined" instead of analyzing nothing.
 */

export class EntryPointError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EntryPointError";
  }
}

export interface EntryPointDetection {
  /** Repository-relative, forward-slash paths of existing files. */
  entries: string[];
  source: "cli" | "package.json" | "convention" | "none";
  notes: string[];
}

const CODE_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs"];
/** Build-output folders: a `main` pointing here usually has its source in src/. */
const BUILD_DIRS = new Set(["dist", "build", "lib", "out"]);
const CONVENTIONS = ["src/index", "src/main", "src/server", "src/app", "index", "server", "app", "main"];

const toSlash = (p: string): string => p.split(path.sep).join("/");

function isFile(p: string): boolean {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

/** Resolves "src/index", "src/index.js" or "src" (directory) to an existing code file. */
function resolveCodeFile(root: string, candidate: string): string | null {
  const base = path.resolve(root, candidate);
  const rel = path.relative(root, base);
  if (rel.startsWith("..") || path.isAbsolute(rel)) return null; // never leave the repo
  if (isFile(base) && CODE_EXTENSIONS.includes(path.extname(base))) return toSlash(rel);
  for (const ext of CODE_EXTENSIONS) {
    if (isFile(base + ext)) return toSlash(path.relative(root, base + ext));
  }
  for (const ext of CODE_EXTENSIONS) {
    if (isFile(path.join(base, `index${ext}`))) {
      return toSlash(path.relative(root, path.join(base, `index${ext}`)));
    }
  }
  return null;
}

/** "dist/server/main.js" -> try "src/server/main.(ts|tsx|js...)" when the build output is not checked in. */
function resolveBuildOutputToSource(root: string, candidate: string): string | null {
  const parts = toSlash(path.normalize(candidate)).replace(/^\.\//, "").split("/");
  const first = parts[0];
  if (parts.length < 2 || first === undefined || !BUILD_DIRS.has(first)) return null;
  const withoutExt = ["src", ...parts.slice(1)].join("/").replace(/\.[cm]?[jt]sx?$/, "");
  return resolveCodeFile(root, withoutExt);
}

function packageJsonCandidates(root: string): string[] {
  let json: unknown;
  try {
    json = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf-8"));
  } catch {
    return [];
  }
  if (typeof json !== "object" || json === null) return [];
  const pkg = json as Record<string, unknown>;
  const out: string[] = [];
  if (typeof pkg.main === "string") out.push(pkg.main);
  if (typeof pkg.bin === "string") out.push(pkg.bin);
  else if (typeof pkg.bin === "object" && pkg.bin !== null) {
    for (const v of Object.values(pkg.bin)) if (typeof v === "string") out.push(v);
  }
  const exp = pkg.exports;
  if (typeof exp === "string") out.push(exp);
  else if (typeof exp === "object" && exp !== null) {
    const dot = (exp as Record<string, unknown>)["."];
    if (typeof dot === "string") out.push(dot);
  }
  return out;
}

export function detectEntryPoints(repoRoot: string, explicit?: string[]): EntryPointDetection {
  const root = fs.realpathSync(repoRoot);

  if (explicit && explicit.length > 0) {
    const entries = explicit.map((entry) => {
      const resolved = resolveCodeFile(root, entry);
      if (!resolved) {
        throw new EntryPointError(
          `Entry point not found (or outside the repository): ${entry}`,
        );
      }
      return resolved;
    });
    return { entries: [...new Set(entries)], source: "cli", notes: [] };
  }

  const notes: string[] = [];
  const found = new Set<string>();
  for (const candidate of packageJsonCandidates(root)) {
    const direct = resolveCodeFile(root, candidate);
    if (direct) {
      found.add(direct);
      continue;
    }
    const fromSource = resolveBuildOutputToSource(root, candidate);
    if (fromSource) {
      found.add(fromSource);
      notes.push(`package.json points to build output "${candidate}"; using source file ${fromSource}.`);
    }
  }
  if (found.size > 0) return { entries: [...found], source: "package.json", notes };

  for (const convention of CONVENTIONS) {
    const resolved = resolveCodeFile(root, convention);
    if (resolved) {
      return {
        entries: [resolved],
        source: "convention",
        notes: [`No usable entry in package.json; using conventional file ${resolved}.`],
      };
    }
  }

  return {
    entries: [],
    source: "none",
    notes: ["No entry point found in package.json or by convention. Pass one with --entry <file>."],
  };
}
