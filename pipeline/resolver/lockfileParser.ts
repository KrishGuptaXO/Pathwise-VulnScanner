import * as fs from "fs";
import * as path from "path";

/**
 * Raw shape of one entry in package-lock.json's `packages` map.
 * This mirrors npm's actual lockfile format (v2/v3) — only the fields
 * Pathwise uses are typed, the rest is ignored by design.
 */
export interface RawLockfilePackageEntry {
  version?: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
  optional?: boolean;
  peer?: boolean;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  /** Only present on the root entry (key: "") */
  name?: string;
  link?: boolean;
}

export interface RawLockfile {
  name: string | null;
  lockfileVersion: number;
  /** Keyed by physical path relative to repo root, e.g. "node_modules/axios".
   *  The root project itself is keyed by the empty string "". */
  packages: Record<string, RawLockfilePackageEntry>;
}

export class LockfileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LockfileError";
  }
}

/**
 * Reads and validates package-lock.json from a repository root.
 * Throws LockfileError with a clear, user-facing message on any
 * validation failure — callers should surface this directly rather
 * than letting a raw JSON.parse error leak out.
 */
export function readLockfile(repoRoot: string): RawLockfile {
  const lockfilePath = path.join(repoRoot, "package-lock.json");
  const packageJsonPath = path.join(repoRoot, "package.json");

  if (!fs.existsSync(packageJsonPath)) {
    throw new LockfileError(
      `No package.json found at ${repoRoot}. Pathwise requires a valid npm project root.`
    );
  }

  if (!fs.existsSync(lockfilePath)) {
    throw new LockfileError(
      `No package-lock.json found at ${repoRoot}. Pathwise requires a committed lockfile ` +
        `(run "npm install" in the target repo first). Yarn/pnpm lockfiles are not yet supported.`
    );
  }

  let raw: unknown;
  try {
    raw = JSON.parse(fs.readFileSync(lockfilePath, "utf-8"));
  } catch (err) {
    throw new LockfileError(
      `package-lock.json is not valid JSON: ${(err as Error).message}`
    );
  }

  if (typeof raw !== "object" || raw === null) {
    throw new LockfileError("package-lock.json did not parse to an object.");
  }

  const obj = raw as Record<string, unknown>;
  const lockfileVersion = obj.lockfileVersion;

  if (typeof lockfileVersion !== "number") {
    throw new LockfileError(
      "package-lock.json is missing a numeric lockfileVersion field."
    );
  }

  if (lockfileVersion < 2) {
    throw new LockfileError(
      `package-lock.json is lockfileVersion ${lockfileVersion} (npm v6 or older format). ` +
        `Pathwise only supports lockfile v2/v3 (npm v7+). Regenerate the lockfile with a ` +
        `current npm version.`
    );
  }

  if (typeof obj.packages !== "object" || obj.packages === null) {
    throw new LockfileError(
      `package-lock.json has lockfileVersion ${lockfileVersion} but no "packages" field. ` +
        `This is unexpected for v2/v3 — the lockfile may be malformed.`
    );
  }

  return {
    name: typeof obj.name === "string" ? obj.name : null,
    lockfileVersion,
    packages: obj.packages as Record<string, RawLockfilePackageEntry>,
  };
}

/** Reads the root package.json for name + direct dependency declarations. */
export interface RootPackageJson {
  name: string | null;
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
  peerDependencies: Record<string, string>;
  optionalDependencies: Record<string, string>;
}

export function readRootPackageJson(repoRoot: string): RootPackageJson {
  const packageJsonPath = path.join(repoRoot, "package.json");
  let raw: unknown;
  try {
    raw = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8"));
  } catch (err) {
    throw new LockfileError(
      `package.json is not valid JSON: ${(err as Error).message}`
    );
  }
  const obj = raw as Record<string, unknown>;
  const asStringRecord = (v: unknown): Record<string, string> =>
    typeof v === "object" && v !== null ? (v as Record<string, string>) : {};

  return {
    name: typeof obj.name === "string" ? obj.name : null,
    dependencies: asStringRecord(obj.dependencies),
    devDependencies: asStringRecord(obj.devDependencies),
    peerDependencies: asStringRecord(obj.peerDependencies),
    optionalDependencies: asStringRecord(obj.optionalDependencies),
  };
}
