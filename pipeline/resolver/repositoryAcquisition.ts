import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

export class RepositoryAcquisitionError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = "RepositoryAcquisitionError";
  }
}

export interface AcquiredRepository {
  /** Local filesystem path where the repo's files can now be read from.
   *  For local input, this is just the resolved input path. For GitHub
   *  input, this is the path git cloned into. */
  localPath: string;
  acquisitionMethod: "local" | "github-clone";
  /** Set when acquisitionMethod === "github-clone" — caller should clean
   *  this up (rmSync recursive) once analysis is complete. Not set for
   *  local input, since we never touch the user's own directory. */
  tempDirToCleanup: string | null;
}

const GITHUB_URL_PATTERN = /^(?:https?:\/\/github\.com\/|git@github\.com:)([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/;

/**
 * Determines whether `input` is a GitHub URL or a local path, and
 * acquires the repository accordingly. This is the abstraction boundary
 * mentioned in the architecture: everything downstream of this function
 * (dependency resolution, vuln matching, etc.) only ever deals with a
 * local filesystem path and does not care where it came from.
 */
export async function acquireRepository(input: string): Promise<AcquiredRepository> {
  const githubMatch = input.match(GITHUB_URL_PATTERN);

  if (githubMatch) {
    return acquireFromGithub(input);
  }

  return acquireLocal(input);
}

function acquireLocal(input: string): AcquiredRepository {
  const resolved = path.resolve(input);
  if (!fs.existsSync(resolved)) {
    throw new RepositoryAcquisitionError(
      `Local path does not exist: ${resolved}`
    );
  }
  if (!fs.statSync(resolved).isDirectory()) {
    throw new RepositoryAcquisitionError(
      `Expected a directory, got a file: ${resolved}`
    );
  }
  return { localPath: resolved, acquisitionMethod: "local", tempDirToCleanup: null };
}

async function acquireFromGithub(url: string): Promise<AcquiredRepository> {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "pathwise-clone-"));

  try {
    // Shallow clone — we only need the current file tree (package.json +
    // lockfile + source), not git history, so --depth 1 keeps this fast.
    await execFileAsync("git", ["clone", "--depth", "1", url, tempDir], {
      timeout: 60_000,
    });
  } catch (err) {
    fs.rmSync(tempDir, { recursive: true, force: true });
    throw new RepositoryAcquisitionError(
      `Failed to clone GitHub repository ${url}: ${(err as Error).message}`,
      err
    );
  }

  return { localPath: tempDir, acquisitionMethod: "github-clone", tempDirToCleanup: tempDir };
}
