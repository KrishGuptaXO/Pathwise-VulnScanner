import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import * as tar from "tar";
import { PackageInstance } from "../types/graph.js";

/**
 * Source acquisition strategy (architectural decision, locked):
 *
 *   ON-DEMAND TARBALL FETCH, not full `npm install`/`npm ci`.
 *
 * We use the exact `resolved` tarball URL already present in the
 * package's lockfile entry (PackageInstance.resolvedUrl) to fetch only
 * the packages that are actually needed for analysis — vulnerable
 * instances and whatever ancestors the call-graph walk steps into —
 * rather than downloading the entire dependency tree upfront.
 *
 * Fallback: if the direct registry tarball fetch fails, retry via the
 * unpkg CDN, which serves the same published package contents.
 *
 * Full `npm install`/`npm ci` is explicitly OUT OF SCOPE as the default
 * mechanism (see project rule #13) and is not implemented here.
 */

const CACHE_DIR_NAME = ".pathwise-cache";
const FETCH_TIMEOUT_MS = 30_000;

export class SourceAcquisitionError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = "SourceAcquisitionError";
  }
}

export interface SourceAcquisitionOptions {
  /** Where extracted package source is cached between calls. Defaults to
   *  a .pathwise-cache directory inside the OS temp dir, keyed by a run ID
   *  so concurrent/repeated runs don't collide or accumulate indefinitely. */
  cacheDir?: string;
}

/**
 * Manages lazy, on-demand fetching and local extraction of package
 * source code. One instance per analysis run — holds the cache directory
 * and an in-memory map to avoid redundant extraction within a run.
 */
export class SourceAcquirer {
  private readonly cacheDir: string;
  private readonly extractedPaths = new Map<string, string>();
  private readonly inFlight = new Map<string, Promise<string>>();

  constructor(options: SourceAcquisitionOptions = {}) {
    this.cacheDir =
      options.cacheDir ??
      path.join(os.tmpdir(), CACHE_DIR_NAME, `run-${Date.now()}-${process.pid}`);
    fs.mkdirSync(this.cacheDir, { recursive: true });
  }

  /**
   * Returns the local filesystem path to the extracted source of a
   * package instance, fetching and extracting it on first request and
   * serving from cache on subsequent requests within this run.
   *
   * This is the interface the static-analysis module calls as its call
   * graph traversal steps into a package it hasn't visited yet — it
   * should NOT pre-fetch every package upfront.
   *
   * Throws SourceAcquisitionError if the package cannot be obtained from
   * either the registry or the CDN fallback.
   */
  async getPackageSource(pkg: PackageInstance): Promise<string> {
    const cacheKey = `${pkg.name}@${pkg.version}`;

    const alreadyExtracted = this.extractedPaths.get(cacheKey);
    if (alreadyExtracted) return alreadyExtracted;

    const inFlight = this.inFlight.get(cacheKey);
    if (inFlight) return inFlight;

    const promise = this.fetchAndExtract(pkg, cacheKey);
    this.inFlight.set(cacheKey, promise);
    try {
      const extractedPath = await promise;
      this.extractedPaths.set(cacheKey, extractedPath);
      return extractedPath;
    } finally {
      this.inFlight.delete(cacheKey);
    }
  }

  private async fetchAndExtract(pkg: PackageInstance, cacheKey: string): Promise<string> {
    const destDir = path.join(this.cacheDir, sanitizeForPath(cacheKey));
    fs.mkdirSync(destDir, { recursive: true });

    const tarballBuffer = await this.fetchTarball(pkg);

    const tmpTarPath = path.join(this.cacheDir, `${sanitizeForPath(cacheKey)}.tgz`);
    fs.writeFileSync(tmpTarPath, tarballBuffer);

    try {
      // npm tarballs always wrap contents in a top-level "package/" dir —
      // strip:1 removes that wrapper so destDir contains the package root
      // directly (e.g. destDir/package.json, not destDir/package/package.json).
      await tar.extract({ file: tmpTarPath, cwd: destDir, strip: 1 });
    } catch (err) {
      throw new SourceAcquisitionError(
        `Failed to extract tarball for ${cacheKey}: ${(err as Error).message}`,
        err
      );
    } finally {
      fs.rmSync(tmpTarPath, { force: true });
    }

    return destDir;
  }

  private async fetchTarball(pkg: PackageInstance): Promise<Buffer> {
    if (pkg.resolvedUrl) {
      try {
        return await downloadBuffer(pkg.resolvedUrl);
      } catch (primaryErr) {
        // Fall through to CDN fallback below, but keep the original
        // error around in case the fallback also fails.
        try {
          return await this.fetchFromCdnFallback(pkg);
        } catch (fallbackErr) {
          throw new SourceAcquisitionError(
            `Could not fetch ${pkg.name}@${pkg.version} from registry ` +
              `(${(primaryErr as Error).message}) or CDN fallback ` +
              `(${(fallbackErr as Error).message}).`
          );
        }
      }
    }

    // No resolved URL at all (e.g. a git/local dependency in the
    // lockfile) — go straight to CDN fallback, which only works for
    // packages actually published to the npm registry.
    try {
      return await this.fetchFromCdnFallback(pkg);
    } catch (err) {
      throw new SourceAcquisitionError(
        `No resolved registry URL for ${pkg.name}@${pkg.version} (likely a ` +
          `git/local/non-registry dependency), and CDN fallback also failed: ` +
          `${(err as Error).message}`,
        err
      );
    }
  }

  /**
   * Fallback path: unpkg serves npm package contents directly but as
   * individual files, not a tarball. We reconstruct a minimal local copy
   * by fetching its file listing then each file — this is slower than a
   * single tarball fetch, which is exactly why it's a fallback and not
   * the default path.
   */
  private async fetchFromCdnFallback(pkg: PackageInstance): Promise<Buffer> {
    // unpkg exposes an npm-compatible tarball-less "?meta" listing; for
    // simplicity and reliability we instead fetch the npm registry's own
    // packument to re-derive the tarball URL (handles cases where the
    // lockfile's resolved URL was stale/malformed) before falling back
    // further to a direct unpkg file-by-file reconstruction is explicitly
    // NOT implemented in v1 — out of scope. If the registry packument
    // lookup also fails, we surface a clear error rather than silently
    // producing incomplete source.
    const packumentUrl = `https://registry.npmjs.org/${encodeNpmName(pkg.name)}`;
    const packumentRes = await fetchWithTimeout(packumentUrl, FETCH_TIMEOUT_MS);
    if (!packumentRes.ok) {
      throw new Error(`registry packument lookup failed: HTTP ${packumentRes.status}`);
    }
    const packument = (await packumentRes.json()) as {
      versions?: Record<string, { dist?: { tarball?: string } }>;
    };
    const tarballUrl = packument.versions?.[pkg.version]?.dist?.tarball;
    if (!tarballUrl) {
      throw new Error(
        `version ${pkg.version} not found in registry packument for ${pkg.name}`
      );
    }
    return downloadBuffer(tarballUrl);
  }

  /** Removes the entire cache directory for this run. Call when analysis
   *  completes to avoid accumulating disk usage across runs. */
  cleanup(): void {
    fs.rmSync(this.cacheDir, { recursive: true, force: true });
  }
}

async function downloadBuffer(url: string): Promise<Buffer> {
  const res = await fetchWithTimeout(url, FETCH_TIMEOUT_MS);
  if (!res.ok) {
    throw new Error(`download failed: HTTP ${res.status} for ${url}`);
  }
  const arrayBuffer = await res.arrayBuffer();
  return Buffer.from(arrayBuffer);
}

async function fetchWithTimeout(url: string, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function sanitizeForPath(s: string): string {
  return s.replace(/[^a-zA-Z0-9.@-]/g, "_");
}

function encodeNpmName(name: string): string {
  // Scoped packages (@scope/name) need their slash percent-encoded when
  // used as a registry packument path segment.
  return name.startsWith("@") ? name.replace("/", "%2F") : name;
}
