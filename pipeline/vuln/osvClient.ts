/**
 * Thin client for the OSV.dev API (https://osv.dev).
 *
 * OSV.dev aggregates vulnerability data from multiple sources including
 * the GitHub Advisory Database (GHSA), so a direct separate GHSA
 * integration is not needed — GHSA data is already present here.
 *
 * Two endpoints are used:
 *  - POST /v1/querybatch — bulk lookup, returns only vulnerability IDs
 *    (no details) for many {package, version} pairs at once. This is
 *    "unhydrated" by design on OSV's side to keep batch responses small.
 *  - GET  /v1/vulns/{id} — fetches the full record for one vulnerability
 *    ID (summary, severity, affected ranges, references, etc).
 *
 * This module only knows how to talk to OSV's wire format. Mapping OSV's
 * shape into Pathwise's own VulnerabilityFinding type happens in
 * vulnerabilityMatcher.ts, deliberately kept separate so a future change
 * to OSV's schema doesn't ripple into the rest of the codebase.
 */

const OSV_BASE_URL = "https://api.osv.dev/v1";

// OSV rejects batches above a server-side limit (documented around
// 500-1000 depending on version). We chunk conservatively at 500.
const QUERYBATCH_CHUNK_SIZE = 500;

const REQUEST_TIMEOUT_MS = 15_000;

export interface OsvBatchQueryItem {
  packageName: string;
  version: string;
  /** Used to map results back to the original package instance after
   *  OSV returns results positionally. */
  packageInstanceId: string;
}

/** Minimal/unhydrated result from querybatch — just IDs, per query, in order. */
interface OsvQueryBatchResponse {
  results: Array<{
    vulns?: Array<{ id: string; modified?: string }>;
    next_page_token?: string;
  }>;
}

/** Full vulnerability record shape from GET /v1/vulns/{id}.
 *  Only the fields Pathwise actually reads are typed; OSV records
 *  contain more fields than this. */
export interface OsvVulnerabilityRecord {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
    }>;
    versions?: string[];
    // ecosystem_specific.imports is an OSV schema extension occasionally
    // used (mainly by OSS-Fuzz-derived data) to list affected
    // symbols/functions. Rarely populated for npm/GHSA advisories, but
    // we check for it defensively rather than assuming it never exists.
    ecosystem_specific?: {
      imports?: Array<{ path?: string; symbols?: string[] }>;
    };
    database_specific?: Record<string, unknown>;
  }>;
  references?: Array<{ type: string; url: string }>;
  database_specific?: { severity?: string; [key: string]: unknown };
}

export class OsvApiError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = "OsvApiError";
  }
}

function withTimeout(ms: number): { signal: AbortSignal; cancel: () => void } {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return { signal: controller.signal, cancel: () => clearTimeout(timer) };
}

/**
 * Queries OSV.dev's batch endpoint for a list of {name, version} pairs.
 * Automatically chunks requests above QUERYBATCH_CHUNK_SIZE.
 *
 * Returns a map from packageInstanceId -> list of vulnerability IDs found
 * (empty array if clean). Throws OsvApiError if a chunk's HTTP request
 * fails outright — callers should catch this per-chunk if partial results
 * are preferable to an all-or-nothing failure (see vulnerabilityMatcher).
 */
export async function queryBatch(
  items: OsvBatchQueryItem[]
): Promise<Map<string, string[]>> {
  const resultMap = new Map<string, string[]>();
  if (items.length === 0) return resultMap;

  for (let i = 0; i < items.length; i += QUERYBATCH_CHUNK_SIZE) {
    const chunk = items.slice(i, i + QUERYBATCH_CHUNK_SIZE);
    const body = {
      queries: chunk.map((item) => ({
        package: { name: item.packageName, ecosystem: "npm" },
        version: item.version,
      })),
    };

    const { signal, cancel } = withTimeout(REQUEST_TIMEOUT_MS);
    let response: Response;
    try {
      response = await fetch(`${OSV_BASE_URL}/querybatch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal,
      });
    } catch (err) {
      cancel();
      throw new OsvApiError(
        `Failed to reach OSV.dev querybatch endpoint: ${(err as Error).message}`,
        err
      );
    }
    cancel();

    if (!response.ok) {
      throw new OsvApiError(
        `OSV.dev querybatch returned HTTP ${response.status} ${response.statusText}`
      );
    }

    const parsed = (await response.json()) as OsvQueryBatchResponse;

    if (!Array.isArray(parsed.results) || parsed.results.length !== chunk.length) {
      throw new OsvApiError(
        `OSV.dev querybatch response shape mismatch: expected ${chunk.length} ` +
          `positional results, got ${parsed.results?.length ?? "none"}. ` +
          `OSV's API may have changed — this client needs updating.`
      );
    }

    // Results are positional: result j answers query j (lengths verified above).
    chunk.forEach((item, j) => {
      const ids = (parsed.results[j]?.vulns ?? []).map((v) => v.id);
      resultMap.set(item.packageInstanceId, ids);
    });
  }

  return resultMap;
}

/**
 * Fetches full details for a single vulnerability ID.
 * Returns null (rather than throwing) if the ID is not found (404) —
 * this can legitimately happen for withdrawn/merged advisories.
 */
export async function getVulnerabilityDetails(
  id: string
): Promise<OsvVulnerabilityRecord | null> {
  const { signal, cancel } = withTimeout(REQUEST_TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetch(`${OSV_BASE_URL}/vulns/${encodeURIComponent(id)}`, { signal });
  } catch (err) {
    cancel();
    throw new OsvApiError(
      `Failed to reach OSV.dev vulns endpoint for ${id}: ${(err as Error).message}`,
      err
    );
  }
  cancel();

  if (response.status === 404) return null;

  if (!response.ok) {
    throw new OsvApiError(
      `OSV.dev vulns/${id} returned HTTP ${response.status} ${response.statusText}`
    );
  }

  return (await response.json()) as OsvVulnerabilityRecord;
}
