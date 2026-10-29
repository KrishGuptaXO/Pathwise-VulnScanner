// TEST/DEMO HELPER ONLY - never imported by production code.
//
// Serves canned OSV.dev responses for a few known package versions so the whole pipeline can be
// exercised offline. Every URL that is NOT api.osv.dev is passed through to the real fetch, so
// lockfile/tarball downloads from the npm registry remain real.
//
// Use in a test:      const restore = installFakeOsv();  ...  restore();
// Use on the CLI:     node --import ./test/helpers/fake-osv-preload.mjs dist/cli/index.js analyze <repo>

// Advisory IDs/summaries mirror public advisories but are TEST DATA, not a source of truth.
const ADVISORIES = {
  "GHSA-w9mr-4mfr-499f": {
    id: "GHSA-w9mr-4mfr-499f",
    summary: "Regular Expression Denial of Service in ms",
    aliases: ["CVE-2015-8315"],
    database_specific: { severity: "HIGH" },
    affected: [
      {
        package: { name: "ms", ecosystem: "npm" },
        ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
      },
    ],
    references: [{ type: "ADVISORY", url: "https://github.com/advisories/GHSA-w9mr-4mfr-499f" }],
  },
  "GHSA-35jh-r3h4-6jhm": {
    id: "GHSA-35jh-r3h4-6jhm",
    summary: "Command Injection in lodash",
    aliases: ["CVE-2021-23337"],
    database_specific: { severity: "HIGH" },
    affected: [
      {
        package: { name: "lodash", ecosystem: "npm" },
        ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
      },
    ],
    references: [{ type: "ADVISORY", url: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm" }],
  },
  "GHSA-xvch-5gv4-984h": {
    id: "GHSA-xvch-5gv4-984h",
    summary: "Prototype Pollution in minimist",
    aliases: ["CVE-2021-44906"],
    database_specific: { severity: "CRITICAL" },
    affected: [
      {
        package: { name: "minimist", ecosystem: "npm" },
        ranges: [{ type: "SEMVER", events: [{ introduced: "1.0.0" }, { fixed: "1.2.6" }] }],
      },
    ],
    references: [{ type: "ADVISORY", url: "https://github.com/advisories/GHSA-xvch-5gv4-984h" }],
  },
  "GHSA-vh95-rmgr-6w4m": {
    id: "GHSA-vh95-rmgr-6w4m",
    summary: "Prototype Pollution in minimist (legacy 0.x)",
    aliases: ["CVE-2020-7598"],
    database_specific: { severity: "MODERATE" },
    affected: [
      {
        package: { name: "minimist", ecosystem: "npm" },
        ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "0.2.1" }] }],
      },
    ],
    references: [{ type: "ADVISORY", url: "https://github.com/advisories/GHSA-vh95-rmgr-6w4m" }],
  },
};

const BY_PACKAGE_VERSION = {
  "lodash@4.17.20": ["GHSA-35jh-r3h4-6jhm"],
  "minimist@1.2.0": ["GHSA-xvch-5gv4-984h"],
  "minimist@0.0.8": ["GHSA-vh95-rmgr-6w4m"],
  "ms@0.7.1": ["GHSA-w9mr-4mfr-499f"],
};

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

/** Replaces globalThis.fetch; returns a function that restores the original. */
export function installFakeOsv() {
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url === "https://api.osv.dev/v1/querybatch") {
      const { queries } = JSON.parse(String(init?.body ?? "{}"));
      return json({
        results: queries.map((q) => ({
          vulns: (BY_PACKAGE_VERSION[`${q.package.name}@${q.version}`] ?? []).map((id) => ({ id })),
        })),
      });
    }
    const detail = /^https:\/\/api\.osv\.dev\/v1\/vulns\/(.+)$/.exec(url);
    if (detail) {
      const advisory = ADVISORIES[decodeURIComponent(detail[1])];
      return advisory ? json(advisory) : json({ code: 5, message: "Bug not found." }, 404);
    }
    return realFetch(input, init);
  };
  return () => {
    globalThis.fetch = realFetch;
  };
}
