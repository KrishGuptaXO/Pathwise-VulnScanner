// Preload for offline demos: `node --import ./test/helpers/fake-osv-preload.mjs dist/cli/index.js ...`
// Makes api.osv.dev return canned data (see fake-osv.mjs). Test/demo use only.
import { installFakeOsv } from "./fake-osv.mjs";

installFakeOsv();
console.error("[demo] OSV.dev responses are CANNED (test/helpers/fake-osv.mjs); registry downloads are real.");
