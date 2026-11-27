# js-calflow-01

Minimal app for testing JavaScript reachability (callflow) analysis. It pins
`axios@1.6.0` and calls public axios APIs, plus a few internal modules directly, to reach
vulnerable methods reported by HDS (`POST /rest/component/signatures/vulnerability`,
`pkg:npm/axios@1.6.0`).

Run: `npm install && npm start` (uses a local HTTP server, no external network).

| index.js call | Vulnerable methods (vulnerability) | Public API only |
| --- | --- | --- |
| `axios.get(...)` (any request) | `mergeConfig()` (CVE-2026-25639) | reachable |
| `axios.get(...)` (any request) | `httpAdapter()`, `httpAdapter/dispatchHttpRequest()` (CVE-2024-39338, CVE-2025-58754, CVE-2026-42034, CVE-2026-42036), `setProxy()` (CVE-2025-62718) | **not reachable** (adapter dynamic dispatch) |
| `new AxiosHeaders(...)` | `AxiosHeaders/constructor()`, `normalizeValue()` (CVE-2026-40175) | reachable |
| `axios.create(...).post(...)` | `mergeConfig()` (CVE-2026-25639) | reachable |
| `axios.postForm(...)` | `toFormData/build()` (CVE-2026-42039) | **not reachable** (transform dynamic dispatch) |
| `axios.post(FormData, JSON content type)` | `formDataToJSON()`, `formDataToJSON/buildPath()` (SONATYPE-2024-0113), anon fn (CVE-2026-67313) | **not reachable** (transform dynamic dispatch) |
| `axios.get('/redirect')` | `dispatchBeforeRedirect()` (SONATYPE-2026-009225) | **not reachable** (adapter dynamic dispatch) |

All 15 signatures HDS returned for axios 1.6.0 are listed above.

### Why public API calls miss most signatures

At runtime every signature above is executed, but the static call graph cannot
follow two dynamic dispatches inside axios:

- **Adapter lookup**: `core/dispatchRequest.js` calls
  `adapters.getAdapter(...)`, which resolves the adapter with
  `knownAdapters[String(name).toLowerCase()]` and then calls `adapter(config)`.
  Everything under `adapters/http.js` (`httpAdapter`, `dispatchHttpRequest`,
  `setProxy`, `dispatchBeforeRedirect`) is therefore unreachable.
- **Transform pipeline**: `core/transformData.js` runs
  `utils.forEach(fns, fn => fn.call(...))` over `transformRequest`, so
  `toFormData` and `formDataToJSON` (called from inside it) are unreachable.

Analyzer output (`Found 3 reachable out of 12 query signatures`; the result
file has 15 entries because `httpAdapter()` appears once per CVE) confirms only
`AxiosHeaders/constructor()`, `normalizeValue()` and `mergeConfig()` are found.

### Direct internal calls

To get static edges past those dispatches, the end of `index.js` imports axios
internals through its package `exports` (dynamic `import()`) and calls them
directly. Results from the analyzer run with these calls:

| index.js call | Vulnerable methods (vulnerability) | Result |
| --- | --- | --- |
| `toFormData(...)` (`axios/unsafe/helpers/toFormData.js`) | `toFormData/build()` (CVE-2026-42039) | reachable |
| `formDataToJSON(...)` (`axios/unsafe/helpers/formDataToJSON.js`) | `formDataToJSON()`, `formDataToJSON/buildPath()` (SONATYPE-2024-0113) | reachable |
| `formDataToStream(...)` (`axios/unsafe/helpers/formDataToStream.js`) | `FormDataPart/constructor()` (CVE-2026-42037) | still not reachable |
| `httpAdapter(config)` (`axios/lib/adapters/http.js`) | `httpAdapter()`, `httpAdapter/dispatchHttpRequest()` (CVE-2024-39338, CVE-2025-58754, CVE-2026-42034, CVE-2026-42036) | still not reachable |
| `__setProxy(...)` (`axios/lib/adapters/http.js`) | `setProxy()` (CVE-2025-62718) | still not reachable |

Notes:

- `FormDataPart` lives in `helpers/formDataToStream.js` (used by the http
  adapter), not in `toFormData`; an earlier version of this table mapped it
  wrongly. Even with `formDataToStream(...)` called directly, CVE-2026-42037
  stays unreachable: `new FormDataPart(...)` runs inside the callback of
  `Array.from(form.entries()).map(...)`, a built-in higher-order call the
  analyzer apparently does not follow (the class is not exported either, so it
  cannot be called directly).
- `httpAdapter` is declared as `export default isHttpAdapterSupported && function httpAdapter(...)`
  and `__setProxy` is `export const __setProxy = setProxy`. The analyzer
  appears not to resolve a function behind a `&&` expression or a re-exported
  alias, so those stay unreachable even with a direct call.
- Not coverable: `dispatchBeforeRedirect()` (not exported, SONATYPE-2026-009225)
  and the anonymous callback passed to `utils.forEachEntry` in `formDataToJSON`
  (CVE-2026-67313), which is invoked dynamically.
- Many other axios 1.6.0 CVEs show as `Unknown`: HDS returned no vulnerable
  method signatures for them, so reachability cannot be determined.

## Running JavaScript reachability analysis with the IQ CLI

This mirrors the `Policy` stage of the `Jenkinsfile` (stage `build`, scan
`package-lock.json`, JS reachability on `index.js`) and additionally writes the
machine-readable reachability results with `-rr, --reachability-result`.

Prerequisites: Java 17+, Node.js on the `PATH` (or pass `-rnp <path>`), a built
IQ CLI jar, and an IQ Server with an application whose public ID is
`js-calflow-01`.

```bash
npm install

java -jar /path/to/nexus-iq-cli.jar \
  -i js-calflow-01 \
  -s http://localhost:8070 \
  -a "<username>:<password>" \
  -t build \
  -rajs \
  -rjs index.js \
  -rjr . \
  -rr reachability-result.json \
  -r policy-result.json \
  package-lock.json
```

| Flag | Purpose |
| --- | --- |
| `-i` | IQ application public ID |
| `-s`, `-a` | IQ Server URL and `user:password` credentials |
| `-t build` | Stage to evaluate against |
| `-rajs` | Enable JavaScript reachability analysis |
| `-rjs index.js` | App source files to analyze (not tests or `node_modules`) |
| `-rjr .` | JS project root (directory with `package.json`) |
| `-rr` | Write reachability results to this JSON file |
| `-r` | Optional: write policy evaluation results to this JSON file |
| `package-lock.json` | Scan target |

The CLI exits with code 1 when policy violations are found; the result files
are still written. In `reachability-result.json`, each entry under
`reachability[].components[].signatures[]` has a `reachable` boolean for the
vulnerable method (`descriptor`) and its vulnerability (`refid`). With public API calls only, the reachable ones for axios 1.6.0 are
CVE-2026-40175 and CVE-2026-25639; the direct internal calls in `index.js` add
CVE-2026-42039 and SONATYPE-2024-0113 (see above), for 4 reachable CVEs in
total.
