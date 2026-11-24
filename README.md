# js-calflow-01

Minimal app for testing JavaScript reachability (callflow) analysis. It pins
`axios@1.6.0` and calls public axios APIs that reach vulnerable methods
reported by HDS (`POST /rest/component/signatures/vulnerability`,
`pkg:npm/axios@1.6.0`).

Run: `npm install && npm start` (uses a local HTTP server, no external network).

| index.js call | Expected reachable vulnerable methods (vulnerability) |
| --- | --- |
| `axios.get(...)` (any request) | `httpAdapter()`, `httpAdapter/dispatchHttpRequest()` (CVE-2024-39338, CVE-2025-58754, CVE-2026-42034, CVE-2026-42036), `setProxy()` (CVE-2025-62718), `mergeConfig()` (CVE-2026-25639) |
| `new AxiosHeaders(...)` | `AxiosHeaders/constructor()`, `normalizeValue()` (CVE-2026-40175) |
| `axios.create(...).post(...)` | `mergeConfig()` (CVE-2026-25639) |
| `axios.postForm(...)` | `toFormData/build()` (CVE-2026-42039), `FormDataPart/constructor()` (CVE-2026-42037) |
| `axios.post(FormData, JSON content type)` | `formDataToJSON()`, `formDataToJSON/buildPath()` (SONATYPE-2024-0113), anon fn (CVE-2026-67313) |
| `axios.get('/redirect')` | `dispatchBeforeRedirect()` (SONATYPE-2026-009225) |

All 15 signatures HDS returned for axios 1.6.0 are listed above. The mapping is
derived from reading axios source, so confirm against the analyzer's output.

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
vulnerable method (`descriptor`) and its vulnerability (`refid`). For axios
1.6.0 the reachable ones are CVE-2026-40175 and CVE-2026-25639.
