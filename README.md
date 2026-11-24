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
