'use strict';

// Test app for reachability analysis. Deliberately uses axios 1.6.0 and calls
// public APIs that reach vulnerable methods reported by HDS (see README.md).
const http = require('http');
const axios = require('axios');
const { AxiosHeaders } = axios;

function startServer() {
  const server = http.createServer((req, res) => {
    if (req.url === '/redirect') {
      res.writeHead(302, { Location: '/hello' });
      return res.end();
    }
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ ok: true, url: req.url, method: req.method }));
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

async function main() {
  const server = await startServer();
  const base = `http://127.0.0.1:${server.address().port}`;

  // httpAdapter(), httpAdapter/dispatchHttpRequest(), setProxy(), mergeConfig(), normalizeValue()
  const plain = await axios.get(`${base}/hello`, { proxy: false });
  console.log('GET', plain.data);

  // AxiosHeaders/constructor(), normalizeValue()
  const headers = new AxiosHeaders({ 'X-Test': 'value', Accept: 'application/json' });
  const withHeaders = await axios.get(`${base}/headers`, { headers, proxy: false });
  console.log('GET with AxiosHeaders', withHeaders.data);

  // mergeConfig() via instance defaults
  const client = axios.create({ baseURL: base, timeout: 5000, proxy: false });
  const viaClient = await client.post('/json', { hello: 'world' });
  console.log('POST via instance', viaClient.data);

  // toFormData/build(), FormDataPart/constructor()
  const form = await axios.postForm(`${base}/form`, { name: 'calflow', nested: { a: 1, b: [1, 2] } }, { proxy: false });
  console.log('POST form', form.data);

  // formDataToJSON(), formDataToJSON/buildPath(): FormData body with a JSON content type
  const fd = new FormData();
  fd.append('user[name]', 'calflow');
  fd.append('user[tags][]', 'a');
  const asJson = await axios.post(`${base}/fd-json`, fd, {
    headers: { 'Content-Type': 'application/json' },
    proxy: false,
  });
  console.log('POST FormData as JSON', asJson.data);

  // dispatchBeforeRedirect(): follow a redirect through follow-redirects
  const redirected = await axios.get(`${base}/redirect`, { proxy: false, maxRedirects: 3 });
  console.log('GET redirect', redirected.data);

  server.close();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
