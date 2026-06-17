'use strict';
const http = require('http');

const PAYLOADS = [
  '<script>alert(1)</script>',
  '<img src=x onerror=alert(1)>',
  '"><svg onload=alert(1)>',
  '<body onload=alert(1)>',
  "';alert(1)//",
];

const ENDPOINTS = [
  { path: '/search',         param: 'q' },
  { path: '/search-escaped', param: 'q' },
  { path: '/search-csp',     param: 'q' },
];

function httpGet(url) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body, headers: res.headers }));
    });
    req.on('error', reject);
    req.setTimeout(5000, () => req.destroy(new Error('Request timed out')));
  });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

function isReflectedRaw(payload, body) {
  return body.includes(payload);
}

function isEscaped(payload, body) {
  const encoded = escapeHtml(payload);
  return body.includes(encoded) && !body.includes(payload);
}

async function scanEndpoint(baseUrl, endpoint) {
  for (const payload of PAYLOADS) {
    const url = `${baseUrl}${endpoint.path}?${endpoint.param}=${encodeURIComponent(payload)}`;
    try {
      const resp = await httpGet(url);
      if (!isReflectedRaw(payload, resp.body)) continue;

      const csp = resp.headers['content-security-policy'] || null;
      return {
        endpoint: endpoint.path,
        vulnerability: 'XSS Reflection',
        evidence: `Payload reflected without HTML encoding: ${payload}`,
        severity: csp ? 'MEDIUM' : 'HIGH',
        payload,
        csp_present: Boolean(csp),
      };
    } catch (_) {
      // skip individual payload failures
    }
  }
  return null;
}

async function main() {
  const args = process.argv.slice(2);
  const tIdx = args.indexOf('--target');
  const target = tIdx !== -1 ? args[tIdx + 1] : 'http://localhost:3000';

  const result = {
    target,
    scanned_at: new Date().toISOString(),
    endpoints_tested: ENDPOINTS.map((e) => e.path),
    findings: [],
    summary: '',
  };

  try {
    await httpGet(`${target}/health`);
  } catch (err) {
    result.error = `Cannot reach target: ${err.message}`;
    result.summary = `Error: cannot reach ${target}`;
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    return;
  }

  for (const endpoint of ENDPOINTS) {
    const finding = await scanEndpoint(target, endpoint);
    if (finding) result.findings.push(finding);
  }

  const n = result.findings.length;
  result.summary = n > 0
    ? `Found ${n} XSS reflection issue(s) across ${ENDPOINTS.length} endpoints`
    : `No XSS reflection vulnerabilities found across ${ENDPOINTS.length} endpoints`;

  process.stdout.write(JSON.stringify(result, null, 2) + '\n');

  process.stderr.write('\n--- XSS Reflection Scanner ---\n');
  process.stderr.write(`Target : ${target}\n`);
  process.stderr.write(`Tested : ${result.endpoints_tested.join(', ')}\n`);
  process.stderr.write(`Issues : ${n}\n`);
  result.findings.forEach((f) => {
    process.stderr.write(`  [${f.severity}] ${f.endpoint}: ${f.evidence}\n`);
  });
}

main().catch((err) => {
  const out = {
    target: 'unknown',
    error: err.message,
    findings: [],
    summary: `Fatal error: ${err.message}`,
  };
  process.stdout.write(JSON.stringify(out, null, 2) + '\n');
});
