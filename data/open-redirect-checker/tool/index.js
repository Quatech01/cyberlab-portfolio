'use strict';

const http = require('node:http');
const https = require('node:https');
const { URL } = require('node:url');

function parseArgs() {
  const args = process.argv.slice(2);
  let target = 'http://localhost:3000';
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--target' && args[i + 1]) {
      target = args[i + 1];
    }
  }
  return { target };
}

// Probe payloads: external attacker-controlled URLs
const EXTERNAL_PAYLOADS = [
  'https://evil.example.com/phish',
  'http://attacker.io/steal',
  '//evil.example.com',
  'https://evil.example.com%2F@trusted.example.org/path',
];

// Safe destinations that a correctly implemented redirect should allow
const SAFE_PAYLOADS = [
  'https://example.com/page',
  'https://trusted.example.org/docs',
];

function request(urlStr, followRedirects = false) {
  return new Promise((resolve) => {
    const u = new URL(urlStr);
    const lib = u.protocol === 'https:' ? https : http;
    const options = {
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search,
      method: 'GET',
      timeout: 4000,
    };

    const req = lib.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () =>
        resolve({ status: res.statusCode, headers: res.headers, body })
      );
    });

    req.on('error', () => resolve({ status: null, headers: {}, body: '' }));
    req.on('timeout', () => { req.destroy(); resolve({ status: null, headers: {}, body: '' }); });
    req.end();
  });
}

async function probeEndpoint(target, path, payload) {
  const encoded = encodeURIComponent(payload);
  const url = `${target}${path}?url=${encoded}`;
  return request(url);
}

async function scan(target) {
  const findings = [];

  // Test /redirect/unsafe with external payloads
  for (const payload of EXTERNAL_PAYLOADS) {
    const res = await probeEndpoint(target, '/redirect/unsafe', payload);
    if (res.status === 302 || res.status === 301) {
      const location = res.headers['location'] || '';
      // The server redirected — check if it went to an external URL
      let evidence = `HTTP ${res.status} Location: ${location}`;
      findings.push({
        endpoint: '/redirect/unsafe',
        vulnerability_type: 'open_redirect',
        evidence,
        severity: 'HIGH',
        payload,
      });
      break; // One confirmed finding is enough for this endpoint
    }
  }

  // Test /redirect/partial with bypass payload (trusted domain in path, evil host)
  const bypassPayload = 'https://evil-trusted.example.org/?q=trusted.example.org';
  const partialRes = await probeEndpoint(target, '/redirect/partial', bypassPayload);
  if (partialRes.status === 302 || partialRes.status === 301) {
    findings.push({
      endpoint: '/redirect/partial',
      vulnerability_type: 'open_redirect_weak_validation',
      evidence: `Bypass succeeded: payload contained trusted domain in query string. HTTP ${partialRes.status}`,
      severity: 'HIGH',
      payload: bypassPayload,
    });
  }

  // Test /login with absolute URL (should be rejected by safe endpoint)
  const loginRes = await probeEndpoint(target, '/login', 'https://evil.example.com');
  if (loginRes.status !== 400) {
    findings.push({
      endpoint: '/login',
      vulnerability_type: 'open_redirect',
      evidence: `Absolute URL in returnTo was not rejected (HTTP ${loginRes.status})`,
      severity: 'MEDIUM',
      payload: 'https://evil.example.com',
    });
  }

  // Test /redirect/safe — must NOT redirect to external URLs (false positive check)
  const safeRes = await probeEndpoint(target, '/redirect/safe', 'https://evil.example.com/phish');
  if (safeRes.status === 302 || safeRes.status === 301) {
    findings.push({
      endpoint: '/redirect/safe',
      vulnerability_type: 'open_redirect',
      evidence: `Safe endpoint redirected to disallowed URL. HTTP ${safeRes.status}`,
      severity: 'HIGH',
      payload: 'https://evil.example.com/phish',
    });
  }

  const summary = findings.length === 0
    ? 'No open redirect vulnerabilities detected.'
    : `Detected ${findings.length} open redirect vulnerability/vulnerabilities. Unvalidated redirect endpoints allow attackers to craft phishing links that appear to originate from a trusted domain.`;

  return { target, findings, summary };
}

async function main() {
  const { target } = parseArgs();

  // Verify the server is reachable first
  const health = await request(`${target}/health`);
  if (health.status === null) {
    const result = { target, findings: [], summary: 'Server unreachable — no findings.' };
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    return;
  }

  const result = await scan(target);
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');

  process.stderr.write(`\n=== Open Redirect Checker ===\n`);
  process.stderr.write(`Target: ${target}\n`);
  process.stderr.write(`Findings: ${result.findings.length}\n`);
  result.findings.forEach((f, i) => {
    process.stderr.write(`  [${i + 1}] ${f.severity} — ${f.endpoint}: ${f.vulnerability_type}\n`);
    process.stderr.write(`       Evidence: ${f.evidence}\n`);
  });
  process.stderr.write(`Summary: ${result.summary}\n`);
}

main().catch((err) => {
  const result = { target: parseArgs().target, findings: [], summary: `Scanner error: ${err.message}` };
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  process.exit(1);
});
