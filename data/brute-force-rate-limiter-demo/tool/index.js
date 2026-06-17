#!/usr/bin/env node

const http = require('http');

const args = process.argv.slice(2);
const targetIdx = args.indexOf('--target');
const target = targetIdx !== -1 ? args[targetIdx + 1] : 'http://localhost:3000';

const PROBE_ATTEMPTS = 10;
const REQUEST_TIMEOUT = 8000;

// Deliberately wrong credentials used for probing
const PROBE_CREDS = Array.from({ length: PROBE_ATTEMPTS }, (_, i) => ({
  username: 'admin',
  password: `probe_attempt_${i + 1}`,
}));

// ─── HTTP helpers using http.request with Connection: close ──────────────────
// Using the http module (not built-in fetch) so each request closes its TCP
// connection immediately. This prevents keep-alive pooling from keeping the
// process alive after all work is done.

function httpRequest(urlStr, method, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlStr);
    const payload = body ? JSON.stringify(body) : null;

    const options = {
      hostname: url.hostname,
      port: parseInt(url.port, 10) || 80,
      path: url.pathname + (url.search || ''),
      method,
      headers: {
        Connection: 'close',
        ...(payload
          ? {
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(payload),
            }
          : {}),
      },
    };

    const req = http.request(options, (res) => {
      let raw = '';
      res.on('data', (chunk) => (raw += chunk));
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(raw) });
        } catch {
          resolve({ status: res.statusCode, body: {} });
        }
      });
      res.on('error', reject);
    });

    req.setTimeout(REQUEST_TIMEOUT, () =>
      req.destroy(new Error(`Request to ${urlStr} timed out after ${REQUEST_TIMEOUT}ms`))
    );
    req.on('error', reject);

    if (payload) req.write(payload);
    req.end();
  });
}

function httpGet(urlStr) {
  return httpRequest(urlStr, 'GET', null);
}

function httpPost(urlStr, body) {
  return httpRequest(urlStr, 'POST', body);
}

// ─── Probe logic ──────────────────────────────────────────────────────────────

async function probeEndpoint(endpoint) {
  const responses = [];
  let rateLimitDetected = false;
  let rateLimitAfter = null;

  for (let i = 0; i < PROBE_ATTEMPTS; i++) {
    try {
      const { status, body } = await httpPost(`${target}${endpoint}`, PROBE_CREDS[i]);
      responses.push({ attempt: i + 1, status, body });

      if (status === 429) {
        rateLimitDetected = true;
        rateLimitAfter = i + 1;
        break;
      }
    } catch (err) {
      responses.push({ attempt: i + 1, error: err.message });
      break;
    }
  }

  return { endpoint, responses, rateLimitDetected, rateLimitAfter };
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  // Verify the server is reachable before probing auth endpoints
  try {
    await httpGet(`${target}/health`);
  } catch (err) {
    const result = {
      target,
      scannedAt: new Date().toISOString(),
      findings: [],
      securePaths: [],
      summary: {
        endpointsTested: 0,
        vulnerableEndpoints: 0,
        rateLimitingDetected: false,
        error: `Cannot reach target: ${err.message}`,
        recommendation: 'Ensure the target server is running and reachable.',
      },
    };
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  const findings = [];
  const securePaths = [];

  // ── Probe the vulnerable endpoint ──────────────────────────────────────────
  const vulnResult = await probeEndpoint('/login/vulnerable');

  if (!vulnResult.rateLimitDetected) {
    findings.push({
      endpoint: '/login/vulnerable',
      vulnerability: 'Missing Rate Limiting',
      evidence: `Completed ${PROBE_ATTEMPTS} consecutive failed login attempts without triggering any rate limit or lockout.`,
      severity: 'HIGH',
      detail:
        'This endpoint accepts an unlimited number of failed login attempts, enabling automated password guessing (brute-force) attacks. An attacker can try thousands of passwords per second until the correct one is found.',
    });
  } else {
    securePaths.push({
      endpoint: '/login/vulnerable',
      protection: 'Rate Limiting Active',
      detail: `Rate limit triggered after ${vulnResult.rateLimitAfter} attempt(s).`,
    });
  }

  // ── Probe the protected endpoint ───────────────────────────────────────────
  const protResult = await probeEndpoint('/login/protected');

  if (!protResult.rateLimitDetected) {
    findings.push({
      endpoint: '/login/protected',
      vulnerability: 'Missing Rate Limiting',
      evidence: `Completed ${PROBE_ATTEMPTS} consecutive failed login attempts without triggering any rate limit or lockout.`,
      severity: 'HIGH',
      detail:
        'The protected endpoint does not appear to enforce rate limiting. All authentication endpoints must implement lockout or throttling.',
    });
  } else {
    securePaths.push({
      endpoint: '/login/protected',
      protection: 'Rate Limiting Active',
      detail: `Rate limit triggered after ${protResult.rateLimitAfter} attempt(s). Subsequent requests correctly receive HTTP 429.`,
    });
  }

  const result = {
    target,
    scannedAt: new Date().toISOString(),
    findings,
    securePaths,
    summary: {
      endpointsTested: 2,
      vulnerableEndpoints: findings.length,
      rateLimitingDetected: protResult.rateLimitDetected || vulnResult.rateLimitDetected,
      recommendation:
        findings.length > 0
          ? 'Implement rate limiting on ALL authentication endpoints. Use a sliding-window counter keyed by IP (and optionally by username) with exponential backoff or a fixed lockout period after threshold failures.'
          : 'All probed endpoints enforce rate limiting. Verify lockout duration and that bypass via IP rotation is also mitigated.',
    },
  };

  // Structured output goes to stdout for programmatic consumption
  console.log(JSON.stringify(result, null, 2));

  // Human-readable summary goes to stderr so stdout stays clean JSON
  console.error('\n─── Brute Force Protection Assessment ───────────────────────');
  console.error(`Target:            ${target}`);
  console.error(`Scanned at:        ${result.scannedAt}`);
  console.error(`Endpoints tested:  ${result.summary.endpointsTested}`);
  console.error(`Vulnerabilities:   ${findings.length}`);

  if (findings.length > 0) {
    findings.forEach((f) => {
      console.error(`\n  [${f.severity}] ${f.endpoint}`);
      console.error(`  Type:     ${f.vulnerability}`);
      console.error(`  Evidence: ${f.evidence}`);
    });
  }

  if (securePaths.length > 0) {
    securePaths.forEach((s) => {
      console.error(`\n  [SECURE] ${s.endpoint}`);
      console.error(`  ${s.detail}`);
    });
  }

  console.error(`\nRecommendation: ${result.summary.recommendation}`);
  console.error('─────────────────────────────────────────────────────────────');
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    const result = {
      target,
      scannedAt: new Date().toISOString(),
      findings: [],
      securePaths: [],
      summary: {
        endpointsTested: 0,
        vulnerableEndpoints: 0,
        rateLimitingDetected: false,
        error: err.message,
        recommendation: 'An unexpected error occurred during the scan.',
      },
    };
    console.log(JSON.stringify(result, null, 2));
    process.exit(0);
  });
