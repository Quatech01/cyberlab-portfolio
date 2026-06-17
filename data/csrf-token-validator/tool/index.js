'use strict';

const args = process.argv.slice(2);
const targetIdx = args.indexOf('--target');
const target = (targetIdx !== -1 ? args[targetIdx + 1] : 'http://localhost:3000').replace(/\/$/, '');

// Unique session ID per tool run — simulates a logged-in user the attacker is
// trying to impersonate.
const SESSION_ID = `scanner-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

async function httpGet(path, extraHeaders = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    return await fetch(`${target}${path}`, {
      headers: { 'x-session-id': SESSION_ID, ...extraHeaders },
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

async function httpPost(path, body, extraHeaders = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    return await fetch(`${target}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-session-id': SESSION_ID,
        ...extraHeaders,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

async function run() {
  const findings = [];
  const checks = {
    vulnerable_transfer_flagged: false,
    protected_transfer_blocked: false,
    csrf_token_rotation_works: false,
    insecure_cookie_flagged: false,
    secure_cookie_passed: false,
  };
  const endpointsTested = [];

  // ── Check 1: /transfer/vulnerable ──────────────────────────────────────────
  // An attacker forges a cross-site POST with no token. If it succeeds, the
  // endpoint is vulnerable.
  try {
    const res = await httpPost('/transfer/vulnerable', { amount: 500, to: 'attacker' });
    const body = await res.json();
    endpointsTested.push('/transfer/vulnerable');

    if (res.status === 200 && body.success) {
      findings.push({
        endpoint: '/transfer/vulnerable',
        vulnerability: 'MISSING_CSRF_PROTECTION',
        evidence: `Cross-origin POST succeeded without any CSRF token (HTTP ${res.status})`,
        severity: 'HIGH',
      });
      checks.vulnerable_transfer_flagged = true;
    }
  } catch (_err) {
    endpointsTested.push('/transfer/vulnerable (unreachable)');
  }

  // ── Check 2: /transfer/protected — without token (should be blocked) ───────
  try {
    const res = await httpPost('/transfer/protected', { amount: 500, to: 'attacker' });
    endpointsTested.push('/transfer/protected (no token)');
    checks.protected_transfer_blocked = res.status === 403;
  } catch (_err) {
    endpointsTested.push('/transfer/protected (unreachable)');
  }

  // ── Check 3: /transfer/protected — with valid token, then token replay ──────
  // Verifies that (a) valid tokens are accepted and (b) each token is single-use.
  try {
    const tokenRes = await httpGet('/csrf-token');
    const { token } = await tokenRes.json();

    const res1 = await httpPost('/transfer/protected', { amount: 100, to: 'bob', csrf_token: token });
    endpointsTested.push('/transfer/protected (with token)');

    if (res1.status === 200) {
      // Replay the same token — must be rejected
      const res2 = await httpPost('/transfer/protected', { amount: 100, to: 'bob', csrf_token: token });
      checks.csrf_token_rotation_works = res2.status === 403;
      endpointsTested.push('/transfer/protected (token replay)');
    }
  } catch (_err) {
    endpointsTested.push('/csrf-token or /transfer/protected (unreachable)');
  }

  // ── Check 4: /account/insecure-cookie — missing SameSite attribute ─────────
  try {
    const res = await httpGet('/account/insecure-cookie');
    const setCookie = res.headers.get('set-cookie') || '';
    endpointsTested.push('/account/insecure-cookie');

    if (!setCookie.toLowerCase().includes('samesite')) {
      findings.push({
        endpoint: '/account/insecure-cookie',
        vulnerability: 'MISSING_SAMESITE_ATTRIBUTE',
        evidence: `Set-Cookie header is missing SameSite — value: "${setCookie}"`,
        severity: 'MEDIUM',
      });
      checks.insecure_cookie_flagged = true;
    }
  } catch (_err) {
    endpointsTested.push('/account/insecure-cookie (unreachable)');
  }

  // ── Check 5: /account/secure-cookie — SameSite=Strict present (safe) ───────
  try {
    const res = await httpGet('/account/secure-cookie');
    const setCookie = res.headers.get('set-cookie') || '';
    endpointsTested.push('/account/secure-cookie');
    checks.secure_cookie_passed = setCookie.toLowerCase().includes('samesite=strict');
  } catch (_err) {
    endpointsTested.push('/account/secure-cookie (unreachable)');
  }

  const result = {
    target,
    session: SESSION_ID,
    findings,
    checks,
    summary: {
      total_endpoints_tested: endpointsTested.length,
      vulnerabilities_found: findings.filter(f => f.severity !== 'INFO').length,
      endpoints_tested: endpointsTested,
    },
  };

  // JSON to stdout for programmatic consumption
  console.log(JSON.stringify(result, null, 2));

  // Human-readable summary to stderr
  console.error('\n=== CSRF VULNERABILITY SCAN SUMMARY ===');
  console.error(`Target  : ${target}`);
  console.error(`Endpoints tested: ${endpointsTested.length}`);
  console.error(`Vulnerabilities : ${result.summary.vulnerabilities_found}`);
  if (findings.length > 0) {
    console.error('');
    for (const f of findings) {
      console.error(`  [${f.severity}] ${f.endpoint}`);
      console.error(`         ${f.vulnerability}`);
      console.error(`         ${f.evidence}`);
    }
  }
  console.error('========================================\n');
}

run().catch(err => {
  const errorResult = {
    target,
    session: SESSION_ID,
    findings: [],
    checks: {},
    summary: {
      total_endpoints_tested: 0,
      vulnerabilities_found: 0,
      error: err.message,
    },
  };
  console.log(JSON.stringify(errorResult, null, 2));
  process.exit(1);
});
