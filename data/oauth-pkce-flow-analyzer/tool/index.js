const http = require('node:http');
const crypto = require('node:crypto');

const args = process.argv.slice(2);
const targetIdx = args.indexOf('--target');
const target = targetIdx !== -1 ? args[targetIdx + 1] : 'http://localhost:3000';

function httpGet(url) {
  return new Promise((resolve) => {
    const req = http.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', () => resolve({ status: 0, body: null }));
    req.setTimeout(5000, () => { req.destroy(); resolve({ status: 0, body: null }); });
  });
}

function httpPost(url, params) {
  return new Promise((resolve) => {
    const body = new URLSearchParams(params).toString();
    const u = new URL(url);
    const options = {
      hostname: u.hostname,
      port: u.port || 80,
      path: u.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body)
      }
    };
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', () => resolve({ status: 0, body: null }));
    req.setTimeout(5000, () => { req.destroy(); resolve({ status: 0, body: null }); });
    req.write(body);
    req.end();
  });
}

async function checkReachable() {
  const res = await httpGet(`${target}/health`);
  return res.status === 200;
}

async function testMissingPkceVerification() {
  const authRes = await httpGet(
    `${target}/auth/authorize?client_id=client_vuln&redirect_uri=http://localhost:9000/cb&response_type=code&state=probe`
  );
  if (!authRes.body || !authRes.body.authorization_code) return null;

  const tokenRes = await httpPost(`${target}/auth/token`, {
    grant_type: 'authorization_code',
    code: authRes.body.authorization_code,
    redirect_uri: 'http://localhost:9000/cb',
    client_id: 'client_vuln'
    // Intentionally omit code_verifier to probe for missing PKCE enforcement
  });

  if (tokenRes.status === 200 && tokenRes.body && tokenRes.body.access_token) {
    return {
      endpoint: '/auth/token',
      vulnerability_type: 'missing_pkce_verification',
      evidence: 'Server issued an access token without a code_verifier — any party that intercepts the authorization code can exchange it for tokens without knowledge of the original verifier secret',
      severity: 'HIGH'
    };
  }
  return null;
}

async function testUnvalidatedRedirectUri() {
  const maliciousUri = 'http://evil.example.com/steal-code';
  const authRes = await httpGet(
    `${target}/auth/authorize?client_id=client_vuln&redirect_uri=${encodeURIComponent(maliciousUri)}&response_type=code&state=probe`
  );

  if (
    authRes.status === 200 &&
    authRes.body &&
    authRes.body.redirect_to &&
    authRes.body.redirect_to.startsWith(maliciousUri)
  ) {
    return {
      endpoint: '/auth/authorize',
      vulnerability_type: 'unvalidated_redirect_uri',
      evidence: `Server accepted an unregistered redirect_uri (${maliciousUri}) and directed the authorization code to it — enables authorization code theft via crafted phishing links`,
      severity: 'HIGH'
    };
  }
  return null;
}

async function run() {
  const reachable = await checkReachable();
  if (!reachable) {
    const result = {
      target,
      findings: [],
      summary: { checks_run: 0, vulnerabilities_found: 0, error: 'target unreachable' }
    };
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    return;
  }

  process.stderr.write(`[*] OAuth 2.0 PKCE vulnerability scanner\n`);
  process.stderr.write(`[*] Target: ${target}\n`);

  const findings = [];

  process.stderr.write(`[*] Check 1: PKCE code_verifier enforcement\n`);
  const pkceResult = await testMissingPkceVerification();
  if (pkceResult) {
    findings.push(pkceResult);
    process.stderr.write(`[!] VULNERABLE: ${pkceResult.vulnerability_type}\n`);
  } else {
    process.stderr.write(`[+] PKCE enforcement appears present\n`);
  }

  process.stderr.write(`[*] Check 2: redirect_uri allowlist validation\n`);
  const redirectResult = await testUnvalidatedRedirectUri();
  if (redirectResult) {
    findings.push(redirectResult);
    process.stderr.write(`[!] VULNERABLE: ${redirectResult.vulnerability_type}\n`);
  } else {
    process.stderr.write(`[+] redirect_uri validation appears present\n`);
  }

  const result = {
    target,
    findings,
    summary: {
      checks_run: 2,
      vulnerabilities_found: findings.length,
      high_severity: findings.filter((f) => f.severity === 'HIGH').length
    }
  };

  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  process.stderr.write(`[*] Scan complete — ${findings.length} issue(s) found\n`);
}

run().catch((err) => {
  const result = {
    target,
    findings: [],
    summary: { checks_run: 0, vulnerabilities_found: 0, error: err.message }
  };
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  process.exit(1);
});
