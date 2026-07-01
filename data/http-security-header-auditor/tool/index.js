const http = require('node:http');

const SECURITY_HEADERS = [
  { name: 'strict-transport-security', label: 'Strict-Transport-Security', weight: 2 },
  { name: 'x-content-type-options',    label: 'X-Content-Type-Options',    weight: 1 },
  { name: 'x-frame-options',           label: 'X-Frame-Options',           weight: 1 },
  { name: 'content-security-policy',   label: 'Content-Security-Policy',   weight: 2 },
  { name: 'referrer-policy',           label: 'Referrer-Policy',           weight: 1 },
  { name: 'permissions-policy',        label: 'Permissions-Policy',        weight: 1 },
];

const MAX_SCORE = SECURITY_HEADERS.reduce((s, h) => s + h.weight, 0); // 8

const ENDPOINTS = ['/headers/none', '/headers/partial', '/headers/full'];

function letterGrade(score) {
  const pct = score / MAX_SCORE;
  if (pct === 1)    return 'A';
  if (pct >= 0.75)  return 'B';
  if (pct >= 0.5)   return 'C';
  if (pct >= 0.25)  return 'D';
  return 'F';
}

function httpGet(url) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, { timeout: 5000 }, (res) => {
      res.resume();
      resolve({ status: res.statusCode, headers: res.headers });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('request timeout')); });
  });
}

async function scanEndpoint(baseUrl, endpoint) {
  const { headers } = await httpGet(`${baseUrl}${endpoint}`);

  const present = [];
  const missing = [];
  let score = 0;

  for (const h of SECURITY_HEADERS) {
    if (headers[h.name]) {
      present.push(h.name);
      score += h.weight;
    } else {
      missing.push(h.name);
    }
  }

  return { endpoint, present, missing, score, grade: letterGrade(score) };
}

async function main() {
  const args = process.argv.slice(2);
  const tIdx = args.indexOf('--target');
  const target = tIdx !== -1 ? args[tIdx + 1] : 'http://localhost:3000';

  // Bail out gracefully if server is unreachable
  try {
    await httpGet(`${target}/health`);
  } catch {
    process.stdout.write(JSON.stringify({
      target,
      findings: [],
      summary: { endpoints_scanned: 0, total_findings: 0, grades: [], error: 'server unreachable' },
    }, null, 2) + '\n');
    return;
  }

  const findings = [];
  const grades = [];

  for (const endpoint of ENDPOINTS) {
    try {
      const scan = await scanEndpoint(target, endpoint);
      grades.push({ endpoint: scan.endpoint, grade: scan.grade });

      if (scan.grade !== 'A') {
        findings.push({
          endpoint: scan.endpoint,
          vulnerability_type: 'missing_security_headers',
          evidence: {
            grade: scan.grade,
            missing_headers: scan.missing,
            present_headers: scan.present,
          },
          severity: scan.grade === 'F' ? 'HIGH' : 'MEDIUM',
        });
      }
    } catch (e) {
      process.stderr.write(`Error scanning ${endpoint}: ${e.message}\n`);
    }
  }

  const result = {
    target,
    findings,
    summary: {
      endpoints_scanned: grades.length,
      total_findings: findings.length,
      grades,
    },
  };

  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  process.stderr.write(`\nScanned ${grades.length} endpoint(s) — ${findings.length} finding(s)\n`);
}

main().catch((e) => {
  process.stderr.write(`Fatal: ${e.message}\n`);
  process.exit(1);
});
