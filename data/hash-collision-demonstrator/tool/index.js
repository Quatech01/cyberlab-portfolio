const crypto = require('crypto');

const args = process.argv.slice(2);
const targetIdx = args.indexOf('--target');
const target = targetIdx !== -1 ? args[targetIdx + 1] : 'http://localhost:3000';

async function fetchJson(url, options = {}) {
  const res = await fetch(url, options);
  return res.json();
}

async function analyzeAlgorithms(baseUrl) {
  const { algorithms } = await fetchJson(`${baseUrl}/algorithms`);
  const findings = [];

  for (const alg of algorithms) {
    if (alg.status === 'broken') {
      findings.push({
        endpoint: '/algorithms',
        vulnerability: `Cryptographically broken hash algorithm: ${alg.name.toUpperCase()}`,
        evidence: `${alg.name.toUpperCase()} (${alg.bits}-bit) — ${alg.reason}`,
        severity: 'critical',
        algorithm: alg.name,
        birthdayBound: alg.birthdayBound,
      });
    } else if (alg.status === 'deprecated') {
      findings.push({
        endpoint: '/algorithms',
        vulnerability: `Deprecated hash algorithm in use: ${alg.name.toUpperCase()}`,
        evidence: `${alg.name.toUpperCase()} (${alg.bits}-bit) — ${alg.reason}`,
        severity: 'high',
        algorithm: alg.name,
        birthdayBound: alg.birthdayBound,
      });
    }
  }

  return { algorithms, findings };
}

async function testVulnerableEndpoint(baseUrl) {
  const testData = 'verify-me';
  const md5Hash = crypto.createHash('md5').update(testData).digest('hex');

  const result = await fetchJson(`${baseUrl}/verify-vulnerable`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ data: testData, expectedHash: md5Hash }),
  });

  const findings = [];
  if (result.algorithm === 'md5') {
    findings.push({
      endpoint: '/verify-vulnerable',
      vulnerability: 'Hash verification uses MD5 — susceptible to collision forgery',
      evidence: result.securityWarning || 'Endpoint computes and compares MD5 hashes',
      severity: 'critical',
      algorithm: 'md5',
    });
  }
  return { result, findings };
}

async function testSafeEndpoint(baseUrl) {
  const testData = 'verify-me';
  const sha256Hash = crypto.createHash('sha256').update(testData).digest('hex');

  return fetchJson(`${baseUrl}/verify-safe`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ data: testData, expectedHash: sha256Hash }),
  });
}

async function testBirthdayDemo(baseUrl) {
  const demo = await fetchJson(`${baseUrl}/birthday-demo`);
  const findings = [];

  if (demo.inputA !== demo.inputB && demo.truncatedHash) {
    findings.push({
      endpoint: '/birthday-demo',
      vulnerability: 'Birthday attack collision proven on MD5 (32-bit prefix)',
      evidence:
        `Two distinct inputs ("${demo.inputA}" and "${demo.inputB}") share MD5 prefix ${demo.truncatedHash} ` +
        `after ${demo.attempts} attempts. Birthday bound for full 128-bit MD5 is ~2^64 operations.`,
      severity: 'critical',
      algorithm: 'md5',
      collisionProven: true,
      attempts: demo.attempts,
    });
  }

  return { demo, findings };
}

async function main() {
  const result = {
    target,
    scanTime: new Date().toISOString(),
    findings: [],
    algorithmSummary: [],
    collisionDemo: null,
    safeEndpointResult: null,
    summary: {},
  };

  try {
    const health = await fetch(`${target}/health`);
    if (!health.ok) throw new Error(`Health check failed: HTTP ${health.status}`);

    const algAnalysis = await analyzeAlgorithms(target);
    result.findings.push(...algAnalysis.findings);
    result.algorithmSummary = algAnalysis.algorithms;

    const vulnTest = await testVulnerableEndpoint(target);
    result.findings.push(...vulnTest.findings);

    const birthdayTest = await testBirthdayDemo(target);
    result.findings.push(...birthdayTest.findings);
    result.collisionDemo = birthdayTest.demo;

    result.safeEndpointResult = await testSafeEndpoint(target);

    result.summary = {
      totalFindings: result.findings.length,
      critical: result.findings.filter((f) => f.severity === 'critical').length,
      high: result.findings.filter((f) => f.severity === 'high').length,
      collisionProven: result.findings.some((f) => f.collisionProven),
      safeAlgorithmsDetected: result.algorithmSummary
        .filter((a) => !a.deprecated)
        .map((a) => a.name),
      weakAlgorithmsDetected: result.findings.map((f) => f.algorithm).filter(Boolean),
    };
  } catch (err) {
    result.error = err.message;
    result.summary = { totalFindings: 0, error: err.message };
  }

  process.stdout.write(JSON.stringify(result, null, 2));
  process.stdout.write('\n\n');

  console.error('===== Hash Algorithm Security Analysis =====');
  console.error(`Target : ${target}`);
  console.error(`Scanned: ${result.scanTime}`);
  console.error(`Findings: ${result.findings.length}`);
  result.findings.forEach((f) => {
    console.error(`  [${f.severity.toUpperCase()}] ${f.vulnerability}`);
    console.error(`    ${f.evidence}`);
  });
  if (result.summary.collisionProven) {
    console.error('\n[!] Birthday attack collision PROVEN: distinct inputs share an MD5 prefix.');
    console.error('    The same mathematical principle scales to full MD5 (2^64 bound).');
    console.error('    SHA-256 requires 2^128 operations — currently infeasible.');
  }
  if (result.error) {
    console.error(`\n[ERROR] ${result.error}`);
  }
}

main().catch((err) => {
  process.stdout.write(JSON.stringify({ target, error: err.message, findings: [], summary: { error: err.message } }, null, 2));
  process.stdout.write('\n');
  process.exit(1);
});
