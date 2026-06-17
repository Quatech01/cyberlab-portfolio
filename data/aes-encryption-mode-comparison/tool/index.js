'use strict';

const args = process.argv.slice(2);
const targetIdx = args.indexOf('--target');
const target = targetIdx !== -1 ? args[targetIdx + 1] : 'http://localhost:3000';

const TEST_PLAINTEXT = 'Encrypt this secret message.';

const ENCRYPT_ENDPOINTS = [
  '/api/vulnerable/encrypt',
  '/api/deprecated/encrypt',
  '/api/acceptable/encrypt',
  '/api/secure/encrypt'
];

async function postJSON(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return res.json();
}

async function getJSON(url) {
  const res = await fetch(url);
  return res.json();
}

function classifySeverity(modeName, hasIV, hasAuthTag, deterministic) {
  if (!hasIV && deterministic) {
    return {
      severity: 'HIGH',
      issues: ['No IV — identical plaintext always produces identical ciphertext, leaking data patterns']
    };
  }
  if (hasIV && !hasAuthTag && modeName === 'CBC') {
    return {
      severity: 'MEDIUM',
      issues: ['No authentication tag — susceptible to padding oracle attacks and ciphertext bit-flipping']
    };
  }
  if (hasIV && !hasAuthTag) {
    return {
      severity: 'LOW',
      issues: ['No authentication tag — ciphertext integrity is not verified (unauthenticated encryption)']
    };
  }
  return { severity: 'NONE', issues: [] };
}

async function run() {
  // Fail fast with structured output if the server is unreachable
  try {
    await getJSON(`${target}/health`);
  } catch (err) {
    const out = {
      error: `Cannot reach server at ${target}: ${err.message}`,
      target,
      timestamp: new Date().toISOString(),
      findings: [],
      summary: { total_modes_tested: 0, vulnerable_modes: 0, secure_modes: 0, risk_score: 'ERROR' }
    };
    process.stdout.write(JSON.stringify(out, null, 2) + '\n');
    process.exit(1);
  }

  const findings = [];

  for (const endpoint of ENCRYPT_ENDPOINTS) {
    try {
      // Two separate encryptions of the same plaintext to check for determinism
      const r1 = await postJSON(`${target}${endpoint}`, { plaintext: TEST_PLAINTEXT });
      const r2 = await postJSON(`${target}${endpoint}`, { plaintext: TEST_PLAINTEXT });

      const modeName  = r1.mode;
      const hasIV     = !!r1.iv;
      const hasAuthTag = !!r1.authTag;
      const deterministic = r1.ciphertext === r2.ciphertext;

      const { severity, issues } = classifySeverity(modeName, hasIV, hasAuthTag, deterministic);

      findings.push({
        endpoint,
        mode: modeName,
        severity,
        vulnerable: severity !== 'NONE',
        uses_iv: hasIV,
        authenticated: hasAuthTag,
        deterministic,
        issues,
        evidence: !hasIV
          ? `Same plaintext encrypted twice produced identical ciphertext: ${r1.ciphertext.slice(0, 32)}...`
          : `Random IV per encryption: first=${r1.iv.slice(0, 16)}... second=${r2.iv.slice(0, 16)}...`
      });
    } catch (err) {
      findings.push({ endpoint, mode: 'UNKNOWN', severity: 'ERROR', vulnerable: false, error: err.message });
    }
  }

  // ECB pattern-revelation test: two identical 16-byte plaintext blocks should
  // produce two identical 16-byte ciphertext blocks under ECB.
  let patternTest = null;
  try {
    const r = await getJSON(`${target}/demo/ecb-weakness`);
    patternTest = {
      endpoint: '/demo/ecb-weakness',
      ecb_blocks_identical: r.ecb?.blocks_identical,
      evidence: r.ecb?.blocks_identical
        ? `ECB block1 === block2 (${r.ecb.block1}): repeated plaintext blocks reveal structure`
        : 'Unexpected: ECB blocks differ'
    };
  } catch (err) {
    patternTest = { endpoint: '/demo/ecb-weakness', error: err.message };
  }

  const vulnerable = findings.filter(f => f.vulnerable);
  const secure     = findings.filter(f => f.severity === 'NONE');

  const riskScore = vulnerable.some(f => f.severity === 'HIGH')   ? 'HIGH'
    : vulnerable.some(f => f.severity === 'MEDIUM') ? 'MEDIUM'
    : vulnerable.length > 0                         ? 'LOW'
    : 'NONE';

  const result = {
    target,
    timestamp: new Date().toISOString(),
    findings,
    pattern_test: patternTest,
    summary: {
      total_modes_tested: findings.filter(f => f.mode !== 'UNKNOWN').length,
      vulnerable_modes: vulnerable.length,
      secure_modes: secure.length,
      risk_score: riskScore,
      recommendation: 'Use AES-GCM (authenticated encryption) for all new implementations'
    }
  };

  // JSON to stdout — the only thing on stdout so callers can parse it directly
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');

  // Human-readable summary to stderr
  process.stderr.write('\n=== AES Encryption Mode Analysis ===\n');
  for (const f of findings) {
    const tag = f.severity === 'HIGH' ? '[HIGH]   '
      : f.severity === 'MEDIUM' ? '[MEDIUM] '
      : f.severity === 'LOW'    ? '[LOW]    '
      : '[OK]     ';
    const detail = f.issues?.[0] ?? (f.error ?? 'No issues detected');
    process.stderr.write(`${tag} ${f.mode ?? 'UNKNOWN'}: ${detail}\n`);
  }
  if (patternTest?.ecb_blocks_identical) {
    process.stderr.write('\n[PATTERN] ECB reveals identical ciphertext blocks for repeated plaintext blocks.\n');
  }
  process.stderr.write(`\nOverall risk score : ${riskScore}\n`);
  process.stderr.write(`Recommendation     : ${result.summary.recommendation}\n`);
}

run().catch(err => {
  const out = { error: err.message, target, timestamp: new Date().toISOString() };
  process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  process.exit(1);
});
