'use strict';

const args = process.argv.slice(2);
const targetIdx = args.indexOf('--target');
const target = targetIdx !== -1 ? args[targetIdx + 1] : 'http://localhost:3000';

// ── Detection rules ────────────────────────────────────────────────────────────

const SQLI_PATTERNS = [
  /'\s*(OR|AND)\s+'?1'?\s*=\s*'?1/i,
  /UNION\s+SELECT/i,
  /DROP\s+TABLE/i,
  /INSERT\s+INTO/i,
  /;\s*SELECT/i,
  /'\s*--/,
  /xp_cmdshell/i,
  /SLEEP\s*\(/i,
  /WAITFOR\s+DELAY/i,
];

const TRAVERSAL_PATTERNS = [
  /\.\.\//,
  /\.\.\\/,
  /%2e%2e/i,
  /%252e/i,
];

// User-agent strings belonging to well-known security scanners and attack tools
const SUSPICIOUS_UA_PATTERNS = [
  /sqlmap/i,
  /nikto/i,
  /masscan/i,
  /nmap/i,
  /dirbuster/i,
  /gobuster/i,
  /wfuzz/i,
  /burpsuite/i,
  /metasploit/i,
  /havij/i,
  /acunetix/i,
  /nessus/i,
  /wpscan/i,
  /nuclei/i,
];

// Flag any IP that makes > 30 requests within a 60-second sliding window
const RATE_THRESHOLD = 30;
const RATE_WINDOW_MS = 60_000;

// Flag any IP that produces >= 10 consecutive 5xx responses
const ERROR_SPIKE_THRESHOLD = 10;

// ── Main ───────────────────────────────────────────────────────────────────────

async function run() {
  let entries;

  try {
    const res = await fetch(`${target}/logs`);
    if (!res.ok) throw new Error(`HTTP ${res.status} from ${target}/logs`);
    const data = await res.json();
    entries = Array.isArray(data.entries) ? data.entries : [];
  } catch (err) {
    const result = {
      target,
      error: err.message,
      findings: [],
      summary: { total_entries: 0, anomalies_found: 0, risk: 'unknown' },
    };
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    process.exit(0);
  }

  const findings = [];

  // Rule 1 — SQL injection patterns in URL path / query string
  for (const entry of entries) {
    let decoded;
    try {
      decoded = decodeURIComponent(entry.path);
    } catch {
      decoded = entry.path;
    }
    if (SQLI_PATTERNS.some((p) => p.test(decoded))) {
      findings.push({
        type: 'sql_injection_attempt',
        endpoint: entry.path,
        evidence: 'SQL keyword or injection pattern detected in URL',
        severity: 'HIGH',
        ip: entry.ip,
        timestamp: entry.timestamp,
      });
    }
  }

  // Rule 2 — Directory traversal sequences
  for (const entry of entries) {
    let decoded;
    try {
      decoded = decodeURIComponent(entry.path);
    } catch {
      decoded = entry.path;
    }
    if (TRAVERSAL_PATTERNS.some((p) => p.test(decoded))) {
      findings.push({
        type: 'directory_traversal_attempt',
        endpoint: entry.path,
        evidence: 'Path traversal sequence (../ or URL-encoded equivalent) detected',
        severity: 'HIGH',
        ip: entry.ip,
        timestamp: entry.timestamp,
      });
    }
  }

  // Rule 3 — Known scanner / attack-tool user agents
  for (const entry of entries) {
    if (SUSPICIOUS_UA_PATTERNS.some((p) => p.test(entry.userAgent))) {
      findings.push({
        type: 'suspicious_user_agent',
        endpoint: entry.path,
        evidence: `Known scanner or attack tool: ${entry.userAgent}`,
        severity: 'MEDIUM',
        ip: entry.ip,
        timestamp: entry.timestamp,
      });
    }
  }

  // Rule 4 — Request-rate anomaly (sliding window per IP)
  const ipTimestamps = {};
  for (const entry of entries) {
    const t = new Date(entry.timestamp).getTime();
    if (!Number.isNaN(t)) {
      (ipTimestamps[entry.ip] = ipTimestamps[entry.ip] || []).push(t);
    }
  }
  const rateAlerted = new Set();
  for (const [ip, times] of Object.entries(ipTimestamps)) {
    const sorted = times.slice().sort((a, b) => a - b);
    for (let i = 0; i < sorted.length; i++) {
      let count = 0;
      const windowEnd = sorted[i] + RATE_WINDOW_MS;
      for (let j = i; j < sorted.length && sorted[j] <= windowEnd; j++) count++;
      if (count > RATE_THRESHOLD && !rateAlerted.has(ip)) {
        rateAlerted.add(ip);
        findings.push({
          type: 'unusual_request_rate',
          endpoint: '*',
          evidence: `${count} requests within 60 s from ${ip} (threshold: ${RATE_THRESHOLD})`,
          severity: 'MEDIUM',
          ip,
          timestamp: new Date(sorted[i]).toISOString(),
        });
        break;
      }
    }
  }

  // Rule 5 — Error spike: >= ERROR_SPIKE_THRESHOLD consecutive 5xx from one IP
  const errorStreak = {};
  const errorAlerted = new Set();
  for (const entry of entries) {
    const ip = entry.ip;
    if (entry.status >= 500) {
      errorStreak[ip] = (errorStreak[ip] || 0) + 1;
      if (errorStreak[ip] >= ERROR_SPIKE_THRESHOLD && !errorAlerted.has(ip)) {
        errorAlerted.add(ip);
        findings.push({
          type: 'error_spike',
          endpoint: entry.path,
          evidence: `${errorStreak[ip]} consecutive 5xx errors from ${ip}`,
          severity: 'MEDIUM',
          ip,
          timestamp: entry.timestamp,
        });
      }
    } else {
      errorStreak[ip] = 0;
    }
  }

  // ── Build result ─────────────────────────────────────────────────────────────

  const highCount = findings.filter((f) => f.severity === 'HIGH').length;
  const risk = highCount > 0 ? 'HIGH' : findings.length > 0 ? 'MEDIUM' : 'LOW';

  const result = {
    target,
    findings,
    summary: {
      total_entries: entries.length,
      anomalies_found: findings.length,
      risk,
      breakdown: {
        sql_injection: findings.filter((f) => f.type === 'sql_injection_attempt').length,
        directory_traversal: findings.filter((f) => f.type === 'directory_traversal_attempt').length,
        suspicious_ua: findings.filter((f) => f.type === 'suspicious_user_agent').length,
        rate_anomaly: findings.filter((f) => f.type === 'unusual_request_rate').length,
        error_spike: findings.filter((f) => f.type === 'error_spike').length,
      },
    },
  };

  process.stdout.write(JSON.stringify(result, null, 2) + '\n');

  // Human-readable summary on stderr so stdout stays parseable JSON
  process.stderr.write('\n--- Log Anomaly Detector ---\n');
  process.stderr.write(`Target:      ${target}\n`);
  process.stderr.write(`Log entries: ${entries.length}\n`);
  process.stderr.write(`Findings:    ${findings.length}  (risk: ${risk})\n`);
  if (findings.length > 0) {
    process.stderr.write('\nTop findings:\n');
    for (const f of findings.slice(0, 8)) {
      process.stderr.write(`  [${f.severity}] ${f.type} — ${f.evidence}\n`);
    }
  }
}

run();
