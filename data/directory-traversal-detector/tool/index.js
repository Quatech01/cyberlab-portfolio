const http = require('node:http');
const { parseArgs } = require('node:util');

const { values } = parseArgs({
  options: {
    target: { type: 'string', default: 'http://localhost:3000' },
  },
  allowPositionals: false,
});

const TARGET = values.target.replace(/\/$/, '');

const SECRET_MARKER = 'SECRET_DATA';

const PAYLOADS = [
  '../secret/config.txt',
  '../secret/users.txt',
  '..%2Fsecret%2Fconfig.txt',
  '..%2Fsecret%2Fusers.txt',
];

const ENDPOINTS = [
  { path: '/files/unsafe', label: 'Unsafe file server (no path validation)' },
  { path: '/files/safe',   label: 'Safe file server (path.resolve + boundary check)' },
];

function httpGet(url) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.setTimeout(5000, () => {
      req.destroy();
      reject(new Error('request timed out'));
    });
    req.on('error', reject);
  });
}

async function scan() {
  // Verify the target is reachable before probing individual endpoints.
  try {
    await httpGet(`${TARGET}/health`);
  } catch (err) {
    const result = {
      target: TARGET,
      findings: [],
      summary: `Server unreachable: ${err.message}`,
    };
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    process.stderr.write(`[directory-traversal-detector] ${result.summary}\n`);
    return;
  }

  const findings = [];

  for (const endpoint of ENDPOINTS) {
    for (const payload of PAYLOADS) {
      let response;
      try {
        response = await httpGet(`${TARGET}${endpoint.path}?file=${payload}`);
      } catch (_err) {
        continue;
      }

      if (response.status === 200 && response.body.includes(SECRET_MARKER)) {
        findings.push({
          endpoint: endpoint.path,
          vulnerability_type: 'path_traversal',
          evidence: `Payload '${payload}' returned HTTP ${response.status} with secret file content`,
          severity: 'HIGH',
        });
        break; // One confirmed finding per endpoint is sufficient.
      }
    }
  }

  const summary = findings.length > 0
    ? `Found ${findings.length} path traversal vulnerability/vulnerabilities. Affected endpoint(s): ${[...new Set(findings.map(f => f.endpoint))].join(', ')}`
    : 'No path traversal vulnerabilities detected';

  const result = { target: TARGET, findings, summary };
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  process.stderr.write(`[directory-traversal-detector] ${summary}\n`);
}

scan().catch((err) => {
  const result = {
    target: TARGET,
    findings: [],
    summary: `Scanner error: ${err.message}`,
  };
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  process.stderr.write(`[directory-traversal-detector] ${result.summary}\n`);
});
