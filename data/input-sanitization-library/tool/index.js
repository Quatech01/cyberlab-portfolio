const http = require('http');

const args = process.argv.slice(2);
const targetIdx = args.indexOf('--target');
const target = targetIdx >= 0 ? args[targetIdx + 1] : 'http://localhost:3000';

function request(url, method = 'GET', body = null) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const options = {
      hostname: parsed.hostname,
      port: parseInt(parsed.port, 10) || 80,
      path: parsed.pathname + parsed.search,
      method,
      headers: { 'Content-Type': 'application/json' }
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });

    req.on('error', reject);
    if (body !== null) req.write(JSON.stringify(body));
    req.end();
  });
}

async function scan(baseUrl) {
  const findings = [];
  let scanned = 0;
  let safeCount = 0;

  const XSS_PAYLOAD = '<script>alert("xss")</script>';
  const PATH_PAYLOAD = '../../../etc/passwd';
  const CMD_PAYLOAD = '127.0.0.1; cat /etc/passwd';

  // --- XSS via unescaped HTML output ---
  const vulnHtml = await request(`${baseUrl}/vuln/html`, 'POST', { input: XSS_PAYLOAD });
  scanned++;
  if (typeof vulnHtml.body.output === 'string' && vulnHtml.body.output.includes('<script>')) {
    findings.push({
      endpoint: '/vuln/html',
      vulnerability: 'Cross-Site Scripting (XSS) — unescaped HTML output',
      evidence: `Payload "${XSS_PAYLOAD}" reflected verbatim in output field`,
      severity: 'HIGH'
    });
  }

  const safeHtml = await request(`${baseUrl}/safe/html`, 'POST', { input: XSS_PAYLOAD });
  scanned++;
  if (safeHtml.status === 200 && typeof safeHtml.body.output === 'string' && !safeHtml.body.output.includes('<script>')) {
    safeCount++;
  }

  // --- Path traversal via unsanitized file parameter ---
  const vulnPath = await request(`${baseUrl}/vuln/path?file=${encodeURIComponent(PATH_PAYLOAD)}`);
  scanned++;
  if (typeof vulnPath.body.constructed_path === 'string' && vulnPath.body.constructed_path.includes('..')) {
    findings.push({
      endpoint: '/vuln/path',
      vulnerability: 'Path Traversal — unsanitized file parameter',
      evidence: `Payload "${PATH_PAYLOAD}" produced: ${vulnPath.body.constructed_path}`,
      severity: 'HIGH'
    });
  }

  const safePath = await request(`${baseUrl}/safe/path?file=${encodeURIComponent(PATH_PAYLOAD)}`);
  scanned++;
  if (safePath.status === 403) {
    safeCount++;
  }

  // --- Command injection via unfiltered metacharacters ---
  const vulnCmd = await request(`${baseUrl}/vuln/command`, 'POST', { input: CMD_PAYLOAD });
  scanned++;
  if (typeof vulnCmd.body.constructed_command === 'string' && vulnCmd.body.constructed_command.includes(';')) {
    findings.push({
      endpoint: '/vuln/command',
      vulnerability: 'Command Injection — shell metacharacters accepted',
      evidence: `Payload "${CMD_PAYLOAD}" embedded in: ${vulnCmd.body.constructed_command}`,
      severity: 'CRITICAL'
    });
  }

  const safeCmd = await request(`${baseUrl}/safe/command`, 'POST', { input: CMD_PAYLOAD });
  scanned++;
  if (safeCmd.status === 400) {
    safeCount++;
  }

  return {
    target: baseUrl,
    timestamp: new Date().toISOString(),
    findings,
    summary: {
      endpoints_scanned: scanned,
      vulnerable: findings.length,
      safe: safeCount,
      vulnerabilities_found: findings.length
    }
  };
}

scan(target)
  .then((result) => {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');

    process.stderr.write('\n--- Input Sanitization Scan ---\n');
    process.stderr.write(`Target : ${result.target}\n`);
    process.stderr.write(`Scanned: ${result.summary.endpoints_scanned} endpoints\n`);
    process.stderr.write(`Issues : ${result.summary.vulnerabilities_found} vulnerabilities found\n`);
    process.stderr.write(`Safe   : ${result.summary.safe} endpoint pairs correctly blocked payloads\n\n`);

    for (const f of result.findings) {
      process.stderr.write(`[${f.severity}] ${f.vulnerability}\n`);
      process.stderr.write(`  Endpoint : ${f.endpoint}\n`);
      process.stderr.write(`  Evidence : ${f.evidence}\n\n`);
    }
  })
  .catch((err) => {
    process.stdout.write(JSON.stringify({ error: err.message, target }, null, 2) + '\n');
    process.exit(1);
  });
