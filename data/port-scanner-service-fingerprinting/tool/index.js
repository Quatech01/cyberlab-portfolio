// Port scanner with service fingerprinting.
//
// Technique: connect to each port, send an HTTP probe, collect whatever the
// server sends back (banner or echoed probe), then classify by response shape:
//
//   HTTP  → response starts with "HTTP/"
//   SMTP  → response contains "220 " and "SMTP" (unsolicited greeting)
//   Echo  → response matches our probe text exactly
//   Open  → port open but no identifiable pattern
//
// Usage: node index.js [--target http://localhost:3000] [--range 10]

const net = require('net');

// ── Argument parsing ─────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const targetIdx = args.indexOf('--target');
const rawTarget = targetIdx !== -1 ? args[targetIdx + 1] : 'http://localhost:3000';
const rangeIdx = args.indexOf('--range');
const portRange = rangeIdx !== -1 ? parseInt(args[rangeIdx + 1]) || 10 : 10;

function parseTarget(target) {
  try {
    const url = new URL(target);
    return {
      host: url.hostname || 'localhost',
      basePort: parseInt(url.port) || (url.protocol === 'https:' ? 443 : 80),
    };
  } catch {
    return { host: target, basePort: 80 };
  }
}

// ── TCP probe ────────────────────────────────────────────────────────────────
// Connects to host:port, sends an HTTP HEAD probe, collects all response data.
// SMTP servers send a greeting before we probe — that gets captured too.
const HTTP_PROBE = 'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n';

function probePort(host, port, timeoutMs = 1500) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let banner = '';
    let done = false;

    const finish = (open) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve({ open, banner });
    };

    socket.setTimeout(timeoutMs);
    socket.connect(port, host, () => {
      socket.write(HTTP_PROBE);
    });
    socket.on('data', (chunk) => { banner += chunk.toString(); });
    socket.on('close', () => finish(true));
    socket.on('timeout', () => finish(banner.length > 0 ? true : false));
    socket.on('error', () => finish(false));
  });
}

// ── Service fingerprinting ───────────────────────────────────────────────────
function fingerprintService(banner) {
  // HTTP: server replied with a proper HTTP response
  if (/^HTTP\/\d/.test(banner)) {
    const serverHeader = banner.match(/^Server:\s*(.+)/im);
    return {
      service: 'http',
      version: serverHeader ? serverHeader[1].trim() : 'unknown',
      confidence: 'HIGH',
    };
  }

  // SMTP: server sent a 220 greeting containing ESMTP/SMTP keyword
  if (/220\s/.test(banner) && /SMTP/i.test(banner)) {
    const greetLine = banner.match(/220\s+([^\r\n]+)/);
    return {
      service: 'smtp',
      version: greetLine ? greetLine[1].trim() : 'unknown',
      confidence: 'HIGH',
    };
  }

  // Echo: response is our own probe reflected back
  if (banner.includes(HTTP_PROBE.substring(0, 20))) {
    return {
      service: 'echo',
      version: 'TCP echo (raw)',
      confidence: 'HIGH',
    };
  }

  // Open but unrecognised
  if (banner.length > 0) {
    return { service: 'unknown', version: 'unrecognised banner', confidence: 'LOW' };
  }

  return { service: 'open', version: 'no banner', confidence: 'LOW' };
}

// ── Scan ─────────────────────────────────────────────────────────────────────
async function scan(host, startPort, endPort) {
  const probes = [];
  for (let p = startPort; p <= endPort; p++) {
    probes.push(
      probePort(host, p).then(({ open, banner }) => ({ port: p, open, banner }))
    );
  }

  const results = await Promise.all(probes);
  const findings = [];

  for (const { port, open, banner } of results) {
    if (!open) continue;
    const { service, version, confidence } = fingerprintService(banner);
    findings.push({
      endpoint: `${host}:${port}`,
      port,
      state: 'open',
      vulnerability_type: 'exposed-service',
      service,
      version,
      evidence: banner.substring(0, 200).replace(/\r\n/g, '\\r\\n'),
      confidence,
      severity: service === 'smtp' ? 'MEDIUM' : 'INFO',
    });
  }

  findings.sort((a, b) => a.port - b.port);
  return findings;
}

// ── Main ─────────────────────────────────────────────────────────────────────
(async () => {
  const { host, basePort } = parseTarget(rawTarget);
  const startPort = basePort;
  const endPort = basePort + portRange;

  const output = {
    target: rawTarget,
    host,
    portRange: `${startPort}-${endPort}`,
    scanTime: new Date().toISOString(),
    findings: [],
    summary: {},
  };

  try {
    output.findings = await scan(host, startPort, endPort);

    const open = output.findings.length;
    const closed = endPort - startPort + 1 - open;
    const services = [...new Set(output.findings.map((f) => f.service))];

    output.summary = {
      openPorts: open,
      closedPorts: closed,
      servicesDetected: services,
      riskLevel: services.includes('smtp') ? 'MEDIUM' : open > 3 ? 'MEDIUM' : 'LOW',
    };
  } catch (err) {
    output.error = err.message;
    output.summary = { openPorts: 0, closedPorts: 0, servicesDetected: [], riskLevel: 'ERROR' };
  }

  // JSON output first (parseable by tests and scripts)
  console.log(JSON.stringify(output, null, 2));

  // Human-readable summary follows
  console.log('\n--- Scan Summary ---');
  console.log(`Target : ${rawTarget}`);
  console.log(`Range  : ${output.portRange} (${endPort - startPort + 1} ports)`);
  console.log(`Open   : ${output.summary.openPorts}`);
  output.findings.forEach((f) => {
    console.log(`  ${String(f.port).padEnd(5)} tcp  OPEN  ${f.service.padEnd(8)}  ${f.version}`);
  });
  console.log(`Risk   : ${output.summary.riskLevel}`);
})();
