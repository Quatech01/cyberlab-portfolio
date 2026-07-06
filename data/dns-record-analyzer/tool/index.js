const http = require('node:http');
const { parseArgs } = require('node:util');

const { values } = parseArgs({
  args: process.argv.slice(2),
  options: {
    target: { type: 'string', default: 'http://localhost:3000' }
  }
});

const TARGET = values.target;

function httpGet(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error(`Invalid JSON from ${url}`));
        }
      });
    }).on('error', reject);
  });
}

function analyzeDomain(domain, records) {
  const findings = [];
  const txtRecords = Array.isArray(records.TXT) ? records.TXT : [];

  const spf = txtRecords.find((r) => r.startsWith('v=spf1'));
  if (!spf) {
    findings.push({
      endpoint: `/dns?domain=${domain}&type=TXT`,
      vulnerability_type: 'missing_spf_record',
      evidence: `No SPF TXT record found for ${domain} — any mail server can send on its behalf`,
      severity: 'HIGH'
    });
  } else if (spf.includes('+all')) {
    findings.push({
      endpoint: `/dns?domain=${domain}&type=TXT`,
      vulnerability_type: 'permissive_spf_record',
      evidence: `SPF record for ${domain} uses +all, permitting any server to send mail: "${spf}"`,
      severity: 'HIGH'
    });
  }

  const dmarc = txtRecords.find((r) => r.startsWith('v=DMARC1'));
  if (!dmarc) {
    findings.push({
      endpoint: `/dns?domain=${domain}&type=TXT`,
      vulnerability_type: 'missing_dmarc_record',
      evidence: `No DMARC TXT record found for ${domain} — SPF/DKIM results are not enforced`,
      severity: 'HIGH'
    });
  } else {
    const policyMatch = dmarc.match(/p=(\w+)/);
    if (policyMatch && policyMatch[1] === 'none') {
      findings.push({
        endpoint: `/dns?domain=${domain}&type=TXT`,
        vulnerability_type: 'dmarc_policy_none',
        evidence: `DMARC for ${domain} uses p=none (monitoring only, no enforcement): "${dmarc}"`,
        severity: 'MEDIUM'
      });
    }
  }

  return findings;
}

async function run() {
  try {
    const { domains } = await httpGet(`${TARGET}/domains`);
    const allFindings = [];

    for (const domain of domains) {
      try {
        const encoded = encodeURIComponent(domain);
        const data = await httpGet(`${TARGET}/dns?domain=${encoded}&type=ALL`);
        const findings = analyzeDomain(domain, data.records);
        allFindings.push(...findings);
      } catch (e) {
        process.stderr.write(`  Warning: could not analyze ${domain}: ${e.message}\n`);
      }
    }

    const highCount = allFindings.filter((f) => f.severity === 'HIGH').length;
    const medCount = allFindings.filter((f) => f.severity === 'MEDIUM').length;

    process.stderr.write(`\nDNS Record Analyzer — ${TARGET}\n`);
    process.stderr.write(`Analyzed ${domains.length} domain(s)\n`);
    process.stderr.write(`  HIGH: ${highCount}  MEDIUM: ${medCount}  Total: ${allFindings.length}\n\n`);

    const result = {
      target: TARGET,
      findings: allFindings,
      summary: `Analyzed ${domains.length} domain(s): ${allFindings.length} issue(s) found — ${highCount} HIGH, ${medCount} MEDIUM`
    };

    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } catch (e) {
    process.stderr.write(`Error: could not reach ${TARGET}: ${e.message}\n`);
    const result = {
      target: TARGET,
      findings: [],
      summary: `Could not connect to ${TARGET} — server may be unreachable`
    };
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  }
}

run().catch((e) => {
  const result = {
    target: TARGET,
    findings: [],
    summary: `Unexpected error: ${e.message}`
  };
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
});
