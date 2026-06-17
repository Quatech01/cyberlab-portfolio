'use strict';

const http = require('http');
const https = require('https');

const args = process.argv.slice(2);
const targetIdx = args.indexOf('--target');
const target = targetIdx !== -1 ? args[targetIdx + 1] : 'http://localhost:3000';

// Calculate Shannon entropy of a byte buffer.
// Returns a value in [0, 8] bits per byte.
// Max (8.0) means every byte value is equally likely — characteristic of
// encrypted or compressed data.  Min (0) means every byte is identical.
function calculateEntropy(buffer) {
  if (buffer.length === 0) return 0;

  const freq = new Uint32Array(256);
  for (const byte of buffer) {
    freq[byte]++;
  }

  let entropy = 0;
  for (const count of freq) {
    if (count === 0) continue;
    const p = count / buffer.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Map entropy to a human-readable risk tier.
function classifyEntropy(entropy) {
  if (entropy < 3.0) {
    return { level: 'LOW',       classification: 'plain_text_or_structured', suspicious: false };
  }
  if (entropy < 6.0) {
    return { level: 'MEDIUM',    classification: 'natural_language_or_code', suspicious: false };
  }
  if (entropy < 7.5) {
    return { level: 'HIGH',      classification: 'compressed_or_binary',     suspicious: true  };
  }
  return   { level: 'VERY_HIGH', classification: 'encrypted_or_packed',      suspicious: true  };
}

// Fetch a URL and return the raw body as a Buffer.
function fetchBuffer(url) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.get(url, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ statusCode: res.statusCode, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    req.setTimeout(5000, () => req.destroy(new Error('Request timed out')));
  });
}

// Fetch a URL and parse the response as JSON.
function fetchJson(url) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error('Server returned non-JSON response')); }
      });
    });
    req.on('error', reject);
    req.setTimeout(5000, () => req.destroy(new Error('Request timed out')));
  });
}

async function main() {
  const result = {
    target,
    timestamp: new Date().toISOString(),
    findings: [],
    summary: {
      total_files_analyzed: 0,
      high_entropy_count: 0,
      suspicious_files: [],
    },
  };

  try {
    const listing = await fetchJson(`${target}/files`);
    const fileList = listing.files || [];

    for (const file of fileList) {
      try {
        const { statusCode, body } = await fetchBuffer(`${target}/files/${file.id}`);
        if (statusCode !== 200) continue;

        const entropy = calculateEntropy(body);
        const tier = classifyEntropy(entropy);

        result.summary.total_files_analyzed++;

        if (tier.suspicious) {
          result.summary.high_entropy_count++;
          result.summary.suspicious_files.push(file.id);

          result.findings.push({
            endpoint:           `/files/${file.id}`,
            vulnerability_type: 'high_entropy_content',
            evidence:           `entropy ${entropy.toFixed(4)} bits/byte exceeds threshold 6.0 — file: ${file.name}`,
            severity:           tier.level === 'VERY_HIGH' ? 'HIGH' : 'MEDIUM',
            entropy:            parseFloat(entropy.toFixed(4)),
            classification:     tier.classification,
            size_bytes:         body.length,
            filename:           file.name,
          });
        }
      } catch (_fileErr) {
        // Individual file fetch errors are non-fatal; continue with remaining files.
      }
    }
  } catch (err) {
    result.error = err.message;
  }

  // JSON output is always written to stdout so callers can parse it reliably.
  console.log(JSON.stringify(result, null, 2));

  // Human-readable summary goes to stderr so it doesn't interfere with JSON parsing.
  process.stderr.write('\n--- File Entropy Analysis ---\n');
  process.stderr.write(`Target:          ${target}\n`);
  process.stderr.write(`Files analyzed:  ${result.summary.total_files_analyzed}\n`);
  process.stderr.write(`Suspicious:      ${result.summary.high_entropy_count}\n`);
  if (result.findings.length > 0) {
    process.stderr.write('Findings:\n');
    for (const f of result.findings) {
      process.stderr.write(`  [${f.severity}] ${f.endpoint}  ${f.entropy} b/B  (${f.classification})\n`);
    }
  }
  if (result.error) {
    process.stderr.write(`Error: ${result.error}\n`);
  }

  process.exit(0);
}

main().catch((err) => {
  const fallback = {
    target,
    timestamp: new Date().toISOString(),
    findings: [],
    error: err.message,
    summary: { total_files_analyzed: 0, high_entropy_count: 0, suspicious_files: [] },
  };
  console.log(JSON.stringify(fallback, null, 2));
  process.exit(1);
});
