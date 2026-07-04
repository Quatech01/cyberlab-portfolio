const { execFile } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);

const TIMEOUT_MS = 30_000;

function isValidHttpUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

// Most tools print only JSON to stdout, but at least one prints a
// human-readable summary to stdout too (after the JSON), instead of stderr.
// Extract just the first balanced {...} object so both styles work.
function extractFirstJsonObject(text) {
  const start = text.indexOf('{');
  if (start === -1) throw new Error('No JSON object found in output');

  let depth = 0;
  for (let i = start; i < text.length; i++) {
    if (text[i] === '{') depth++;
    if (text[i] === '}') {
      depth--;
      if (depth === 0) return JSON.parse(text.slice(start, i + 1));
    }
  }
  throw new Error('Unbalanced JSON object in output');
}

// Runs a project's tool against `target` and parses its JSON stdout.
// Uses execFile with an argument array (never a shell string) so `target`
// can never be interpreted as a shell command, regardless of its content.
async function runTool(toolPath, target) {
  if (!isValidHttpUrl(target)) {
    throw new Error('Target must be a valid http:// or https:// URL');
  }

  const isPython = toolPath.endsWith('.py');
  const pyExe = process.platform === 'win32' ? 'py' : 'python3';
  const interpreter = isPython ? pyExe : process.execPath;

  let stdout;
  try {
    ({ stdout } = await execFileAsync(
      interpreter,
      [toolPath, '--target', target],
      { timeout: TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024 }
    ));
  } catch (err) {
    if (err.killed) {
      throw new Error(`Scan timed out after ${TIMEOUT_MS / 1000}s`);
    }
    // Tools that fail to reach the target still print JSON + exit non-zero
    // in some cases; fall back to whatever stdout was captured.
    stdout = err.stdout || '';
    if (!stdout.trim()) {
      throw new Error(err.stderr || err.message);
    }
  }

  try {
    return extractFirstJsonObject(stdout);
  } catch {
    throw new Error('Tool did not return valid JSON');
  }
}

module.exports = { runTool, isValidHttpUrl };
