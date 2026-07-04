// One-time/rerunnable script: for each known project, starts its own demo
// server on a random local port, runs its own tool against itself, and
// saves the JSON output to portfolio/examples/<slug>.json for display on
// the public (no-auth) project pages. All execution here stays localhost-only.

const fs = require('fs');
const path = require('path');
const http = require('http');
const { spawn } = require('child_process');

const projects = require('../lib/projects');
const { runTool } = require('../lib/runner');

function waitForPort(port, retries = 25, delayMs = 300) {
  return new Promise((resolve, reject) => {
    let attempts = 0;
    const check = () => {
      const req = http.get(`http://127.0.0.1:${port}/health`, (res) => {
        if (res.statusCode === 200) return resolve();
        tryAgain();
      });
      req.on('error', tryAgain);
      req.setTimeout(500, () => { req.destroy(); tryAgain(); });
    };
    const tryAgain = () => {
      if (++attempts >= retries) return reject(new Error(`Port ${port} not ready after ${retries} attempts`));
      setTimeout(check, delayMs);
    };
    check();
  });
}

async function captureNodeProject(project) {
  const serverPath = path.join(projects.REPOS_DIR, project.slug, 'server', 'index.js');
  const toolPath = projects.getToolPath(project.slug);

  delete require.cache[require.resolve(serverPath)];
  const { start } = require(serverPath);

  const port = 4100 + Math.floor(Math.random() * 900);
  const server = await start(port);

  try {
    const result = await runTool(toolPath, `http://localhost:${port}`);
    const outPath = path.join(projects.EXAMPLES_DIR, `${project.slug}.json`);
    fs.writeFileSync(outPath, JSON.stringify(result, null, 2));
    console.log(`captured: ${project.slug}`);
  } finally {
    server.close();
  }
}

async function capturePythonProject(project) {
  const serverDir = path.join(projects.REPOS_DIR, project.slug, 'server');
  const toolPath = projects.getToolPath(project.slug);
  const port = 4100 + Math.floor(Math.random() * 900);

  const pyExe = process.platform === 'win32' ? 'py' : 'python3';
  const startCmd = [
    '-c',
    `import sys; sys.path.insert(0, '.'); from main import start; import time; s = start(${port}); time.sleep(60)`,
  ];
  const serverProc = spawn(pyExe, startCmd, {
    cwd: serverDir,
    stdio: 'ignore',
  });

  try {
    await waitForPort(port);
    const result = await runTool(toolPath, `http://127.0.0.1:${port}`);
    const outPath = path.join(projects.EXAMPLES_DIR, `${project.slug}.json`);
    fs.writeFileSync(outPath, JSON.stringify(result, null, 2));
    console.log(`captured: ${project.slug}`);
  } finally {
    serverProc.kill('SIGKILL');
  }
}

async function captureOne(project) {
  if (project.language === 'python') {
    await capturePythonProject(project);
  } else {
    await captureNodeProject(project);
  }
}

async function main() {
  fs.mkdirSync(projects.EXAMPLES_DIR, { recursive: true });

  for (const project of projects.listProjects()) {
    try {
      await captureOne(project);
    } catch (err) {
      console.error(`failed: ${project.slug} — ${err.message}`);
    }
  }
}

main();
