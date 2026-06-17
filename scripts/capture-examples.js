// One-time/rerunnable script: for each known project, starts its own demo
// server on a random local port, runs its own tool against itself, and
// saves the JSON output to portfolio/examples/<slug>.json for display on
// the public (no-auth) project pages. All execution here stays localhost-only.

const fs = require('fs');
const path = require('path');

const projects = require('../lib/projects');
const { runTool } = require('../lib/runner');

async function captureOne(project) {
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
