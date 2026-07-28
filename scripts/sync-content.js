// Snapshots content from the live ../../repos/ + ../../history.json into
// portfolio/data/, so the portfolio app is fully self-contained and can be
// deployed as its own repo without needing the sibling repos/ folder.
//
// Run this whenever repos/ or history.json changes, then commit data/.

const fs = require('fs');
const path = require('path');

const projects = require('../lib/projects');

function main() {
  fs.mkdirSync(projects.DATA_DIR, { recursive: true });

  const history = JSON.parse(fs.readFileSync(projects.SOURCE_HISTORY_PATH, 'utf-8'));
  fs.writeFileSync(
    path.join(projects.DATA_DIR, 'history.json'),
    JSON.stringify(history, null, 2)
  );

  const successful = history.filter((entry) => entry.status === 'success');

  for (const entry of successful) {
    const slug = entry.project;
    const srcDir = path.join(projects.REPOS_DIR, slug);
    const destDir = path.join(projects.DATA_DIR, slug);

    fs.mkdirSync(destDir, { recursive: true });
    fs.copyFileSync(
      path.join(srcDir, 'README.md'),
      path.join(destDir, 'README.md')
    );

    // Security tools have a tool/ directory; fullstack apps do not
    const isFullstack = entry.project_type === 'fullstack_app';
    if (!isFullstack) {
      fs.mkdirSync(path.join(destDir, 'tool'), { recursive: true });
      const toolFile = entry.language === 'python' ? 'main.py' : 'index.js';
      const toolSrc = path.join(srcDir, 'tool', toolFile);
      if (fs.existsSync(toolSrc)) {
        fs.copyFileSync(toolSrc, path.join(destDir, 'tool', toolFile));
      }
    }

    console.log(`synced: ${slug}`);
  }
}

main();
