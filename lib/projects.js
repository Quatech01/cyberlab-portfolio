const fs = require('fs');
const path = require('path');

// REPOS_DIR points at the live sibling repos/ folder — only used by
// scripts/sync-content.js when re-snapshotting locally. The running app
// never reads from it, so portfolio/ is fully self-contained for deployment.
const REPOS_DIR = path.join(__dirname, '..', '..', 'repos');
const SOURCE_HISTORY_PATH = path.join(__dirname, '..', '..', 'history.json');

const DATA_DIR = path.join(__dirname, '..', 'data');
const HISTORY_PATH = path.join(DATA_DIR, 'history.json');
const EXAMPLES_DIR = path.join(__dirname, '..', 'examples');

function loadHistory() {
  const raw = fs.readFileSync(HISTORY_PATH, 'utf-8');
  return JSON.parse(raw).filter((entry) => entry.status === 'success');
}

// All known project slugs, derived from history.json (the test-gated source
// of truth). Used to validate user input before touching the filesystem.
function listProjects() {
  return loadHistory().map((entry) => ({
    slug: entry.project,
    title: entry.title,
    description: entry.description,
    category: entry.category,
    summary: entry.summary,
    repo: entry.repo,
    date: entry.date,
    testsPassed: entry.tests_passed,
    conceptsDemonstrated: entry.concepts_demonstrated,
  }));
}

function isKnownProject(slug) {
  return listProjects().some((p) => p.slug === slug);
}

function getProject(slug) {
  return listProjects().find((p) => p.slug === slug) || null;
}

function getReadme(slug) {
  if (!isKnownProject(slug)) return null;
  const readmePath = path.join(DATA_DIR, slug, 'README.md');
  try {
    return fs.readFileSync(readmePath, 'utf-8');
  } catch {
    return null;
  }
}

function getExampleOutput(slug) {
  if (!isKnownProject(slug)) return null;
  const examplePath = path.join(EXAMPLES_DIR, `${slug}.json`);
  try {
    return JSON.parse(fs.readFileSync(examplePath, 'utf-8'));
  } catch {
    return null;
  }
}

function getToolPath(slug) {
  if (!isKnownProject(slug)) return null;
  return path.join(DATA_DIR, slug, 'tool', 'index.js');
}

module.exports = {
  listProjects,
  isKnownProject,
  getProject,
  getReadme,
  getExampleOutput,
  getToolPath,
  REPOS_DIR,
  SOURCE_HISTORY_PATH,
  DATA_DIR,
  EXAMPLES_DIR,
};
