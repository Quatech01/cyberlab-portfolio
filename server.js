require('dotenv').config();

const path = require('path');
const express = require('express');
const session = require('express-session');
const { marked } = require('marked');

const projects = require('./lib/projects');
const { checkPassword, requireAuth } = require('./lib/auth');
const { runTool } = require('./lib/runner');

const app = express();
const PORT = process.env.PORT || 4000;

if (!process.env.SESSION_SECRET || !process.env.PORTFOLIO_PASSWORD) {
  console.error(
    'Missing PORTFOLIO_PASSWORD or SESSION_SECRET. Copy .env.example to .env and fill it in.'
  );
  process.exit(1);
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const isProduction = process.env.NODE_ENV === 'production';
if (isProduction) {
  // Render terminates TLS at its proxy; trust it so secure cookies work.
  app.set('trust proxy', 1);
}

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax', secure: isProduction },
  })
);

// ---- Public routes (read-only, no code execution) ----

app.get('/', (req, res) => {
  res.render('index', { projects: projects.listProjects() });
});

app.get('/project/:slug', (req, res) => {
  const project = projects.getProject(req.params.slug);
  if (!project) return res.status(404).send('Project not found');

  const readme = projects.getReadme(project.slug);
  const exampleOutput = projects.getExampleOutput(project.slug);

  res.render('project', {
    project,
    readmeHtml: readme ? marked.parse(readme) : null,
    exampleOutput,
  });
});

// ---- Auth ----

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { password } = req.body;
  if (checkPassword(password || '')) {
    req.session.authenticated = true;
    return res.redirect('/scan');
  }
  res.status(401).render('login', { error: 'Incorrect password' });
});

app.post('/logout', requireAuth, (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// ---- Auth-gated live scanning ----

app.get('/scan', requireAuth, (req, res) => {
  res.render('scan', { projects: projects.listProjects() });
});

app.post('/api/scan', requireAuth, async (req, res) => {
  const { project: slug, target } = req.body || {};

  if (!slug || !projects.isKnownProject(slug)) {
    return res.status(400).json({ error: 'Unknown project' });
  }
  if (!target || typeof target !== 'string') {
    return res.status(400).json({ error: 'Target is required' });
  }

  try {
    const toolPath = projects.getToolPath(slug);
    const result = await runTool(toolPath, target);
    res.json({ ok: true, result });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`CyberLab portfolio running on http://localhost:${PORT}`);
});
