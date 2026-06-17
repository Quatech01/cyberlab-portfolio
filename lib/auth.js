const crypto = require('crypto');

function sha256(value) {
  return crypto.createHash('sha256').update(value, 'utf-8').digest();
}

function checkPassword(submitted) {
  const expected = process.env.PORTFOLIO_PASSWORD;
  if (!expected) return false;
  const a = sha256(submitted);
  const b = sha256(expected);
  return crypto.timingSafeEqual(a, b);
}

function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) {
    return next();
  }
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  return res.redirect('/login');
}

module.exports = { checkPassword, requireAuth };
