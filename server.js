const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const multer = require('multer');
const { X509Certificate, randomBytes } = require('crypto');
const forge = require('node-forge');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const cron = require('node-cron');
const tls  = require('tls');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || '/data/certs.db';
const AUTH_USERNAME = process.env.AUTH_USERNAME || 'admin';
const AUTH_PASSWORD = process.env.AUTH_PASSWORD || 'changeme';
if (!process.env.AUTH_PASSWORD || process.env.AUTH_PASSWORD === 'changeme') {
  console.warn('WARNING: AUTH_PASSWORD is not set or is the insecure default "changeme". Set the AUTH_PASSWORD environment variable before going to production.');
}
const SESSION_SECRET = process.env.SESSION_SECRET || randomBytes(32).toString('hex');
if (!process.env.SESSION_SECRET) {
  console.warn('WARNING: SESSION_SECRET is not set. A random secret is being used — all sessions will be invalidated on every restart. Set SESSION_SECRET in your environment.');
}

// Ensure data directory exists
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(DB_PATH);

// Init schema
db.exec(`
  CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    fqdn TEXT NOT NULL,
    expiration_date TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_id INTEGER NOT NULL,
    hostname TEXT NOT NULL,
    responsible_person TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT,
    role TEXT NOT NULL DEFAULT 'viewer',
    auth_provider TEXT NOT NULL DEFAULT 'local',
    entra_oid TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    last_login_at TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS cert_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    restricted INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS cert_group_members (
    group_id INTEGER NOT NULL,
    certificate_id INTEGER NOT NULL,
    PRIMARY KEY (group_id, certificate_id),
    FOREIGN KEY (group_id) REFERENCES cert_groups(id) ON DELETE CASCADE,
    FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS user_group_members (
    group_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    PRIMARY KEY (group_id, user_id),
    FOREIGN KEY (group_id) REFERENCES cert_groups(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS notification_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_id INTEGER NOT NULL,
    expiration_date TEXT NOT NULL,
    threshold_days INTEGER NOT NULL,
    recipient TEXT NOT NULL,
    sent_at TEXT DEFAULT (datetime('now')),
    UNIQUE (certificate_id, expiration_date, threshold_days, recipient)
  );

  CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    permission TEXT NOT NULL DEFAULT 'read',
    active INTEGER NOT NULL DEFAULT 1,
    last_used_at TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT DEFAULT (datetime('now')),
    user_id INTEGER,
    username TEXT,
    action TEXT NOT NULL,
    target TEXT,
    details TEXT,
    ip TEXT
  );

  CREATE TABLE IF NOT EXISTS cert_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    last_checked TEXT,
    last_status TEXT NOT NULL DEFAULT 'pending',
    live_expiry TEXT,
    live_subject TEXT,
    last_error TEXT,
    UNIQUE(certificate_id, url),
    FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE
  );
`);

// Migrations for existing databases
try { db.exec(`ALTER TABLE hosts ADD COLUMN responsible_person TEXT NOT NULL DEFAULT ''`); } catch (_) {}
try { db.exec(`ALTER TABLE certificates ADD COLUMN cert_data TEXT`); } catch (_) {}
try { db.exec(`ALTER TABLE certificates ADD COLUMN password TEXT NOT NULL DEFAULT ''`); } catch (_) {}
try { db.exec(`ALTER TABLE certificates ADD COLUMN note TEXT NOT NULL DEFAULT ''`); } catch (_) {}
try { db.exec(`ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT ''`); } catch (_) {}
try { db.exec(`ALTER TABLE users ADD COLUMN last_login_at TEXT`); } catch (_) {}
try { db.exec(`ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0`); } catch (_) {}
try { db.exec(`CREATE TABLE IF NOT EXISTS cert_groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '', restricted INTEGER NOT NULL DEFAULT 0, created_at TEXT DEFAULT (datetime('now')))`); } catch (_) {}
try { db.exec(`ALTER TABLE cert_groups ADD COLUMN restricted INTEGER NOT NULL DEFAULT 0`); } catch (_) {}
try { db.exec(`CREATE TABLE IF NOT EXISTS cert_group_members (group_id INTEGER NOT NULL, certificate_id INTEGER NOT NULL, PRIMARY KEY (group_id, certificate_id), FOREIGN KEY (group_id) REFERENCES cert_groups(id) ON DELETE CASCADE, FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE)`); } catch (_) {}
try { db.exec(`CREATE TABLE IF NOT EXISTS user_group_members (group_id INTEGER NOT NULL, user_id INTEGER NOT NULL, PRIMARY KEY (group_id, user_id), FOREIGN KEY (group_id) REFERENCES cert_groups(id) ON DELETE CASCADE, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)`); } catch (_) {}
try { db.exec(`CREATE TABLE IF NOT EXISTS notification_log (id INTEGER PRIMARY KEY AUTOINCREMENT, certificate_id INTEGER NOT NULL, expiration_date TEXT NOT NULL, threshold_days INTEGER NOT NULL, recipient TEXT NOT NULL, sent_at TEXT DEFAULT (datetime('now')), UNIQUE (certificate_id, expiration_date, threshold_days, recipient))`); } catch (_) {}
try { db.exec(`CREATE TABLE IF NOT EXISTS api_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, key_prefix TEXT NOT NULL, permission TEXT NOT NULL DEFAULT 'read', active INTEGER NOT NULL DEFAULT 1, last_used_at TEXT, created_at TEXT DEFAULT (datetime('now')))`); } catch (_) {}
try { db.exec(`CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT DEFAULT (datetime('now')), user_id INTEGER, username TEXT, action TEXT NOT NULL, target TEXT, details TEXT, ip TEXT)`); } catch (_) {}
try { db.exec(`CREATE TABLE IF NOT EXISTS cert_urls (id INTEGER PRIMARY KEY AUTOINCREMENT, certificate_id INTEGER NOT NULL, url TEXT NOT NULL, last_checked TEXT, last_status TEXT NOT NULL DEFAULT 'pending', live_expiry TEXT, live_subject TEXT, last_error TEXT, UNIQUE(certificate_id, url), FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE)`); } catch (_) {}

// Seed notification settings from environment variables (only if not already set in DB)
{
  const upsertIfMissing = db.prepare(
    'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING'
  );
  const envSettings = [
    ['smtp_host',              process.env.SMTP_HOST],
    ['smtp_port',              process.env.SMTP_PORT],
    ['smtp_user',              process.env.SMTP_USER],
    ['smtp_pass',              process.env.SMTP_PASS],
    ['smtp_from',              process.env.SMTP_FROM],
    ['smtp_tls',               process.env.SMTP_TLS],
    ['notifications_enabled',  process.env.NOTIFICATIONS_ENABLED],
    ['notify_responsible',     process.env.NOTIFY_RESPONSIBLE],
    ['notify_renewal',         process.env.NOTIFY_RENEWAL],
    ['threshold_1',            process.env.THRESHOLD_1],
    ['threshold_2',            process.env.THRESHOLD_2],
    ['threshold_3',            process.env.THRESHOLD_3],
    ['admin_emails',           process.env.ADMIN_EMAILS],
    ['app_url',                process.env.APP_URL],
  ];
  for (const [key, val] of envSettings) {
    if (val !== undefined) upsertIfMissing.run(key, val);
  }
}

// Seed admin user on first boot if users table is empty
(async () => {
  const count = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  if (count === 0) {
    const hash = await bcrypt.hash(AUTH_PASSWORD, 12);
    db.prepare(
      'INSERT INTO users (username, email, password_hash, role, auth_provider, active) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(AUTH_USERNAME, AUTH_USERNAME + '@localhost', hash, 'admin', 'local', 1);
    console.log(`Seeded admin user "${AUTH_USERNAME}" from environment variables`);
  }
})();

// Ensure default_viewers group always exists
db.prepare(
  `INSERT OR IGNORE INTO cert_groups (name, description, restricted) VALUES ('default_viewers', 'System group — members can view all certificates but cannot download files or retrieve passwords', 1)`
).run();

// Helper: returns true if the user should have restricted view-only access
function isRestrictedViewer(userId, userRole) {
  if (userRole === 'admin' || userRole === 'editor') return false;
  return !!db.prepare(`
    SELECT 1 FROM user_group_members ugm
    JOIN cert_groups cg ON cg.id = ugm.group_id
    WHERE ugm.user_id = ? AND cg.restricted = 1 LIMIT 1
  `).get(userId);
}

// Helper: add a user to default_viewers (safe, silently ignores duplicates)
function addToDefaultViewers(userId) {
  const grp = db.prepare("SELECT id FROM cert_groups WHERE name = 'default_viewers'").get();
  if (grp) {
    try { db.prepare('INSERT OR IGNORE INTO user_group_members (group_id, user_id) VALUES (?, ?)').run(grp.id, userId); } catch (_) {}
  }
}

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 2 * 1024 * 1024 } });

app.use(express.json());

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'
  }
}));

// --- Auth middleware ---
const CHANGE_PASSWORD_EXEMPT = new Set([
  '/api/auth/me', '/api/auth/change-password', '/api/auth/logout', '/api/version'
]);

function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    // Block API calls (except exempt paths) if user must change their password
    if (req.path.startsWith('/api/') && !CHANGE_PASSWORD_EXEMPT.has(req.path)) {
      const user = db.prepare('SELECT must_change_password FROM users WHERE id = ?').get(req.session.userId);
      if (user && user.must_change_password) {
        return res.status(403).json({ error: 'password_change_required' });
      }
    }
    return next();
  }
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
  res.redirect('/login');
}

function requireRole(...roles) {
  return [
    requireAuth,
    (req, res, next) => {
      if (roles.includes(req.session.userRole)) return next();
      res.status(403).json({ error: 'Forbidden' });
    }
  ];
}

// --- Login rate limiting ---
const loginAttempts = new Map(); // ip -> { count, resetAt }
const LOGIN_MAX_ATTEMPTS = 10;
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 minutes

function checkLoginRateLimit(ip) {
  const now = Date.now();
  let entry = loginAttempts.get(ip);
  if (!entry || now > entry.resetAt) {
    entry = { count: 1, resetAt: now + LOGIN_WINDOW_MS };
    loginAttempts.set(ip, entry);
    return true;
  }
  entry.count++;
  return entry.count <= LOGIN_MAX_ATTEMPTS;
}

// Periodically clean up expired entries to avoid memory growth
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of loginAttempts) {
    if (now > entry.resetAt) loginAttempts.delete(ip);
  }
}, LOGIN_WINDOW_MS);

// --- HTML escaping for email templates ---
function htmlEsc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// --- Certificate field validation ---
function validateCertFields(name, fqdn, expiration_date) {
  if (!name || typeof name !== 'string' || name.trim().length === 0 || name.length > 255) {
    return 'name must be a non-empty string under 255 characters';
  }
  if (!fqdn || typeof fqdn !== 'string' || fqdn.trim().length === 0 || fqdn.length > 255) {
    return 'fqdn must be a non-empty string under 255 characters';
  }
  if (!expiration_date || !/^\d{4}-\d{2}-\d{2}$/.test(expiration_date) || isNaN(Date.parse(expiration_date))) {
    return 'expiration_date must be a valid date in YYYY-MM-DD format';
  }
  return null;
}

// --- Audit logging ---
function logEvent(req, action, target = '', details = '') {
  const userId = req.session && req.session.userId ? req.session.userId : null;
  const username = req.session && req.session.username ? req.session.username : 'system';
  const ip = req.socket?.remoteAddress || '';
  try {
    db.prepare('INSERT INTO audit_log (user_id, username, action, target, details, ip) VALUES (?, ?, ?, ?, ?, ?)')
      .run(userId, username, action, target || '', details || '', ip);
  } catch (_) {}
}

// --- Public routes ---

app.get('/login', (req, res) => {
  if (req.session && req.session.userId) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public/login.html'));
});

app.get('/style.css', (req, res) => res.sendFile(path.join(__dirname, 'public/style.css')));

// Version
app.get('/api/version', (req, res) => {
  res.json({ version: require('./package.json').version });
});

// Returns enabled auth providers
app.get('/api/auth/providers', (req, res) => {
  const entraEnabled = db.prepare("SELECT value FROM settings WHERE key = 'entra_enabled'").get();
  const entra = entraEnabled && entraEnabled.value === 'true';
  res.json({ local: true, entra });
});

// Local login
app.post('/api/auth/login', async (req, res) => {
  const clientIp = req.socket?.remoteAddress || '';
  if (!checkLoginRateLimit(clientIp)) {
    return res.status(429).json({ error: 'Too many login attempts. Please try again in 15 minutes.' });
  }

  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });

  // Guard against bcrypt DoS with excessively long passwords
  if (typeof password === 'string' && password.length > 1024) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ? AND auth_provider = ? AND active = 1').get(username, 'local');
  if (!user) {
    logEvent(req, 'auth.login_failed', username, 'invalid credentials');
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const valid = await bcrypt.compare(password, user.password_hash || '');
  if (!valid) {
    logEvent(req, 'auth.login_failed', username, 'invalid credentials');
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.userRole = user.role;
  db.prepare("UPDATE users SET last_login_at = datetime('now') WHERE id = ?").run(user.id);
  res.json({ ok: true });
  logEvent(req, 'auth.login', user.username, `role:${user.role}`);
});

app.post('/api/auth/logout', (req, res) => {
  logEvent(req, 'auth.logout', req.session.username || '');
  req.session.destroy(() => res.json({ ok: true }));
});

// Entra ID login — redirect to Microsoft
app.get('/api/auth/entra/login', async (req, res) => {
  try {
    const tenantRow = db.prepare("SELECT value FROM settings WHERE key = 'entra_tenant_id'").get();
    const clientRow = db.prepare("SELECT value FROM settings WHERE key = 'entra_client_id'").get();
    const secretRow = db.prepare("SELECT value FROM settings WHERE key = 'entra_client_secret'").get();
    const redirectRow = db.prepare("SELECT value FROM settings WHERE key = 'entra_redirect_uri'").get();
    const enabledRow = db.prepare("SELECT value FROM settings WHERE key = 'entra_enabled'").get();

    if (!enabledRow || enabledRow.value !== 'true') {
      return res.redirect('/login?error=entra_disabled');
    }
    if (!tenantRow || !clientRow || !secretRow || !redirectRow) {
      return res.redirect('/login?error=entra_not_configured');
    }

    let msal;
    try { msal = require('@azure/msal-node'); } catch {
      return res.redirect('/login?error=entra_failed');
    }

    const msalApp = new msal.ConfidentialClientApplication({
      auth: {
        clientId: clientRow.value,
        clientSecret: secretRow.value,
        authority: `https://login.microsoftonline.com/${tenantRow.value}`
      }
    });

    const state = randomBytes(16).toString('hex');
    req.session.entraState = state;

    const authUrl = await msalApp.getAuthCodeUrl({
      scopes: ['openid', 'profile', 'email'],
      redirectUri: redirectRow.value,
      state
    });

    res.redirect(authUrl);
  } catch (e) {
    console.error('Entra login error:', e);
    res.redirect('/login?error=entra_failed');
  }
});

// Entra ID callback
app.get('/api/auth/entra/callback', async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) {
      console.error('Entra callback error from Microsoft:', error);
      return res.redirect('/login?error=entra_failed');
    }

    if (!state || state !== req.session.entraState) {
      return res.redirect('/login?error=invalid_state');
    }
    req.session.entraState = null;

    const tenantRow = db.prepare("SELECT value FROM settings WHERE key = 'entra_tenant_id'").get();
    const clientRow = db.prepare("SELECT value FROM settings WHERE key = 'entra_client_id'").get();
    const secretRow = db.prepare("SELECT value FROM settings WHERE key = 'entra_client_secret'").get();
    const redirectRow = db.prepare("SELECT value FROM settings WHERE key = 'entra_redirect_uri'").get();

    let msal;
    try { msal = require('@azure/msal-node'); } catch {
      return res.redirect('/login?error=entra_failed');
    }

    const msalApp = new msal.ConfidentialClientApplication({
      auth: {
        clientId: clientRow.value,
        clientSecret: secretRow.value,
        authority: `https://login.microsoftonline.com/${tenantRow.value}`
      }
    });

    const tokenResponse = await msalApp.acquireTokenByCode({
      code,
      scopes: ['openid', 'profile', 'email'],
      redirectUri: redirectRow.value
    });

    const oid = tokenResponse.uniqueId || tokenResponse.account?.homeAccountId;
    const email = tokenResponse.account?.username || '';
    const name = tokenResponse.account?.name || email.split('@')[0] || 'entra_user';

    // Find or create user
    let user = db.prepare('SELECT * FROM users WHERE entra_oid = ?').get(oid);
    if (!user) {
      // Try to find by email
      user = db.prepare('SELECT * FROM users WHERE email = ? AND auth_provider = ?').get(email, 'entra');
    }
    if (!user) {
      // Create new Entra user with viewer role
      const safeUsername = name.replace(/[^a-zA-Z0-9._-]/g, '_').toLowerCase();
      let username = safeUsername;
      let suffix = 1;
      while (db.prepare('SELECT id FROM users WHERE username = ?').get(username)) {
        username = safeUsername + suffix++;
      }
      const insertedId = db.prepare(
        'INSERT INTO users (username, email, password_hash, role, auth_provider, entra_oid, active) VALUES (?, ?, ?, ?, ?, ?, ?)'
      ).run(username, email, null, 'viewer', 'entra', oid, 1).lastInsertRowid;
      addToDefaultViewers(insertedId);
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(insertedId);
    } else {
      // Update OID if needed
      if (!user.entra_oid) {
        db.prepare('UPDATE users SET entra_oid = ? WHERE id = ?').run(oid, user.id);
      }
    }

    if (!user.active) {
      return res.redirect('/login?error=account_disabled');
    }

    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.userRole = user.role;
    db.prepare("UPDATE users SET last_login_at = datetime('now') WHERE id = ?").run(user.id);
    res.redirect('/');
    logEvent(req, 'auth.entra_login', user.username, `role:${user.role}`);
  } catch (e) {
    console.error('Entra callback error:', e);
    res.redirect('/login?error=entra_failed');
  }
});

// Auth info (requires auth)
app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, username, display_name, email, role, must_change_password FROM users WHERE id = ?').get(req.session.userId);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  res.json({ ...user, restricted: isRestrictedViewer(req.session.userId, req.session.userRole) });
});

app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  const { new_password } = req.body;
  if (!new_password || new_password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  if (new_password.length > 1024) {
    return res.status(400).json({ error: 'Password must be under 1024 characters' });
  }
  const hash = await bcrypt.hash(new_password, 12);
  db.prepare('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?').run(hash, req.session.userId);
  logEvent(req, 'user.change_password', req.session.username, 'self');
  res.json({ ok: true });
});

// --- User management routes (admin only) ---

app.get('/api/users', ...requireRole('admin'), (req, res) => {
  const users = db.prepare('SELECT id, username, display_name, email, role, auth_provider, active, last_login_at, created_at FROM users ORDER BY created_at ASC').all();
  res.json(users);
});

app.post('/api/users', ...requireRole('admin'), async (req, res) => {
  const { username, display_name = '', email, password, role, auth_provider = 'local', active = 1 } = req.body;
  if (!username || !email || !role) {
    return res.status(400).json({ error: 'username, email, and role are required' });
  }
  if (!['admin', 'editor', 'viewer'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  if (auth_provider === 'local' && !password) {
    return res.status(400).json({ error: 'Password is required for local users' });
  }
  if (password && password.length > 1024) {
    return res.status(400).json({ error: 'Password must be under 1024 characters' });
  }

  try {
    const password_hash = password ? await bcrypt.hash(password, 12) : null;
    const mustChange = auth_provider === 'local' ? 1 : 0;
    const info = db.prepare(
      'INSERT INTO users (username, display_name, email, password_hash, role, auth_provider, active, must_change_password) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(username, display_name, email, password_hash, role, auth_provider, active ? 1 : 0, mustChange);
    const user = db.prepare('SELECT id, username, display_name, email, role, auth_provider, active, last_login_at, created_at FROM users WHERE id = ?').get(info.lastInsertRowid);
    if (user.role !== 'admin') addToDefaultViewers(user.id);
    res.status(201).json(user);
    logEvent(req, 'user.create', user.username, `role:${user.role}`);
    sendWelcomeEmail(user.username, user.display_name || '', user.email, password || null, user.role, getSetting('app_url')).catch(err =>
      console.error('[notify] Welcome email error:', err.message)
    );
  } catch (e) {
    if (e.message && e.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }
    throw e;
  }
});

app.put('/api/users/:id', ...requireRole('admin'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { username, display_name, email, password, role, active } = req.body;

  const existing = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'User not found' });

  // Prevent demoting the last admin
  if (existing.role === 'admin' && role && role !== 'admin') {
    const adminCount = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND active = 1").get().c;
    if (adminCount <= 1) {
      return res.status(400).json({ error: 'Cannot demote the last admin user' });
    }
  }

  // Prevent deactivating the last admin
  if (existing.role === 'admin' && active === 0) {
    const adminCount = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND active = 1").get().c;
    if (adminCount <= 1) {
      return res.status(400).json({ error: 'Cannot deactivate the last admin user' });
    }
  }

  try {
    const newUsername = username !== undefined ? username : existing.username;
    const newDisplayName = display_name !== undefined ? display_name : existing.display_name;
    const newEmail = email !== undefined ? email : existing.email;
    const newRole = role !== undefined ? role : existing.role;
    const newActive = active !== undefined ? (active ? 1 : 0) : existing.active;
    let newHash = existing.password_hash;
    if (password) {
      newHash = await bcrypt.hash(password, 12);
    }

    db.prepare(
      'UPDATE users SET username = ?, display_name = ?, email = ?, password_hash = ?, role = ?, active = ? WHERE id = ?'
    ).run(newUsername, newDisplayName, newEmail, newHash, newRole, newActive, id);

    const updated = db.prepare('SELECT id, username, display_name, email, role, auth_provider, active, last_login_at, created_at FROM users WHERE id = ?').get(id);
    res.json(updated);
    logEvent(req, 'user.update', updated.username, `role:${updated.role},active:${updated.active}`);
  } catch (e) {
    if (e.message && e.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }
    throw e;
  }
});

// PATCH /api/users/:id/active — quick enable/disable toggle (admin only)
app.patch('/api/users/:id/active', ...requireRole('admin'), (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { active } = req.body;
  if (active === undefined) return res.status(400).json({ error: 'active is required' });

  if (id === req.session.userId) {
    return res.status(400).json({ error: 'You cannot disable your own account' });
  }

  const user = db.prepare('SELECT id, username, role, active FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (!active && user.role === 'admin') {
    const adminCount = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND active = 1").get().c;
    if (adminCount <= 1) return res.status(400).json({ error: 'Cannot disable the last active admin' });
  }

  const newActive = active ? 1 : 0;
  db.prepare('UPDATE users SET active = ? WHERE id = ?').run(newActive, id);
  logEvent(req, 'user.update', user.username, `active:${newActive}`);
  res.json({ ok: true, active: newActive });
});

// GET /api/users/suggestions — username + email for autocomplete (any authenticated user)
app.get('/api/users/suggestions', requireAuth, (req, res) => {
  const users = db.prepare(
    "SELECT username, display_name, email FROM users WHERE active = 1 ORDER BY username ASC"
  ).all();
  res.json(users);
});

app.delete('/api/users/:id', ...requireRole('admin'), (req, res) => {
  const id = parseInt(req.params.id, 10);

  // Prevent deleting own account
  if (id === req.session.userId) {
    return res.status(400).json({ error: 'You cannot delete your own account' });
  }

  const existing = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'User not found' });

  // Prevent deleting the last admin
  if (existing.role === 'admin') {
    const adminCount = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND active = 1").get().c;
    if (adminCount <= 1) {
      return res.status(400).json({ error: 'Cannot delete the last admin user' });
    }
  }

  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  logEvent(req, 'user.delete', existing.username, `role:${existing.role}`);
  res.status(204).end();
});

// --- Settings routes (admin only) ---

app.get('/api/settings/entra', ...requireRole('admin'), (req, res) => {
  const keys = ['entra_enabled', 'entra_tenant_id', 'entra_client_id', 'entra_client_secret', 'entra_redirect_uri'];
  const result = {};
  for (const key of keys) {
    const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
    if (key === 'entra_client_secret' && row && row.value) {
      result[key] = '••••••••';
    } else {
      result[key] = row ? row.value : '';
    }
  }
  res.json(result);
});

app.put('/api/settings/entra', ...requireRole('admin'), (req, res) => {
  const { entra_enabled, entra_tenant_id, entra_client_id, entra_client_secret, entra_redirect_uri } = req.body;

  const upsert = db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value');

  const tx = db.transaction(() => {
    if (entra_enabled !== undefined) upsert.run('entra_enabled', entra_enabled ? 'true' : 'false');
    if (entra_tenant_id !== undefined) upsert.run('entra_tenant_id', entra_tenant_id);
    if (entra_client_id !== undefined) upsert.run('entra_client_id', entra_client_id);
    // Only update secret if it's not the mask
    if (entra_client_secret !== undefined && entra_client_secret !== '••••••••') {
      upsert.run('entra_client_secret', entra_client_secret);
    }
    if (entra_redirect_uri !== undefined) upsert.run('entra_redirect_uri', entra_redirect_uri);
  });
  tx();

  logEvent(req, 'settings.entra_update', '', 'Entra ID settings updated');
  res.json({ ok: true });
});

// GET /api/users/:id/groups — list groups the user belongs to
app.get('/api/users/:id/groups', ...requireRole('admin'), (req, res) => {
  const uid = parseInt(req.params.id, 10);
  const groups = db.prepare(`
    SELECT g.id, g.name FROM cert_groups g
    JOIN user_group_members ugm ON ugm.group_id = g.id
    WHERE ugm.user_id = ? ORDER BY g.name ASC
  `).all(uid);
  res.json(groups);
});

// PUT /api/users/:id/groups — replace group memberships for a user (admin only)
app.put('/api/users/:id/groups', ...requireRole('admin'), (req, res) => {
  const uid = parseInt(req.params.id, 10);
  const { group_ids = [] } = req.body;
  if (!db.prepare('SELECT 1 FROM users WHERE id = ?').get(uid)) {
    return res.status(404).json({ error: 'User not found' });
  }
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM user_group_members WHERE user_id = ?').run(uid);
    for (const gid of group_ids) {
      try { db.prepare('INSERT INTO user_group_members (group_id, user_id) VALUES (?, ?)').run(gid, uid); } catch (_) {}
    }
  });
  tx();
  res.json({ ok: true });
});

// --- Group management routes ---

// GET /api/groups — list all groups with counts
app.get('/api/groups', requireAuth, (req, res) => {
  const groups = db.prepare(`
    SELECT g.id, g.name, g.description, g.restricted, g.created_at,
      (SELECT COUNT(*) FROM user_group_members WHERE group_id = g.id) AS user_count,
      (SELECT COUNT(*) FROM cert_group_members WHERE group_id = g.id) AS cert_count
    FROM cert_groups g ORDER BY g.name ASC
  `).all();
  res.json(groups);
});

// POST /api/groups — create group (admin only)
app.post('/api/groups', ...requireRole('admin'), (req, res) => {
  const { name, description = '' } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'name is required' });
  try {
    const info = db.prepare('INSERT INTO cert_groups (name, description) VALUES (?, ?)').run(name.trim(), description);
    const group = db.prepare('SELECT * FROM cert_groups WHERE id = ?').get(info.lastInsertRowid);
    res.status(201).json({ ...group, user_count: 0, cert_count: 0 });
    logEvent(req, 'group.create', group.name);
  } catch (e) {
    if (e.message && e.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'A group with that name already exists' });
    }
    throw e;
  }
});

// PUT /api/groups/:id — update group (admin only)
app.put('/api/groups/:id', ...requireRole('admin'), (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { name, description } = req.body;
  const existing = db.prepare('SELECT * FROM cert_groups WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'Group not found' });

  const newName = name !== undefined ? name.trim() : existing.name;
  const newDesc = description !== undefined ? description : existing.description;

  // Protect the system group name
  if (existing.restricted && name !== undefined && name.trim() !== existing.name) {
    return res.status(400).json({ error: 'The name of a restricted system group cannot be changed' });
  }

  try {
    db.prepare('UPDATE cert_groups SET name = ?, description = ? WHERE id = ?').run(newName, newDesc, id);
    const updated = db.prepare(`
      SELECT g.id, g.name, g.description, g.restricted, g.created_at,
        (SELECT COUNT(*) FROM user_group_members WHERE group_id = g.id) AS user_count,
        (SELECT COUNT(*) FROM cert_group_members WHERE group_id = g.id) AS cert_count
      FROM cert_groups g WHERE g.id = ?
    `).get(id);
    res.json(updated);
    logEvent(req, 'group.update', updated.name);
  } catch (e) {
    if (e.message && e.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'A group with that name already exists' });
    }
    throw e;
  }
});

// DELETE /api/groups/:id — delete group (admin only)
app.delete('/api/groups/:id', ...requireRole('admin'), (req, res) => {
  const id = parseInt(req.params.id, 10);
  const existing = db.prepare('SELECT * FROM cert_groups WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'Group not found' });
  if (existing.restricted) return res.status(400).json({ error: 'System groups cannot be deleted' });
  db.prepare('DELETE FROM cert_groups WHERE id = ?').run(id);
  logEvent(req, 'group.delete', existing.name);
  res.status(204).end();
});

// GET /api/groups/:id/users — list users in group
app.get('/api/groups/:id/users', requireAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const users = db.prepare(`
    SELECT u.id, u.username, u.email, u.role
    FROM users u
    JOIN user_group_members ugm ON ugm.user_id = u.id
    WHERE ugm.group_id = ?
    ORDER BY u.username ASC
  `).all(id);
  res.json(users);
});

// PUT /api/groups/:id/users — replace user list (admin only)
app.put('/api/groups/:id/users', ...requireRole('admin'), (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { user_ids = [] } = req.body;
  const existing = db.prepare('SELECT * FROM cert_groups WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'Group not found' });

  const tx = db.transaction(() => {
    db.prepare('DELETE FROM user_group_members WHERE group_id = ?').run(id);
    for (const uid of user_ids) {
      try { db.prepare('INSERT INTO user_group_members (group_id, user_id) VALUES (?, ?)').run(id, uid); } catch (_) {}
    }
  });
  tx();

  const users = db.prepare(`
    SELECT u.id, u.username, u.email, u.role
    FROM users u
    JOIN user_group_members ugm ON ugm.user_id = u.id
    WHERE ugm.group_id = ?
    ORDER BY u.username ASC
  `).all(id);
  res.json(users);
});

// GET /api/groups/:id/certs — list cert ids in group
app.get('/api/groups/:id/certs', requireAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const certs = db.prepare(`
    SELECT c.id, c.name, c.fqdn
    FROM certificates c
    JOIN cert_group_members cgm ON cgm.certificate_id = c.id
    WHERE cgm.group_id = ?
    ORDER BY c.name ASC
  `).all(id);
  res.json(certs);
});

// PUT /api/groups/:id/certs — replace cert list (admin only)
app.put('/api/groups/:id/certs', ...requireRole('admin'), (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { cert_ids = [] } = req.body;
  const existing = db.prepare('SELECT * FROM cert_groups WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'Group not found' });

  const tx = db.transaction(() => {
    db.prepare('DELETE FROM cert_group_members WHERE group_id = ?').run(id);
    for (const cid of cert_ids) {
      try { db.prepare('INSERT INTO cert_group_members (group_id, certificate_id) VALUES (?, ?)').run(id, cid); } catch (_) {}
    }
  });
  tx();

  const certs = db.prepare(`
    SELECT c.id, c.name, c.fqdn
    FROM certificates c
    JOIN cert_group_members cgm ON cgm.certificate_id = c.id
    WHERE cgm.group_id = ?
    ORDER BY c.name ASC
  `).all(id);
  res.json(certs);
});

// --- API Key middleware ---

function requireApiKey(permission = 'read') {
  return (req, res, next) => {
    const raw = req.headers['x-api-key'] ||
      (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
    if (!raw) return res.status(401).json({ error: 'API key required. Provide X-API-Key header.' });

    const hash = require('crypto').createHash('sha256').update(raw).digest('hex');
    const key = db.prepare('SELECT * FROM api_keys WHERE key_hash = ? AND active = 1').get(hash);
    if (!key) return res.status(401).json({ error: 'Invalid or inactive API key' });

    if (permission === 'readwrite' && key.permission === 'read') {
      return res.status(403).json({ error: 'This API key is read-only' });
    }

    db.prepare("UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?").run(key.id);
    req.apiKey = key;
    next();
  };
}

// --- API v1 (external, API key auth) ---

const certListQuery = () => db.prepare(`
  SELECT c.id, c.name, c.fqdn, c.expiration_date, c.password, c.note, c.created_at,
         CASE WHEN c.cert_data IS NOT NULL AND c.cert_data != '' THEN 1 ELSE 0 END AS has_cert,
         (SELECT GROUP_CONCAT(h.hostname || char(31) || h.responsible_person, '||')
          FROM hosts h WHERE h.certificate_id = c.id) AS hosts_raw,
         (SELECT GROUP_CONCAT(cg.id || char(31) || cg.name, '||')
          FROM cert_group_members cgm
          JOIN cert_groups cg ON cg.id = cgm.group_id
          WHERE cgm.certificate_id = c.id) AS groups_raw,
         (SELECT GROUP_CONCAT(cu.id || char(31) || cu.url || char(31) || cu.last_status, '||')
          FROM cert_urls cu WHERE cu.certificate_id = c.id) AS urls_raw
  FROM certificates c ORDER BY c.expiration_date ASC
`);

function parseCertRows(rows) {
  return rows.map(c => ({
    ...c,
    hosts: c.hosts_raw
      ? c.hosts_raw.split('||').map(s => { const [hostname, responsible_person] = s.split('\x1f'); return { hostname, responsible_person: responsible_person || '' }; })
      : [],
    groups: c.groups_raw
      ? c.groups_raw.split('||').map(s => { const [id, name] = s.split('\x1f'); return { id: parseInt(id, 10), name }; })
      : [],
    urls: c.urls_raw
      ? c.urls_raw.split('||').map(s => { const [id, url, last_status] = s.split('\x1f'); return { id: parseInt(id, 10), url, last_status }; })
      : [],
    hosts_raw: undefined,
    groups_raw: undefined,
    urls_raw: undefined,
  }));
}

app.get('/api/v1/certificates', requireApiKey('read'), (req, res) => {
  res.json(parseCertRows(certListQuery().all()));
});

app.get('/api/v1/certificates/:id', requireApiKey('read'), (req, res) => {
  const cert = db.prepare('SELECT * FROM certificates WHERE id = ?').get(req.params.id);
  if (!cert) return res.status(404).json({ error: 'Not found' });
  const hosts = db.prepare('SELECT hostname, responsible_person FROM hosts WHERE certificate_id = ?').all(req.params.id);
  const groups = db.prepare('SELECT cg.id, cg.name FROM cert_groups cg JOIN cert_group_members cgm ON cgm.group_id = cg.id WHERE cgm.certificate_id = ?').all(req.params.id);
  res.json({ ...cert, has_cert: !!cert.cert_data, cert_data: undefined, hosts, groups });
});

app.post('/api/v1/certificates', requireApiKey('readwrite'), (req, res) => {
  const { name, fqdn, expiration_date, password = '', note = '', hosts = [], group_ids = [] } = req.body;
  if (!name || !fqdn || !expiration_date) return res.status(400).json({ error: 'name, fqdn, and expiration_date are required' });

  const insert = db.prepare('INSERT INTO certificates (name, fqdn, expiration_date, password, note, cert_data) VALUES (?, ?, ?, ?, ?, ?)');
  const insertHost = db.prepare('INSERT INTO hosts (certificate_id, hostname, responsible_person) VALUES (?, ?, ?)');
  const insertGroupMember = db.prepare('INSERT OR IGNORE INTO cert_group_members (group_id, certificate_id) VALUES (?, ?)');

  const certId = db.transaction(() => {
    const id = insert.run(name, fqdn, expiration_date, password, note, null).lastInsertRowid;
    for (const h of hosts) { if (h.hostname?.trim()) insertHost.run(id, h.hostname.trim(), h.responsible_person || ''); }
    for (const gid of group_ids) { try { insertGroupMember.run(gid, id); } catch (_) {} }
    return id;
  })();

  const cert = db.prepare('SELECT id, name, fqdn, expiration_date, password, note, created_at FROM certificates WHERE id = ?').get(certId);
  const hostRows = db.prepare('SELECT hostname, responsible_person FROM hosts WHERE certificate_id = ?').all(certId);
  res.status(201).json({ ...cert, hosts: hostRows });
  db.prepare("INSERT INTO audit_log (username, action, target, details, ip) VALUES (?, ?, ?, ?, ?)").run(`apikey:${req.apiKey.name}`, 'cert.create', cert.name, `fqdn:${cert.fqdn}`, req.socket?.remoteAddress || '');
});

app.put('/api/v1/certificates/:id', requireApiKey('readwrite'), async (req, res) => {
  const { name, fqdn, expiration_date, password = '', note = '', hosts = [], group_ids = [] } = req.body;
  const id = req.params.id;
  const existing = db.prepare('SELECT * FROM certificates WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'Not found' });
  const oldExpiry = existing.expiration_date;

  const update = db.prepare('UPDATE certificates SET name = ?, fqdn = ?, expiration_date = ?, password = ?, note = ? WHERE id = ?');
  const deleteHosts = db.prepare('DELETE FROM hosts WHERE certificate_id = ?');
  const insertHost = db.prepare('INSERT INTO hosts (certificate_id, hostname, responsible_person) VALUES (?, ?, ?)');
  const deleteGroups = db.prepare('DELETE FROM cert_group_members WHERE certificate_id = ?');
  const insertGroup = db.prepare('INSERT OR IGNORE INTO cert_group_members (group_id, certificate_id) VALUES (?, ?)');

  db.transaction(() => {
    update.run(name, fqdn, expiration_date, password, note, id);
    deleteHosts.run(id);
    for (const h of hosts) { if (h.hostname?.trim()) insertHost.run(id, h.hostname.trim(), h.responsible_person || ''); }
    deleteGroups.run(id);
    for (const gid of group_ids) { try { insertGroup.run(gid, id); } catch (_) {} }
  })();

  const updated = db.prepare('SELECT id, name, fqdn, expiration_date, password, note, created_at FROM certificates WHERE id = ?').get(id);
  const hostRows = db.prepare('SELECT hostname, responsible_person FROM hosts WHERE certificate_id = ?').all(id);
  res.json({ ...updated, hosts: hostRows });
  db.prepare("INSERT INTO audit_log (username, action, target, details, ip) VALUES (?, ?, ?, ?, ?)").run(`apikey:${req.apiKey.name}`, 'cert.update', updated.name, `fqdn:${updated.fqdn}`, req.socket?.remoteAddress || '');
  if (expiration_date && expiration_date > oldExpiry) {
    sendRenewalNotification(id, updated.name, updated.fqdn, oldExpiry, expiration_date).catch(() => {});
    runUrlChecksForCert(id).catch(() => {});
  }
});

app.delete('/api/v1/certificates/:id', requireApiKey('readwrite'), (req, res) => {
  const cert = db.prepare('SELECT * FROM certificates WHERE id = ?').get(req.params.id);
  if (!cert) return res.status(404).json({ error: 'Not found' });
  db.prepare('DELETE FROM certificates WHERE id = ?').run(req.params.id);
  db.prepare("INSERT INTO audit_log (username, action, target, details, ip) VALUES (?, ?, ?, ?, ?)").run(`apikey:${req.apiKey.name}`, 'cert.delete', cert.name, `fqdn:${cert.fqdn}`, req.socket?.remoteAddress || '');
  res.status(204).end();
});

app.get('/api/v1/groups', requireApiKey('read'), (req, res) => {
  res.json(db.prepare('SELECT id, name, description FROM cert_groups ORDER BY name ASC').all());
});

// --- API Key management (session-auth, admin only) ---

app.get('/api/apikeys', ...requireRole('admin'), (req, res) => {
  const keys = db.prepare('SELECT id, name, key_prefix, permission, active, last_used_at, created_at FROM api_keys ORDER BY created_at DESC').all();
  res.json(keys);
});

app.post('/api/apikeys', ...requireRole('admin'), (req, res) => {
  const { name, permission = 'read' } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'name is required' });
  if (!['read', 'readwrite'].includes(permission)) return res.status(400).json({ error: 'permission must be read or readwrite' });

  const rawKey = 'cmm_' + require('crypto').randomBytes(24).toString('hex');
  const hash = require('crypto').createHash('sha256').update(rawKey).digest('hex');
  const prefix = rawKey.slice(0, 12);

  const info = db.prepare('INSERT INTO api_keys (name, key_hash, key_prefix, permission) VALUES (?, ?, ?, ?)').run(name.trim(), hash, prefix, permission);
  logEvent(req, 'apikey.create', name.trim(), `permission:${permission}`);
  res.status(201).json({ id: info.lastInsertRowid, name: name.trim(), key: rawKey, key_prefix: prefix, permission, active: 1, created_at: new Date().toISOString() });
});

app.put('/api/apikeys/:id', ...requireRole('admin'), (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { active } = req.body;
  const key = db.prepare('SELECT * FROM api_keys WHERE id = ?').get(id);
  if (!key) return res.status(404).json({ error: 'Not found' });
  db.prepare('UPDATE api_keys SET active = ? WHERE id = ?').run(active ? 1 : 0, id);
  logEvent(req, 'apikey.update', key.name, `active:${active ? 1 : 0}`);
  res.json({ ok: true });
});

app.delete('/api/apikeys/:id', ...requireRole('admin'), (req, res) => {
  const key = db.prepare('SELECT * FROM api_keys WHERE id = ?').get(req.params.id);
  if (!key) return res.status(404).json({ error: 'Not found' });
  db.prepare('DELETE FROM api_keys WHERE id = ?').run(req.params.id);
  logEvent(req, 'apikey.delete', key.name, `permission:${key.permission}`);
  res.status(204).end();
});

// --- Protected routes ---
app.use(requireAuth);

// Settings page — must be before express.static so admin check runs first
app.get('/settings', (req, res) => {
  if (req.session.userRole !== 'admin') return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public/settings.html'));
});

// Block direct .html access to settings page for non-admins
app.get('/settings.html', (req, res) => {
  if (req.session.userRole !== 'admin') return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public/settings.html'));
});

app.use(express.static(path.join(__dirname, 'public')));

// --- Certificates ---

app.get('/api/certificates', requireAuth, (req, res) => {
  const restricted = isRestrictedViewer(req.session.userId, req.session.userRole);
  const isAdmin = req.session.userRole === 'admin';

  // Restricted viewers see all certs; normal non-admins see only their groups
  const certs = db.prepare(`
    SELECT c.id, c.name, c.fqdn, c.expiration_date, c.password, c.note, c.created_at,
           CASE WHEN c.cert_data IS NOT NULL AND c.cert_data != '' THEN 1 ELSE 0 END AS has_cert,
           (SELECT GROUP_CONCAT(h.hostname || char(31) || h.responsible_person, '||')
            FROM hosts h WHERE h.certificate_id = c.id) AS hosts_raw,
           (SELECT GROUP_CONCAT(cg.id || char(31) || cg.name, '||')
            FROM cert_group_members cgm
            JOIN cert_groups cg ON cg.id = cgm.group_id
            WHERE cgm.certificate_id = c.id) AS groups_raw,
           (SELECT GROUP_CONCAT(cu.id || char(31) || cu.url || char(31) || cu.last_status, '||')
            FROM cert_urls cu WHERE cu.certificate_id = c.id) AS urls_raw
    FROM certificates c
    WHERE
      ? = 'admin'
      OR ? = 1
      OR EXISTS (
        SELECT 1 FROM cert_group_members x
        JOIN user_group_members ugm ON ugm.group_id = x.group_id
        WHERE x.certificate_id = c.id AND ugm.user_id = ?
      )
    ORDER BY c.expiration_date ASC
  `).all(req.session.userRole, restricted ? 1 : 0, req.session.userId);

  const result = certs.map(c => ({
    ...c,
    password: (isAdmin || !restricted) ? c.password : '',
    hosts: c.hosts_raw
      ? c.hosts_raw.split('||').map(s => { const [hostname, responsible_person] = s.split('\x1f'); return { hostname, responsible_person: responsible_person || '' }; })
      : [],
    groups: c.groups_raw
      ? c.groups_raw.split('||').map(s => { const [id, name] = s.split('\x1f'); return { id: parseInt(id, 10), name }; })
      : [],
    urls: c.urls_raw
      ? c.urls_raw.split('||').map(s => { const [id, url, last_status] = s.split('\x1f'); return { id: parseInt(id, 10), url, last_status }; })
      : [],
    hosts_raw: undefined,
    groups_raw: undefined,
    urls_raw: undefined
  }));

  res.json(result);
});

// Extract metadata from a parsed X509Certificate
function extractCertMeta(pem) {
  const cert = new X509Certificate(pem);
  const expiration_date = new Date(cert.validTo).toISOString().split('T')[0];
  const cnMatch = cert.subject.match(/CN=([^,\n\r]+)/);
  const cn = cnMatch ? cnMatch[1].trim() : '';
  let fqdn = cn;
  if (cert.subjectAltName) {
    const dnsMatch = cert.subjectAltName.match(/DNS:([^,\s]+)/);
    if (dnsMatch) fqdn = dnsMatch[1].trim();
  }
  return { expiration_date, name: cn, fqdn };
}

// Parse a PFX/PKCS12 buffer, return PEM of the leaf certificate
async function parsePfx(buffer, password = '') {
  const p12Der = buffer.toString('binary');
  let p12Asn1;
  try {
    p12Asn1 = forge.asn1.fromDer(p12Der);
  } catch {
    throw new Error('File is not a valid PFX/PKCS#12 file');
  }

  // Try node-forge first (fast, no network).
  // Attempt strict=true then strict=false (skips SHA-256 MAC check on modern PFX).
  for (const strict of [true, false]) {
    try {
      const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, strict, password);
      const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
      if (certBags.length === 0) throw new Error('No certificates found in PFX file');
      const leaf = certBags.find(b => !b.cert.basicConstraints?.cA) || certBags[0];
      return forge.pki.certificateToPem(leaf.cert);
    } catch (e) {
      if (!strict) break; // both modes failed — fall through to native path
    }
  }

  // node-forge couldn't parse it (common with modern Windows PFX using SHA-256 MAC or AES).
  // Validate the password using Node's built-in TLS (uses the bundled OpenSSL — no system binary needed).
  try {
    tls.createSecureContext({ pfx: buffer, passphrase: password });
  } catch {
    const err = new Error('Incorrect password');
    err.needsPassword = true;
    throw err;
  }

  // Password is valid. Walk the PFX ASN.1 structure directly to extract cert bags.
  // In Windows-generated PFX files cert bags live in a plain (unencrypted) ContentInfo,
  // so they can be read without any decryption or network handshake.
  const pem = extractCertFromPfxAsn1(p12Asn1);
  if (pem) return pem;

  // Final fallback: loopback TLS handshake.
  return extractCertViaTlsServer(buffer, password);
}

// Walk the PFX ASN.1 tree and pull cert DER bytes from any plain (unencrypted) SafeContents.
// Windows-generated PFX files store cert bags in unencrypted ContentInfo; only the key bag
// is password-encrypted. This lets us extract the cert without any decryption at all.
function extractCertFromPfxAsn1(p12Asn1) {
  const OID_DATA      = '1.2.840.113549.1.7.1';
  const OID_CERT_BAG  = '1.2.840.113549.1.12.10.1.3';
  const OID_X509_CERT = '1.2.840.113549.1.9.22.1';

  try {
    // PFX SEQUENCE: [version, authSafeContentInfo, macData?]
    const authSafeCI = p12Asn1.value[1];
    if (forge.asn1.derToOid(authSafeCI.value[0].value) !== OID_DATA) return null;

    // authSafe [0] OCTET STRING → AuthenticatedSafe SEQUENCE OF ContentInfo
    const authSafe = forge.asn1.fromDer(authSafeCI.value[1].value[0].value);

    const certDers = [];
    for (const ci of authSafe.value) {
      if (forge.asn1.derToOid(ci.value[0].value) !== OID_DATA) continue; // skip encrypted

      // Plain data ContentInfo: [0] OCTET STRING → SafeContents
      const sc = forge.asn1.fromDer(ci.value[1].value[0].value);
      for (const bag of sc.value) {
        try {
          if (forge.asn1.derToOid(bag.value[0].value) !== OID_CERT_BAG) continue;
          // CertBag: [0] → SEQUENCE { certId OID, certValue [0] OCTET STRING }
          const certBag = bag.value[1].value[0];
          if (forge.asn1.derToOid(certBag.value[0].value) !== OID_X509_CERT) continue;
          certDers.push(certBag.value[1].value[0].value); // binary DER string
        } catch (_) {}
      }
    }

    if (certDers.length === 0) return null;

    // Prefer leaf cert (not a CA)
    let chosen = certDers[0];
    for (const der of certDers) {
      try {
        const cert = forge.pki.certificateFromAsn1(forge.asn1.fromDer(der));
        const bc = cert.getExtension('basicConstraints');
        if (!bc || !bc.cA) { chosen = der; break; }
      } catch (_) {}
    }

    const b64 = Buffer.from(chosen, 'binary').toString('base64').match(/.{1,64}/g).join('\n');
    return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
  } catch {
    return null;
  }
}

// Start a loopback TLS server from the PFX and connect a TLS client to extract the leaf certificate.
// Using a proper TLS client (rather than raw TCP) means the handshake completes correctly
// regardless of TLS version (1.2 or 1.3) or key/cipher type.
function extractCertViaTlsServer(pfxBuffer, password) {
  return new Promise((resolve, reject) => {
    let server, client;
    const cleanup = () => {
      try { client?.destroy(); } catch (_) {}
      try { server?.close(); } catch (_) {}
    };
    const timer = setTimeout(() => { cleanup(); reject(new Error('Certificate extraction timed out')); }, 10000);

    // SECLEVEL=0 allows legacy key sizes (e.g. short RSA) that some PFX files contain.
    // This is safe here because the server is a loopback-only ephemeral instance.
    const PFX_TLS_OPTS = { ciphers: 'ALL:@SECLEVEL=0', minVersion: 'TLSv1.2' };

    const ctx = tls.createSecureContext({ pfx: pfxBuffer, passphrase: password });
    server = tls.createServer({ secureContext: ctx, ...PFX_TLS_OPTS }, () => {});
    server.on('error', () => {});

    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      let resolved = false;

      // Use a proper TLS client so the handshake completes regardless of TLS version or cipher.
      // rejectUnauthorized:false accepts any certificate — safe because this is a loopback server
      // we just created ourselves.
      client = tls.connect({ host: '127.0.0.1', port, rejectUnauthorized: false, ...PFX_TLS_OPTS }, () => {
        try {
          const peerCert = client.getPeerCertificate();
          client.destroy();
          if (!peerCert || !peerCert.raw) {
            if (!resolved) { clearTimeout(timer); cleanup(); reject(new Error('No certificate received from TLS server')); }
            return;
          }
          resolved = true;
          clearTimeout(timer);
          cleanup();
          const b64 = peerCert.raw.toString('base64').match(/.{1,64}/g).join('\n');
          resolve(`-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`);
        } catch (e) {
          if (!resolved) { clearTimeout(timer); cleanup(); reject(e); }
        }
      });

      client.on('error', (e) => {
        if (!resolved) { clearTimeout(timer); cleanup(); reject(e); }
      });
    });
  });
}

// Parse a certificate file and return metadata (must be before /:id)
app.post('/api/certificates/parse', requireAuth, upload.single('cert'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  try {
    const isPem = req.file.buffer.slice(0, 10).toString('ascii').startsWith('-----');
    let pem;

    if (isPem) {
      pem = req.file.buffer.toString('utf8');
    } else {
      // PFX / PKCS#12
      const password = req.body.password || '';
      pem = await parsePfx(req.file.buffer, password);
    }

    const meta = extractCertMeta(pem);
    res.json({ ...meta, cert_data: pem });
  } catch (e) {
    const status = e.needsPassword ? 401 : 400;
    res.status(status).json({ error: e.message, needsPassword: !!e.needsPassword });
  }
});

// Download stored certificate file
app.get('/api/certificates/:id/download', requireAuth, (req, res) => {
  if (isRestrictedViewer(req.session.userId, req.session.userRole)) {
    return res.status(403).json({ error: 'Download not permitted for your account' });
  }
  const cert = db.prepare('SELECT name, cert_data FROM certificates WHERE id = ?').get(req.params.id);
  if (!cert) return res.status(404).json({ error: 'Not found' });
  if (!cert.cert_data) return res.status(404).json({ error: 'No certificate file stored' });
  const filename = cert.name.replace(/[^a-zA-Z0-9._-]/g, '_') + '.pem';
  res.setHeader('Content-Type', 'application/x-pem-file');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  logEvent(req, 'cert.download', cert.name);
  res.send(cert.cert_data);
});

app.get('/api/certificates/:id', requireAuth, (req, res) => {
  const certId = req.params.id;
  const restricted = isRestrictedViewer(req.session.userId, req.session.userRole);
  const isAdmin = req.session.userRole === 'admin';

  // Enforce the same group visibility rules as the list endpoint
  const canAccess = db.prepare(`
    SELECT 1 FROM certificates c
    WHERE c.id = ?
      AND (
        ? = 'admin'
        OR ? = 1
        OR EXISTS (
          SELECT 1 FROM cert_group_members x
          JOIN user_group_members ugm ON ugm.group_id = x.group_id
          WHERE x.certificate_id = c.id AND ugm.user_id = ?
        )
      )
  `).get(certId, req.session.userRole, restricted ? 1 : 0, req.session.userId);

  if (!canAccess) return res.status(404).json({ error: 'Not found' });

  const cert = db.prepare('SELECT * FROM certificates WHERE id = ?').get(certId);
  if (!cert) return res.status(404).json({ error: 'Not found' });

  const hosts = db.prepare('SELECT hostname, responsible_person FROM hosts WHERE certificate_id = ?').all(certId);
  const groups = db.prepare('SELECT cg.id, cg.name FROM cert_groups cg JOIN cert_group_members cgm ON cgm.group_id = cg.id WHERE cgm.certificate_id = ?').all(certId);
  res.json({
    ...cert,
    password: (isAdmin || !restricted) ? cert.password : '',
    has_cert: !!cert.cert_data,
    cert_data: undefined,
    hosts,
    groups
  });
});

app.post('/api/certificates', ...requireRole('admin', 'editor'), (req, res) => {
  const { name, fqdn, expiration_date, password = '', note = '', cert_data = null, hosts = [], group_ids = [] } = req.body;
  const validationError = validateCertFields(name, fqdn, expiration_date);
  if (validationError) return res.status(400).json({ error: validationError });
  if (note && note.length > 1000) return res.status(400).json({ error: 'note must be under 1000 characters' });

  const insert = db.prepare('INSERT INTO certificates (name, fqdn, expiration_date, password, note, cert_data) VALUES (?, ?, ?, ?, ?, ?)');
  const insertHost = db.prepare('INSERT INTO hosts (certificate_id, hostname, responsible_person) VALUES (?, ?, ?)');
  const deleteGroupMembers = db.prepare('DELETE FROM cert_group_members WHERE certificate_id = ?');
  const insertGroupMember = db.prepare('INSERT INTO cert_group_members (group_id, certificate_id) VALUES (?, ?)');

  const tx = db.transaction(() => {
    const info = insert.run(name, fqdn, expiration_date, password, note, cert_data);
    const certId = info.lastInsertRowid;
    for (const h of hosts) {
      if (h.hostname && h.hostname.trim()) insertHost.run(certId, h.hostname.trim(), h.responsible_person || '');
    }
    deleteGroupMembers.run(certId);
    for (const gid of group_ids) {
      try { insertGroupMember.run(gid, certId); } catch (_) {}
    }
    return certId;
  });

  const certId = tx();
  const cert = db.prepare('SELECT id, name, fqdn, expiration_date, password, note, created_at FROM certificates WHERE id = ?').get(certId);
  const hostRows = db.prepare('SELECT hostname, responsible_person FROM hosts WHERE certificate_id = ?').all(certId);
  const groupRows = db.prepare('SELECT cg.id, cg.name FROM cert_groups cg JOIN cert_group_members cgm ON cgm.group_id = cg.id WHERE cgm.certificate_id = ?').all(certId);
  res.status(201).json({ ...cert, has_cert: !!cert_data, hosts: hostRows, groups: groupRows });
  logEvent(req, 'cert.create', cert.name, `fqdn:${cert.fqdn}`);

  // Notify all responsible persons on the newly created certificate
  const assignedPersons = new Map();
  for (const h of hosts) {
    if (!h.hostname?.trim() || !h.responsible_person?.trim()) continue;
    const u = h.responsible_person.trim();
    if (!assignedPersons.has(u)) assignedPersons.set(u, []);
    assignedPersons.get(u).push(h.hostname.trim());
  }
  sendCertAssignmentEmails(name, fqdn, expiration_date, assignedPersons).catch(err =>
    console.error('[notify] Assignment notification error:', err.message)
  );
});

app.put('/api/certificates/:id', ...requireRole('admin', 'editor'), async (req, res) => {
  const { name, fqdn, expiration_date, password = '', note = '', cert_data, hosts = [], group_ids = [] } = req.body;
  const id = req.params.id;

  const validationError = validateCertFields(name, fqdn, expiration_date);
  if (validationError) return res.status(400).json({ error: validationError });
  if (note && note.length > 1000) return res.status(400).json({ error: 'note must be under 1000 characters' });

  const cert = db.prepare('SELECT * FROM certificates WHERE id = ?').get(id);
  if (!cert) return res.status(404).json({ error: 'Not found' });
  const oldExpiry = cert.expiration_date;

  // Capture existing responsible persons before the update so we can diff afterwards
  const oldResponsible = new Set(
    db.prepare('SELECT DISTINCT responsible_person FROM hosts WHERE certificate_id = ?')
      .all(id).map(r => r.responsible_person).filter(Boolean)
  );

  // Only update cert_data if a new one was provided
  const newCertData = cert_data !== undefined ? cert_data : cert.cert_data;

  const update = db.prepare('UPDATE certificates SET name = ?, fqdn = ?, expiration_date = ?, password = ?, note = ?, cert_data = ? WHERE id = ?');
  const deleteHosts = db.prepare('DELETE FROM hosts WHERE certificate_id = ?');
  const insertHost = db.prepare('INSERT INTO hosts (certificate_id, hostname, responsible_person) VALUES (?, ?, ?)');
  const deleteGroupMembers = db.prepare('DELETE FROM cert_group_members WHERE certificate_id = ?');
  const insertGroupMember = db.prepare('INSERT INTO cert_group_members (group_id, certificate_id) VALUES (?, ?)');

  const tx = db.transaction(() => {
    update.run(name, fqdn, expiration_date, password, note, newCertData, id);
    deleteHosts.run(id);
    for (const h of hosts) {
      if (h.hostname && h.hostname.trim()) insertHost.run(id, h.hostname.trim(), h.responsible_person || '');
    }
    deleteGroupMembers.run(id);
    for (const gid of group_ids) {
      try { insertGroupMember.run(gid, id); } catch (_) {}
    }
  });

  tx();
  const updated = db.prepare('SELECT id, name, fqdn, expiration_date, password, note, created_at FROM certificates WHERE id = ?').get(id);
  const hostRows = db.prepare('SELECT hostname, responsible_person FROM hosts WHERE certificate_id = ?').all(id);
  const groupRows = db.prepare('SELECT cg.id, cg.name FROM cert_groups cg JOIN cert_group_members cgm ON cgm.group_id = cg.id WHERE cgm.certificate_id = ?').all(id);
  res.json({ ...updated, has_cert: !!newCertData, hosts: hostRows, groups: groupRows });
  logEvent(req, 'cert.update', updated.name, `fqdn:${updated.fqdn}`);

  // Notify responsible persons who are newly assigned (not present in old host list)
  const assignedPersons = new Map();
  for (const h of hosts) {
    if (!h.hostname?.trim() || !h.responsible_person?.trim()) continue;
    const u = h.responsible_person.trim();
    if (oldResponsible.has(u)) continue; // already was responsible — no notification needed
    if (!assignedPersons.has(u)) assignedPersons.set(u, []);
    assignedPersons.get(u).push(h.hostname.trim());
  }
  sendCertAssignmentEmails(name, fqdn, expiration_date, assignedPersons).catch(err =>
    console.error('[notify] Assignment notification error:', err.message)
  );

  if (expiration_date && expiration_date > oldExpiry) {
    sendRenewalNotification(id, updated.name, updated.fqdn, oldExpiry, expiration_date).catch(err =>
      console.error('[notify] Renewal notification error:', err.message)
    );
    runUrlChecksForCert(id).catch(err => console.error('[urlcheck] Renewal recheck error:', err.message));
  }
});

app.delete('/api/certificates/:id', ...requireRole('admin', 'editor'), (req, res) => {
  const cert = db.prepare('SELECT * FROM certificates WHERE id = ?').get(req.params.id);
  if (!cert) return res.status(404).json({ error: 'Not found' });

  db.prepare('DELETE FROM certificates WHERE id = ?').run(req.params.id);
  logEvent(req, 'cert.delete', cert.name, `fqdn:${cert.fqdn}`);
  res.status(204).end();
});

// --- Certificate URL monitoring ---

app.get('/api/certificates/:id/urls', requireAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!db.prepare('SELECT id FROM certificates WHERE id = ?').get(id)) return res.status(404).json({ error: 'Not found' });
  res.json(db.prepare('SELECT * FROM cert_urls WHERE certificate_id = ? ORDER BY id ASC').all(id));
});

app.post('/api/certificates/:id/urls', ...requireRole('admin', 'editor'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { url } = req.body;
  if (!url || !url.trim()) return res.status(400).json({ error: 'url is required' });

  const cert = db.prepare('SELECT id, expiration_date FROM certificates WHERE id = ?').get(id);
  if (!cert) return res.status(404).json({ error: 'Certificate not found' });

  try { const u = new URL(url.trim()); if (u.protocol !== 'https:') throw new Error(); }
  catch { return res.status(400).json({ error: 'URL must be a valid HTTPS URL' }); }

  let urlId;
  try {
    urlId = db.prepare('INSERT INTO cert_urls (certificate_id, url) VALUES (?, ?)').run(id, url.trim()).lastInsertRowid;
  } catch (e) {
    if (e.message && e.message.includes('UNIQUE')) return res.status(409).json({ error: 'This URL is already added to this certificate' });
    throw e;
  }

  logEvent(req, 'cert.url_add', url.trim(), `cert_id:${id}`);

  const result = await checkCertUrl(url.trim(), cert.expiration_date);
  db.prepare(`UPDATE cert_urls SET last_checked = datetime('now'), last_status = ?, live_expiry = ?, live_subject = ?, last_error = ? WHERE id = ?`)
    .run(result.status, result.live_expiry || null, result.live_subject || null, result.error || null, urlId);
  db.prepare('INSERT INTO audit_log (username, action, target, details, ip) VALUES (?, ?, ?, ?, ?)')
    .run('system', 'urlcheck.' + result.status, url.trim(), `cert_id:${id},live_expiry:${result.live_expiry || 'n/a'}`, '');

  res.status(201).json(db.prepare('SELECT * FROM cert_urls WHERE id = ?').get(urlId));
});

app.delete('/api/certificates/:id/urls/:urlId', ...requireRole('admin', 'editor'), (req, res) => {
  const certId = parseInt(req.params.id, 10);
  const urlId  = parseInt(req.params.urlId, 10);
  const urlRow = db.prepare('SELECT * FROM cert_urls WHERE id = ? AND certificate_id = ?').get(urlId, certId);
  if (!urlRow) return res.status(404).json({ error: 'Not found' });
  db.prepare('DELETE FROM cert_urls WHERE id = ?').run(urlId);
  logEvent(req, 'cert.url_remove', urlRow.url, `cert_id:${certId}`);
  res.status(204).end();
});

app.post('/api/certificates/:id/urls/:urlId/check', ...requireRole('admin', 'editor'), async (req, res) => {
  const certId = parseInt(req.params.id, 10);
  const urlId  = parseInt(req.params.urlId, 10);
  const urlRow = db.prepare('SELECT * FROM cert_urls WHERE id = ? AND certificate_id = ?').get(urlId, certId);
  if (!urlRow) return res.status(404).json({ error: 'Not found' });
  const cert = db.prepare('SELECT expiration_date FROM certificates WHERE id = ?').get(certId);
  if (!cert) return res.status(404).json({ error: 'Certificate not found' });

  const result = await checkCertUrl(urlRow.url, cert.expiration_date);
  db.prepare(`UPDATE cert_urls SET last_checked = datetime('now'), last_status = ?, live_expiry = ?, live_subject = ?, last_error = ? WHERE id = ?`)
    .run(result.status, result.live_expiry || null, result.live_subject || null, result.error || null, urlId);
  db.prepare('INSERT INTO audit_log (username, action, target, details, ip) VALUES (?, ?, ?, ?, ?)')
    .run('system', 'urlcheck.' + result.status, urlRow.url, `cert_id:${certId},live_expiry:${result.live_expiry || 'n/a'}`, '');

  res.json(db.prepare('SELECT * FROM cert_urls WHERE id = ?').get(urlId));
});

// --- URL certificate check helpers ---

async function checkCertUrl(urlStr, expectedExpiry) {
  return new Promise((resolve) => {
    let parsedUrl;
    try { parsedUrl = new URL(urlStr); }
    catch { return resolve({ status: 'error', error: 'Invalid URL' }); }

    if (parsedUrl.protocol !== 'https:') {
      return resolve({ status: 'error', error: 'URL must use HTTPS' });
    }

    const host = parsedUrl.hostname;
    const port = parsedUrl.port ? parseInt(parsedUrl.port, 10) : 443;
    let resolved = false;
    const done = (r) => { if (!resolved) { resolved = true; resolve(r); } };

    const timer = setTimeout(() => { done({ status: 'error', error: 'Connection timed out' }); }, 10000);

    const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false }, () => {
      clearTimeout(timer);
      try {
        const cert = socket.getPeerCertificate();
        socket.destroy();
        if (!cert || !cert.valid_to) return done({ status: 'error', error: 'No certificate received' });
        const liveExpiry = new Date(cert.valid_to).toISOString().split('T')[0];
        const liveSubject = (cert.subject && cert.subject.CN) || '';
        const status = (expectedExpiry && liveExpiry === expectedExpiry) ? 'match' : 'mismatch';
        done({ status, live_expiry: liveExpiry, live_subject: liveSubject });
      } catch (e) {
        done({ status: 'error', error: e.message });
      }
    });

    socket.on('error', (err) => { clearTimeout(timer); done({ status: 'error', error: err.message }); });
  });
}

async function runUrlChecksForCert(certId) {
  const cert = db.prepare('SELECT expiration_date FROM certificates WHERE id = ?').get(certId);
  if (!cert) return;
  const urls = db.prepare('SELECT * FROM cert_urls WHERE certificate_id = ?').all(certId);
  for (const urlRow of urls) {
    try {
      const result = await checkCertUrl(urlRow.url, cert.expiration_date);
      db.prepare(
        `UPDATE cert_urls SET last_checked = datetime('now'), last_status = ?, live_expiry = ?, live_subject = ?, last_error = ? WHERE id = ?`
      ).run(result.status, result.live_expiry || null, result.live_subject || null, result.error || null, urlRow.id);
      db.prepare('INSERT INTO audit_log (username, action, target, details, ip) VALUES (?, ?, ?, ?, ?)')
        .run('system', 'urlcheck.' + result.status, urlRow.url, `cert_id:${certId},live_expiry:${result.live_expiry || 'n/a'}`, '');
    } catch (e) {
      console.error('[urlcheck] Error checking', urlRow.url, ':', e.message);
    }
  }
}

async function runAllUrlChecks() {
  const certIds = db.prepare('SELECT DISTINCT certificate_id FROM cert_urls').all();
  for (const row of certIds) {
    await runUrlChecksForCert(row.certificate_id);
  }
}

// --- Certificate assignment notification ---
// assignments: Map<username, string[]>  (username → list of hostnames they are responsible for)

async function sendCertAssignmentEmails(certName, fqdn, expirationDate, assignments) {
  if (getSetting('notifications_enabled', 'false') !== 'true') return;
  const transporter = createTransporter();
  if (!transporter) return;

  const fromAddress = getSetting('smtp_from', 'certmanmon@localhost');
  const appUrl     = getSetting('app_url', '');
  const expFormatted = new Date(expirationDate + 'T00:00:00').toLocaleDateString('en-GB', {
    year: 'numeric', month: 'long', day: 'numeric'
  });

  for (const [username, hostnames] of assignments) {
    if (!username) continue;
    const user = db.prepare('SELECT display_name, email FROM users WHERE username = ? AND active = 1').get(username);
    if (!user || !user.email) continue;

    const greeting = user.display_name ? `Hi ${htmlEsc(user.display_name)},` : 'Hi,';
    const hostBadges = hostnames.map(h =>
      `<span style="display:inline-block;margin:3px 4px 3px 0;padding:4px 12px;background:#f1f5f9;border:1px solid #e2e8f0;border-radius:5px;font-family:'Courier New',Courier,monospace;font-size:13px;color:#0f172a">${htmlEsc(h)}</span>`
    ).join('');

    const assignBody = `<p style="margin:0 0 20px;font-size:15px;color:#334155;line-height:1.6">
      ${greeting}<br><br>You have been assigned as the responsible contact for the following host${hostnames.length > 1 ? 's' : ''} on certificate <strong>${htmlEsc(certName)}</strong>:
    </p>
    <div style="margin-bottom:20px">${hostBadges}</div>
    ${emailInfoTable([
      { label: 'Certificate', value: htmlEsc(certName) },
      { label: 'Domain',      value: htmlEsc(fqdn), mono: true },
      { label: 'Expires',     value: htmlEsc(expFormatted) },
    ])}
    ${appUrl ? emailBtn(appUrl, 'View in CertManMon', '#6366f1') : ''}`;

    const html = emailShell('#6366f1', 'CertManMon · Certificate Monitor', 'Certificate Responsibility', '', assignBody);

    try {
      await transporter.sendMail({
        from: fromAddress,
        to: user.email,
        subject: `[CertManMon] You are responsible for certificate "${certName}"`,
        html
      });
      console.log(`[notify] Assignment email sent to ${user.email} for cert "${certName}"`);
    } catch (err) {
      console.error(`[notify] Assignment email failed for ${user.email}:`, err.message);
    }
  }
}

// --- Welcome email helper ---

async function sendWelcomeEmail(username, display_name, email, password, role, appUrl) {
  const transporter = createTransporter();
  if (!transporter) return;

  const fromAddress = getSetting('smtp_from', 'certmanmon@localhost');
  const roleLabels = { admin: 'Admin', editor: 'Editor', viewer: 'Viewer' };
  const loginUrl = appUrl || '';

  const pwRow = password
    ? { label: 'Password', value: `<span style="font-family:'Courier New',Courier,monospace;background:#f1f5f9;padding:3px 8px;border-radius:4px;border:1px solid #e2e8f0;font-size:13px">${htmlEsc(password)}</span>`, mono: false }
    : { label: 'Password', value: '<span style="color:#64748b;font-style:italic">Set by your administrator</span>' };

  const welcomeRows = [
    { label: 'Username', value: `<strong>${htmlEsc(username)}</strong>` },
    ...(display_name ? [{ label: 'Name', value: htmlEsc(display_name) }] : []),
    { label: 'Email',    value: htmlEsc(email) },
    pwRow,
    { label: 'Role',     value: `<span style="display:inline-block;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:700;background:#ede9fe;color:#5b21b6">${htmlEsc(roleLabels[role] || role)}</span>` },
  ];

  const greeting = display_name ? `Hi ${htmlEsc(display_name)},` : 'Hi,';
  const welcomeBody = `<p style="margin:0 0 20px;font-size:15px;color:#334155;line-height:1.6">
    ${greeting}<br><br>Your CertManMon account has been created. Use the credentials below to sign in${password ? ' — you will be asked to change your password on first login' : ''}.
  </p>
  ${emailInfoTable(welcomeRows)}
  ${loginUrl ? emailBtn(loginUrl + '/login', 'Sign in to CertManMon', '#6366f1') : ''}`;

  const html = emailShell('#6366f1', 'CertManMon · Account Created', 'Welcome to CertManMon', '', welcomeBody);

  try {
    await transporter.sendMail({
      from: fromAddress,
      to: email,
      subject: '[CertManMon] Your account has been created',
      html
    });
    console.log(`[notify] Welcome email sent to ${email}`);
  } catch (err) {
    console.error(`[notify] Welcome email failed for ${email}:`, err.message);
  }
}

// --- Renewal notification helper ---

async function sendRenewalNotification(certId, certName, fqdn, oldExpiry, newExpiry) {
  if (getSetting('notify_renewal', 'false') !== 'true') return;
  if (getSetting('notifications_enabled', 'false') !== 'true') return;

  const transporter = createTransporter();
  if (!transporter) return;

  const fromAddress = getSetting('smtp_from', 'certmanmon@localhost');
  const appUrl = getSetting('app_url');
  const adminEmails = getSetting('admin_emails', '').split(',').map(s => s.trim()).filter(Boolean);
  const notifyResponsible = getSetting('notify_responsible', 'true') === 'true';

  const recipients = new Set(adminEmails);
  if (notifyResponsible) {
    const hosts = db.prepare('SELECT responsible_person FROM hosts WHERE certificate_id = ?').all(certId);
    for (const h of hosts) {
      if (!h.responsible_person) continue;
      const person = h.responsible_person.trim();
      const user = db.prepare('SELECT email FROM users WHERE email = ? OR username = ? LIMIT 1').get(person, person);
      if (user) recipients.add(user.email);
      else if (person.includes('@')) recipients.add(person);
    }
  }

  const oldFmt = new Date(oldExpiry + 'T00:00:00').toLocaleDateString('en-GB', { year:'numeric', month:'long', day:'numeric' });
  const newFmt = new Date(newExpiry + 'T00:00:00').toLocaleDateString('en-GB', { year:'numeric', month:'long', day:'numeric' });

  const renewalHero = `<p style="margin:0;font-size:15px;color:#374151">Certificate renewed successfully</p>
    <table cellpadding="0" cellspacing="0" style="margin:16px auto 0"><tr>
      <td style="text-align:center;padding:0 16px">
        <p style="margin:0;font-size:11px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.8px;font-weight:600">Previous expiry</p>
        <p style="margin:6px 0 0;font-size:16px;color:#ef4444;font-weight:700;text-decoration:line-through">${htmlEsc(oldFmt)}</p>
      </td>
      <td style="padding:0 10px;font-size:22px;color:#16a34a;font-weight:700">&rarr;</td>
      <td style="text-align:center;padding:0 16px">
        <p style="margin:0;font-size:11px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.8px;font-weight:600">New expiry</p>
        <p style="margin:6px 0 0;font-size:18px;color:#16a34a;font-weight:800">${htmlEsc(newFmt)}</p>
      </td>
    </tr></table>`;

  const renewalBody = `<p style="margin:0 0 20px;font-size:15px;color:#334155;line-height:1.6">
    The following certificate has been renewed and is now valid until <strong style="color:#16a34a">${htmlEsc(newFmt)}</strong>.
  </p>
  ${emailInfoTable([
    { label: 'Certificate', value: htmlEsc(certName) },
    { label: 'Domain',      value: htmlEsc(fqdn), mono: true },
  ])}
  ${appUrl ? emailBtn(appUrl, 'View in CertManMon', '#16a34a') : ''}`;

  const html = emailShell('#16a34a', 'CertManMon · Certificate Monitor', 'Certificate Renewed', renewalHero, renewalBody);

  const subject = `[CertManMon] Certificate "${certName}" has been renewed`;
  for (const recipient of recipients) {
    try {
      await transporter.sendMail({ from: fromAddress, to: recipient, subject, html });
      console.log(`[notify] Renewal notice sent to ${recipient} for cert "${certName}"`);
      db.prepare('INSERT INTO audit_log (username, action, target, details, ip) VALUES (?, ?, ?, ?, ?)').run('system', 'notify.renewal', certName, `to:${recipient}`, '');
    } catch (err) {
      console.error(`[notify] Renewal notice failed for ${recipient}:`, err.message);
    }
  }
}

// --- Notification helpers ---

function getSetting(key, defaultVal = '') {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : defaultVal;
}

function createTransporter() {
  const host = getSetting('smtp_host');
  const port = parseInt(getSetting('smtp_port', '587'), 10);
  const user = getSetting('smtp_user');
  const pass = getSetting('smtp_pass');
  const tls  = getSetting('smtp_tls', 'true') === 'true';
  if (!host) return null;
  return nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    requireTLS: tls && port !== 465,
    ignoreTLS: !tls,
    auth: user ? { user, pass } : undefined
  });
}

function emailBtn(url, label, color) {
  return `<table cellpadding="0" cellspacing="0" style="margin-top:24px"><tr><td style="background:${color};border-radius:7px"><a href="${htmlEsc(url)}" style="display:inline-block;padding:11px 26px;color:#ffffff;text-decoration:none;font-size:14px;font-weight:700;font-family:Arial,Helvetica,sans-serif">${label} &rarr;</a></td></tr></table>`;
}

function emailInfoTable(rows) {
  // rows: [{label, value, mono, accent}]
  return `<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;font-family:Arial,Helvetica,sans-serif">
  ${rows.map((r, i) => `<tr>
    <td style="padding:11px 16px;font-size:12px;color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;background:#f8fafc;width:130px${i > 0 ? ';border-top:1px solid #e2e8f0' : ''}">${r.label}</td>
    <td style="padding:11px 16px;font-size:14px;color:${r.accent || '#0f172a'};font-weight:${r.accent ? '700' : '500'}${r.mono ? ';font-family:\'Courier New\',Courier,monospace' : ''}${i > 0 ? ';border-top:1px solid #e2e8f0' : ''}">${r.value}</td>
  </tr>`).join('')}
</table>`;
}

function emailShell(accentColor, headerLabel, title, heroHtml, bodyHtml) {
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>${title}</title></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:Arial,Helvetica,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:32px 16px">
  <tr><td align="center">
    <table cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;background:#ffffff;border-radius:10px;border:1px solid #e2e8f0">
      <tr><td style="background:${accentColor};border-radius:10px 10px 0 0;padding:22px 32px">
        <p style="margin:0 0 5px;font-size:11px;color:rgba(255,255,255,0.7);text-transform:uppercase;letter-spacing:1.2px;font-weight:600">${htmlEsc(headerLabel)}</p>
        <h1 style="margin:0;color:#ffffff;font-size:20px;font-weight:700;line-height:1.3">${title}</h1>
      </td></tr>
      ${heroHtml ? `<tr><td style="background:#f8fafc;padding:24px 32px;text-align:center;border-bottom:1px solid #e2e8f0">${heroHtml}</td></tr>` : ''}
      <tr><td style="padding:28px 32px">${bodyHtml}</td></tr>
      <tr><td style="padding:14px 32px;background:#f8fafc;border-top:1px solid #e2e8f0;border-radius:0 0 10px 10px">
        <p style="margin:0;font-size:12px;color:#94a3b8;text-align:center">Sent by <strong>CertManMon</strong> &middot; If you did not expect this email, contact your administrator</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`;
}

function buildEmailHtml(certName, fqdn, expirationDate, daysLeft, thresholdDays, appUrl = '') {
  const urgency = daysLeft <= 7 ? 'critical' : daysLeft <= 14 ? 'warning' : 'notice';
  const accent  = urgency === 'critical' ? '#dc2626' : urgency === 'warning' ? '#d97706' : '#2563eb';
  const heroBg  = urgency === 'critical' ? '#fef2f2' : urgency === 'warning' ? '#fffbeb' : '#eff6ff';
  const heroTxt = urgency === 'critical' ? '#991b1b' : urgency === 'warning' ? '#92400e' : '#1e40af';
  const title   = urgency === 'critical' ? 'Certificate Expiry Alert' : 'Certificate Expiry Reminder';
  const expFmt  = new Date(expirationDate + 'T00:00:00').toLocaleDateString('en-GB', { year:'numeric', month:'long', day:'numeric' });

  const hero = `<table width="100%" cellpadding="0" cellspacing="0" style="background:${heroBg};border-radius:8px"><tr><td style="padding:20px;text-align:center">
    <p style="margin:0;font-size:60px;font-weight:800;color:${heroTxt};line-height:1;letter-spacing:-2px">${daysLeft}</p>
    <p style="margin:6px 0 0;font-size:13px;color:${accent};font-weight:700;text-transform:uppercase;letter-spacing:1px">day${daysLeft !== 1 ? 's' : ''} until expiry</p>
  </td></tr></table>`;

  const body = `<p style="margin:0 0 20px;font-size:15px;color:#334155;line-height:1.6">
    This certificate expires on <strong style="color:${accent}">${htmlEsc(expFmt)}</strong>. Please renew it before it expires to avoid service disruption.
  </p>
  ${emailInfoTable([
    { label: 'Certificate', value: htmlEsc(certName) },
    { label: 'Domain',      value: htmlEsc(fqdn), mono: true },
    { label: 'Expires',     value: htmlEsc(expFmt), accent },
  ])}
  ${appUrl ? emailBtn(appUrl, 'View in CertManMon', accent) : ''}`;

  return emailShell(accent, 'CertManMon · Certificate Monitor', title, hero, body);
}

async function runNotificationCheck() {
  if (getSetting('notifications_enabled', 'false') !== 'true') return;

  const transporter = createTransporter();
  if (!transporter) { console.log('[notify] SMTP not configured, skipping'); return; }

  const fromAddress = getSetting('smtp_from', 'certmanmon@localhost');
  const thresholds = [
    parseInt(getSetting('threshold_1', '30'), 10),
    parseInt(getSetting('threshold_2', '14'), 10),
    parseInt(getSetting('threshold_3', '7'),  10),
  ].filter(t => t > 0);
  const adminEmails = getSetting('admin_emails', '').split(',').map(s => s.trim()).filter(Boolean);
  const notifyResponsible = getSetting('notify_responsible', 'true') === 'true';

  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const certs = db.prepare('SELECT id, name, fqdn, expiration_date FROM certificates').all();

  for (const cert of certs) {
    const expiry = new Date(cert.expiration_date);
    expiry.setHours(0, 0, 0, 0);
    const daysLeft = Math.round((expiry - today) / 86400000);
    if (daysLeft < 0) continue; // already expired, skip

    for (const threshold of thresholds) {
      if (daysLeft > threshold) continue;

      // Collect recipients
      const recipients = new Set(adminEmails);
      if (notifyResponsible) {
        // Get responsible_person field from hosts for this cert
        const hosts = db.prepare('SELECT responsible_person FROM hosts WHERE certificate_id = ?').all(cert.id);
        for (const h of hosts) {
          if (!h.responsible_person) continue;
          // Match by email or username in users table
          const person = h.responsible_person.trim();
          const user = db.prepare('SELECT email FROM users WHERE email = ? OR username = ? LIMIT 1').get(person, person);
          if (user) recipients.add(user.email);
          else if (person.includes('@')) recipients.add(person); // treat as raw email
        }
      }

      for (const recipient of recipients) {
        // Check if already sent this combination
        const alreadySent = db.prepare(
          'SELECT 1 FROM notification_log WHERE certificate_id = ? AND expiration_date = ? AND threshold_days = ? AND recipient = ?'
        ).get(cert.id, cert.expiration_date, threshold, recipient);
        if (alreadySent) continue;

        const html = buildEmailHtml(cert.name, cert.fqdn, cert.expiration_date, daysLeft, threshold, getSetting('app_url'));
        const subject = `[CertManMon] Certificate "${cert.name}" expires in ${daysLeft} day${daysLeft !== 1 ? 's' : ''}`;
        try {
          await transporter.sendMail({ from: fromAddress, to: recipient, subject, html });
          db.prepare(
            'INSERT OR IGNORE INTO notification_log (certificate_id, expiration_date, threshold_days, recipient) VALUES (?, ?, ?, ?)'
          ).run(cert.id, cert.expiration_date, threshold, recipient);
          console.log(`[notify] Sent to ${recipient} for cert "${cert.name}" (${daysLeft}d, threshold ${threshold}d)`);
          db.prepare('INSERT INTO audit_log (username, action, target, details, ip) VALUES (?, ?, ?, ?, ?)').run('system', 'notify.sent', cert.name, `to:${recipient},days:${daysLeft},threshold:${threshold}`, '');
        } catch (err) {
          console.error(`[notify] Failed to send to ${recipient}:`, err.message);
        }
      }
    }
  }
}

// --- Notification API routes ---

app.get('/api/settings/notifications', ...requireRole('admin'), (req, res) => {
  const keys = ['notifications_enabled', 'smtp_host', 'smtp_port', 'smtp_user', 'smtp_from',
                 'smtp_tls', 'threshold_1', 'threshold_2', 'threshold_3',
                 'admin_emails', 'notify_responsible', 'notify_renewal', 'app_url'];
  const result = {};
  for (const k of keys) result[k] = getSetting(k);
  // Mask password
  result.smtp_pass = getSetting('smtp_pass') ? '••••••••' : '';
  res.json(result);
});

app.put('/api/settings/notifications', ...requireRole('admin'), (req, res) => {
  const allowed = ['notifications_enabled', 'smtp_host', 'smtp_port', 'smtp_user', 'smtp_pass',
                   'smtp_from', 'smtp_tls', 'threshold_1', 'threshold_2', 'threshold_3',
                   'admin_emails', 'notify_responsible', 'notify_renewal', 'app_url'];
  const upsert = db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value');
  const tx = db.transaction(() => {
    for (const k of allowed) {
      if (req.body[k] === undefined) continue;
      // Don't overwrite password if placeholder sent
      if (k === 'smtp_pass' && req.body[k] === '••••••••') continue;
      upsert.run(k, String(req.body[k]));
    }
  });
  tx();
  logEvent(req, 'settings.notifications_update', '', 'Notification settings updated');
  res.json({ ok: true });
});

app.post('/api/settings/notifications/test', ...requireRole('admin'), async (req, res) => {
  const { to } = req.body;
  if (!to) return res.status(400).json({ error: 'to address required' });
  const transporter = createTransporter();
  if (!transporter) return res.status(400).json({ error: 'SMTP not configured' });
  const fromAddress = getSetting('smtp_from', 'certmanmon@localhost');
  try {
    await transporter.sendMail({
      from: fromAddress,
      to,
      subject: '[CertManMon] Test email',
      html: buildEmailHtml('test.example.com', '*.example.com', new Date(Date.now() + 14 * 86400000).toISOString().slice(0, 10), 14, 14, getSetting('app_url'))
    });
    logEvent(req, 'notify.test', to, 'Test email sent');
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/settings/notifications/run', ...requireRole('admin'), async (req, res) => {
  try {
    await runNotificationCheck();
    logEvent(req, 'notify.run', '', 'Manual notification check triggered');
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Daily notification check at 08:00
cron.schedule('0 8 * * *', () => {
  runNotificationCheck().catch(err => console.error('[notify] cron error:', err.message));
});

// URL certificate live-check every 30 minutes
cron.schedule('*/30 * * * *', () => {
  runAllUrlChecks().catch(err => console.error('[urlcheck] cron error:', err.message));
});

// --- Audit log routes ---

app.get('/api/logs', ...requireRole('admin'), (req, res) => {
  const { action = '', search = '' } = req.query;
  const pageNum = Math.max(1, parseInt(req.query.page, 10) || 1);
  const pageSize = Math.min(Math.max(1, parseInt(req.query.limit, 10) || 50), 200);
  const offset = (pageNum - 1) * pageSize;

  let where = '1=1';
  const params = [];

  if (action) {
    where += ' AND action LIKE ?';
    params.push(action + '%');
  }
  if (search) {
    where += ' AND (username LIKE ? OR target LIKE ? OR details LIKE ? OR action LIKE ?)';
    const s = '%' + search + '%';
    params.push(s, s, s, s);
  }

  const total = db.prepare(`SELECT COUNT(*) AS c FROM audit_log WHERE ${where}`).get(...params).c;
  const rows = db.prepare(`SELECT * FROM audit_log WHERE ${where} ORDER BY id DESC LIMIT ? OFFSET ?`).all(...params, pageSize, offset);

  res.json({ total, page: pageNum, limit: pageSize, rows });
});

app.delete('/api/logs', ...requireRole('admin'), (req, res) => {
  db.prepare('DELETE FROM audit_log').run();
  logEvent(req, 'logs.cleared', '', 'Audit log cleared');
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`CertManMon running on port ${PORT}`));
