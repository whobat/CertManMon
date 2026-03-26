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

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || '/data/certs.db';
const AUTH_USERNAME = process.env.AUTH_USERNAME || 'admin';
const AUTH_PASSWORD = process.env.AUTH_PASSWORD || 'changeme';
const SESSION_SECRET = process.env.SESSION_SECRET || randomBytes(32).toString('hex');

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
`);

// Migrations for existing databases
try { db.exec(`ALTER TABLE hosts ADD COLUMN responsible_person TEXT NOT NULL DEFAULT ''`); } catch (_) {}
try { db.exec(`ALTER TABLE certificates ADD COLUMN cert_data TEXT`); } catch (_) {}
try { db.exec(`ALTER TABLE certificates ADD COLUMN password TEXT NOT NULL DEFAULT ''`); } catch (_) {}
try { db.exec(`ALTER TABLE certificates ADD COLUMN note TEXT NOT NULL DEFAULT ''`); } catch (_) {}
try { db.exec(`ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT ''`); } catch (_) {}
try { db.exec(`CREATE TABLE IF NOT EXISTS cert_groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '', created_at TEXT DEFAULT (datetime('now')))`); } catch (_) {}
try { db.exec(`CREATE TABLE IF NOT EXISTS cert_group_members (group_id INTEGER NOT NULL, certificate_id INTEGER NOT NULL, PRIMARY KEY (group_id, certificate_id), FOREIGN KEY (group_id) REFERENCES cert_groups(id) ON DELETE CASCADE, FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE)`); } catch (_) {}
try { db.exec(`CREATE TABLE IF NOT EXISTS user_group_members (group_id INTEGER NOT NULL, user_id INTEGER NOT NULL, PRIMARY KEY (group_id, user_id), FOREIGN KEY (group_id) REFERENCES cert_groups(id) ON DELETE CASCADE, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)`); } catch (_) {}
try { db.exec(`CREATE TABLE IF NOT EXISTS notification_log (id INTEGER PRIMARY KEY AUTOINCREMENT, certificate_id INTEGER NOT NULL, expiration_date TEXT NOT NULL, threshold_days INTEGER NOT NULL, recipient TEXT NOT NULL, sent_at TEXT DEFAULT (datetime('now')), UNIQUE (certificate_id, expiration_date, threshold_days, recipient))`); } catch (_) {}
try { db.exec(`CREATE TABLE IF NOT EXISTS api_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, key_prefix TEXT NOT NULL, permission TEXT NOT NULL DEFAULT 'read', active INTEGER NOT NULL DEFAULT 1, last_used_at TEXT, created_at TEXT DEFAULT (datetime('now')))`); } catch (_) {}
try { db.exec(`CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT DEFAULT (datetime('now')), user_id INTEGER, username TEXT, action TEXT NOT NULL, target TEXT, details TEXT, ip TEXT)`); } catch (_) {}

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

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 2 * 1024 * 1024 } });

app.use(express.json());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax' }
}));

// --- Auth middleware ---
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
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

// --- Audit logging ---
function logEvent(req, action, target = '', details = '') {
  const userId = req.session && req.session.userId ? req.session.userId : null;
  const username = req.session && req.session.username ? req.session.username : 'system';
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || '';
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

// Returns enabled auth providers
app.get('/api/auth/providers', (req, res) => {
  const entraEnabled = db.prepare("SELECT value FROM settings WHERE key = 'entra_enabled'").get();
  const entra = entraEnabled && entraEnabled.value === 'true';
  res.json({ local: true, entra });
});

// Local login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });

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
    res.redirect('/');
    logEvent(req, 'auth.entra_login', user.username, `role:${user.role}`);
  } catch (e) {
    console.error('Entra callback error:', e);
    res.redirect('/login?error=entra_failed');
  }
});

// Auth info (requires auth)
app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, username, display_name, email, role FROM users WHERE id = ?').get(req.session.userId);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  res.json(user);
});

// --- User management routes (admin only) ---

app.get('/api/users', ...requireRole('admin'), (req, res) => {
  const users = db.prepare('SELECT id, username, display_name, email, role, auth_provider, active, created_at FROM users ORDER BY created_at ASC').all();
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

  try {
    const password_hash = password ? await bcrypt.hash(password, 12) : null;
    const info = db.prepare(
      'INSERT INTO users (username, display_name, email, password_hash, role, auth_provider, active) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(username, display_name, email, password_hash, role, auth_provider, active ? 1 : 0);
    const user = db.prepare('SELECT id, username, display_name, email, role, auth_provider, active, created_at FROM users WHERE id = ?').get(info.lastInsertRowid);
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

    const updated = db.prepare('SELECT id, username, display_name, email, role, auth_provider, active, created_at FROM users WHERE id = ?').get(id);
    res.json(updated);
    logEvent(req, 'user.update', updated.username, `role:${updated.role},active:${updated.active}`);
  } catch (e) {
    if (e.message && e.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }
    throw e;
  }
});

// GET /api/users/suggestions — username + email for autocomplete (any authenticated user)
app.get('/api/users/suggestions', requireAuth, (req, res) => {
  const users = db.prepare(
    "SELECT username, email FROM users WHERE active = 1 ORDER BY username ASC"
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
    SELECT g.id, g.name, g.description, g.created_at,
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

  try {
    db.prepare('UPDATE cert_groups SET name = ?, description = ? WHERE id = ?').run(newName, newDesc, id);
    const updated = db.prepare(`
      SELECT g.id, g.name, g.description, g.created_at,
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
          WHERE cgm.certificate_id = c.id) AS groups_raw
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
    hosts_raw: undefined,
    groups_raw: undefined,
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
  const certs = db.prepare(`
    SELECT c.id, c.name, c.fqdn, c.expiration_date, c.password, c.note, c.created_at,
           CASE WHEN c.cert_data IS NOT NULL AND c.cert_data != '' THEN 1 ELSE 0 END AS has_cert,
           (SELECT GROUP_CONCAT(h.hostname || char(31) || h.responsible_person, '||')
            FROM hosts h WHERE h.certificate_id = c.id) AS hosts_raw,
           (SELECT GROUP_CONCAT(cg.id || char(31) || cg.name, '||')
            FROM cert_group_members cgm
            JOIN cert_groups cg ON cg.id = cgm.group_id
            WHERE cgm.certificate_id = c.id) AS groups_raw
    FROM certificates c
    WHERE
      ? = 'admin'
      OR EXISTS (
        SELECT 1 FROM cert_group_members x
        JOIN user_group_members ugm ON ugm.group_id = x.group_id
        WHERE x.certificate_id = c.id AND ugm.user_id = ?
      )
    ORDER BY c.expiration_date ASC
  `).all(req.session.userRole, req.session.userId);

  const result = certs.map(c => ({
    ...c,
    hosts: c.hosts_raw
      ? c.hosts_raw.split('||').map(s => { const [hostname, responsible_person] = s.split('\x1f'); return { hostname, responsible_person: responsible_person || '' }; })
      : [],
    groups: c.groups_raw
      ? c.groups_raw.split('||').map(s => { const [id, name] = s.split('\x1f'); return { id: parseInt(id, 10), name }; })
      : [],
    hosts_raw: undefined,
    groups_raw: undefined
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
function parsePfx(buffer, password = '') {
  const p12Der = buffer.toString('binary');
  let p12Asn1;
  try {
    p12Asn1 = forge.asn1.fromDer(p12Der);
  } catch {
    throw new Error('File is not a valid PFX/PKCS#12 file');
  }
  let p12;
  try {
    p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);
  } catch (e) {
    const msg = e.message || '';
    if (msg.includes('MAC') || msg.includes('mac') || msg.includes('password') || msg.includes('decrypt')) {
      const err = new Error('Incorrect password');
      err.needsPassword = true;
      throw err;
    }
    throw e;
  }
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
  if (certBags.length === 0) throw new Error('No certificates found in PFX file');
  // Pick the leaf cert (not a CA) if possible
  const leaf = certBags.find(b => !b.cert.basicConstraints?.cA) || certBags[0];
  return forge.pki.certificateToPem(leaf.cert);
}

// Parse a certificate file and return metadata (must be before /:id)
app.post('/api/certificates/parse', requireAuth, upload.single('cert'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  try {
    const isPem = req.file.buffer.slice(0, 10).toString('ascii').startsWith('-----');
    let pem;

    if (isPem) {
      pem = req.file.buffer.toString('utf8');
    } else {
      // PFX / PKCS#12
      const password = req.body.password || '';
      pem = parsePfx(req.file.buffer, password);
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
  const cert = db.prepare('SELECT * FROM certificates WHERE id = ?').get(req.params.id);
  if (!cert) return res.status(404).json({ error: 'Not found' });

  const hosts = db.prepare('SELECT hostname, responsible_person FROM hosts WHERE certificate_id = ?').all(req.params.id);
  const groups = db.prepare('SELECT cg.id, cg.name FROM cert_groups cg JOIN cert_group_members cgm ON cgm.group_id = cg.id WHERE cgm.certificate_id = ?').all(req.params.id);
  res.json({ ...cert, has_cert: !!cert.cert_data, cert_data: undefined, hosts, groups });
});

app.post('/api/certificates', ...requireRole('admin', 'editor'), (req, res) => {
  const { name, fqdn, expiration_date, password = '', note = '', cert_data = null, hosts = [], group_ids = [] } = req.body;
  if (!name || !fqdn || !expiration_date) {
    return res.status(400).json({ error: 'name, fqdn, and expiration_date are required' });
  }

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
});

app.put('/api/certificates/:id', ...requireRole('admin', 'editor'), async (req, res) => {
  const { name, fqdn, expiration_date, password = '', note = '', cert_data, hosts = [], group_ids = [] } = req.body;
  const id = req.params.id;

  const cert = db.prepare('SELECT * FROM certificates WHERE id = ?').get(id);
  if (!cert) return res.status(404).json({ error: 'Not found' });
  const oldExpiry = cert.expiration_date;

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
  if (expiration_date && expiration_date > oldExpiry) {
    sendRenewalNotification(id, updated.name, updated.fqdn, oldExpiry, expiration_date).catch(err =>
      console.error('[notify] Renewal notification error:', err.message)
    );
  }
});

app.delete('/api/certificates/:id', ...requireRole('admin', 'editor'), (req, res) => {
  const cert = db.prepare('SELECT * FROM certificates WHERE id = ?').get(req.params.id);
  if (!cert) return res.status(404).json({ error: 'Not found' });

  db.prepare('DELETE FROM certificates WHERE id = ?').run(req.params.id);
  logEvent(req, 'cert.delete', cert.name, `fqdn:${cert.fqdn}`);
  res.status(204).end();
});

// --- Welcome email helper ---

async function sendWelcomeEmail(username, display_name, email, password, role, appUrl) {
  const transporter = createTransporter();
  if (!transporter) return;

  const fromAddress = getSetting('smtp_from', 'certmanmon@localhost');
  const roleLabels = { admin: 'Admin', editor: 'Editor', viewer: 'Viewer' };
  const loginUrl = appUrl || '';
  const loginBtn = loginUrl
    ? `<a href="${loginUrl}/login" style="display:inline-block;margin-top:20px;padding:10px 20px;background:#6366f1;color:#fff;text-decoration:none;border-radius:6px;font-size:14px;font-weight:600">Sign in to CertManMon &rarr;</a>`
    : '';

  const credentialsRow = password
    ? `<tr><td style="padding:6px 0;color:#94a3b8;width:140px">Password</td><td style="padding:6px 0;font-family:monospace;background:#1a1f2e;padding:4px 8px;border-radius:4px">${password}</td></tr>`
    : `<tr><td style="padding:6px 0;color:#94a3b8;width:140px">Password</td><td style="padding:6px 0;color:#94a3b8">Set by your administrator</td></tr>`;

  const html = `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;background:#1a1f2e;color:#e2e8f0;padding:24px">
  <div style="max-width:520px;margin:0 auto;background:#252c3b;border-radius:8px;overflow:hidden">
    <div style="background:#6366f1;padding:16px 24px">
      <h2 style="margin:0;color:#fff;font-size:18px">Welcome to CertManMon</h2>
    </div>
    <div style="padding:24px">
      <p style="margin:0 0 16px">${display_name ? `Hi ${display_name},<br><br>` : ''}Your account has been created. Here are your login credentials:</p>
      <table style="width:100%;border-collapse:collapse;font-size:14px">
        <tr><td style="padding:6px 0;color:#94a3b8;width:140px">Username</td><td style="padding:6px 0"><strong>${username}</strong></td></tr>
        ${display_name ? `<tr><td style="padding:6px 0;color:#94a3b8">Name</td><td style="padding:6px 0">${display_name}</td></tr>` : ''}
        <tr><td style="padding:6px 0;color:#94a3b8">Email</td><td style="padding:6px 0">${email}</td></tr>
        ${credentialsRow}
        <tr><td style="padding:6px 0;color:#94a3b8">Role</td><td style="padding:6px 0">${roleLabels[role] || role}</td></tr>
      </table>
      ${loginBtn}
      <p style="margin:20px 0 0;font-size:12px;color:#64748b">If you did not expect this email, please contact your administrator.</p>
    </div>
  </div>
</body>
</html>`;

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

  const linkBtn = appUrl
    ? `<a href="${appUrl}" style="display:inline-block;margin-top:20px;padding:10px 20px;background:#22c55e;color:#fff;text-decoration:none;border-radius:6px;font-size:14px;font-weight:600">View Certificates &rarr;</a>`
    : '';

  const html = `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;background:#1a1f2e;color:#e2e8f0;padding:24px">
  <div style="max-width:520px;margin:0 auto;background:#252c3b;border-radius:8px;overflow:hidden">
    <div style="background:#22c55e;padding:16px 24px">
      <h2 style="margin:0;color:#fff;font-size:18px">Certificate Renewed</h2>
    </div>
    <div style="padding:24px">
      <p style="margin:0 0 16px">The following certificate has been renewed:</p>
      <table style="width:100%;border-collapse:collapse;font-size:14px">
        <tr><td style="padding:6px 0;color:#94a3b8;width:140px">Certificate Name</td><td style="padding:6px 0"><strong>${certName}</strong></td></tr>
        <tr><td style="padding:6px 0;color:#94a3b8">FQDN</td><td style="padding:6px 0">${fqdn}</td></tr>
        <tr><td style="padding:6px 0;color:#94a3b8">Previous Expiry</td><td style="padding:6px 0;color:#f87171">${oldExpiry}</td></tr>
        <tr><td style="padding:6px 0;color:#94a3b8">New Expiry</td><td style="padding:6px 0;color:#4ade80"><strong>${newExpiry}</strong></td></tr>
      </table>
      ${linkBtn}
      <p style="margin:20px 0 0;font-size:12px;color:#64748b">This notification was sent by CertManMon.</p>
    </div>
  </div>
</body>
</html>`;

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

function buildEmailHtml(certName, fqdn, expirationDate, daysLeft, thresholdDays, appUrl = '') {
  const urgency = daysLeft <= 7 ? 'critical' : daysLeft <= 14 ? 'warning' : 'notice';
  const color = urgency === 'critical' ? '#e74c3c' : urgency === 'warning' ? '#f39c12' : '#3498db';
  const linkBtn = appUrl
    ? `<a href="${appUrl}" style="display:inline-block;margin-top:20px;padding:10px 20px;background:${color};color:#fff;text-decoration:none;border-radius:6px;font-size:14px;font-weight:600">View Certificates &rarr;</a>`
    : '';
  return `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;background:#1a1f2e;color:#e2e8f0;padding:24px">
  <div style="max-width:520px;margin:0 auto;background:#252c3b;border-radius:8px;overflow:hidden">
    <div style="background:${color};padding:16px 24px">
      <h2 style="margin:0;color:#fff;font-size:18px">Certificate Expiry ${urgency === 'critical' ? 'Alert' : 'Reminder'}</h2>
    </div>
    <div style="padding:24px">
      <p style="margin:0 0 16px">The following certificate will expire in <strong style="color:${color}">${daysLeft} day${daysLeft !== 1 ? 's' : ''}</strong> (threshold: ${thresholdDays} days):</p>
      <table style="width:100%;border-collapse:collapse;font-size:14px">
        <tr><td style="padding:6px 0;color:#94a3b8;width:140px">Certificate Name</td><td style="padding:6px 0"><strong>${certName}</strong></td></tr>
        <tr><td style="padding:6px 0;color:#94a3b8">FQDN</td><td style="padding:6px 0">${fqdn}</td></tr>
        <tr><td style="padding:6px 0;color:#94a3b8">Expiration Date</td><td style="padding:6px 0;color:${color}"><strong>${expirationDate}</strong></td></tr>
      </table>
      ${linkBtn}
      <p style="margin:20px 0 0;font-size:12px;color:#64748b">This notification was sent by CertManMon.</p>
    </div>
  </div>
</body>
</html>`;
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

// --- Audit log routes ---

app.get('/api/logs', ...requireRole('admin'), (req, res) => {
  const { page = 1, limit = 50, action = '', search = '' } = req.query;
  const offset = (parseInt(page, 10) - 1) * parseInt(limit, 10);
  const pageSize = Math.min(parseInt(limit, 10), 200);

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

  res.json({ total, page: parseInt(page, 10), limit: pageSize, rows });
});

app.delete('/api/logs', ...requireRole('admin'), (req, res) => {
  db.prepare('DELETE FROM audit_log').run();
  logEvent(req, 'logs.cleared', '', 'Audit log cleared');
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`CertManMon running on port ${PORT}`));
