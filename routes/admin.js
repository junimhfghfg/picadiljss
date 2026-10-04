const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { getDb, saveDb, genId } = require('../database');

const JWT_SECRET = 'keyauth-secret-key-change-in-production';

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Token não fornecido' });
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ success: false, message: 'Token inválido' });
  }
}

router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const db = getDb();
  const admin = db.admins.find(a => a.username === username);
  if (!admin || !bcrypt.compareSync(password, admin.password)) {
    return res.status(401).json({ success: false, message: 'Credenciais inválidas' });
  }
  const token = jwt.sign({ id: admin.id, username: admin.username }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ success: true, token });
});

router.post('/change-password', authMiddleware, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const db = getDb();
  const admin = db.admins.find(a => a.id === req.admin.id);
  if (!bcrypt.compareSync(currentPassword, admin.password)) {
    return res.status(400).json({ success: false, message: 'Senha atual incorreta' });
  }
  admin.password = bcrypt.hashSync(newPassword, 10);
  saveDb();
  res.json({ success: true, message: 'Senha alterada' });
});

router.get('/apps', authMiddleware, (req, res) => {
  const db = getDb();
  const apps = [...db.apps].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json({ success: true, data: apps });
});

router.post('/apps', authMiddleware, (req, res) => {
  const { name, version } = req.body;
  const db = getDb();
  const id = uuidv4();
  const secret = uuidv4().replace(/-/g, '');
  const app = { id, name, secret, version: version || '1.0', status: 1, created_at: new Date().toISOString() };
  db.apps.push(app);
  saveDb();
  res.json({ success: true, data: app });
});

router.delete('/apps/:id', authMiddleware, (req, res) => {
  const db = getDb();
  const appId = req.params.id;
  db.apps = db.apps.filter(a => a.id !== appId);
  db.keys = db.keys.filter(k => k.app_id !== appId);
  db.users = db.users.filter(u => u.app_id !== appId);
  db.logs = db.logs.filter(l => l.app_id !== appId);
  db.blacklists = db.blacklists.filter(b => b.app_id !== appId);
  db.variables = db.variables.filter(v => v.app_id !== appId);
  db.sessions = db.sessions.filter(s => s.app_id !== appId);
  saveDb();
  res.json({ success: true });
});

router.put('/apps/:id', authMiddleware, (req, res) => {
  const { name, version, status } = req.body;
  const db = getDb();
  const app = db.apps.find(a => a.id === req.params.id);
  if (app) {
    app.name = name;
    app.version = version;
    app.status = status;
    saveDb();
  }
  res.json({ success: true });
});

router.get('/keys/:appId', authMiddleware, (req, res) => {
  const db = getDb();
  const keys = db.keys.filter(k => k.app_id === req.params.appId).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json({ success: true, data: keys });
});

router.post('/keys/generate', authMiddleware, (req, res) => {
  const { appId, amount, duration, durationUnit, level, maxUses, prefix, note } = req.body;
  const db = getDb();
  const keys = [];

  for (let i = 0; i < (amount || 1); i++) {
    const pfx = prefix ? `${prefix}-` : '';
    const keyValue = `${pfx}${uuidv4().replace(/-/g, '').substring(0, 20).toUpperCase()}`;
    const key = {
      id: genId(),
      key_value: keyValue,
      app_id: appId,
      duration: duration || 1,
      duration_unit: durationUnit || 'days',
      level: level || 1,
      max_uses: maxUses || 1,
      used_count: 0,
      status: 'unused',
      note: note || '',
      created_at: new Date().toISOString()
    };
    db.keys.push(key);
    keys.push(keyValue);
  }

  saveDb();
  res.json({ success: true, data: keys });
});

router.delete('/keys/:id', authMiddleware, (req, res) => {
  const db = getDb();
  db.keys = db.keys.filter(k => k.id !== parseInt(req.params.id));
  saveDb();
  res.json({ success: true });
});

router.post('/keys/delete-all/:appId', authMiddleware, (req, res) => {
  const db = getDb();
  const { status } = req.body;
  if (status) {
    db.keys = db.keys.filter(k => !(k.app_id === req.params.appId && k.status === status));
  } else {
    db.keys = db.keys.filter(k => k.app_id !== req.params.appId);
  }
  saveDb();
  res.json({ success: true });
});

router.post('/keys/ban/:id', authMiddleware, (req, res) => {
  const db = getDb();
  const key = db.keys.find(k => k.id === parseInt(req.params.id));
  if (!key) return res.status(404).json({ success: false, message: 'Key não encontrada' });
  key.status = key.status === 'banned' ? 'unused' : 'banned';
  saveDb();
  res.json({ success: true, status: key.status });
});

router.get('/users/:appId', authMiddleware, (req, res) => {
  const db = getDb();
  const users = db.users.filter(u => u.app_id === req.params.appId).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json({ success: true, data: users });
});

router.post('/users/create', authMiddleware, (req, res) => {
  const { appId, username, password, email, level, days } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, message: 'Usuario e senha obrigatorios' });
  const db = getDb();
  const existing = db.users.find(u => u.username === username && u.app_id === appId);
  if (existing) return res.status(400).json({ success: false, message: 'Usuario ja existe nesta aplicacao' });
  const hashedPw = bcrypt.hashSync(password, 10);
  const expiry = new Date();
  expiry.setDate(expiry.getDate() + (days || 30));
  db.users.push({
    id: genId(), username, password: hashedPw, email: email || '', app_id: appId,
    hwid: '', ip: '', key_value: '', level: level || 1,
    expiry: expiry.toISOString(), banned: 0, ban_reason: '',
    created_at: new Date().toISOString(), last_login: null
  });
  saveDb();
  res.json({ success: true });
});

router.delete('/users/:id', authMiddleware, (req, res) => {
  const db = getDb();
  db.users = db.users.filter(u => u.id !== parseInt(req.params.id));
  db.sessions = db.sessions.filter(s => s.user_id !== parseInt(req.params.id));
  saveDb();
  res.json({ success: true });
});

router.post('/users/ban/:id', authMiddleware, (req, res) => {
  const { reason } = req.body;
  const db = getDb();
  const user = db.users.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ success: false });
  user.banned = user.banned ? 0 : 1;
  user.ban_reason = reason || '';
  saveDb();
  res.json({ success: true, banned: user.banned });
});

router.post('/users/reset-hwid/:id', authMiddleware, (req, res) => {
  const db = getDb();
  const user = db.users.find(u => u.id === parseInt(req.params.id));
  if (user) { user.hwid = ''; saveDb(); }
  res.json({ success: true });
});

router.put('/users/:id', authMiddleware, (req, res) => {
  const { expiry, level, email } = req.body;
  const db = getDb();
  const user = db.users.find(u => u.id === parseInt(req.params.id));
  if (user) {
    user.expiry = expiry;
    user.level = level;
    user.email = email;
    saveDb();
  }
  res.json({ success: true });
});

router.post('/users/extend/:id', authMiddleware, (req, res) => {
  const { days } = req.body;
  const db = getDb();
  const user = db.users.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ success: false });
  let expiry = user.expiry ? new Date(user.expiry) : new Date();
  if (expiry < new Date()) expiry = new Date();
  expiry.setDate(expiry.getDate() + (days || 30));
  user.expiry = expiry.toISOString();
  saveDb();
  res.json({ success: true, expiry: user.expiry });
});

router.get('/logs/:appId', authMiddleware, (req, res) => {
  const db = getDb();
  const logs = db.logs.filter(l => l.app_id === req.params.appId).sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, 500);
  res.json({ success: true, data: logs });
});

router.delete('/logs/:appId', authMiddleware, (req, res) => {
  const db = getDb();
  db.logs = db.logs.filter(l => l.app_id !== req.params.appId);
  saveDb();
  res.json({ success: true });
});

router.get('/blacklist/:appId', authMiddleware, (req, res) => {
  const db = getDb();
  const list = db.blacklists.filter(b => b.app_id === req.params.appId).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json({ success: true, data: list });
});

router.post('/blacklist', authMiddleware, (req, res) => {
  const { appId, type, value } = req.body;
  const db = getDb();
  db.blacklists.push({ id: genId(), app_id: appId, type, value, created_at: new Date().toISOString() });
  saveDb();
  res.json({ success: true });
});

router.delete('/blacklist/:id', authMiddleware, (req, res) => {
  const db = getDb();
  db.blacklists = db.blacklists.filter(b => b.id !== parseInt(req.params.id));
  saveDb();
  res.json({ success: true });
});

router.get('/variables/:appId', authMiddleware, (req, res) => {
  const db = getDb();
  const vars = db.variables.filter(v => v.app_id === req.params.appId).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json({ success: true, data: vars });
});

router.post('/variables', authMiddleware, (req, res) => {
  const { appId, varName, varValue } = req.body;
  const db = getDb();
  db.variables.push({ id: genId(), app_id: appId, var_name: varName, var_value: varValue, created_at: new Date().toISOString() });
  saveDb();
  res.json({ success: true });
});

router.delete('/variables/:id', authMiddleware, (req, res) => {
  const db = getDb();
  db.variables = db.variables.filter(v => v.id !== parseInt(req.params.id));
  saveDb();
  res.json({ success: true });
});

router.get('/stats/:appId', authMiddleware, (req, res) => {
  const db = getDb();
  const appId = req.params.appId;
  const appKeys = db.keys.filter(k => k.app_id === appId);
  const now = new Date();

  res.json({
    success: true,
    data: {
      totalKeys: appKeys.length,
      usedKeys: appKeys.filter(k => k.status === 'used').length,
      unusedKeys: appKeys.filter(k => k.status === 'unused').length,
      bannedKeys: appKeys.filter(k => k.status === 'banned').length,
      totalUsers: db.users.filter(u => u.app_id === appId).length,
      bannedUsers: db.users.filter(u => u.app_id === appId && u.banned).length,
      onlineUsers: db.sessions.filter(s => s.app_id === appId && new Date(s.expires_at) > now).length
    }
  });
});

module.exports = router;
