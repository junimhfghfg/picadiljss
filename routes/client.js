const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { getDb, saveDb, genId } = require('../database');

function addLog(appId, action, details, ip, username) {
  const db = getDb();
  db.logs.push({ id: genId(), app_id: appId, action, details: details || '', ip: ip || '', username: username || '', created_at: new Date().toISOString() });
  saveDb();
}

function calcExpiry(durationUnit, duration) {
  const expiry = new Date();
  switch (durationUnit) {
    case 'hours': expiry.setHours(expiry.getHours() + duration); break;
    case 'days': expiry.setDate(expiry.getDate() + duration); break;
    case 'weeks': expiry.setDate(expiry.getDate() + duration * 7); break;
    case 'months': expiry.setMonth(expiry.getMonth() + duration); break;
    case 'years': expiry.setFullYear(expiry.getFullYear() + duration); break;
    case 'lifetime': expiry.setFullYear(expiry.getFullYear() + 100); break;
  }
  return expiry;
}

router.get('/apps-list', (req, res) => {
  const db = getDb();
  const apps = db.apps.filter(a => a.status).map(a => ({ id: a.id, name: a.name, secret: a.secret }));
  res.json({ success: true, data: apps });
});

router.post('/init', (req, res) => {
  const { app_id, app_secret, version } = req.body;
  const db = getDb();
  const app = db.apps.find(a => a.id === app_id && a.secret === app_secret);
  if (!app) return res.json({ success: false, message: 'Aplicação não encontrada' });
  if (!app.status) return res.json({ success: false, message: 'Aplicação desativada' });
  if (version && app.version !== version) return res.json({ success: false, message: `Versão desatualizada. Versão atual: ${app.version}` });
  const sessionId = uuidv4();
  addLog(app_id, 'init', 'Aplicação iniciada', req.ip, '');
  res.json({ success: true, session_id: sessionId, app_name: app.name });
});

router.post('/register', (req, res) => {
  const { app_id, username, password, key: keyValue, email, hwid } = req.body;
  const db = getDb();
  const app = db.apps.find(a => a.id === app_id);
  if (!app) return res.json({ success: false, message: 'App inválida' });

  const existing = db.users.find(u => u.username === username && u.app_id === app_id);
  if (existing) return res.json({ success: false, message: 'Usuário já existe' });

  const blacklisted = db.blacklists.find(b => b.app_id === app_id && ((b.type === 'hwid' && b.value === (hwid || '')) || (b.type === 'ip' && b.value === req.ip)));
  if (blacklisted) return res.json({ success: false, message: 'Você está na blacklist' });

  let expiry = null;
  let level = 1;

  if (keyValue) {
    const key = db.keys.find(k => k.key_value === keyValue && k.app_id === app_id && k.status === 'unused');
    if (!key) return res.json({ success: false, message: 'Key inválida ou já utilizada' });

    expiry = calcExpiry(key.duration_unit, key.duration);
    level = key.level;
    key.status = 'used';
    key.used_count++;
  }

  const hashedPw = password ? bcrypt.hashSync(password, 10) : null;
  db.users.push({
    id: genId(), username, password: hashedPw, email: email || '', app_id,
    hwid: hwid || '', ip: req.ip, key_value: keyValue || '', level,
    expiry: expiry ? expiry.toISOString() : null, banned: 0, ban_reason: '',
    created_at: new Date().toISOString(), last_login: null
  });

  saveDb();
  addLog(app_id, 'register', `Usuário ${username} registrado`, req.ip, username);
  res.json({ success: true, message: 'Registro realizado com sucesso' });
});

router.post('/login', (req, res) => {
  const { app_id, username, password, hwid } = req.body;
  const db = getDb();
  const app = db.apps.find(a => a.id === app_id);
  if (!app) return res.json({ success: false, message: 'App inválida' });

  const user = db.users.find(u => u.username === username && u.app_id === app_id);
  if (!user) return res.json({ success: false, message: 'Usuário não encontrado' });
  if (user.banned) return res.json({ success: false, message: `Conta banida. Motivo: ${user.ban_reason || 'N/A'}` });
  if (user.password && !bcrypt.compareSync(password, user.password)) {
    return res.json({ success: false, message: 'Senha incorreta' });
  }

  const blacklisted = db.blacklists.find(b => b.app_id === app_id && ((b.type === 'hwid' && b.value === (hwid || '')) || (b.type === 'ip' && b.value === req.ip)));
  if (blacklisted) return res.json({ success: false, message: 'Você está na blacklist' });

  if (user.expiry && new Date(user.expiry) < new Date()) {
    return res.json({ success: false, message: 'Sua licença expirou' });
  }

  if (user.hwid && hwid && user.hwid !== hwid) {
    return res.json({ success: false, message: 'HWID diferente. Contate o administrador para reset.' });
  }

  if (!user.hwid && hwid) user.hwid = hwid;
  user.last_login = new Date().toISOString();
  user.ip = req.ip;

  const sessionId = uuidv4();
  const expiresAt = new Date();
  expiresAt.setHours(expiresAt.getHours() + 24);
  db.sessions.push({ id: sessionId, user_id: user.id, app_id, ip: req.ip, created_at: new Date().toISOString(), expires_at: expiresAt.toISOString() });

  saveDb();
  addLog(app_id, 'login', `Usuário ${username} logou`, req.ip, username);
  res.json({
    success: true, session_id: sessionId,
    username: user.username, email: user.email,
    level: user.level, expiry: user.expiry, hwid: user.hwid || hwid
  });
});

router.post('/license', (req, res) => {
  const { app_id, key: keyValue, hwid } = req.body;
  const db = getDb();
  const app = db.apps.find(a => a.id === app_id);
  if (!app) return res.json({ success: false, message: 'App inválida' });

  const key = db.keys.find(k => k.key_value === keyValue && k.app_id === app_id);
  if (!key) return res.json({ success: false, message: 'Key não encontrada' });
  if (key.status === 'banned') return res.json({ success: false, message: 'Key banida' });
  if (key.status === 'used' && key.used_count >= key.max_uses) return res.json({ success: false, message: 'Key já utilizada' });

  const expiry = calcExpiry(key.duration_unit, key.duration);
  key.status = 'used';
  key.used_count++;
  saveDb();

  addLog(app_id, 'license', `Key ${keyValue} ativada`, req.ip, '');
  res.json({ success: true, level: key.level, expiry: expiry.toISOString() });
});

router.post('/reset-hwid', (req, res) => {
  const { app_id, username, password } = req.body;
  const db = getDb();
  const app = db.apps.find(a => a.id === app_id);
  if (!app) return res.json({ success: false, message: 'App inválida' });

  const user = db.users.find(u => u.username === username && u.app_id === app_id);
  if (!user) return res.json({ success: false, message: 'Usuário não encontrado' });
  if (user.password && !bcrypt.compareSync(password, user.password)) {
    return res.json({ success: false, message: 'Senha incorreta' });
  }

  user.hwid = '';
  saveDb();
  addLog(app_id, 'reset-hwid', `HWID resetado para ${username}`, req.ip, username);
  res.json({ success: true, message: 'HWID resetado com sucesso' });
});

router.post('/check-session', (req, res) => {
  const { session_id } = req.body;
  const db = getDb();
  const session = db.sessions.find(s => s.id === session_id && new Date(s.expires_at) > new Date());
  if (!session) return res.json({ success: false, message: 'Sessão inválida ou expirada' });
  const user = db.users.find(u => u.id === session.user_id);
  if (!user) return res.json({ success: false, message: 'Usuário não encontrado' });
  if (user.banned) return res.json({ success: false, message: 'Conta banida' });
  res.json({ success: true, username: user.username, level: user.level, expiry: user.expiry });
});

router.post('/var', (req, res) => {
  const { app_id, var_name } = req.body;
  const db = getDb();
  const v = db.variables.find(x => x.app_id === app_id && x.var_name === var_name);
  if (!v) return res.json({ success: false, message: 'Variável não encontrada' });
  res.json({ success: true, value: v.var_value });
});

module.exports = router;
