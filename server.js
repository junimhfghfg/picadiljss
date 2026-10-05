require('dotenv').config();
const express = require('express');
const admin   = require('firebase-admin');

// ── Firebase Admin SDK ────────────────────────────────────────────────────────
// Usa as credenciais do serviceAccount.json que você vai baixar do Firebase Console
const serviceAccount = require('./serviceAccount.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL
});

const db  = admin.database();
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Helper: gera timestamp legível ───────────────────────────────────────────
function nowISO() {
  return new Date().toISOString();
}

// ── Helper: monta objeto seguro a partir do body do KeyAuth ──────────────────
function buildEntry(body) {
  return {
    // Campos padrão enviados pelo KeyAuth em todos os eventos
    username:   body.username   || body.user    || 'unknown',
    key:        body.key        || body.license || null,
    ip:         body.ip         || body.clientip || null,
    hwid:       body.hwid       || null,
    appName:    body.appname    || body.app      || null,
    eventType:  body.type       || body.action   || 'unknown',
    // Campos extras opcionais
    email:      body.email      || null,
    country:    body.country    || null,
    // Metadados do registro
    timestamp:  nowISO(),
    raw:        body            // guarda o payload completo para debug
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /webhook/login
// KeyAuth dispara quando um usuário faz login com sucesso
// ─────────────────────────────────────────────────────────────────────────────
app.post('/webhook/login', async (req, res) => {
  try {
    const entry = buildEntry(req.body);
    console.log('[LOGIN]', entry.username, entry.ip, entry.timestamp);

    // Salva em /logins/<username>/<autoId>
    const ref = db.ref(`logins/${sanitize(entry.username)}`);
    await ref.push(entry);

    // Atualiza último login do usuário em /users/<username>/lastLogin
    await db.ref(`users/${sanitize(entry.username)}`).update({
      lastLogin:  entry.timestamp,
      lastIp:     entry.ip,
      lastHwid:   entry.hwid,
      appName:    entry.appName
    });

    res.status(200).json({ status: 'ok', event: 'login' });
  } catch (err) {
    console.error('[LOGIN ERROR]', err.message);
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /webhook/key-created
// KeyAuth dispara quando uma nova key/licença é criada
// ─────────────────────────────────────────────────────────────────────────────
app.post('/webhook/key-created', async (req, res) => {
  try {
    const entry = buildEntry(req.body);
    console.log('[KEY CREATED]', entry.key, entry.timestamp);

    // Salva em /keys/<autoId>
    const ref = db.ref('keys');
    await ref.push({
      key:       entry.key,
      appName:   entry.appName,
      createdBy: entry.username,
      timestamp: entry.timestamp,
      raw:       entry.raw
    });

    res.status(200).json({ status: 'ok', event: 'key-created' });
  } catch (err) {
    console.error('[KEY CREATED ERROR]', err.message);
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /webhook/register
// KeyAuth dispara quando um usuário se registra (resgata a key pela 1ª vez)
// ─────────────────────────────────────────────────────────────────────────────
app.post('/webhook/register', async (req, res) => {
  try {
    const entry = buildEntry(req.body);
    console.log('[REGISTER]', entry.username, entry.key, entry.timestamp);

    // Salva em /registers/<autoId>
    await db.ref('registers').push(entry);

    // Cria/atualiza o perfil do usuário em /users/<username>
    await db.ref(`users/${sanitize(entry.username)}`).set({
      username:   entry.username,
      key:        entry.key,
      ip:         entry.ip,
      hwid:       entry.hwid,
      email:      entry.email,
      appName:    entry.appName,
      registeredAt: entry.timestamp,
      lastLogin:    entry.timestamp
    });

    res.status(200).json({ status: 'ok', event: 'register' });
  } catch (err) {
    console.error('[REGISTER ERROR]', err.message);
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /webhook/all  (rota genérica — caso queira um único endpoint no KeyAuth)
// ─────────────────────────────────────────────────────────────────────────────
app.post('/webhook/all', async (req, res) => {
  try {
    const entry = buildEntry(req.body);
    const type  = entry.eventType;
    console.log(`[ALL/${type}]`, entry.username, entry.timestamp);

    // Salva em /events/<type>/<autoId>
    await db.ref(`events/${sanitize(type)}`).push(entry);

    res.status(200).json({ status: 'ok', event: type });
  } catch (err) {
    console.error('[ALL ERROR]', err.message);
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// ── Healthcheck ───────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'online', time: nowISO() });
});

// ── Sanitiza strings para usar como chave no Firebase (sem ., #, $, [, ]) ───
function sanitize(str) {
  if (!str) return 'unknown';
  return String(str).replace(/[.#$\[\]]/g, '_');
}

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[SERVER] Rodando na porta ${PORT}`);
  console.log(`[SERVER] Endpoints disponiveis:`);
  console.log(`  POST /webhook/login`);
  console.log(`  POST /webhook/register`);
  console.log(`  POST /webhook/key-created`);
  console.log(`  POST /webhook/all`);
  console.log(`  GET  /`);
});
