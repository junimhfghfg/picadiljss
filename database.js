const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const DB_PATH = path.join(__dirname, 'data.json');
let db = null;
let nextId = 1;

function loadDb() {
  if (db) return db;
  try {
    if (fs.existsSync(DB_PATH)) {
      const raw = fs.readFileSync(DB_PATH, 'utf8');
      db = JSON.parse(raw);
      nextId = db._nextId || 1;
      return db;
    }
  } catch {}
  db = {
    _nextId: 1,
    admins: [],
    apps: [],
    keys: [],
    users: [],
    sessions: [],
    logs: [],
    blacklists: [],
    variables: []
  };
  saveDb();
  return db;
}

function saveDb() {
  db._nextId = nextId;
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf8');
}

function genId() {
  return nextId++;
}

function getDb() {
  return loadDb();
}

function initialize() {
  const data = loadDb();

  if (data.admins.length === 0) {
    const hashedPassword = bcrypt.hashSync('admin', 10);
    data.admins.push({ id: genId(), username: 'admin', password: hashedPassword, created_at: new Date().toISOString() });
    console.log('Admin padrão criado - usuario: admin / senha: admin');
  }

  if (data.apps.length === 0) {
    const appId = uuidv4();
    const secret = uuidv4().replace(/-/g, '');
    data.apps.push({ id: appId, name: 'Minha Aplicação', secret, version: '1.0', status: 1, created_at: new Date().toISOString() });
    console.log(`App padrão criada - ID: ${appId}`);
  }

  saveDb();
}

module.exports = { getDb, saveDb, genId, initialize };
