const express = require('express');
const path = require('path');
const cors = require('cors');
const db = require('./database');
const apiRoutes = require('./routes/api');
const adminRoutes = require('./routes/admin');
const clientRoutes = require('./routes/client');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use('/api/admin', adminRoutes);
app.use('/api/client', clientRoutes);
app.use('/api', apiRoutes);

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

db.initialize();

app.listen(PORT, () => {
  console.log(`KeyAuth System rodando em http://localhost:${PORT}`);
});
