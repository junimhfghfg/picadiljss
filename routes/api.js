const express = require('express');
const router = express.Router();

router.get('/health', (req, res) => {
  res.json({ success: true, message: 'KeyAuth System Online', timestamp: new Date().toISOString() });
});

module.exports = router;
