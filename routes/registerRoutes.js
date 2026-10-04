const express = require("express");
const db = require("../db");
const { generateApiKey } = require("../middleware/auth");

const router = express.Router();

const REGISTRATION_TOKEN = process.env.REGISTRATION_TOKEN || "";

// Public self-service server registration (requires shared registration token)
router.post("/api/register-server", (req, res) => {
  const token = req.headers["x-registration-token"] || "";
  if (!REGISTRATION_TOKEN || token !== REGISTRATION_TOKEN) {
    return res.status(401).json({ error: "Invalid registration token" });
  }

  const { name, hostname, ip_address } = req.body || {};
  if (!name) {
    return res.status(400).json({ error: "name required" });
  }

  const api_key = generateApiKey();
  const info = db
    .prepare(
      "INSERT INTO servers (name, hostname, ip_address, api_key, status) VALUES (?, ?, ?, ?, 'offline')"
    )
    .run(name, hostname || name, ip_address || null, api_key);

  const server = db.prepare("SELECT * FROM servers WHERE id = ?").get(info.lastInsertRowid);
  res.json({ api_key, server });
});

module.exports = router;
