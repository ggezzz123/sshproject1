const express = require("express");
const db = require("../db");
const { jwtAuth, requireAdmin, generateApiKey } = require("../middleware/auth");

const router = express.Router();
router.use(jwtAuth);

// A server is visible/mutable by its owner, or by any admin
function canAccessServer(req, server) {
  return req.user.role === "admin" || server.user_id === req.user.id;
}

// Admin: every server across all users (with owner). User: only their own servers.
router.get("/servers", (req, res) => {
  const isAdmin = req.user.role === "admin";
  const servers = db
    .prepare(
      `SELECT s.*, u.username AS owner,
        (SELECT COUNT(*) FROM ssh_logs l WHERE l.server_id = s.id) AS log_count,
        (SELECT COUNT(*) FROM incidents i WHERE i.server_id = s.id AND i.status = 'OPEN') AS open_incidents
       FROM servers s LEFT JOIN users u ON u.id = s.user_id
       ${isAdmin ? "" : "WHERE s.user_id = ?"} ORDER BY s.id DESC`
    )
    .all(...(isAdmin ? [] : [req.user.id]));
  res.json(servers);
});

router.get("/users", requireAdmin, (req, res) => {
  const users = db
    .prepare(
      `SELECT u.id, u.username, u.role,
        (SELECT COUNT(*) FROM servers s WHERE s.user_id = u.id) AS server_count
       FROM users u ORDER BY u.id`
    )
    .all();
  res.json(users);
});

// Self-service: only the caller's own servers/keys (used by /get-key)
router.get("/my-servers", (req, res) => {
  const servers = db
    .prepare("SELECT * FROM servers WHERE user_id = ? ORDER BY id DESC")
    .all(req.user.id);
  res.json(servers);
});

router.get("/servers/:id", (req, res) => {
  const server = db.prepare("SELECT * FROM servers WHERE id = ?").get(req.params.id);
  if (!server || !canAccessServer(req, server)) return res.status(404).json({ error: "ไม่พบข้อมูล" });
  res.json(server);
});

router.post("/servers", (req, res) => {
  const { name, hostname, ip_address } = req.body || {};
  if (!name) return res.status(400).json({ error: "กรุณาตั้งชื่อเซิร์ฟเวอร์" });
  const api_key = generateApiKey();
  const info = db
    .prepare(
      "INSERT INTO servers (name, hostname, ip_address, api_key, status, user_id) VALUES (?, ?, ?, ?, 'offline', ?)"
    )
    .run(name, hostname || name, ip_address || null, api_key, req.user.id);
  res.json(db.prepare("SELECT * FROM servers WHERE id = ?").get(info.lastInsertRowid));
});

router.post("/servers/:id/regenerate-key", (req, res) => {
  const server = db.prepare("SELECT * FROM servers WHERE id = ?").get(req.params.id);
  if (!server || !canAccessServer(req, server)) return res.status(404).json({ error: "ไม่พบข้อมูล" });
  const api_key = generateApiKey();
  db.prepare("UPDATE servers SET api_key = ? WHERE id = ?").run(api_key, server.id);
  res.json(db.prepare("SELECT * FROM servers WHERE id = ?").get(server.id));
});

router.delete("/servers/:id", (req, res) => {
  const server = db.prepare("SELECT * FROM servers WHERE id = ?").get(req.params.id);
  if (!server || !canAccessServer(req, server)) return res.status(404).json({ error: "ไม่พบข้อมูล" });
  // logs and incidents reference the server, so they go first (foreign keys are enforced)
  db.exec("BEGIN");
  try {
    db.prepare("DELETE FROM ssh_logs WHERE server_id = ?").run(server.id);
    db.prepare("DELETE FROM incidents WHERE server_id = ?").run(server.id);
    db.prepare("DELETE FROM servers WHERE id = ?").run(server.id);
    db.exec("COMMIT");
  } catch (e) {
    db.exec("ROLLBACK");
    throw e;
  }
  res.json({ status: "deleted" });
});

module.exports = router;
