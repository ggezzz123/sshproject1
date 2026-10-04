const express = require("express");
const db = require("../db");
const { jwtAuth, serverScope, canAccessServerId } = require("../middleware/auth");

const router = express.Router();
router.use(jwtAuth);

router.get("/logs", (req, res) => {
  const { limit = 200, offset = 0, event_type, server_id, source_ip } = req.query;
  const sc = serverScope(req, "l.server_id");
  const clauses = [...sc.clauses];
  const params = [...sc.params];
  if (event_type) {
    clauses.push("l.event_type = ?");
    params.push(event_type);
  }
  if (server_id) {
    clauses.push("l.server_id = ?");
    params.push(server_id);
  }
  if (source_ip) {
    clauses.push("l.source_ip = ?");
    params.push(source_ip);
  }
  const where = clauses.length ? "WHERE " + clauses.join(" AND ") : "";
  const logs = db
    .prepare(
      `SELECT l.*, s.hostname AS server_hostname FROM ssh_logs l
       LEFT JOIN servers s ON s.id = l.server_id
       ${where} ORDER BY l.event_time DESC LIMIT ? OFFSET ?`
    )
    .all(...params, Number(limit), Number(offset));
  const total = db
    .prepare(`SELECT COUNT(*) AS c FROM ssh_logs l ${where}`)
    .get(...params).c;
  res.json({ logs, total });
});

router.get("/logs/:id", (req, res) => {
  const log = db.prepare("SELECT * FROM ssh_logs WHERE id = ?").get(req.params.id);
  if (!log || !canAccessServerId(req, log.server_id)) {
    return res.status(404).json({ error: "Not found" });
  }
  res.json(log);
});

module.exports = router;
