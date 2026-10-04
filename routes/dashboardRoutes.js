const express = require("express");
const db = require("../db");
const { jwtAuth, requireAdmin } = require("../middleware/auth");

const router = express.Router();
router.use(jwtAuth);
router.use(requireAdmin);

router.get("/dashboard/summary", (req, res) => {
  const servers = db.prepare("SELECT COUNT(*) AS c FROM servers").get().c;
  const online = db.prepare("SELECT COUNT(*) AS c FROM servers WHERE status = 'online'").get().c;
  const incidents = db.prepare("SELECT COUNT(*) AS c FROM incidents WHERE status = 'OPEN'").get().c;
  const critical = db
    .prepare("SELECT COUNT(*) AS c FROM incidents WHERE status = 'OPEN' AND risk_level = 'CRITICAL'")
    .get().c;
  const totalLogs = db.prepare("SELECT COUNT(*) AS c FROM ssh_logs").get().c;
  res.json({ servers, online, incidents, critical, totalLogs });
});

router.get("/dashboard/risk", (req, res) => {
  const rows = db
    .prepare(
      "SELECT risk_level, COUNT(*) AS c FROM incidents WHERE status = 'OPEN' GROUP BY risk_level"
    )
    .all();
  const map = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  for (const r of rows) map[r.risk_level] = r.c;
  res.json(map);
});

router.get("/dashboard/recent-incidents", (req, res) => {
  const incidents = db
    .prepare(
      `SELECT i.*, s.hostname AS server_hostname FROM incidents i
       LEFT JOIN servers s ON s.id = i.server_id
       ORDER BY i.detected_at DESC LIMIT 10`
    )
    .all();
  res.json(incidents);
});

router.get("/dashboard/recent-logs", (req, res) => {
  const logs = db
    .prepare(
      `SELECT l.*, s.hostname AS server_hostname FROM ssh_logs l
       LEFT JOIN servers s ON s.id = l.server_id
       ORDER BY l.event_time DESC LIMIT 20`
    )
    .all();
  res.json(logs);
});

module.exports = router;
