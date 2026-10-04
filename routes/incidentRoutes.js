const express = require("express");
const db = require("../db");
const { jwtAuth, requireAdmin } = require("../middleware/auth");

const router = express.Router();
router.use(jwtAuth);
router.use(requireAdmin);

router.get("/incidents", (req, res) => {
  const { status, risk_level } = req.query;
  const clauses = [];
  const params = [];
  if (status) {
    clauses.push("i.status = ?");
    params.push(status);
  }
  if (risk_level) {
    clauses.push("i.risk_level = ?");
    params.push(risk_level);
  }
  const where = clauses.length ? "WHERE " + clauses.join(" AND ") : "";
  const incidents = db
    .prepare(
      `SELECT i.*, s.hostname AS server_hostname FROM incidents i
       LEFT JOIN servers s ON s.id = i.server_id
       ${where} ORDER BY i.detected_at DESC`
    )
    .all(...params);
  res.json(incidents);
});

router.get("/incidents/:id", (req, res) => {
  const incident = db.prepare("SELECT * FROM incidents WHERE id = ?").get(req.params.id);
  if (!incident) return res.status(404).json({ error: "Not found" });
  res.json(incident);
});

router.patch("/incidents/:id/status", (req, res) => {
  const { status } = req.body || {};
  if (!["OPEN", "CLOSED", "RESOLVED"].includes(status)) {
    return res.status(400).json({ error: "Invalid status" });
  }
  db.prepare("UPDATE incidents SET status = ? WHERE id = ?").run(status, req.params.id);
  res.json(db.prepare("SELECT * FROM incidents WHERE id = ?").get(req.params.id));
});

module.exports = router;
