// Attack simulator for the web "ทดสอบการโจมตี" page. Fake SSH events go only to the caller's own
// dedicated test servers (servers.is_test = 1), which are created on first use and removed with DELETE.
const express = require("express");
const db = require("../db");
const { jwtAuth, generateApiKey } = require("../middleware/auth");
const { ingestLogs } = require("./agentRoutes");
const { withTestAlerts } = require("../analysisEngine");
const { makeScenarios, demoCountry } = require("../simulation");

const router = express.Router();
router.use("/api/simulate", jwtAuth);

const TEST_SERVERS = 2; // the cross-host scenario needs two
const lastRun = new Map(); // userId -> time of the last run

function testServers(userId) {
  return db.prepare("SELECT * FROM servers WHERE user_id = ? AND is_test = 1 ORDER BY id").all(userId);
}

function ensureTestServers(userId) {
  let list = testServers(userId);
  for (let i = list.length; i < TEST_SERVERS; i++) {
    db.prepare(
      "INSERT INTO servers (name, hostname, ip_address, api_key, status, user_id, is_test) VALUES (?, ?, NULL, ?, 'offline', ?, 1)"
    ).run(`ทดสอบ-${i + 1}`, `sim-test-${i + 1}`, generateApiKey(), userId);
  }
  return testServers(userId);
}

function summary(userId) {
  const servers = testServers(userId).map((s) => ({
    id: s.id,
    name: s.name,
    logs: db.prepare("SELECT COUNT(*) AS c FROM ssh_logs WHERE server_id = ?").get(s.id).c,
    incidents: db.prepare("SELECT COUNT(*) AS c FROM incidents WHERE server_id = ?").get(s.id).c,
  }));
  return { servers };
}

router.get("/api/simulate", (req, res) => {
  const scenarios = makeScenarios(1).map(({ name, label, desc_th, expect_th, hosts }) => ({ name, label, desc: desc_th, expect: expect_th, hosts }));
  res.json({ scenarios, ...summary(req.user.id) });
});

router.post("/api/simulate", (req, res) => {
  const { scenario, alerts } = req.body || {};
  if (Date.now() - (lastRun.get(req.user.id) || 0) < 3000) {
    return res.status(429).json({ error: "กรุณารอสักครู่ก่อนจำลองครั้งถัดไป" });
  }
  const all = makeScenarios(Math.floor(Math.random() * 200) + 20);
  const chosen = scenario === "all" ? all : all.filter((s) => s.name === scenario);
  if (!chosen.length) return res.status(400).json({ error: "ไม่พบสถานการณ์นี้" });
  lastRun.set(req.user.id, Date.now());

  const servers = ensureTestServers(req.user.id);
  const startIso = new Date().toISOString();
  let events = 0;
  withTestAlerts(!!alerts, () => {
    for (const s of chosen) {
      for (const [hostIdx, logs] of Object.entries(s.build())) {
        const server = servers[Number(hostIdx) % servers.length];
        ingestLogs({ agent_version: "web-sim", logs }, server.api_key, req.ip, server, { countryFor: demoCountry });
        events += logs.length;
      }
    }
  });

  const ids = servers.map((s) => s.id);
  const incidents = db
    .prepare(
      `SELECT i.id, i.attack_type, i.risk_level, i.description, i.source_ip, s.name AS server_name
       FROM incidents i JOIN servers s ON s.id = i.server_id
       WHERE i.server_id IN (${ids.map(() => "?").join(",")}) AND julianday(COALESCE(i.last_seen, i.detected_at)) >= julianday(?)
       ORDER BY CASE i.risk_level WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END, i.id`
    )
    .all(...ids, startIso);
  res.json({ events, incidents, ...summary(req.user.id) });
});

router.delete("/api/simulate", (req, res) => {
  const ids = testServers(req.user.id).map((s) => s.id);
  db.exec("BEGIN");
  try {
    for (const id of ids) {
      db.prepare("DELETE FROM ssh_logs WHERE server_id = ?").run(id);
      db.prepare("DELETE FROM incidents WHERE server_id = ?").run(id);
      db.prepare("DELETE FROM servers WHERE id = ?").run(id);
    }
    db.exec("COMMIT");
  } catch (e) {
    db.exec("ROLLBACK");
    throw e;
  }
  res.json({ removed: ids.length });
});

module.exports = router;
