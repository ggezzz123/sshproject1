const express = require("express");
const db = require("../db");
const { apiKeyAuth } = require("../middleware/auth");
const { calculateRisk, maxRisk } = require("../detectionEngine");

const router = express.Router();

const FAILED_TYPES = new Set(["ssh_login_failed", "ssh_invalid_user"]);
const SUCCESS_TYPES = new Set(["ssh_login_success"]);
const WINDOW_MS = 10 * 60 * 1000; // 10 minutes

function findOrCreateServer(hostname, apiKey, ip) {
  let server = db
    .prepare("SELECT * FROM servers WHERE hostname = ?")
    .get(hostname);
  if (!server) {
    const info = db
      .prepare(
        "INSERT INTO servers (name, hostname, ip_address, api_key, status, last_seen) VALUES (?, ?, ?, ?, 'online', datetime('now'))"
      )
      .run(hostname, hostname, ip || null, apiKey);
    server = db.prepare("SELECT * FROM servers WHERE id = ?").get(info.lastInsertRowid);
  } else {
    db.prepare(
      "UPDATE servers SET status = 'online', last_seen = datetime('now'), ip_address = COALESCE(?, ip_address) WHERE id = ?"
    ).run(ip || null, server.id);
  }
  return server;
}

function countFailed(serverId, ip) {
  const since = new Date(Date.now() - WINDOW_MS).toISOString();
  const row = db
    .prepare(
      "SELECT COUNT(*) AS c FROM ssh_logs WHERE server_id = ? AND source_ip = ? AND event_type IN ('ssh_login_failed','ssh_invalid_user') AND event_time >= ?"
    )
    .get(serverId, ip, since);
  return row.c;
}

function upsertIncident(serverId, ip, risk, failedAttempts, description) {
  const existing = db
    .prepare(
      "SELECT * FROM incidents WHERE server_id = ? AND source_ip = ? AND status = 'OPEN' ORDER BY id DESC LIMIT 1"
    )
    .get(serverId, ip);

  if (existing) {
    const newRisk = maxRisk(existing.risk_level, risk);
    db.prepare(
      "UPDATE incidents SET risk_level = ?, failed_attempts = ?, description = ? WHERE id = ?"
    ).run(newRisk, failedAttempts, description, existing.id);
  } else {
    db.prepare(
      "INSERT INTO incidents (server_id, source_ip, risk_level, failed_attempts, description, detected_at, status) VALUES (?, ?, ?, ?, ?, datetime('now'), 'OPEN')"
    ).run(serverId, ip, risk, failedAttempts, description);
  }
}

function processDetection(serverId, log) {
  const ip = log.ip_address || log.source_ip;
  if (!ip) return;
  const type = log.event_type;

  if (FAILED_TYPES.has(type)) {
    const failed = countFailed(serverId, ip);
    const risk = calculateRisk(failed, false);
    upsertIncident(serverId, ip, risk, failed, `Failed login attempts from ${ip}`);
  } else if (SUCCESS_TYPES.has(type)) {
    const failed = countFailed(serverId, ip);
    if (failed >= 5) {
      upsertIncident(serverId, ip, "CRITICAL", failed, `Brute force followed by successful login from ${ip}`);
    }
  }
}

function ingestLogs(payload, apiKey, remoteIp, matchedServer) {
  const hostname = payload.hostname || "unknown";
  const logs = Array.isArray(payload.logs) ? payload.logs : [];
  let server = matchedServer;
  if (server) {
    db.prepare(
      "UPDATE servers SET status = 'online', last_seen = datetime('now'), hostname = COALESCE(?, hostname), ip_address = COALESCE(?, ip_address) WHERE id = ?"
    ).run(hostname !== "unknown" ? hostname : null, remoteIp || null, server.id);
    server = db.prepare("SELECT * FROM servers WHERE id = ?").get(server.id);
  } else {
    server = findOrCreateServer(hostname, apiKey, remoteIp);
  }

  const insert = db.prepare(
    "INSERT INTO ssh_logs (server_id, event_time, source_ip, username, event_type, severity, message) VALUES (?, ?, ?, ?, ?, ?, ?)"
  );

db.exec("BEGIN");
  try {
    for (const log of logs) {
      insert.run(
        server.id,
        log.timestamp || new Date().toISOString(),
        log.ip_address || log.source_ip || null,
        log.username || null,
        log.event_type || "unknown",
        log.severity || "info",
        log.message || null
      );
    }
    db.exec("COMMIT");
  } catch (e) {
    db.exec("ROLLBACK");
    throw e;
  }

  for (const log of logs) {
    processDetection(server.id, log);
  }

  return { server, received: logs.length };
}

// Python agent posts here
router.post("/api/logs", apiKeyAuth, (req, res) => {
  try {
    const { received } = ingestLogs(req.body, req.apiKey, req.ip, req.server);
    res.json({ status: "success", received });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Internal error" });
  }
});

// note.md-style agent endpoints
router.post("/api/agent/logs", apiKeyAuth, (req, res) => {
  try {
    const { received } = ingestLogs(req.body, req.apiKey, req.ip, req.server);
    res.json({ status: "success", received });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Internal error" });
  }
});

router.post("/api/agent/register", apiKeyAuth, (req, res) => {
  const { serverId, hostname, ip_address } = req.body || {};
  const name = serverId || hostname || "unknown";
  let server = db.prepare("SELECT * FROM servers WHERE hostname = ?").get(name);
  if (!server) {
    const info = db
      .prepare(
        "INSERT INTO servers (name, hostname, ip_address, api_key, status, last_seen) VALUES (?, ?, ?, ?, 'online', datetime('now'))"
      )
      .run(name, name, ip_address || null, req.apiKey);
    server = db.prepare("SELECT * FROM servers WHERE id = ?").get(info.lastInsertRowid);
  }
  res.json({ status: "success", serverId: server.id });
});

router.post("/api/agent/heartbeat", apiKeyAuth, (req, res) => {
  const { serverId, hostname } = req.body || {};
  const key = serverId || hostname;
  if (key) {
    db.prepare(
      "UPDATE servers SET status = 'online', last_seen = datetime('now') WHERE hostname = ? OR id = ?"
    ).run(key, Number.isInteger(key) ? key : -1);
  }
  res.json({ status: "success" });
});

module.exports = router;
