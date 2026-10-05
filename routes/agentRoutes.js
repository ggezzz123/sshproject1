const express = require("express");
const db = require("../db");
const { apiKeyAuth } = require("../middleware/auth");
const { analyzeBatch } = require("../analysisEngine");
const { countryOf } = require("../geo");

const router = express.Router();

// Timestamps without a zone (older agents send "YYYY-MM-DD HH:MM:SS" in the server's local time)
// are interpreted with this offset.
const LOG_TZ_OFFSET = process.env.LOG_TZ_OFFSET || "+07:00";

function normalizeTimestamp(ts) {
  if (!ts) return new Date().toISOString();
  let s = String(ts).trim();
  if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(s)) s = s.replace(" ", "T") + LOG_TZ_OFFSET;
  const d = new Date(s);
  return isNaN(d) ? new Date().toISOString() : d.toISOString();
}

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
    "INSERT INTO ssh_logs (server_id, event_time, source_ip, username, event_type, severity, message, country) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
  );

  const normalized = logs.map((log) => {
    const event_time = normalizeTimestamp(log.timestamp);
    return {
      event_time,
      t: new Date(event_time).getTime(),
      ip: log.ip_address || log.source_ip || null,
      user: log.username || null,
      type: log.event_type || "unknown",
      severity: log.severity || "info",
      message: log.message || null,
    };
  });

  db.exec("BEGIN");
  try {
    for (const l of normalized) {
      insert.run(server.id, l.event_time, l.ip, l.user, l.type, l.severity, l.message, countryOf(l.ip));
    }
    db.exec("COMMIT");
  } catch (e) {
    db.exec("ROLLBACK");
    throw e;
  }

  try {
    analyzeBatch(server.id, normalized);
  } catch (e) {
    console.error("[analysis]", e);
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
