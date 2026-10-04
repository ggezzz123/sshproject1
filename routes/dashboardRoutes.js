const express = require("express");
const db = require("../db");
const { jwtAuth, serverScope, canAccessServerId } = require("../middleware/auth");
const { analyzeIp } = require("../analysisEngine");

const router = express.Router();
router.use(jwtAuth);

const H = 3600 * 1000;
const D = 24 * H;
const RANGES = { "24h": 24 * H, "7d": 7 * D, "30d": 30 * D };
const FAIL_SQL = "l.event_type IN ('ssh_login_failed','ssh_invalid_user')";

router.get("/dashboard/analytics", (req, res) => {
  const { server_id, severity, event_type } = req.query;
  const range = RANGES[req.query.range] || req.query.range === "all" ? req.query.range : "24h";

  // Base filter shared by every log query: permission scope + dashboard filters
  const sc = serverScope(req, "l.server_id");
  const base = [...sc.clauses];
  const baseParams = [...sc.params];
  if (server_id) {
    if (!canAccessServerId(req, Number(server_id))) return res.status(404).json({ error: "Not found" });
    base.push("l.server_id = ?");
    baseParams.push(Number(server_id));
  }
  if (severity) { base.push("l.severity = ?"); baseParams.push(severity); }
  if (event_type) { base.push("l.event_type = ?"); baseParams.push(event_type); }

  const now = Date.now();
  let from;
  let bucketMs;
  if (range === "all") {
    const where = base.length ? "WHERE " + base.join(" AND ") : "";
    const min = db.prepare(`SELECT MIN(julianday(l.event_time)) AS j FROM ssh_logs l ${where}`).get(...baseParams).j;
    from = min != null ? Math.round((min - 2440587.5) * D) : now - 30 * D;
    const span = now - from;
    bucketMs = span <= 2 * D ? H : span <= 120 * D ? D : 7 * D;
    from = Math.floor(from / bucketMs) * bucketMs;
  } else {
    from = now - RANGES[range];
    bucketMs = range === "24h" ? H : range === "7d" ? 6 * H : D;
  }
  const buckets = Math.max(1, Math.ceil((now - from) / bucketMs));
  const prevFrom = range === "all" ? null : from - (now - from);

  const logWhere = (fromMs, toMs) => ({
    sql: "WHERE " + [...base, "julianday(l.event_time) >= julianday(?)", "julianday(l.event_time) < julianday(?)"].join(" AND "),
    params: [...baseParams, new Date(fromMs).toISOString(), new Date(toMs).toISOString()],
  });

  const kpiSql = (w) =>
    db.prepare(
      `SELECT COUNT(*) AS total,
        COALESCE(SUM(${FAIL_SQL}),0) AS failed,
        COALESCE(SUM(l.event_type = 'ssh_login_success'),0) AS success,
        COUNT(DISTINCT CASE WHEN ${FAIL_SQL} THEN l.source_ip END) AS attackers
       FROM ssh_logs l ${w.sql}`
    ).get(...w.params);

  const cur = logWhere(from, now + 1000);
  const kpis = { current: kpiSql(cur), previous: prevFrom != null ? kpiSql(logWhere(prevFrom, from)) : null };

  const seriesRows = db
    .prepare(
      `SELECT CAST(((julianday(l.event_time) - julianday(?)) * 86400000) / ? AS INTEGER) AS b,
        COUNT(*) AS total,
        COALESCE(SUM(${FAIL_SQL}),0) AS failed,
        COALESCE(SUM(l.event_type = 'ssh_login_success'),0) AS success,
        COUNT(DISTINCT CASE WHEN ${FAIL_SQL} THEN l.source_ip END) AS attackers
       FROM ssh_logs l ${cur.sql} GROUP BY b`
    )
    .all(new Date(from).toISOString(), bucketMs, ...cur.params);
  const series = Array.from({ length: buckets }, (_, i) => ({ t: from + i * bucketMs, total: 0, failed: 0, success: 0, attackers: 0 }));
  for (const r of seriesRows) if (r.b >= 0 && r.b < buckets) Object.assign(series[r.b], { total: r.total, failed: r.failed, success: r.success, attackers: r.attackers });

  const bySeverity = db.prepare(`SELECT l.severity AS key, COUNT(*) AS count FROM ssh_logs l ${cur.sql} GROUP BY l.severity ORDER BY count DESC`).all(...cur.params);
  const byType = db.prepare(`SELECT l.event_type AS key, COUNT(*) AS count FROM ssh_logs l ${cur.sql} GROUP BY l.event_type ORDER BY count DESC`).all(...cur.params);
  const topIps = db
    .prepare(
      `SELECT l.source_ip AS ip, COALESCE(SUM(${FAIL_SQL}),0) AS failed, COALESCE(SUM(l.event_type = 'ssh_login_success'),0) AS success,
        COUNT(DISTINCT l.server_id) AS hosts, COUNT(*) AS total
       FROM ssh_logs l ${cur.sql} AND l.source_ip IS NOT NULL GROUP BY l.source_ip HAVING failed > 0 ORDER BY failed DESC LIMIT 8`
    )
    .all(...cur.params);
  const topUsers = db
    .prepare(
      `SELECT l.username AS user, COUNT(*) AS count, SUM(l.event_type = 'ssh_invalid_user') AS invalid
       FROM ssh_logs l ${cur.sql} AND ${FAIL_SQL} AND l.username IS NOT NULL GROUP BY l.username ORDER BY count DESC LIMIT 8`
    )
    .all(...cur.params);

  // Incidents active during the selected period (same permission + server filter)
  const isc = serverScope(req, "i.server_id");
  const iWhere = [...isc.clauses, "julianday(COALESCE(i.last_seen, i.detected_at)) >= julianday(?)"];
  const iParams = [...isc.params, new Date(from).toISOString()];
  if (server_id) { iWhere.push("i.server_id = ?"); iParams.push(Number(server_id)); }
  const iSql = "WHERE " + iWhere.join(" AND ");
  const incidents = {
    byAttack: db.prepare(`SELECT i.attack_type AS key, COUNT(*) AS count FROM incidents i ${iSql} GROUP BY i.attack_type ORDER BY count DESC`).all(...iParams),
    byRisk: db.prepare(`SELECT i.risk_level AS key, COUNT(*) AS count FROM incidents i ${iSql} GROUP BY i.risk_level`).all(...iParams),
    open: db.prepare(`SELECT COUNT(*) AS c FROM incidents i ${iSql} AND i.status = 'OPEN'`).get(...iParams).c,
    recent: db
      .prepare(
        `SELECT i.*, s.hostname AS server_hostname FROM incidents i LEFT JOIN servers s ON s.id = i.server_id
         ${iSql} ORDER BY CASE i.status WHEN 'OPEN' THEN 0 ELSE 1 END,
         CASE i.risk_level WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END, i.id DESC LIMIT 12`
      )
      .all(...iParams),
  };

  const servers =
    req.user.role === "admin"
      ? db.prepare("SELECT id, name, hostname FROM servers ORDER BY name").all()
      : db.prepare("SELECT id, name, hostname FROM servers WHERE user_id = ? ORDER BY name").all(req.user.id);

  res.json({ range, from, to: now, bucketMs, kpis, series, bySeverity, byType, topIps, topUsers, incidents, servers });
});

router.get("/analysis/ip/:ip", (req, res) => {
  const serverIds =
    req.user.role === "admin"
      ? null
      : db.prepare("SELECT id FROM servers WHERE user_id = ?").all(req.user.id).map((r) => r.id);
  res.json(analyzeIp(req.params.ip, serverIds));
});

module.exports = router;
