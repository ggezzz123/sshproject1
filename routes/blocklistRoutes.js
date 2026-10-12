// Blacklist / whitelist page API, auto-block settings, and the list each agent enforces with its firewall.
const express = require("express");
const crypto = require("crypto");
const db = require("../db");
const { apiKeyAuth, jwtAuth } = require("../middleware/auth");
const blocklist = require("../blocklist");
const { RISK_ORDER } = require("../detectionEngine");

const router = express.Router();

// Agent polls this every ~30s and applies the result with iptables / ip6tables
router.get("/api/agent/blocklist", apiKeyAuth, (req, res) => {
  const list = blocklist.listForServer(req.server || null);
  if (req.server) db.prepare("UPDATE servers SET blocklist_synced_at = ? WHERE id = ?").run(new Date().toISOString(), req.server.id);
  const version = crypto.createHash("sha1").update(JSON.stringify(list)).digest("hex").slice(0, 16);
  res.json({ version, ...list });
});

router.use("/api/ip-rules", jwtAuth);

const isAdmin = (req) => req.user.role === "admin";
const MAX_MINUTES = 365 * 1440;

router.get("/api/ip-rules", (req, res) => {
  blocklist.purgeExpired();
  const rules = db
    .prepare(
      `SELECT r.*, u.username AS owner, s.hostname AS server_hostname FROM ip_rules r
       LEFT JOIN users u ON u.id = r.user_id LEFT JOIN servers s ON s.id = r.server_id
       ${isAdmin(req) ? "" : "WHERE r.user_id IS NULL OR r.user_id = ?"} ORDER BY r.created_at DESC`
    )
    .all(...(isAdmin(req) ? [] : [req.user.id]));
  const servers = db
    .prepare(
      `SELECT id, name, hostname, status, blocklist_synced_at FROM servers WHERE COALESCE(is_test, 0) = 0
       ${isAdmin(req) ? "" : "AND user_id = ?"} ORDER BY name`
    )
    .all(...(isAdmin(req) ? [] : [req.user.id]));
  res.json({ rules, servers, settings: blocklist.settingsFor(req.user.id), your_ip: req.ip });
});

router.post("/api/ip-rules", (req, res) => {
  const { ip, kind, reason, minutes, global } = req.body || {};
  if (!["block", "allow"].includes(kind)) return res.status(400).json({ error: "ประเภทรายการไม่ถูกต้อง" });
  const norm = blocklist.normalize(ip);
  if (!norm) return res.status(400).json({ error: "รูปแบบ IP ไม่ถูกต้อง ใส่ได้ทั้ง IPv4, IPv6 หรือช่วงแบบ CIDR เช่น 203.0.113.0/24" });
  if (global && !isAdmin(req)) return res.status(403).json({ error: "เฉพาะผู้ดูแลระบบที่เพิ่มกฎสำหรับทุกเซิร์ฟเวอร์ได้" });
  const mins = Math.floor(Number(minutes) || 0);
  if (mins < 0 || mins > MAX_MINUTES) return res.status(400).json({ error: "ระยะเวลาไม่ถูกต้อง" });
  if (kind === "block") {
    const c = blocklist.parseCidr(norm);
    if (c.bits < (c.v === 4 ? 8 : 32)) return res.status(400).json({ error: "ช่วง IP กว้างเกินไป" });
    if (req.ip && blocklist.covers(norm, req.ip.replace(/^::ffff:/, ""))) {
      return res.status(400).json({ error: "IP นี้ครอบคลุม IP ที่คุณใช้อยู่ตอนนี้ บล็อกแล้วอาจ SSH เข้าเครื่องตัวเองไม่ได้" });
    }
  }
  const rule = blocklist.upsertRule({
    userId: global ? null : req.user.id, ip: norm, kind, minutes: mins, source: "manual",
    reason: String(reason || "").trim().slice(0, 200) || null, createdBy: req.user.id,
  });
  res.json(rule);
});

function ownRule(req, res) {
  const rule = db.prepare("SELECT * FROM ip_rules WHERE id = ?").get(req.params.id);
  const mine = rule && (rule.user_id === req.user.id || isAdmin(req));
  if (!mine) {
    res.status(rule && rule.user_id == null ? 403 : 404).json({ error: rule ? "กฎนี้ตั้งโดยผู้ดูแลระบบ แก้ไขไม่ได้" : "ไม่พบรายการ" });
    return null;
  }
  return rule;
}

router.delete("/api/ip-rules/:id", (req, res) => {
  const rule = ownRule(req, res);
  if (!rule) return;
  db.prepare("DELETE FROM ip_rules WHERE id = ?").run(rule.id);
  res.json({ ok: true });
});

// Move an entry to the other list (e.g. an auto-blocked IP that turns out to be trusted)
router.post("/api/ip-rules/:id/move", (req, res) => {
  const rule = ownRule(req, res);
  if (!rule) return;
  const kind = rule.kind === "block" ? "allow" : "block";
  const moved = blocklist.upsertRule({
    userId: rule.user_id, ip: rule.ip, kind, source: "manual", createdBy: req.user.id,
    reason: kind === "allow" ? "ย้ายจาก Blacklist" : "ย้ายจาก Whitelist",
  });
  res.json(moved);
});

router.put("/api/ip-rules/settings", (req, res) => {
  const { enabled, min_risk, minutes } = req.body || {};
  const risk = String(min_risk || "").toUpperCase();
  if (!(risk in RISK_ORDER)) return res.status(400).json({ error: "ระดับความเสี่ยงไม่ถูกต้อง" });
  const mins = Math.floor(Number(minutes));
  if (!(mins >= 0 && mins <= MAX_MINUTES)) return res.status(400).json({ error: "ระยะเวลาไม่ถูกต้อง" });
  res.json(blocklist.saveSettings(req.user.id, { enabled: !!enabled, min_risk: risk, minutes: mins }));
});

module.exports = router;
