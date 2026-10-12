// IP blacklist / whitelist and automatic blocking.
// Rules belong to a user (apply to all of that user's servers) or are global (user_id NULL, admin only).
// Agents fetch the effective list for their server (GET /api/agent/blocklist) and enforce it with iptables.
// A whitelisted IP is never auto-blocked, and on the agent its ACCEPT rule comes before every DROP.
const net = require("net");
const db = require("./db");
const { RISK_ORDER } = require("./detectionEngine");
const notifier = require("./notifier");

const DEFAULTS = {
  enabled: !/^(0|false|no|off)$/i.test(process.env.AUTO_BLOCK || "true"),
  min_risk: (process.env.AUTO_BLOCK_MIN_RISK || "HIGH").toUpperCase(),
  minutes: Number(process.env.AUTO_BLOCK_MINUTES || 1440), // 0 = until removed
};

/* ---------------- IP / CIDR parsing ---------------- */

// "1.2.3.4" | "1.2.3.0/24" | "2001:db8::/32" -> { v: 4|6, base: BigInt, bits } or null
function parseCidr(input) {
  const s = String(input || "").trim();
  const [addr, prefix, extra] = s.split("/");
  if (extra !== undefined) return null;
  const v = net.isIP(addr);
  if (!v) return null;
  const max = v === 4 ? 32 : 128;
  const bits = prefix === undefined ? max : /^\d{1,3}$/.test(prefix) ? Number(prefix) : NaN;
  if (!(bits >= 0 && bits <= max)) return null;
  const value = v === 4 ? v4ToBig(addr) : v6ToBig(addr);
  const mask = bits === 0 ? 0n : ((1n << BigInt(bits)) - 1n) << BigInt(max - bits);
  return { v, base: value & mask, bits, max };
}

function v4ToBig(a) {
  return a.split(".").reduce((n, o) => (n << 8n) + BigInt(Number(o)), 0n);
}

function v6ToBig(a) {
  let s = a.split("%")[0];
  const m = /(\d+\.\d+\.\d+\.\d+)$/.exec(s); // ::ffff:1.2.3.4
  if (m) {
    const n = v4ToBig(m[1]);
    s = s.slice(0, -m[1].length) + ((n >> 16n).toString(16)) + ":" + ((n & 0xffffn).toString(16));
  }
  const [head, tail] = s.split("::");
  const h = head ? head.split(":") : [];
  const t = tail !== undefined && tail ? tail.split(":") : [];
  const groups = tail !== undefined ? [...h, ...Array(8 - h.length - t.length).fill("0"), ...t] : h;
  return groups.reduce((n, g) => (n << 16n) + BigInt(parseInt(g || "0", 16)), 0n);
}

// Canonical text for storing: plain IP when it is a single address, otherwise network/prefix
function normalize(input) {
  const c = parseCidr(input);
  if (!c) return null;
  const addr = String(input).trim().split("/")[0];
  if (c.bits === c.max) return addr.toLowerCase();
  return `${addr.toLowerCase()}/${c.bits}`;
}

function covers(rule, ip) {
  const r = parseCidr(rule);
  const a = parseCidr(ip);
  if (!r || !a || r.v !== a.v) return false;
  const shift = BigInt(r.max - r.bits);
  return a.base >> shift === r.base >> shift;
}

// Never auto-block loopback / unspecified addresses
function neverBlock(ip) {
  return ["127.0.0.0/8", "::1/128", "0.0.0.0/32", "::/128"].some((r) => covers(r, ip));
}

/* ---------------- Rules ---------------- */

const nowIso = () => new Date().toISOString();

function purgeExpired() {
  db.prepare("DELETE FROM ip_rules WHERE expires_at IS NOT NULL AND expires_at <= ?").run(nowIso());
}

// Active rules that apply to servers of userId (their own + global)
function activeRules(userId) {
  purgeExpired();
  return db
    .prepare("SELECT * FROM ip_rules WHERE user_id IS NULL OR user_id = ? ORDER BY id")
    .all(userId == null ? -1 : userId);
}

function matching(userId, ip, kind) {
  return activeRules(userId).find((r) => r.kind === kind && covers(r.ip, ip)) || null;
}

// Adds a rule, or turns the owner's existing rule for the same IP into this one (e.g. blacklist -> whitelist)
function upsertRule({ userId, ip, kind, source = "manual", reason = null, minutes = 0, incidentId = null, serverId = null, createdBy = null }) {
  const norm = normalize(ip);
  if (!norm) throw new Error("invalid ip");
  const expires = kind === "block" && minutes > 0 ? new Date(Date.now() + minutes * 60e3).toISOString() : null;
  const existing = db
    .prepare("SELECT id FROM ip_rules WHERE ip = ? AND " + (userId == null ? "user_id IS NULL" : "user_id = ?"))
    .get(...(userId == null ? [norm] : [norm, userId]));
  if (existing) {
    db.prepare(
      "UPDATE ip_rules SET kind = ?, source = ?, reason = ?, expires_at = ?, incident_id = ?, server_id = ?, created_by = ?, created_at = ? WHERE id = ?"
    ).run(kind, source, reason, expires, incidentId, serverId, createdBy, nowIso(), existing.id);
    return db.prepare("SELECT * FROM ip_rules WHERE id = ?").get(existing.id);
  }
  const info = db
    .prepare(
      `INSERT INTO ip_rules (user_id, ip, kind, source, reason, incident_id, server_id, created_by, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(userId == null ? null : userId, norm, kind, source, reason, incidentId, serverId, createdBy, nowIso(), expires);
  return db.prepare("SELECT * FROM ip_rules WHERE id = ?").get(info.lastInsertRowid);
}

/* ---------------- Settings ---------------- */

function settingsFor(userId) {
  const u = userId == null ? null : db.prepare("SELECT autoblock_enabled, autoblock_min_risk, autoblock_minutes FROM users WHERE id = ?").get(userId);
  if (!u) return { ...DEFAULTS };
  return {
    enabled: u.autoblock_enabled == null ? DEFAULTS.enabled : !!u.autoblock_enabled,
    min_risk: u.autoblock_min_risk || DEFAULTS.min_risk,
    minutes: u.autoblock_minutes == null ? DEFAULTS.minutes : u.autoblock_minutes,
  };
}

function saveSettings(userId, { enabled, min_risk, minutes }) {
  db.prepare("UPDATE users SET autoblock_enabled = ?, autoblock_min_risk = ?, autoblock_minutes = ? WHERE id = ?").run(
    enabled ? 1 : 0, min_risk, minutes, userId
  );
  return settingsFor(userId);
}

/* ---------------- Automatic blocking ---------------- */

function durationText(minutes) {
  if (!minutes) return "ถาวร (จนกว่าจะปลดบล็อก)";
  if (minutes % 1440 === 0) return `${minutes / 1440} วัน`;
  if (minutes % 60 === 0) return `${minutes / 60} ชั่วโมง`;
  return `${minutes} นาที`;
}

// Called by the analysis engine whenever an incident is created/escalated.
// Returns the new rule, or null when nothing was blocked.
function autoBlock({ server, incident, risk, title }) {
  const ip = incident.source_ip;
  if (!ip || !normalize(ip) || neverBlock(ip)) return null;
  const owner = server.user_id == null ? null : server.user_id;
  const cfg = settingsFor(owner);
  if (!cfg.enabled || (RISK_ORDER[risk] ?? -1) < (RISK_ORDER[cfg.min_risk] ?? 2)) return null;
  if (matching(owner, ip, "allow") || matching(owner, ip, "block")) return null;
  const rule = upsertRule({
    userId: owner, ip, kind: "block", source: "auto", minutes: cfg.minutes,
    reason: `${title} (${risk})`, incidentId: incident.id, serverId: incident.server_id,
  });

  const text = [
    "🚫 บล็อก IP อัตโนมัติ",
    `IP: ${rule.ip}`,
    `เซิร์ฟเวอร์ที่ถูกโจมตี: ${server.hostname || server.name || "-"}`,
    `สาเหตุ: ${title} · ความเสี่ยง ${risk}`,
    incident.username ? `บัญชีที่ถูกลอง: ${incident.username}` : null,
    `ระยะเวลา: ${durationText(cfg.minutes)}`,
    "agent จะใส่กฎ firewall ภายใน ~30 วินาที · ปลดบล็อกได้ที่เมนู Blacklist / Whitelist",
  ].filter(Boolean).join("\n");
  notifier
    .sendText(text, { userId: owner, payload: { event: "ip_blocked", rule, incident_id: incident.id } })
    .catch((e) => console.error("[autoblock:alert]", e.message));
  return rule;
}

/* ---------------- Agent list ---------------- */

// What the agent on `server` must enforce. Whitelist wins over blacklist for the same address.
function listForServer(server) {
  const rules = activeRules(server ? server.user_id : null);
  const allow = [...new Set(rules.filter((r) => r.kind === "allow").map((r) => r.ip))];
  const block = [...new Set(rules.filter((r) => r.kind === "block" && !allow.includes(r.ip)).map((r) => r.ip))];
  return { allow, block };
}

module.exports = {
  parseCidr, normalize, covers, neverBlock, activeRules, matching, upsertRule, purgeExpired,
  settingsFor, saveSettings, autoBlock, listForServer, durationText, DEFAULTS,
};
