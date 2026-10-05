// Behavioural analysis of SSH events: correlates IP + user + host + time + event sequence,
// classifies attack patterns, maintains incidents and triggers alerts.
// Every window is anchored to the events' own timestamps (not arrival time), so late or
// backlogged batches are judged against the moment they actually happened.
const db = require("./db");
const { calculateRisk, maxRisk, RISK_ORDER } = require("./detectionEngine");
const notifier = require("./notifier");

const MIN = 60 * 1000;
const HOUR = 60 * MIN;
const FAIL = new Set(["ssh_login_failed", "ssh_invalid_user"]);
const ATTACK = new Set(["ssh_login_failed", "ssh_invalid_user", "connection_closed_preauth"]);
const OFF_HOURS_TZ = process.env.ALERT_TZ || "Asia/Bangkok";

const ATTACK_TYPES = {
  brute_force: "เดารหัสผ่าน (Brute force)",
  brute_force_success: "ล็อกอินสำเร็จหลังเดารหัสหลายครั้ง",
  password_spraying: "ลองรหัสเดียวกับหลายบัญชี (Password spraying)",
  credential_stuffing: "ใช้รหัสที่รั่วไหล (Credential stuffing)",
  compromised_account: "พยายามเข้าบัญชีที่ถูกเจาะแล้วซ้ำ",
  username_enumeration: "สุ่มเดาชื่อผู้ใช้",
  ssh_scanning: "สแกนพอร์ต SSH",
  abnormal_burst: "พฤติกรรมผิดปกติ: เชื่อมต่อถี่ผิดปกติ",
  new_source_login: "พฤติกรรมผิดปกติ: ล็อกอินจากแหล่งใหม่",
  cross_host: "โจมตีหลายเซิร์ฟเวอร์พร้อมกัน",
  post_compromise: "ใช้สิทธิ์สูงหลังถูกเจาะ",
};

// Thresholds (per source IP unless noted)
const T = {
  bruteMinFails: 3,
  sprayWindow: 60 * MIN, sprayMinUsers: 5, sprayMaxPerUser: 3, sprayMinValidUsers: 3,
  stuffWindow: 15 * MIN, stuffMinUsers: 10, stuffMaxRatio: 1.5, stuffMinValidShare: 0.3,
  alertCooldown: 30 * MIN,
  enumWindow: 15 * MIN, enumMedium: 5, enumHigh: 20,
  scanWindow: 10 * MIN, scanMedium: 10, scanHigh: 50,
  burstWindow: MIN, burstMin: 20,
  successLookback: 30 * MIN, successMinFails: 5,
  accountWindow: 24 * HOUR, accountMinOtherIps: 2,
  newSourceMinHistory: 3,
  crossWindow: 60 * MIN, crossMinHosts: 2,
  postWindow: 60 * MIN,
};

const toMs = (iso) => new Date(iso).getTime();
const toIso = (ms) => new Date(ms).toISOString();

function eventsFor({ serverId, serverIds, ip, username, fromMs, toMs: endMs }) {
  const clauses = ["julianday(event_time) >= julianday(?)", "julianday(event_time) <= julianday(?)"];
  const params = [toIso(fromMs), toIso(endMs)];
  if (serverId != null) { clauses.push("server_id = ?"); params.push(serverId); }
  if (serverIds) {
    if (!serverIds.length) return [];
    clauses.push(`server_id IN (${serverIds.map(() => "?").join(",")})`);
    params.push(...serverIds);
  }
  if (ip) { clauses.push("source_ip = ?"); params.push(ip); }
  if (username) { clauses.push("username = ?"); params.push(username); }
  return db
    .prepare(
      `SELECT id, server_id, event_type AS type, username AS user, source_ip AS ip, event_time, message
       FROM ssh_logs WHERE ${clauses.join(" AND ")} ORDER BY julianday(event_time), id`
    )
    .all(...params)
    .map((r) => ({ ...r, t: toMs(r.event_time) }));
}

function hourIn(ms, tz) {
  return Number(new Intl.DateTimeFormat("en-US", { hour: "numeric", hourCycle: "h23", timeZone: tz }).format(ms));
}

function countBy(list, key) {
  const m = new Map();
  for (const e of list) m.set(e[key], (m.get(e[key]) || 0) + 1);
  return m;
}

/* ---------------- Incident store + alerting ---------------- */

// One alert per attack type + attacker + risk across servers (cross-host fires on every host)
const recentAlerts = new Map();
function alertIsDuplicate(type, key, risk) {
  const id = `${type}|${key}|${risk}`;
  const now = Date.now();
  for (const [k, t] of recentAlerts) if (now - t > T.alertCooldown) recentAlerts.delete(k);
  if (recentAlerts.has(id)) return true;
  recentAlerts.set(id, now);
  return false;
}

// A specific classification replaces the generic brute-force incident for the same IP
function supersedeBruteForce(serverId, ip, byType) {
  db.prepare(
    `UPDATE incidents SET status = 'CLOSED', description = description || ' (แทนที่ด้วย ' || ? || ')'
     WHERE server_id = ? AND source_ip = ? AND attack_type = 'brute_force' AND status = 'OPEN'`
  ).run(ATTACK_TYPES[byType], serverId, ip);
}

function upsertIncident(f) {
  const nowIso = new Date().toISOString();
  const existing = db
    .prepare(
      "SELECT * FROM incidents WHERE server_id = ? AND attack_type = ? AND incident_key = ? AND status = 'OPEN' ORDER BY id DESC LIMIT 1"
    )
    .get(f.serverId, f.type, f.key);
  const evidence = JSON.stringify(f.evidence || {});
  let id;
  let risk = f.risk;
  if (existing) {
    risk = maxRisk(existing.risk_level, f.risk);
    db.prepare(
      `UPDATE incidents SET risk_level = ?, failed_attempts = MAX(COALESCE(failed_attempts,0), ?), description = ?,
       evidence = ?, last_seen = ?, username = COALESCE(?, username), source_ip = COALESCE(?, source_ip) WHERE id = ?`
    ).run(risk, f.count || 0, f.description, evidence, nowIso, f.username || null, f.ip || null, existing.id);
    id = existing.id;
  } else {
    const info = db
      .prepare(
        `INSERT INTO incidents (server_id, source_ip, risk_level, failed_attempts, description, detected_at, status,
         attack_type, incident_key, username, last_seen, evidence)
         VALUES (?, ?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, ?)`
      )
      .run(f.serverId, f.ip || null, f.risk, f.count || 0, f.description, nowIso, f.type, f.key, f.username || null, nowIso, evidence);
    id = Number(info.lastInsertRowid);
  }

  const row = db.prepare("SELECT * FROM incidents WHERE id = ?").get(id);
  if (notifier.shouldAlert(risk, row.alerted_risk)) {
    db.prepare("UPDATE incidents SET alerted_risk = ? WHERE id = ?").run(risk, id);
    if (alertIsDuplicate(f.type, f.key, risk)) return row;
    const server = db.prepare("SELECT hostname, name FROM servers WHERE id = ?").get(f.serverId) || {};
    const verdict = row.source_ip ? analyzeIp(row.source_ip, null).verdict.text : null;
    notifier
      .send({ ...row, risk_level: risk, title: ATTACK_TYPES[f.type] || f.type, server_hostname: server.hostname || server.name, verdict })
      .catch((e) => console.error("[alert]", e.message));
  }
  return row;
}

/* ---------------- Detectors ---------------- */

function analyzeIpOnServer(serverId, ip, refMs) {
  const ev = eventsFor({ serverId, ip, fromMs: refMs - T.sprayWindow, toMs: refMs });
  const within = (ms) => ev.filter((e) => e.t >= refMs - ms);
  const fails = (list) => list.filter((e) => FAIL.has(e.type));

  // The most specific classification of this IP's failures; plain brute force is the fallback
  let specific = null;

  // Successful login after many failures
  const successes = ev.filter((e) => e.type === "ssh_login_success");
  const lastSuccess = successes[successes.length - 1];
  if (lastSuccess) {
    const before = ev.filter((e) => FAIL.has(e.type) && e.t <= lastSuccess.t && e.t >= lastSuccess.t - T.successLookback);
    if (before.length >= T.successMinFails) {
      specific = "brute_force_success";
      upsertIncident({
        serverId, ip, type: "brute_force_success", key: `ip:${ip}`, risk: "CRITICAL", count: before.length, username: lastSuccess.user,
        description: `ล็อกอินผิด ${before.length} ครั้ง แล้วล็อกอินสำเร็จเป็น "${lastSuccess.user}" จาก ${ip}`,
        evidence: { success_at: lastSuccess.event_time, account: lastSuccess.user },
      });
    }
  }

  // Credential stuffing (many accounts, ~1 try each, fast, hitting real accounts) — checked before
  // spraying/enumeration. Lists made almost entirely of non-existent users are enumeration instead.
  const f15 = fails(within(T.stuffWindow));
  const users15 = countBy(f15, "user");
  const validShare = f15.length ? f15.filter((e) => e.type === "ssh_login_failed").length / f15.length : 0;
  const stuffing = users15.size >= T.stuffMinUsers && f15.length / users15.size <= T.stuffMaxRatio && validShare >= T.stuffMinValidShare;
  if (stuffing) {
    specific = specific || "credential_stuffing";
    const hit = within(T.stuffWindow).find((e) => e.type === "ssh_login_success");
    upsertIncident({
      serverId, ip, type: "credential_stuffing", key: `ip:${ip}`, risk: hit ? "CRITICAL" : "HIGH", count: f15.length,
      username: hit ? hit.user : null,
      description: `ลองล็อกอิน ${users15.size} บัญชี บัญชีละประมาณครั้งเดียว (${f15.length} ครั้งใน 15 นาที) จาก ${ip}` +
        (hit ? ` — ล็อกอินสำเร็จเป็น "${hit.user}"` : ""),
      evidence: { accounts: [...users15.keys()].slice(0, 20), compromised: hit ? hit.user : null },
    });
  }

  // Password spraying (few tries per existing account, across many accounts)
  const f60 = fails(within(T.sprayWindow));
  const users60 = countBy(f60, "user");
  const validUsers = new Set(f60.filter((e) => e.type === "ssh_login_failed").map((e) => e.user));
  const maxPerUser = Math.max(0, ...users60.values());
  if (!stuffing && users60.size >= T.sprayMinUsers && maxPerUser <= T.sprayMaxPerUser && validUsers.size >= T.sprayMinValidUsers) {
    const hit = ev.find((e) => e.type === "ssh_login_success" && users60.has(e.user));
    specific = specific || "password_spraying";
    upsertIncident({
      serverId, ip, type: "password_spraying", key: `ip:${ip}`, risk: hit ? "CRITICAL" : "HIGH", count: f60.length,
      username: hit ? hit.user : null,
      description: `ลองล็อกอิน ${users60.size} บัญชี บัญชีละไม่เกิน ${maxPerUser} ครั้ง จาก ${ip} (ใน 60 นาที)` +
        (hit ? ` — ล็อกอินสำเร็จเป็น "${hit.user}"` : ""),
      evidence: { accounts: [...users60.keys()].slice(0, 20), compromised: hit ? hit.user : null },
    });
  }

  // Username enumeration / invalid-user probing
  const invalid15 = within(T.enumWindow).filter((e) => e.type === "ssh_invalid_user");
  const invalidUsers = new Set(invalid15.map((e) => e.user));
  if (!stuffing && invalidUsers.size >= T.enumMedium) {
    specific = specific || "username_enumeration";
    upsertIncident({
      serverId, ip, type: "username_enumeration", key: `ip:${ip}`,
      risk: invalidUsers.size >= T.enumHigh ? "HIGH" : "MEDIUM", count: invalid15.length,
      description: `สุ่มชื่อผู้ใช้ที่ไม่มีอยู่จริง ${invalidUsers.size} ชื่อ จาก ${ip} ภายใน 15 นาที`,
      evidence: { usernames: [...invalidUsers].slice(0, 20) },
    });
  }

  // SSH scanning: connections dropped before authentication
  const scans = within(T.scanWindow).filter((e) => e.type === "connection_closed_preauth");
  if (scans.length >= T.scanMedium) {
    upsertIncident({
      serverId, ip, type: "ssh_scanning", key: `ip:${ip}`, risk: scans.length >= T.scanHigh ? "HIGH" : "MEDIUM", count: scans.length,
      description: `เชื่อมต่อโดยไม่ล็อกอิน ${scans.length} ครั้ง จาก ${ip} ภายใน 10 นาที (น่าจะเป็นเครื่องมือสแกน)`,
    });
  }

  // Abnormal source behavior: burst rate
  const burst = within(T.burstWindow);
  if (burst.length >= T.burstMin) {
    upsertIncident({
      serverId, ip, type: "abnormal_burst", key: `ip:${ip}`, risk: "HIGH", count: burst.length,
      description: `มีเหตุการณ์ SSH ${burst.length} ครั้ง จาก ${ip} ภายใน 1 นาที (น่าจะเป็นโปรแกรมอัตโนมัติ)`,
    });
  }

  // Brute force (10 min, note.md risk thresholds) — only when no more specific pattern explains it
  if (specific) {
    supersedeBruteForce(serverId, ip, specific);
    return;
  }
  const f10 = fails(within(10 * MIN));
  if (f10.length >= T.bruteMinFails) {
    upsertIncident({
      serverId, ip, type: "brute_force", key: `ip:${ip}`, risk: calculateRisk(f10.length, false), count: f10.length,
      description: `ล็อกอินผิด ${f10.length} ครั้ง จาก ${ip} ภายใน 10 นาที`,
      evidence: { users: [...countBy(f10, "user").keys()].slice(0, 10) },
    });
  }
}

// Abnormal source behavior: a known account logs in from a never-before-seen IP
function checkNewSource(serverId, success) {
  const history = db
    .prepare(
      `SELECT source_ip, COUNT(*) AS c FROM ssh_logs WHERE server_id = ? AND username = ? AND event_type = 'ssh_login_success'
       AND julianday(event_time) < julianday(?) GROUP BY source_ip`
    )
    .all(serverId, success.user, success.event_time);
  const total = history.reduce((s, r) => s + r.c, 0);
  if (total < T.newSourceMinHistory || history.some((r) => r.source_ip === success.ip)) return;

  const hour = hourIn(success.t, OFF_HOURS_TZ);
  const offHours = hour < 6;
  const priorAttacks = db
    .prepare(
      `SELECT COUNT(*) AS c FROM ssh_logs WHERE source_ip = ? AND event_type IN ('ssh_login_failed','ssh_invalid_user')
       AND julianday(event_time) < julianday(?)`
    )
    .get(success.ip, success.event_time).c;
  upsertIncident({
    serverId, ip: success.ip, type: "new_source_login", key: `user:${success.user}|ip:${success.ip}`, username: success.user,
    risk: offHours || priorAttacks > 0 ? "HIGH" : "MEDIUM", count: 1,
    description: `"${success.user}" ล็อกอินจาก ${success.ip} ซึ่งไม่เคยใช้มาก่อน (เคยใช้ ${history.length} IP)` +
      (offHours ? ` เวลา ${String(hour).padStart(2, "0")}:00 (นอกเวลาทำการ)` : "") +
      (priorAttacks > 0 ? `; IP นี้เคยล็อกอินผิดมาแล้ว ${priorAttacks} ครั้ง` : ""),
    evidence: { known_ips: history.map((r) => r.source_ip).slice(0, 10), off_hours: offHours },
  });
}

// Repeated attempts on an account that was already compromised (24h)
function checkCompromisedAccount(serverId, username, refMs) {
  const compromise = db
    .prepare(
      `SELECT * FROM incidents WHERE server_id = ? AND username = ? AND risk_level = 'CRITICAL'
       AND attack_type IN ('brute_force_success','credential_stuffing','password_spraying')
       AND julianday(detected_at) >= julianday(?) ORDER BY id DESC LIMIT 1`
    )
    .get(serverId, username, toIso(refMs - T.accountWindow));
  if (!compromise) return;
  const after = eventsFor({ serverId, username, fromMs: toMs(compromise.detected_at) - 30 * MIN, toMs: refMs })
    .filter((e) => e.ip && e.ip !== compromise.source_ip && (FAIL.has(e.type) || e.type === "ssh_login_success"));
  const otherIps = new Set(after.map((e) => e.ip));
  if (otherIps.size < T.accountMinOtherIps) return;
  const reused = after.find((e) => e.type === "ssh_login_success");
  upsertIncident({
    serverId, ip: reused ? reused.ip : after[after.length - 1].ip, type: "compromised_account", key: `user:${username}`,
    username, risk: reused ? "CRITICAL" : "HIGH", count: after.length,
    description: `บัญชีที่ถูกเจาะ "${username}" (ถูกเจาะครั้งแรกจาก ${compromise.source_ip}) กำลังถูกลองเข้าจากอีก ${otherIps.size} IP` +
      (reused ? `; ล็อกอินสำเร็จจาก ${reused.ip}` : ""),
    evidence: { first_breach_ip: compromise.source_ip, other_ips: [...otherIps].slice(0, 20) },
  });
}

// Cross-host correlation: one attacker IP hitting several monitored servers
function checkCrossHost(ip, refMs) {
  const ev = eventsFor({ ip, fromMs: refMs - T.crossWindow, toMs: refMs });
  const attackHosts = new Set(ev.filter((e) => ATTACK.has(e.type)).map((e) => e.server_id));
  if (attackHosts.size < T.crossMinHosts) return;
  const success = ev.find((e) => e.type === "ssh_login_success" && attackHosts.has(e.server_id));
  const attempts = ev.filter((e) => ATTACK.has(e.type)).length;
  for (const serverId of attackHosts) {
    upsertIncident({
      serverId, ip, type: "cross_host", key: `ip:${ip}`, risk: success ? "CRITICAL" : "HIGH", count: attempts,
      description: `${ip} โจมตีเซิร์ฟเวอร์ ${attackHosts.size} เครื่องภายใน 60 นาที (${attempts} ครั้ง)` +
        (success ? " และล็อกอินสำเร็จได้หนึ่งเครื่อง" : ""),
      evidence: { host_count: attackHosts.size },
    });
  }
}

// Post-compromise: privileged commands by an account right after a suspicious login
function checkPostCompromise(serverId, sudo) {
  if (!sudo.user) return;
  const logins = eventsFor({ serverId, username: sudo.user, fromMs: sudo.t - T.postWindow, toMs: sudo.t })
    .filter((e) => e.type === "ssh_login_success" && e.ip);
  for (const login of logins.reverse()) {
    const breach = db
      .prepare(
        `SELECT id FROM incidents WHERE server_id = ? AND source_ip = ? AND status = 'OPEN' AND risk_level = 'CRITICAL'
         AND attack_type IN ('brute_force_success','credential_stuffing','password_spraying','compromised_account','cross_host')`
      )
      .get(serverId, login.ip);
    if (breach) {
      upsertIncident({
        serverId, ip: login.ip, type: "post_compromise", key: `ip:${login.ip}`, username: sudo.user, risk: "CRITICAL", count: 1,
        description: `"${sudo.user}" ใช้คำสั่งสิทธิ์สูงหลังล็อกอินที่น่าสงสัยจาก ${login.ip}: ${sudo.message || "sudo"}`,
        evidence: { command: sudo.message || null, login_at: login.event_time },
      });
      return;
    }
  }
}

/* ---------------- Batch entry point ---------------- */

function analyzeBatch(serverId, logs) {
  const now = Date.now();
  const byIp = new Map();
  for (const l of logs) {
    if (!l.ip) continue;
    byIp.set(l.ip, Math.min(now, Math.max(byIp.get(l.ip) || 0, l.t)));
  }
  for (const [ip, ref] of byIp) analyzeIpOnServer(serverId, ip, ref);

  for (const l of logs) {
    if (l.type === "ssh_login_success" && l.user && l.ip) checkNewSource(serverId, l);
  }
  const accounts = new Map();
  for (const l of logs) {
    if (l.user && (FAIL.has(l.type) || l.type === "ssh_login_success")) {
      accounts.set(l.user, Math.min(now, Math.max(accounts.get(l.user) || 0, l.t)));
    }
  }
  for (const [user, ref] of accounts) checkCompromisedAccount(serverId, user, ref);
  for (const [ip, ref] of byIp) checkCrossHost(ip, ref);
  for (const l of logs) if (l.type === "sudo_command") checkPostCompromise(serverId, l);
}

/* ---------------- Sequence analysis / verdict ---------------- */

const PHASE = {
  connection_closed_preauth: "สำรวจเป้าหมาย",
  ssh_invalid_user: "เดาชื่อผู้ใช้",
  ssh_login_failed: "เดารหัสผ่าน",
  ssh_login_success: "เข้าระบบได้",
  sudo_command: "ใช้สิทธิ์สูง",
  session_closed: "ปิดเซสชัน",
};

// serverIds: null = all servers (admin / alerts), array = restrict to these servers
function analyzeIp(ip, serverIds) {
  const latest = db
    .prepare(
      `SELECT MAX(julianday(event_time)) AS j FROM ssh_logs WHERE source_ip = ?` +
        (serverIds ? ` AND server_id IN (${serverIds.map(() => "?").join(",") || "NULL"})` : "")
    )
    .get(ip, ...(serverIds || []));
  if (!latest || latest.j == null) {
    return { ip, events: 0, hosts: [], users: [], counts: {}, sequence: [], timeline: [], incidents: [], verdict: { text: "ไม่พบกิจกรรม", risk: "LOW" } };
  }
  const refMs = Math.round((latest.j - 2440587.5) * 86400000);
  const ev = eventsFor({ serverIds, ip, fromMs: refMs - 24 * HOUR, toMs: refMs });

  // sudo has no source IP: attribute privileged commands by accounts this IP logged into
  const logins = ev.filter((e) => e.type === "ssh_login_success");
  const priv = [];
  for (const login of logins) {
    const sudos = eventsFor({ serverId: login.server_id, username: login.user, fromMs: login.t, toMs: login.t + T.postWindow })
      .filter((e) => e.type === "sudo_command");
    priv.push(...sudos);
  }
  const all = [...ev, ...priv].sort((a, b) => a.t - b.t);

  const sequence = [];
  for (const e of all) {
    const phase = PHASE[e.type] || e.type;
    const last = sequence[sequence.length - 1];
    if (last && last.phase === phase) { last.count++; last.end = e.event_time; }
    else sequence.push({ phase, count: 1, start: e.event_time, end: e.event_time });
  }

  const hostRows = db
    .prepare(`SELECT id, name, hostname FROM servers WHERE id IN (${[...new Set(all.map((e) => e.server_id))].join(",") || "NULL"})`)
    .all();
  const counts = Object.fromEntries(countBy(all, "type"));
  const users = [...countBy(all.filter((e) => e.user), "user")].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([u, c]) => ({ user: u, count: c }));

  const incidents = db
    .prepare(
      `SELECT i.id, i.attack_type, i.risk_level, i.status, i.description, i.detected_at, i.evidence, s.hostname AS server_hostname
       FROM incidents i LEFT JOIN servers s ON s.id = i.server_id WHERE i.source_ip = ?` +
        (serverIds ? ` AND i.server_id IN (${serverIds.map(() => "?").join(",") || "NULL"})` : "") +
        " ORDER BY i.id DESC LIMIT 20"
    )
    .all(ip, ...(serverIds || []));

  const open = incidents.filter((i) => i.status === "OPEN");
  const firstAttack = all.find((e) => ATTACK.has(e.type));
  // A typo followed by a login is not a compromise: require a detected pattern or real volume
  const accessAfterAttack = firstAttack && logins.find((e) =>
    e.t > firstAttack.t &&
    (open.length > 0 || all.filter((x) => ATTACK.has(x.type) && x.t < e.t).length >= T.successMinFails));
  const types = new Set(open.map((i) => i.attack_type));
  const byRisk = (a, b) => RISK_ORDER[b.risk_level] - RISK_ORDER[a.risk_level];
  const topIncident = [...open].sort(byRisk)[0];
  const mainPattern = [...open].filter((i) => i.attack_type !== "cross_host").sort(byRisk)[0];
  // Users only see their own hosts; the cross-host incident records the true number of targets
  const crossHosts = Math.max(
    hostRows.length,
    ...open.filter((i) => i.attack_type === "cross_host").map((i) => {
      try { return JSON.parse(i.evidence || "{}").host_count || 0; } catch (e) { return 0; }
    })
  );

  let verdict;
  if (accessAfterAttack && priv.length) {
    verdict = { risk: "CRITICAL", text: `ถูกเจาะเต็มรูปแบบ: มีการโจมตี แล้วล็อกอินเป็น "${accessAfterAttack.user}" และใช้คำสั่งสิทธิ์สูง` };
  } else if (accessAfterAttack) {
    verdict = { risk: "CRITICAL", text: `บัญชีถูกเจาะ: ล็อกอินสำเร็จเป็น "${accessAfterAttack.user}" หลังมีการโจมตี` };
  } else if (types.has("cross_host")) {
    const counts2 = countBy(all, "type");
    const main = mainPattern
      ? ATTACK_TYPES[mainPattern.attack_type]
      : (counts2.get("ssh_invalid_user") || 0) > (counts2.get("ssh_login_failed") || 0) ? "การเดาชื่อผู้ใช้" : "การลองล็อกอิน";
    verdict = { risk: "HIGH", text: `โจมตีหลายเครื่อง: ${main} กับเซิร์ฟเวอร์ ${crossHosts} เครื่อง ยังไม่มีการล็อกอินสำเร็จ` };
  } else if (topIncident) {
    verdict = { risk: topIncident.risk_level, text: `กำลังถูกโจมตีแบบ${ATTACK_TYPES[topIncident.attack_type] || topIncident.attack_type} ยังไม่มีการล็อกอินสำเร็จ` };
  } else if (firstAttack) {
    const n = all.filter((e) => ATTACK.has(e.type)).length;
    verdict = logins.length
      ? { risk: "LOW", text: `น่าจะปกติ: ล็อกอินผิด ${n} ครั้งก่อนล็อกอินสำเร็จ ไม่พบรูปแบบการโจมตี` }
      : { risk: "LOW", text: `กิจกรรมน่าสงสัยปริมาณน้อย (${n} ครั้ง)` };
  } else {
    verdict = { risk: "LOW", text: "กิจกรรมปกติ (ไม่พบสัญญาณการโจมตี)" };
  }

  return {
    ip,
    events: all.length,
    first_seen: all[0].event_time,
    last_seen: all[all.length - 1].event_time,
    hosts: hostRows.map((h) => h.hostname || h.name),
    users,
    counts,
    sequence,
    timeline: all.slice(-50).map((e) => ({ time: e.event_time, type: e.type, user: e.user, host: (hostRows.find((h) => h.id === e.server_id) || {}).hostname })),
    incidents,
    verdict,
  };
}

module.exports = { analyzeBatch, analyzeIp, ATTACK_TYPES };
