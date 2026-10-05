// Sign-in history per account (shown on the Profile page).
const db = require("./db");
const { countryOf } = require("./geo");

const KEEP_PER_USER = 100;

function recordLogin(userId, method, success, req) {
  const ip = req.ip || null;
  db.prepare(
    "INSERT INTO logins (user_id, method, success, ip_address, country, user_agent, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
  ).run(userId, method, success ? 1 : 0, ip, countryOf(ip), String(req.headers["user-agent"] || "").slice(0, 300), new Date().toISOString());
  db.prepare(
    "DELETE FROM logins WHERE user_id = ? AND id NOT IN (SELECT id FROM logins WHERE user_id = ? ORDER BY id DESC LIMIT ?)"
  ).run(userId, userId, KEEP_PER_USER);
  if (success) db.prepare("UPDATE users SET last_login_at = ? WHERE id = ?").run(new Date().toISOString(), userId);
}

function recentLogins(userId, limit = 30) {
  return db
    .prepare("SELECT id, method, success, ip_address, country, user_agent, created_at FROM logins WHERE user_id = ? ORDER BY id DESC LIMIT ?")
    .all(userId, limit);
}

module.exports = { recordLogin, recentLogins };
