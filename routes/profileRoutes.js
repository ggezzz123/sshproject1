const express = require("express");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const db = require("../db");
const { jwtAuth, signToken } = require("../middleware/auth");
const { sendMail, enabled: mailEnabled } = require("../mailer");

const router = express.Router();

const SECRET = process.env.JWT_SECRET || "change-me";
const VERIFY_TTL_MS = 24 * 3600 * 1000;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/* ---------- signed email-verification token (stateless) ---------- */
function sign(body) {
  return crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
}
function makeVerifyToken(user) {
  const body = Buffer.from(JSON.stringify({ u: user.id, e: user.email, x: Date.now() + VERIFY_TTL_MS })).toString("base64url");
  return `${body}.${sign("verify." + body)}`;
}
function readVerifyToken(token) {
  const [body, sig] = String(token || "").split(".");
  if (!body || !sig) return null;
  const expected = sign("verify." + body);
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    return p.x > Date.now() ? p : null;
  } catch (e) {
    return null;
  }
}

function baseUrl(req) {
  return (process.env.PUBLIC_URL || `${req.protocol}://${req.get("host")}`).replace(/\/$/, "");
}

const lastSent = new Map(); // userId -> time of the last verification mail (resend throttle)
async function sendVerification(req, user) {
  const link = `${baseUrl(req)}/api/auth/verify-email?token=${makeVerifyToken(user)}`;
  return sendMail({
    to: user.email,
    subject: "Verify your email - SSH Monitor",
    text: `Hi ${user.username},\n\nConfirm this email address for your SSH Monitor account:\n${link}\n\nThe link is valid for 24 hours. If you did not request this, ignore this email.`,
  });
}

const isLocal = (u) => !u.provider || u.provider === "local";
const getUser = (id) => db.prepare("SELECT * FROM users WHERE id = ?").get(id);

function profileOf(u) {
  const servers = db.prepare("SELECT COUNT(*) AS c FROM servers WHERE user_id = ?").get(u.id).c;
  return {
    id: u.id,
    username: u.username,
    role: u.role,
    email: u.email || null,
    email_verified: !!u.email_verified,
    provider: u.provider || "local",
    has_password: isLocal(u),
    created_at: u.created_at || null,
    last_login_at: u.last_login_at || null,
    servers,
    mail_configured: mailEnabled,
  };
}

/* ---------- public: link from the verification email ---------- */
router.get("/api/auth/verify-email", (req, res) => {
  const p = readVerifyToken(req.query.token);
  const user = p && getUser(p.u);
  if (!user || user.email !== p.e) {
    return res.redirect("/app#error=" + encodeURIComponent("Verification link is invalid or expired"));
  }
  db.prepare("UPDATE users SET email_verified = 1 WHERE id = ?").run(user.id);
  res.redirect("/app#verified=1");
});

/* ---------- signed-in user ---------- */
router.use("/api/profile", jwtAuth);

router.get("/api/profile", (req, res) => {
  const u = getUser(req.user.id);
  if (!u) return res.status(404).json({ error: "Account not found" });
  res.json(profileOf(u));
});

router.patch("/api/profile/email", async (req, res) => {
  const u = getUser(req.user.id);
  const email = String((req.body || {}).email || "").trim().toLowerCase();
  if (!EMAIL_RE.test(email) || email.length > 255) return res.status(400).json({ error: "Invalid email address" });
  if (isLocal(u) && !bcrypt.compareSync(String((req.body || {}).current_password || ""), u.password_hash)) {
    return res.status(403).json({ error: "Current password is incorrect" });
  }
  if (email === (u.email || "").toLowerCase()) return res.status(400).json({ error: "That is already your email" });
  if (db.prepare("SELECT 1 FROM users WHERE lower(email) = ? AND id != ?").get(email, u.id)) {
    return res.status(409).json({ error: "That email is already used by another account" });
  }
  db.prepare("UPDATE users SET email = ?, email_verified = 0 WHERE id = ?").run(email, u.id);
  const updated = getUser(u.id);
  lastSent.set(u.id, Date.now());
  const sent = await sendVerification(req, updated);
  res.json({ ...profileOf(updated), verification_sent: sent });
});

router.post("/api/profile/email/verify-request", async (req, res) => {
  const u = getUser(req.user.id);
  if (!u.email) return res.status(400).json({ error: "Add an email address first" });
  if (u.email_verified) return res.status(400).json({ error: "Email is already verified" });
  if (Date.now() - (lastSent.get(u.id) || 0) < 60000) {
    return res.status(429).json({ error: "Please wait a minute before requesting another email" });
  }
  lastSent.set(u.id, Date.now());
  const sent = await sendVerification(req, u);
  res.json({ verification_sent: sent, mail_configured: mailEnabled });
});

router.post("/api/profile/password", (req, res) => {
  const u = getUser(req.user.id);
  if (!isLocal(u)) return res.status(400).json({ error: `This account signs in with ${u.provider}; it has no password` });
  const { current_password, new_password, confirm_password } = req.body || {};
  if (!bcrypt.compareSync(String(current_password || ""), u.password_hash)) {
    return res.status(403).json({ error: "Current password is incorrect" });
  }
  if (!new_password || new_password.length < 6) return res.status(400).json({ error: "New password must be at least 6 characters" });
  if (new_password !== confirm_password) return res.status(400).json({ error: "Passwords do not match" });
  if (new_password === current_password) return res.status(400).json({ error: "New password must differ from the current one" });
  // Bumping token_version signs every other session out; this one gets a fresh token.
  db.prepare("UPDATE users SET password_hash = ?, token_version = COALESCE(token_version, 0) + 1 WHERE id = ?").run(
    bcrypt.hashSync(new_password, 10),
    u.id
  );
  res.json({ token: signToken(getUser(u.id)) });
});

router.post("/api/profile/logout-everywhere", (req, res) => {
  db.prepare("UPDATE users SET token_version = COALESCE(token_version, 0) + 1 WHERE id = ?").run(req.user.id);
  res.json({ token: signToken(getUser(req.user.id)) });
});

router.delete("/api/profile", (req, res) => {
  const u = getUser(req.user.id);
  if (u.role === "admin") return res.status(403).json({ error: "Admin accounts cannot be deleted here" });
  const { password, confirm_username } = req.body || {};
  const ok = isLocal(u) ? bcrypt.compareSync(String(password || ""), u.password_hash) : confirm_username === u.username;
  if (!ok) return res.status(403).json({ error: isLocal(u) ? "Password is incorrect" : "Type your username to confirm" });
  db.exec("BEGIN");
  try {
    const own = "(SELECT id FROM servers WHERE user_id = ?)";
    db.prepare(`DELETE FROM ssh_logs WHERE server_id IN ${own}`).run(u.id);
    db.prepare(`DELETE FROM incidents WHERE server_id IN ${own}`).run(u.id);
    db.prepare("DELETE FROM servers WHERE user_id = ?").run(u.id);
    db.prepare("DELETE FROM registrations WHERE user_id = ?").run(u.id);
    db.prepare("DELETE FROM users WHERE id = ?").run(u.id);
    db.exec("COMMIT");
  } catch (e) {
    db.exec("ROLLBACK");
    throw e;
  }
  res.json({ ok: true });
});

module.exports = router;
