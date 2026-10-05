const express = require("express");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const db = require("../db");
const { jwtAuth, signToken } = require("../middleware/auth");
const { sendMail, enabled: mailEnabled } = require("../mailer");
const { recentLogins } = require("../loginLog");

const router = express.Router();

const SECRET = process.env.JWT_SECRET || "change-me";
const VERIFY_TTL_MS = 24 * 3600 * 1000;
const RESET_TTL_MS = 3600 * 1000;
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
    avatar: u.avatar || null,
    mail_configured: mailEnabled,
  };
}

/* ---------- password reset (stateless token, single use) ---------- */
// The token embeds a fingerprint of the current password hash, so it stops working once the password changes.
const hashTag = (u) => crypto.createHash("sha256").update(String(u.password_hash)).digest("base64url").slice(0, 16);
function makeResetToken(user) {
  const body = Buffer.from(JSON.stringify({ u: user.id, h: hashTag(user), x: Date.now() + RESET_TTL_MS })).toString("base64url");
  return `${body}.${sign("reset." + body)}`;
}
function readResetToken(token) {
  const [body, sig] = String(token || "").split(".");
  if (!body || !sig) return null;
  const expected = sign("reset." + body);
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    const user = p.x > Date.now() && getUser(p.u);
    return user && isLocal(user) && hashTag(user) === p.h ? user : null;
  } catch (e) {
    return null;
  }
}

const lastReset = new Map(); // userId -> time of the last reset mail
router.post("/api/auth/forgot-password", async (req, res) => {
  const id = String((req.body || {}).identifier || "").trim();
  // Same answer whether or not the account exists, so this can't be used to discover accounts
  const answer = { ok: true, mail_configured: mailEnabled };
  if (!id) return res.status(400).json({ error: "Enter your email or username" });
  const user = db.prepare("SELECT * FROM users WHERE lower(email) = lower(?) OR username = ?").get(id, id);
  if (!user || !isLocal(user) || !user.email) return res.json(answer);
  if (Date.now() - (lastReset.get(user.id) || 0) < 60000) return res.json(answer);
  lastReset.set(user.id, Date.now());
  const link = `${baseUrl(req)}/app#reset=${makeResetToken(user)}`;
  await sendMail({
    to: user.email,
    subject: "Reset your password - SSH Monitor",
    text: `Hi ${user.username},\n\nSomeone (hopefully you) asked to reset the password of your SSH Monitor account.\nSet a new password here:\n${link}\n\nThe link is valid for 1 hour and works once. If you did not ask for this, ignore this email; your password stays the same.`,
  });
  res.json(answer);
});

router.post("/api/auth/reset-password", (req, res) => {
  const { token, new_password, confirm_password } = req.body || {};
  const user = readResetToken(token);
  if (!user) return res.status(400).json({ error: "This reset link is invalid, expired or already used" });
  if (!new_password || new_password.length < 6) return res.status(400).json({ error: "New password must be at least 6 characters" });
  if (new_password !== confirm_password) return res.status(400).json({ error: "Passwords do not match" });
  // Opening the emailed link also proves the address belongs to the user. All sessions are signed out.
  db.prepare(
    "UPDATE users SET password_hash = ?, email_verified = 1, token_version = COALESCE(token_version, 0) + 1 WHERE id = ?"
  ).run(bcrypt.hashSync(new_password, 10), user.id);
  res.json({ ok: true, username: user.username });
});

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

router.get("/api/profile/logins", (req, res) => {
  res.json(recentLogins(req.user.id));
});

// Profile picture: the browser crops/resizes it to a small square image; stored as a data URL.
// Only PNG / JPEG / WebP are accepted (checked by their file signature) - never SVG, which could carry scripts.
const AVATAR_MAX_BYTES = 200 * 1024;
const AVATAR_SIGNATURES = {
  png: (b) => b.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])),
  jpeg: (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff,
  webp: (b) => b.slice(0, 4).toString("latin1") === "RIFF" && b.slice(8, 12).toString("latin1") === "WEBP",
};
router.put("/api/profile/avatar", (req, res) => {
  const m = /^data:image\/(png|jpeg|webp);base64,([A-Za-z0-9+/=]+)$/.exec(String((req.body || {}).image || ""));
  if (!m) return res.status(400).json({ error: "Use a PNG, JPEG or WebP image" });
  const bytes = Buffer.from(m[2], "base64");
  if (bytes.length > AVATAR_MAX_BYTES) return res.status(413).json({ error: "Image is too large (max 200 KB after resizing)" });
  if (!AVATAR_SIGNATURES[m[1]](bytes)) return res.status(400).json({ error: "The file is not a valid image" });
  db.prepare("UPDATE users SET avatar = ? WHERE id = ?").run(`data:image/${m[1]};base64,${bytes.toString("base64")}`, req.user.id);
  res.json(profileOf(getUser(req.user.id)));
});

router.delete("/api/profile/avatar", (req, res) => {
  db.prepare("UPDATE users SET avatar = NULL WHERE id = ?").run(req.user.id);
  res.json(profileOf(getUser(req.user.id)));
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
    db.prepare("DELETE FROM logins WHERE user_id = ?").run(u.id);
    db.prepare("DELETE FROM users WHERE id = ?").run(u.id);
    db.exec("COMMIT");
  } catch (e) {
    db.exec("ROLLBACK");
    throw e;
  }
  res.json({ ok: true });
});

module.exports = router;
