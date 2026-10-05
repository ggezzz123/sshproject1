const express = require("express");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const db = require("../db");
const { signToken } = require("../middleware/auth");
const { mirrorRegistration } = require("../oracleSync");

const router = express.Router();

const SECRET = process.env.JWT_SECRET || "change-me";
const TURNSTILE_SITE_KEY = process.env.TURNSTILE_SITE_KEY || "";
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET || "";
const CAPTCHA_TTL_MS = 5 * 60 * 1000;

const OAUTH = {
  google: {
    id: process.env.GOOGLE_CLIENT_ID,
    secret: process.env.GOOGLE_CLIENT_SECRET,
    authUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    scope: "openid email profile",
  },
  github: {
    id: process.env.GITHUB_CLIENT_ID,
    secret: process.env.GITHUB_CLIENT_SECRET,
    authUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    scope: "read:user user:email",
  },
};

function publicUser(u) {
  return { id: u.id, username: u.username, role: u.role };
}

// Stores the sign-up in SQLite and mirrors it to Oracle (if configured).
function recordRegistration(userId, method, req) {
  const createdAt = new Date().toISOString();
  const userAgent = String(req.headers["user-agent"] || "").slice(0, 300);
  const info = db.prepare(
    "INSERT INTO registrations (user_id, method, ip_address, user_agent, created_at) VALUES (?, ?, ?, ?, ?)"
  ).run(userId, method, req.ip || null, userAgent, createdAt);
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
  mirrorRegistration(user, { id: info.lastInsertRowid, method, ip: req.ip, userAgent, createdAt });
}

/* ---------- Anti-bot ---------- */
function sign(payload) {
  return crypto.createHmac("sha256", SECRET).update(payload).digest("hex");
}

// Built-in fallback: a signed, expiring arithmetic challenge (no external service needed).
function newChallenge() {
  const a = crypto.randomInt(1, 20);
  const b = crypto.randomInt(1, 20);
  const exp = Date.now() + CAPTCHA_TTL_MS;
  const nonce = crypto.randomBytes(8).toString("hex");
  const body = `${a + b}.${exp}.${nonce}`;
  return { question: `${a} + ${b} = ?`, token: `${body}.${sign(body)}` };
}

const usedChallenges = new Map();
function checkChallenge(token, answer) {
  const parts = String(token || "").split(".");
  if (parts.length !== 4) return false;
  const [sum, exp, nonce, sig] = parts;
  const expected = sign(`${sum}.${exp}.${nonce}`);
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
  const now = Date.now();
  for (const [k, v] of usedChallenges) if (v < now) usedChallenges.delete(k);
  if (Number(exp) < now || usedChallenges.has(nonce)) return false;
  if (String(answer).trim() !== sum) return false;
  usedChallenges.set(nonce, Number(exp)); // one-time use
  return true;
}

async function verifyHuman(req) {
  const { captcha_token, captcha_answer } = req.body || {};
  if (TURNSTILE_SECRET) {
    if (!captcha_token) return false;
    try {
      const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ secret: TURNSTILE_SECRET, response: captcha_token, remoteip: req.ip || "" }),
      });
      return !!(await r.json()).success;
    } catch (e) {
      return false;
    }
  }
  return checkChallenge(captcha_token, captcha_answer);
}

router.get("/api/auth/config", (req, res) => {
  const out = {
    turnstileSiteKey: TURNSTILE_SITE_KEY && TURNSTILE_SECRET ? TURNSTILE_SITE_KEY : null,
    providers: Object.keys(OAUTH).filter((k) => OAUTH[k].id && OAUTH[k].secret),
  };
  if (!out.turnstileSiteKey) out.challenge = newChallenge();
  res.json(out);
});

router.get("/api/auth/captcha", (req, res) => res.json(newChallenge()));

/* ---------- Local login / register ---------- */
router.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "username and password required" });
  }
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user || (user.provider && user.provider !== "local") || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  db.prepare("UPDATE users SET last_login_at = ? WHERE id = ?").run(new Date().toISOString(), user.id);
  res.json({ token: signToken(user), user: publicUser(user) });
});

router.post("/api/auth/register", async (req, res) => {
  const { username, password, confirm_password, email } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "username and password required" });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "password must be at least 6 characters" });
  }
  if (password !== confirm_password) {
    return res.status(400).json({ error: "passwords do not match" });
  }
  if (!(await verifyHuman(req))) {
    return res.status(400).json({ error: "Bot check failed, please try again" });
  }
  if (db.prepare("SELECT 1 FROM users WHERE username = ?").get(username)) {
    return res.status(409).json({ error: "username already taken" });
  }
  const mail = email ? String(email).trim().toLowerCase() : null;
  if (mail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mail)) {
    return res.status(400).json({ error: "Invalid email address" });
  }
  if (mail && db.prepare("SELECT 1 FROM users WHERE lower(email) = ?").get(mail)) {
    return res.status(409).json({ error: "email already used by another account" });
  }
  const hash = bcrypt.hashSync(password, 10);
  const info = db
    .prepare(
      "INSERT INTO users (username, password_hash, role, email, provider, created_at) VALUES (?, ?, 'user', ?, 'local', ?)"
    )
    .run(username, hash, mail, new Date().toISOString());
  recordRegistration(info.lastInsertRowid, "local", req);
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(info.lastInsertRowid);
  res.json({ token: signToken(user), user: publicUser(user) });
});

/* ---------- Google / GitHub OAuth ---------- */
function baseUrl(req) {
  return (process.env.PUBLIC_URL || `${req.protocol}://${req.get("host")}`).replace(/\/$/, "");
}
function cookie(req, name) {
  const m = (req.headers.cookie || "").split(/;\s*/).find((c) => c.startsWith(name + "="));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : null;
}

router.get("/api/auth/oauth/:provider", (req, res) => {
  const p = OAUTH[req.params.provider];
  if (!p || !p.id || !p.secret) return res.status(404).send("Provider not configured");
  const state = crypto.randomBytes(16).toString("hex");
  const secure = baseUrl(req).startsWith("https") ? "; Secure" : "";
  res.setHeader("Set-Cookie", `oauth_state=${state}; HttpOnly; SameSite=Lax; Path=/api/auth; Max-Age=600${secure}`);
  const q = new URLSearchParams({
    client_id: p.id,
    redirect_uri: `${baseUrl(req)}/api/auth/oauth/${req.params.provider}/callback`,
    response_type: "code",
    scope: p.scope,
    state,
  });
  res.redirect(`${p.authUrl}?${q}`);
});

async function fetchProfile(provider, p, code, redirectUri) {
  const tokRes = await fetch(p.tokenUrl, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: p.id,
      client_secret: p.secret,
      code,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
    }),
  });
  const tok = await tokRes.json();
  if (!tok.access_token) throw new Error("token exchange failed");
  const h = { Authorization: `Bearer ${tok.access_token}`, Accept: "application/json", "User-Agent": "ssh-monitor" };
  if (provider === "google") {
    const u = await (await fetch("https://openidconnect.googleapis.com/v1/userinfo", { headers: h })).json();
    if (!u.sub) throw new Error("no profile");
    return { id: String(u.sub), email: u.email_verified ? u.email : null, verified: !!u.email_verified, name: u.name || (u.email || "").split("@")[0] };
  }
  const u = await (await fetch("https://api.github.com/user", { headers: h })).json();
  if (!u.id) throw new Error("no profile");
  let email = null;
  const emails = await (await fetch("https://api.github.com/user/emails", { headers: h })).json();
  if (Array.isArray(emails)) email = (emails.find((e) => e.primary && e.verified) || {}).email || null;
  return { id: String(u.id), email, verified: !!email, name: u.login };
}

router.get("/api/auth/oauth/:provider/callback", async (req, res) => {
  const provider = req.params.provider;
  const p = OAUTH[provider];
  if (!p || !p.id || !p.secret) return res.status(404).send("Provider not configured");
  const fail = (msg) => res.redirect("/app#error=" + encodeURIComponent(msg));
  const { code, state } = req.query;
  const saved = cookie(req, "oauth_state");
  if (!code || !state || !saved || state !== saved) return fail("OAuth state mismatch");
  try {
    const prof = await fetchProfile(provider, p, code, `${baseUrl(req)}/api/auth/oauth/${provider}/callback`);
    let user = db.prepare("SELECT * FROM users WHERE provider = ? AND provider_id = ?").get(provider, prof.id);
    if (!user) {
      let username = `${provider}_${String(prof.name || prof.id).replace(/[^\w.-]/g, "").slice(0, 40)}`;
      if (db.prepare("SELECT 1 FROM users WHERE username = ?").get(username)) {
        username += "_" + crypto.randomBytes(2).toString("hex");
      }
      // "!" is not a valid bcrypt hash, so password login can never succeed for OAuth accounts
      const info = db
        .prepare(
          "INSERT INTO users (username, password_hash, role, email, email_verified, provider, provider_id, created_at) VALUES (?, '!', 'user', ?, ?, ?, ?, ?)"
        )
        .run(username, prof.email ? prof.email.toLowerCase() : null, prof.verified ? 1 : 0, provider, prof.id, new Date().toISOString());
      recordRegistration(info.lastInsertRowid, provider, req);
      user = db.prepare("SELECT * FROM users WHERE id = ?").get(info.lastInsertRowid);
    }
    db.prepare("UPDATE users SET last_login_at = ? WHERE id = ?").run(new Date().toISOString(), user.id);
    res.setHeader("Set-Cookie", "oauth_state=; Path=/api/auth; Max-Age=0");
    res.redirect("/app#token=" + signToken(user));
  } catch (e) {
    fail("OAuth login failed");
  }
});

module.exports = router;
