const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const db = require("../db");

const VALID_API_KEYS = (process.env.VALID_API_KEYS || "")
  .split(",")
  .map((k) => k.trim())
  .filter(Boolean);

const JWT_SECRET = process.env.JWT_SECRET || "change-me";

function generateApiKey() {
  return "sk_" + crypto.randomBytes(24).toString("hex");
}

// Agent endpoints: validate Bearer API key (static list OR registered server key)
function apiKeyAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing API key" });
  }
  const key = auth.replace("Bearer ", "");

  if (VALID_API_KEYS.includes(key)) {
    req.apiKey = key;
    return next();
  }

  const server = db.prepare("SELECT * FROM servers WHERE api_key = ?").get(key);
  if (!server) {
    return res.status(401).json({ error: "Invalid API key" });
  }
  req.apiKey = key;
  req.server = server;
  next();
}

// Dashboard endpoints: validate JWT
function jwtAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing token" });
  }
  const token = auth.replace("Bearer ", "");
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    // Tokens die when the account is deleted or its token_version changes (password change / sign-out everywhere)
    const row = db.prepare("SELECT token_version FROM users WHERE id = ?").get(payload.id);
    if (!row || (row.token_version || 0) !== (payload.tv || 0)) {
      return res.status(401).json({ error: "เซสชันหมดอายุ กรุณาล็อกอินใหม่" });
    }
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function signToken(user) {
  return jwt.sign({ id: user.id, username: user.username, role: user.role, tv: user.token_version || 0 }, JWT_SECRET, {
    expiresIn: "12h",
  });
}

// Restricts a route (after jwtAuth) to admin accounts only
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ error: "ต้องเป็นผู้ดูแลระบบเท่านั้น" });
  }
  next();
}

// Admins see everything; regular users only see rows belonging to their own servers.
// `col` is the (aliased) server_id column of the table being queried.
function serverScope(req, col) {
  if (req.user.role === "admin") return { clauses: [], params: [] };
  return {
    clauses: [`${col} IN (SELECT id FROM servers WHERE user_id = ?)`],
    params: [req.user.id],
  };
}

function canAccessServerId(req, serverId) {
  if (req.user.role === "admin") return true;
  const row = db.prepare("SELECT user_id FROM servers WHERE id = ?").get(serverId);
  return !!row && row.user_id === req.user.id;
}

module.exports = {
  apiKeyAuth,
  jwtAuth,
  requireAdmin,
  signToken,
  generateApiKey,
  serverScope,
  canAccessServerId,
  VALID_API_KEYS,
};
