const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const db = require("../db");

const VALID_API_KEYS = (process.env.VALID_API_KEYS || "demo_api_key_12345,test_key_67890")
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
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function signToken(user) {
  return jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, {
    expiresIn: "12h",
  });
}

// Restricts a route (after jwtAuth) to admin accounts only
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}

module.exports = { apiKeyAuth, jwtAuth, requireAdmin, signToken, generateApiKey, VALID_API_KEYS };
