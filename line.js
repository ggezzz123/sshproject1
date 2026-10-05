// LINE Messaging API helpers (LINE Notify was discontinued on 2025-03-31).
// One LINE Official Account bot for the whole system; each user links their own LINE from the Profile page.
const crypto = require("crypto");

const API = (process.env.LINE_API_BASE || "https://api.line.me").replace(/\/$/, ""); // overridable for tests
const token = () => process.env.LINE_CHANNEL_ACCESS_TOKEN || "";
const secret = () => process.env.LINE_CHANNEL_SECRET || "";
const configured = () => !!token();
const canLink = () => !!(token() && secret());

async function call(path, body, method = "POST") {
  const res = await fetch(API + path, {
    method,
    headers: { Authorization: `Bearer ${token()}`, ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) throw new Error(`LINE ${path} HTTP ${res.status} ${await res.text().catch(() => "")}`);
  return res.status === 200 ? res.json().catch(() => ({})) : {};
}

const push = (to, text) => call("/v2/bot/message/push", { to, messages: [{ type: "text", text: String(text).slice(0, 4900) }] });
const reply = (replyToken, text) => call("/v2/bot/message/reply", { replyToken, messages: [{ type: "text", text: String(text).slice(0, 4900) }] });

// Bot name / LINE ID for the "add friend" button; cached for an hour
let botCache = null;
async function botInfo() {
  if (!configured()) return null;
  if (botCache && Date.now() - botCache.at < 3600e3) return botCache.info;
  const b = await call("/v2/bot/info", null, "GET");
  const id = b.premiumId || b.basicId || "";
  const info = { name: b.displayName || "SSH Monitor", lineId: id, addUrl: id ? `https://line.me/R/ti/p/${encodeURIComponent(id)}` : null };
  botCache = { at: Date.now(), info };
  return info;
}

// Webhook requests are signed: base64(HMAC-SHA256(channel secret, raw body))
function validSignature(rawBody, signature) {
  if (!secret() || !rawBody || !signature) return false;
  const expected = crypto.createHmac("sha256", secret()).update(rawBody).digest("base64");
  return signature.length === expected.length && crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

module.exports = { configured, canLink, push, reply, botInfo, validSignature };
