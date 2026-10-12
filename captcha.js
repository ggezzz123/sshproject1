// Anti-bot check shared by sign-up, login (after repeated failures) and forgot-password.
// Picks the first one configured: Google reCAPTCHA v2 checkbox (RECAPTCHA_SITE_KEY + RECAPTCHA_SECRET),
// Cloudflare Turnstile (TURNSTILE_SITE_KEY + TURNSTILE_SECRET), else a built-in signed, expiring,
// single-use arithmetic challenge.
const crypto = require("crypto");

const SECRET = process.env.JWT_SECRET || "change-me";
const RECAPTCHA_SITE_KEY = process.env.RECAPTCHA_SITE_KEY || "";
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET || "";
const USE_RECAPTCHA = !!(RECAPTCHA_SITE_KEY && RECAPTCHA_SECRET);
const TURNSTILE_SITE_KEY = process.env.TURNSTILE_SITE_KEY || "";
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET || "";
const CAPTCHA_TTL_MS = 5 * 60 * 1000;

function sign(payload) {
  return crypto.createHmac("sha256", SECRET).update(payload).digest("hex");
}

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

// Both Google and Cloudflare verify a widget token with the same form-encoded POST
async function verifyRemote(url, secret, token, req) {
  if (!token) return false;
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ secret, response: token, remoteip: req.ip || "" }),
    });
    return !!(await r.json()).success;
  } catch (e) {
    return false;
  }
}

async function verifyHuman(req) {
  const { captcha_token, captcha_answer } = req.body || {};
  if (USE_RECAPTCHA) {
    return verifyRemote("https://www.google.com/recaptcha/api/siteverify", RECAPTCHA_SECRET, captcha_token, req);
  }
  if (TURNSTILE_SECRET) {
    return verifyRemote("https://challenges.cloudflare.com/turnstile/v0/siteverify", TURNSTILE_SECRET, captcha_token, req);
  }
  return checkChallenge(captcha_token, captcha_answer);
}

// What the browser needs to render the check: a reCAPTCHA or Turnstile site key, or a fresh math challenge.
function captchaConfig() {
  if (USE_RECAPTCHA) return { recaptchaSiteKey: RECAPTCHA_SITE_KEY, turnstileSiteKey: null };
  const turnstileSiteKey = TURNSTILE_SITE_KEY && TURNSTILE_SECRET ? TURNSTILE_SITE_KEY : null;
  return turnstileSiteKey ? { turnstileSiteKey } : { turnstileSiteKey: null, challenge: newChallenge() };
}

const CAPTCHA_FAILED = "ยืนยันว่าไม่ใช่บอทไม่ผ่าน กรุณาลองใหม่";

module.exports = { verifyHuman, captchaConfig, CAPTCHA_FAILED };
