// Linking a user's LINE account (Profile page) and the LINE webhook that completes the link.
// Flow: user clicks "เชื่อม LINE" -> gets a 6-digit code -> adds the bot as a friend and sends the code
// -> the webhook matches the code and stores the LINE userId on the account.
const express = require("express");
const crypto = require("crypto");
const db = require("../db");
const { jwtAuth } = require("../middleware/auth");
const line = require("../line");

const router = express.Router();
router.use("/api/profile/line", jwtAuth);

const CODE_TTL_MS = 10 * 60 * 1000;
const codes = new Map(); // code -> { userId, exp }

function cleanup() {
  const now = Date.now();
  for (const [c, v] of codes) if (v.exp < now) codes.delete(c);
}

async function status(userId) {
  const u = db.prepare("SELECT line_user_id FROM users WHERE id = ?").get(userId) || {};
  let bot = null;
  try { bot = await line.botInfo(); } catch (e) { console.error("[line]", e.message); }
  return { configured: line.canLink(), linked: !!u.line_user_id, bot };
}

router.get("/api/profile/line", async (req, res) => res.json(await status(req.user.id)));

router.post("/api/profile/line/link", async (req, res) => {
  if (!line.canLink()) return res.status(400).json({ error: "ผู้ดูแลระบบยังไม่ได้ตั้งค่า LINE" });
  cleanup();
  for (const [c, v] of codes) if (v.userId === req.user.id) codes.delete(c); // one active code per user
  let code;
  do code = String(crypto.randomInt(100000, 1000000)); while (codes.has(code));
  codes.set(code, { userId: req.user.id, exp: Date.now() + CODE_TTL_MS });
  res.json({ code, expires_in: CODE_TTL_MS / 1000, ...(await status(req.user.id)) });
});

router.post("/api/profile/line/test", async (req, res) => {
  const u = db.prepare("SELECT username, line_user_id FROM users WHERE id = ?").get(req.user.id);
  if (!u || !u.line_user_id) return res.status(400).json({ error: "ยังไม่ได้เชื่อม LINE" });
  try {
    await line.push(u.line_user_id, `✅ ทดสอบแจ้งเตือนจาก SSH Monitor\nบัญชี: ${u.username}\nถ้าเห็นข้อความนี้ แปลว่าการแจ้งเตือนทาง LINE ใช้งานได้`);
    res.json({ ok: true });
  } catch (e) {
    console.error("[line]", e.message);
    res.status(502).json({ error: "ส่งข้อความทาง LINE ไม่สำเร็จ กรุณาตรวจการตั้งค่า LINE" });
  }
});

router.delete("/api/profile/line", (req, res) => {
  db.prepare("UPDATE users SET line_user_id = NULL WHERE id = ?").run(req.user.id);
  res.json({ ok: true });
});

// Called by LINE. Always answers 200 quickly; replies are sent afterwards.
router.post("/api/line/webhook", (req, res) => {
  if (!line.validSignature(req.rawBody, req.get("x-line-signature"))) return res.status(401).end();
  res.status(200).end();
  for (const ev of (req.body && req.body.events) || []) {
    const lineUserId = ev.source && ev.source.userId;
    if (!lineUserId || !ev.replyToken) continue;
    let text = null;
    if (ev.type === "follow") {
      text = "สวัสดีครับ 👋 นี่คือบอทแจ้งเตือนของ SSH Monitor\nส่งรหัส 6 หลักจากหน้าโปรไฟล์ (เมนูเชื่อม LINE) มาที่แชทนี้ เพื่อรับแจ้งเตือนการโจมตีเซิร์ฟเวอร์ของคุณ";
    } else if (ev.type === "message" && ev.message && ev.message.type === "text") {
      cleanup();
      const m = /\b(\d{6})\b/.exec(ev.message.text || "");
      const hit = m && codes.get(m[1]);
      if (hit) {
        codes.delete(m[1]);
        db.prepare("UPDATE users SET line_user_id = ? WHERE id = ?").run(lineUserId, hit.userId);
        const u = db.prepare("SELECT username FROM users WHERE id = ?").get(hit.userId) || {};
        text = `✅ เชื่อม LINE กับบัญชี "${u.username}" เรียบร้อยแล้ว\nเมื่อเซิร์ฟเวอร์ของคุณถูกโจมตี จะมีแจ้งเตือนส่งมาที่นี่`;
      } else {
        text = m ? "รหัสไม่ถูกต้องหรือหมดอายุแล้ว กรุณากด \"เชื่อม LINE\" ในหน้าโปรไฟล์เพื่อรับรหัสใหม่" : "ส่งรหัส 6 หลักจากหน้าโปรไฟล์ เพื่อเชื่อม LINE กับบัญชี SSH Monitor ของคุณ";
      }
    }
    if (text) line.reply(ev.replyToken, text).catch((e) => console.error("[line]", e.message));
  }
});

module.exports = router;
