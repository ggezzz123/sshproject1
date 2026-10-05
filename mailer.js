// Sends email through SMTP when SMTP_HOST is configured. Without it the message is only written
// to the server log (handy for local development) and sendMail() resolves to false.
const nodemailer = require("nodemailer");

const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM } = process.env;
const enabled = !!SMTP_HOST;

const transport = enabled
  ? nodemailer.createTransport({
      host: SMTP_HOST,
      port: Number(SMTP_PORT || 587),
      secure: Number(SMTP_PORT) === 465,
      auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
    })
  : null;

async function sendMail({ to, subject, text }) {
  if (!enabled) {
    console.log(`[mail] SMTP not configured - would send to ${to}: ${subject}\n${text}`);
    return false;
  }
  try {
    await transport.sendMail({ from: SMTP_FROM || SMTP_USER, to, subject, text });
    return true;
  } catch (e) {
    console.error("[mail] send failed:", e.message);
    return false;
  }
}

module.exports = { sendMail, enabled };
