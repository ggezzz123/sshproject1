// Sends incident alerts to every channel configured via environment variables.
// LINE Notify was discontinued (2025-03-31); LINE uses the Messaging API push endpoint.
const { RISK_ORDER } = require("./detectionEngine");
const db = require("./db");
const line = require("./line");

const MIN_RISK = (process.env.ALERT_MIN_RISK || "HIGH").toUpperCase();

function channels() {
  const e = process.env;
  const list = [];
  if (e.LINE_CHANNEL_ACCESS_TOKEN && e.LINE_TO) {
    list.push({
      name: "line",
      url: (process.env.LINE_API_BASE || "https://api.line.me").replace(/\/$/, "") + "/v2/bot/message/push",
      headers: { Authorization: `Bearer ${e.LINE_CHANNEL_ACCESS_TOKEN}` },
      body: (text) => ({ to: e.LINE_TO, messages: [{ type: "text", text: text.slice(0, 4900) }] }),
    });
  }
  if (e.DISCORD_WEBHOOK_URL) {
    list.push({ name: "discord", url: e.DISCORD_WEBHOOK_URL, body: (text) => ({ content: text.slice(0, 1900) }) });
  }
  if (e.SLACK_WEBHOOK_URL) {
    list.push({ name: "slack", url: e.SLACK_WEBHOOK_URL, body: (text) => ({ text }) });
  }
  if (e.TELEGRAM_BOT_TOKEN && e.TELEGRAM_CHAT_ID) {
    list.push({
      name: "telegram",
      url: `https://api.telegram.org/bot${e.TELEGRAM_BOT_TOKEN}/sendMessage`,
      body: (text) => ({ chat_id: e.TELEGRAM_CHAT_ID, text }),
    });
  }
  if (e.WEBHOOK_URL) {
    list.push({ name: "webhook", url: e.WEBHOOK_URL, body: (text, incident) => ({ text, incident }) });
  }
  return list;
}

function shouldAlert(risk, alreadyAlerted) {
  if ((RISK_ORDER[risk] ?? -1) < (RISK_ORDER[MIN_RISK] ?? 2)) return false;
  return !alreadyAlerted || RISK_ORDER[risk] > (RISK_ORDER[alreadyAlerted] ?? -1);
}

const RISK_ICON = { CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "🟢" };

function formatMessage(incident) {
  const base = (process.env.PUBLIC_URL || "").replace(/\/$/, "");
  const lines = [
    `${RISK_ICON[incident.risk_level] || "⚠️"} [${incident.risk_level}] ${incident.title}`,
    `เซิร์ฟเวอร์: ${incident.server_hostname || "-"}`,
    incident.source_ip ? `IP ต้นทาง: ${incident.source_ip}` : null,
    incident.username ? `บัญชี: ${incident.username}` : null,
    incident.description,
    incident.verdict ? `การประเมิน: ${incident.verdict}` : null,
    `เวลา: ${new Date().toLocaleString("th-TH", { timeZone: process.env.ALERT_TZ || "Asia/Bangkok" })}`,
    base ? `ดูรายละเอียด: ${base}/app` : null,
  ];
  return lines.filter(Boolean).join("\n");
}

// LINE accounts linked (Profile page) by the owner of the attacked server
function ownerLineIds(incident) {
  if (!line.configured() || !incident.server_id) return [];
  const row = db
    .prepare("SELECT u.line_user_id FROM servers s JOIN users u ON u.id = s.user_id WHERE s.id = ? AND u.line_user_id IS NOT NULL")
    .get(incident.server_id);
  const id = row && row.line_user_id;
  return id && id !== process.env.LINE_TO ? [id] : []; // LINE_TO already gets everything
}

async function send(incident) {
  const text = formatMessage(incident);
  const owners = ownerLineIds(incident).map((to) =>
    line.push(to, text).catch((e) => console.error(`[alert:line-owner] ${e.message}`))
  );
  await Promise.all([
    ...owners,
    ...channels().map(async (ch) => {
      try {
        const res = await fetch(ch.url, {
          method: "POST",
          headers: { "Content-Type": "application/json", ...(ch.headers || {}) },
          body: JSON.stringify(ch.body(text, incident)),
          signal: AbortSignal.timeout(8000),
        });
        if (!res.ok) console.error(`[alert:${ch.name}] HTTP ${res.status} ${await res.text().catch(() => "")}`);
      } catch (e) {
        console.error(`[alert:${ch.name}] ${e.message}`);
      }
    }),
  ]);
}

module.exports = { send, shouldAlert, formatMessage, channels };
