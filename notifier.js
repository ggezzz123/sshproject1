// Sends incident alerts to every channel configured via environment variables.
// LINE Notify was discontinued (2025-03-31); LINE uses the Messaging API push endpoint.
const { RISK_ORDER } = require("./detectionEngine");

const MIN_RISK = (process.env.ALERT_MIN_RISK || "HIGH").toUpperCase();

function channels() {
  const e = process.env;
  const list = [];
  if (e.LINE_CHANNEL_ACCESS_TOKEN && e.LINE_TO) {
    list.push({
      name: "line",
      url: "https://api.line.me/v2/bot/message/push",
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

function formatMessage(incident) {
  const lines = [
    `[${incident.risk_level}] ${incident.title}`,
    `Server: ${incident.server_hostname || "-"}`,
    incident.source_ip ? `Source IP: ${incident.source_ip}` : null,
    incident.username ? `Account: ${incident.username}` : null,
    incident.description,
    incident.verdict ? `Assessment: ${incident.verdict}` : null,
    `Time: ${new Date().toISOString()}`,
  ];
  return lines.filter(Boolean).join("\n");
}

async function send(incident) {
  const text = formatMessage(incident);
  await Promise.all(
    channels().map(async (ch) => {
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
    })
  );
}

module.exports = { send, shouldAlert, formatMessage, channels };
