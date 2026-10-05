#!/usr/bin/env node
// Fake SSH agent: sends every event type and every attack pattern to a monitor.
//
//   node tools/simulate.js --url http://localhost:5000 --key sk_YOUR_TEST_KEY
//   node tools/simulate.js --url https://your-host --key sk_TEST_KEY_1,sk_TEST_KEY_2 --scenario cross_host
//   node tools/simulate.js --key sk_YOUR_TEST_KEY --live        (endless trickle of mixed events, Ctrl+C to stop)
//   node tools/simulate.js --list
//   node tools/simulate.js                 (no arguments: it asks for the URL and the API key)
//
// Use a DEDICATED test server's key (create one in Get Key). The bot does NOT send a
// hostname, so the server keeps the name you gave it in the dashboard - sending one would
// overwrite it (that's how a real agent is meant to report its actual machine name).
// Source IPs come from the reserved documentation ranges (RFC 5737), so they never hit a real host.
// The same scenarios can also be run from the web app (menu: ทดสอบการโจมตี).

const args = process.argv.slice(2);
const opt = (name, def) => {
  const i = args.indexOf("--" + name);
  return i === -1 ? def : args[i + 1] && !args[i + 1].startsWith("--") ? args[i + 1] : true;
};
const DEFAULT_URL = "http://localhost:5000";
const cleanUrl = (u) => String(u).trim().replace(/\/+$/, "");
const parseKeys = (s) => String(s).split(/[,\s]+/).map((k) => k.replace(/^["']|["']$/g, "").replace(/^Bearer$/i, "")).filter(Boolean);
const URL_GIVEN = opt("url", null) !== null && opt("url", null) !== true;
let URL_BASE = cleanUrl(URL_GIVEN ? opt("url") : DEFAULT_URL);
let KEYS = parseKeys(opt("key", process.env.MONITOR_API_KEY || ""));
const ONLY = opt("scenario", "all");
const LIVE = opt("live", false) === true;
const PAUSE = Number(opt("pause", 700));

const { makeScenarios, makeLivePool } = require("../simulation");

const run = Math.floor(Math.random() * 200) + 20; // unique per run so each run opens fresh incidents
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function send(hostIdx, logs) {
  const key = KEYS[hostIdx % KEYS.length];
  let res;
  try {
    res = await fetch(URL_BASE + "/api/logs", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + key },
      // No "hostname" field on purpose - see the note above the require() block.
    body: JSON.stringify({ agent_version: "sim", timestamp: new Date().toISOString(), logs }),
      signal: AbortSignal.timeout(60000),
    });
  } catch (e) {
    const why = (e.cause && (e.cause.code || e.cause.message)) || e.message;
    throw new Error(`cannot reach ${URL_BASE} (${why}). Is the server running / is the URL right? (Render free may need ~60s to wake up)`);
  }
  if (res.status === 401) throw new Error("API key rejected (401) - copy the key of a server from Get Key");
  if (!res.ok) throw new Error(`HTTP ${res.status} ${await res.text()}`);
  return logs.length;
}

/* Scenarios live in ../simulation.js (shared with the web "attack test" page); order matters there */
const scenarios = makeScenarios(run);
const LIVE_POOL = makeLivePool();

/* ---------------- Prompts (used when --url / --key are not given) ---------------- */
const readline = require("readline");
let rl = null;
const queued = [];
let waiting = null;
let inputClosed = false;
// Lines are queued as they arrive, so pasted/piped answers are never dropped between questions
function ask(question) {
  if (!rl) {
    rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.on("line", (line) => {
      if (waiting) { const w = waiting; waiting = null; w(line.trim()); } else queued.push(line.trim());
    });
    rl.on("close", () => {
      inputClosed = true;
      if (waiting) { const w = waiting; waiting = null; w(""); }
    });
  }
  if (!inputClosed) { rl.setPrompt(question); rl.prompt(); }
  if (queued.length) return Promise.resolve(queued.shift());
  if (inputClosed) return Promise.resolve("");
  return new Promise((resolve) => { waiting = resolve; });
}

async function promptForSettings() {
  let askedKey = false;
  if (!URL_GIVEN) {
    const u = await ask(`Monitor URL [${DEFAULT_URL}] (Enter = local; e.g. https://ssh-monitor.tail634b6e.ts.net): `);
    if (u) {
      const local = /^(localhost|127\.|10\.|192\.168\.|\[?::1)/i.test(u);
      URL_BASE = cleanUrl(/^https?:\/\//i.test(u) ? u : (local ? "http://" : "https://") + u);
    }
  }
  if (!KEYS.length) {
    console.log("\nCreate a DEDICATED test server in the dashboard (Get Key) and copy its API key.");
    KEYS = parseKeys(await ask("API key (several allowed, separated by commas): "));
    askedKey = true;
  }
  if (askedKey && KEYS.length === 1 && (ONLY === "all" || ONLY === "cross_host")) {
    const second = parseKeys(await ask("Second test server's API key for the cross-host scenario (Enter to skip): "));
    KEYS.push(...second);
  }
  console.log("");
}

/* ---------------- Main ---------------- */
async function main() {
  if (args.includes("--list")) {
    console.log("Scenarios:\n" + scenarios.map((s) => `  ${s.name.padEnd(22)} ${s.desc}`).join("\n"));
    return;
  }
  if (!URL_GIVEN || !KEYS.length) await promptForSettings();
  if (rl) rl.close();
  if (!KEYS.length) {
    console.error("No API key entered. Create a test server in the dashboard (Get Key), then run again.");
    process.exit(1);
  }

  if (LIVE) {
    console.log(`Live mode -> ${URL_BASE}  (Ctrl+C to stop)`);
    for (let n = 0; ; n++) {
      const batch = Array.from({ length: 1 + Math.floor(Math.random() * 4) }, () => LIVE_POOL[Math.floor(Math.random() * LIVE_POOL.length)]());
      try { await send(n, batch); console.log(new Date().toLocaleTimeString(), "sent", batch.map((b) => b.event_type).join(", ")); }
      catch (e) { console.error("send failed:", e.message); }
      await sleep(2000 + Math.random() * 3000);
    }
  }

  const chosen = ONLY === "all" ? scenarios : scenarios.filter((s) => s.name === ONLY);
  if (!chosen.length) { console.error(`Unknown scenario "${ONLY}". Use --list.`); process.exit(1); }

  console.log(`Target: ${URL_BASE}   servers (keys): ${KEYS.length}   run id: ${run}\n`);
  let sent = 0, skipped = 0;
  for (const s of chosen) {
    if (s.hosts > KEYS.length) {
      console.log(`SKIP  ${s.name.padEnd(22)} needs ${s.hosts} API keys (pass --key k1,k2)`);
      skipped++;
      continue;
    }
    try {
      let n = 0;
      for (const [host, logs] of Object.entries(s.build())) n += await send(Number(host), logs);
      sent += n;
      console.log(`OK    ${s.name.padEnd(22)} ${String(n).padStart(3)} events   -> ${s.expect}`);
    } catch (e) {
      console.log(`FAIL  ${s.name.padEnd(22)} ${e.message}`);
    }
    await sleep(PAUSE);
  }
  console.log(`\nDone: ${sent} events sent, ${skipped} scenario(s) skipped. Open the dashboard (Incidents / Dashboard) to see the results.`);
}

main().catch((e) => { console.error(e.message); process.exit(1); });
