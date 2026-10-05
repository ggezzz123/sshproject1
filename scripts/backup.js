// Makes a consistent copy of the SQLite database (safe while the server is running) and keeps the last N.
//   node scripts/backup.js
// BACKUP_DIR (in .env) sets where copies go; default is the OneDrive folder if there is one (so the copy
// also leaves this PC), otherwise data/backups. BACKUP_KEEP sets how many to keep (default 14).
require("dotenv").config({ path: require("path").join(__dirname, "..", ".env") });
const fs = require("fs");
const path = require("path");
const { DatabaseSync } = require("node:sqlite");

const root = path.join(__dirname, "..");
const dbPath = path.resolve(root, process.env.DB_PATH || "data/ssh-monitor.db");
const dir =
  process.env.BACKUP_DIR ||
  (process.env.OneDrive ? path.join(process.env.OneDrive, "SSH-Monitor-backups") : path.join(root, "data", "backups"));
const keep = Number(process.env.BACKUP_KEEP || 14);

fs.mkdirSync(dir, { recursive: true });
const stamp = new Date().toISOString().replace(/[:T]/g, "-").slice(0, 19);
const target = path.join(dir, `ssh-monitor-${stamp}.db`);

const db = new DatabaseSync(dbPath, { readOnly: true });
db.exec(`VACUUM INTO '${target.replace(/'/g, "''")}'`);
db.close();

const old = fs
  .readdirSync(dir)
  .filter((f) => /^ssh-monitor-.*\.db$/.test(f))
  .sort()
  .reverse()
  .slice(keep);
for (const f of old) fs.unlinkSync(path.join(dir, f));

console.log(`[backup] ${target} (${Math.round(fs.statSync(target).size / 1024)} KB), removed ${old.length} old copy(ies)`);
