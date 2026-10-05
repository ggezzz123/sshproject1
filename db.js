const path = require("path");
const fs = require("fs");
const { DatabaseSync } = require("node:sqlite");

const DB_PATH = process.env.DB_PATH || path.join(__dirname, "data", "ssh-monitor.db");
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new DatabaseSync(DB_PATH);
db.exec("PRAGMA journal_mode = WAL;");
db.exec("PRAGMA foreign_keys = ON;");

db.exec(`
CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,
    hostname VARCHAR(255),
    ip_address VARCHAR(45),
    api_key VARCHAR(255) NOT NULL,
    status VARCHAR(20) DEFAULT 'offline',
    last_seen DATETIME,
    user_id INTEGER REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(30) NOT NULL
);

CREATE TABLE IF NOT EXISTS ssh_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER,
    event_time DATETIME NOT NULL,
    source_ip VARCHAR(45),
    username VARCHAR(100),
    event_type VARCHAR(50),
    severity VARCHAR(20),
    message TEXT,
    FOREIGN KEY (server_id) REFERENCES servers(id)
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER,
    source_ip VARCHAR(45),
    risk_level VARCHAR(20) NOT NULL,
    failed_attempts INTEGER DEFAULT 0,
    description TEXT,
    detected_at DATETIME NOT NULL,
    status VARCHAR(30) DEFAULT 'OPEN',
    FOREIGN KEY (server_id) REFERENCES servers(id)
);

CREATE INDEX IF NOT EXISTS idx_logs_time ON ssh_logs(event_time);
CREATE INDEX IF NOT EXISTS idx_logs_ip ON ssh_logs(source_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
`);

// Migrate databases created before newer columns existed
function addColumns(table, defs) {
  const existing = db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
  for (const [name, type] of Object.entries(defs)) {
    if (!existing.includes(name)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${type}`);
  }
}
addColumns("users", {
  email: "VARCHAR(255)",
  provider: "VARCHAR(20) DEFAULT 'local'",
  provider_id: "VARCHAR(100)",
  created_at: "DATETIME",
  email_verified: "INTEGER DEFAULT 0",
  last_login_at: "DATETIME",
  token_version: "INTEGER DEFAULT 0",
  avatar: "TEXT",
  line_user_id: "VARCHAR(64)",
});
addColumns("ssh_logs", { country: "VARCHAR(2)" });
db.exec(`
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_provider ON users(provider, provider_id) WHERE provider_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS logins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    method VARCHAR(20) NOT NULL,
    success INTEGER NOT NULL,
    ip_address VARCHAR(45),
    country VARCHAR(2),
    user_agent TEXT,
    created_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_logins_user ON logins(user_id, id);
CREATE TABLE IF NOT EXISTS registrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    method VARCHAR(20) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at DATETIME NOT NULL
);
`);
addColumns("servers", { user_id: "INTEGER REFERENCES users(id)", is_test: "INTEGER DEFAULT 0" });
addColumns("incidents", {
  attack_type: "VARCHAR(50) DEFAULT 'brute_force'",
  incident_key: "VARCHAR(255)",
  username: "VARCHAR(100)",
  last_seen: "DATETIME",
  evidence: "TEXT",
  alerted_risk: "VARCHAR(20)",
});
db.exec(`
CREATE INDEX IF NOT EXISTS idx_logs_server_time ON ssh_logs(server_id, event_time);
CREATE INDEX IF NOT EXISTS idx_logs_user ON ssh_logs(username);
CREATE INDEX IF NOT EXISTS idx_logs_country ON ssh_logs(country);
CREATE INDEX IF NOT EXISTS idx_incidents_key ON incidents(server_id, attack_type, incident_key, status);
`);

module.exports = db;
