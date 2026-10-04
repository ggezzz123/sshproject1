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

// Migrate databases created before the servers.user_id column existed
const serverColumns = db.prepare("PRAGMA table_info(servers)").all().map((c) => c.name);
if (!serverColumns.includes("user_id")) {
  db.exec("ALTER TABLE servers ADD COLUMN user_id INTEGER REFERENCES users(id)");
}

module.exports = db;
