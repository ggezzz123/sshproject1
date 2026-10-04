require("dotenv").config();
const path = require("path");
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const db = require("./db");

const app = express();
// Behind Render's proxy req.ip would otherwise be the proxy's address. Only enable when a
// proxy really sits in front, or clients could spoof their IP via X-Forwarded-For.
if (process.env.TRUST_PROXY) {
  const v = process.env.TRUST_PROXY;
  app.set("trust proxy", /^\d+$/.test(v) ? Number(v) : v === "true" ? true : v);
}
app.use(cors());
app.use(express.json({ limit: "5mb" }));

// Seed default admin user
function seedAdmin() {
  const username = process.env.ADMIN_USERNAME || "admin";
  const password = process.env.ADMIN_PASSWORD || "admin123";
  const existing = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!existing) {
    const hash = bcrypt.hashSync(password, 10);
    db.prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')").run(
      username,
      hash
    );
    console.log(`[seed] Created admin user "${username}"`);
  }
}
seedAdmin();

// API routes
app.use(require("./routes/agentRoutes"));
app.use(require("./routes/authRoutes"));
app.use("/api", require("./routes/serverRoutes"));
app.use("/api", require("./routes/logRoutes"));
app.use("/api", require("./routes/incidentRoutes"));
app.use("/api", require("./routes/dashboardRoutes"));

// Public self-service key page
app.get("/get-key", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "get-key.html"));
});

// Dashboard app (landing page is public/index.html at "/")
app.get("/app", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "app.html"));
});

// Agent installer + agent script, fetched by `curl .../install.sh | sudo bash`
app.get("/install.sh", (req, res) => {
  res.type("text/x-shellscript").sendFile(path.join(__dirname, "agent", "install.sh"));
});
app.get("/agent/agentssh_v2.py", (req, res) => {
  res.type("text/x-python").sendFile(path.join(__dirname, "agent", "agentssh_v2.py"));
});

// Static frontend
app.use(express.static(path.join(__dirname, "public")));
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = Number(process.env.PORT || 5000);
const HOST = process.env.HOST || "0.0.0.0";
app.listen(PORT, HOST, () => {
  console.log(`SSH Monitor dashboard running at http://${HOST}:${PORT}`);
});
