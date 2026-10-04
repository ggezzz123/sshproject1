const { useState, useEffect, useCallback } = React;

const TOKEN_KEY = "ssh_monitor_token";

function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}
function setToken(t) {
  if (t) localStorage.setItem(TOKEN_KEY, t);
  else localStorage.removeItem(TOKEN_KEY);
}
function decodeToken(t) {
  try { return JSON.parse(atob(t.split(".")[1])); } catch (e) { return null; }
}

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  const token = getToken();
  if (token) headers["Authorization"] = "Bearer " + token;
  const url = path.startsWith('http') ? path : (API_CONFIG.BACKEND_URL + path);
  const res = await fetch(url, { ...opts, headers });
  if (res.status === 401) {
    setToken(null);
    throw new Error("Unauthorized");
  }
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).error || msg; } catch (e) {}
    throw new Error(msg);
  }
  return res.json();
}

const SEVERITY_CHIP = {
  info: "info",
  warning: "warning",
  high: "error",
  low: "muted",
  critical: "critical",
};

const EVENT_LABEL = {
  ssh_login_success: "Login Success",
  ssh_login_failed: "Login Failed",
  ssh_invalid_user: "Invalid User",
  sudo_command: "Sudo Command",
  session_closed: "Session Closed",
  connection_closed_preauth: "Conn Closed (preauth)",
};

function Chip({ kind, children }) {
  return <span className={"chip " + (kind || "muted")}>{children}</span>;
}

function riskChip(level) {
  const map = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low" };
  return <Chip kind={map[level] || "muted"}>{level}</Chip>;
}

function fmtTime(s) {
  if (!s) return "-";
  const d = new Date(s);
  if (isNaN(d)) return s;
  return d.toLocaleString();
}

/* ---------- Login / Register ---------- */
function Login({ onLogin }) {
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const data = await api("/api/auth/" + mode, {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      setToken(data.token);
      onLogin(data.user);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <h1>SSH Monitor</h1>
        <div className="sub">Security monitoring system</div>
        {error && <div className="error-banner">{error}</div>}
        <div className="field">
          <label>Username</label>
          <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
        </div>
        <div className="field">
          <label>Password</label>
          <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        <button className="btn primary" style={{ width: "100%" }} disabled={loading}>
          {loading ? "Please wait..." : mode === "login" ? "Sign In" : "Create Account"}
        </button>
        <div style={{ marginTop: 16, textAlign: "center", fontSize: 13, color: "var(--text-muted)" }}>
          {mode === "login" ? (
            <>No account? <a href="#" onClick={(e) => { e.preventDefault(); setMode("register"); setError(""); }}>Register</a></>
          ) : (
            <>Already have an account? <a href="#" onClick={(e) => { e.preventDefault(); setMode("login"); setError(""); }}>Sign in</a></>
          )}
        </div>
      </form>
    </div>
  );
}

/* ---------- Dashboard ---------- */
function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [risk, setRisk] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    api("/api/dashboard/summary").then(setSummary).catch(() => {});
    api("/api/dashboard/risk").then(setRisk).catch(() => {});
    api("/api/dashboard/recent-incidents").then(setIncidents).catch(() => {});
    api("/api/dashboard/recent-logs").then(setLogs).catch(() => {});
  }, []);

  return (
    <div>
      <div className="page-title">
        <h1>Dashboard</h1>
        <div className="sub">Real-time SSH security overview</div>
      </div>

      <div className="stat-grid">
        <div className="stat-card">
          <div className="label">Servers</div>
          <div className="value blue">{summary ? summary.servers : "-"}</div>
        </div>
        <div className="stat-card">
          <div className="label">Online</div>
          <div className="value green">{summary ? summary.online : "-"}</div>
        </div>
        <div className="stat-card">
          <div className="label">Incidents</div>
          <div className="value amber">{summary ? summary.incidents : "-"}</div>
        </div>
        <div className="stat-card">
          <div className="label">Critical</div>
          <div className="value red">{summary ? summary.critical : "-"}</div>
        </div>
      </div>

      <div className="section">
        <div className="section-head"><h3>Risk Overview</h3></div>
        <div className="risk-grid">
          {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((lvl) => (
            <div className="risk-cell" key={lvl}>
              <div className="n" style={{ color: lvl === "CRITICAL" ? "var(--red)" : lvl === "HIGH" ? "var(--warning)" : lvl === "MEDIUM" ? "var(--blue)" : "var(--success)" }}>
                {risk ? risk[lvl] : "-"}
              </div>
              <div className="t">{lvl}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="grid-2">
        <div className="section">
          <div className="section-head"><h3>Recent Incidents</h3></div>
          <div className="card">
            {incidents.length === 0 ? (
              <div className="empty">No incidents</div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Time</th><th>IP</th><th>Risk</th><th>Status</th></tr></thead>
                  <tbody>
                    {incidents.map((i) => (
                      <tr key={i.id}>
                        <td className="mono">{fmtTime(i.detected_at)}</td>
                        <td className="mono">{i.source_ip || "-"}</td>
                        <td>{riskChip(i.risk_level)}</td>
                        <td><Chip kind={i.status === "OPEN" ? "error" : "success"}>{i.status}</Chip></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        <div className="section">
          <div className="section-head"><h3>Recent Logs</h3></div>
          <div className="card">
            {logs.length === 0 ? (
              <div className="empty">No logs</div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Time</th><th>Event</th><th>User</th><th>IP</th></tr></thead>
                  <tbody>
                    {logs.map((l) => (
                      <tr key={l.id}>
                        <td className="mono">{fmtTime(l.event_time)}</td>
                        <td><Chip kind={SEVERITY_CHIP[l.severity] || "muted"}>{EVENT_LABEL[l.event_type] || l.event_type}</Chip></td>
                        <td>{l.username || "-"}</td>
                        <td className="mono">{l.source_ip || "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ---------- Servers ---------- */
function Servers() {
  const [servers, setServers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState("");
  const [hostname, setHostname] = useState("");
  const [ip, setIp] = useState("");
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(null);

  const load = useCallback(() => {
    api("/api/servers").then((d) => { setServers(d); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  async function createServer(e) {
    e.preventDefault();
    setError("");
    setCreating(true);
    try {
      await api("/api/servers", {
        method: "POST",
        body: JSON.stringify({ name, hostname, ip_address: ip }),
      });
      setName(""); setHostname(""); setIp("");
      load();
    } catch (err) {
      setError(err.message);
    } finally {
      setCreating(false);
    }
  }

  async function regenerate(id) {
    await api("/api/servers/" + id + "/regenerate-key", { method: "POST" });
    load();
  }

  function copyKey(key, id) {
    navigator.clipboard.writeText(key).then(() => {
      setCopied(id);
      setTimeout(() => setCopied(null), 1500);
    });
  }

  return (
    <div>
      <div className="page-title">
        <h1>Servers</h1>
        <div className="sub">Register an SSH server to get its API key</div>
      </div>

      <div className="card" style={{ marginBottom: 24 }}>
        <h4 style={{ marginBottom: 12 }}>Add Server</h4>
        {error && <div className="error-banner">{error}</div>}
        <form onSubmit={createServer} className="toolbar">
          <input className="input" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} required />
          <input className="input" placeholder="Hostname" value={hostname} onChange={(e) => setHostname(e.target.value)} />
          <input className="input" placeholder="IP address" value={ip} onChange={(e) => setIp(e.target.value)} />
          <button className="btn primary" disabled={creating}>{creating ? "Creating..." : "Add Server"}</button>
        </form>
      </div>

      <div className="card">
        {loading ? (
          <div className="empty">Loading...</div>
        ) : servers.length === 0 ? (
          <div className="empty">No servers registered yet</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Name</th><th>Hostname</th><th>IP</th><th>Status</th><th>API Key</th><th>Logs</th><th>Incidents</th><th>Actions</th></tr>
              </thead>
              <tbody>
                {servers.map((s) => (
                  <tr key={s.id}>
                    <td>{s.name}</td>
                    <td className="mono">{s.hostname || "-"}</td>
                    <td className="mono">{s.ip_address || "-"}</td>
                    <td><Chip kind={s.status === "online" ? "success" : "muted"}>{s.status}</Chip></td>
                    <td className="mono" style={{ maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={s.api_key}>{s.api_key || "-"}</td>
                    <td className="mono">{s.log_count}</td>
                    <td className="mono">{s.open_incidents}</td>
                    <td>
                      <button className="btn ghost sm" onClick={() => copyKey(s.api_key, s.id)}>{copied === s.id ? "Copied!" : "Copy Key"}</button>
                      <button className="btn ghost sm" onClick={() => regenerate(s.id)}>Regenerate</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

/* ---------- Logs ---------- */
function Logs() {
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [eventType, setEventType] = useState("");
  const [sourceIp, setSourceIp] = useState("");
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    const q = new URLSearchParams();
    if (eventType) q.set("event_type", eventType);
    if (sourceIp) q.set("source_ip", sourceIp);
    q.set("limit", "200");
    api("/api/logs?" + q.toString())
      .then((d) => { setLogs(d.logs); setTotal(d.total); setLoading(false); })
      .catch(() => setLoading(false));
  }, [eventType, sourceIp]);

  useEffect(() => { load(); }, [load]);

  return (
    <div>
      <div className="page-title">
        <h1>Logs</h1>
        <div className="sub">{total} total events</div>
      </div>
      <div className="toolbar">
        <select className="input" value={eventType} onChange={(e) => setEventType(e.target.value)}>
          <option value="">All events</option>
          {Object.entries(EVENT_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <input className="input" placeholder="Filter by IP" value={sourceIp} onChange={(e) => setSourceIp(e.target.value)} />
        <button className="btn secondary sm" onClick={load}>Refresh</button>
      </div>
      <div className="card">
        {loading ? (
          <div className="empty">Loading...</div>
        ) : logs.length === 0 ? (
          <div className="empty">No logs</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Time</th><th>Server</th><th>Event</th><th>User</th><th>IP</th><th>Severity</th></tr>
              </thead>
              <tbody>
                {logs.map((l) => (
                  <tr key={l.id}>
                    <td className="mono">{fmtTime(l.event_time)}</td>
                    <td className="mono">{l.server_hostname || "-"}</td>
                    <td>{EVENT_LABEL[l.event_type] || l.event_type}</td>
                    <td>{l.username || "-"}</td>
                    <td className="mono">{l.source_ip || "-"}</td>
                    <td><Chip kind={SEVERITY_CHIP[l.severity] || "muted"}>{l.severity}</Chip></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

/* ---------- Incidents ---------- */
function Incidents() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    api("/api/incidents").then((d) => { setIncidents(d); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  async function setStatus(id, status) {
    await api("/api/incidents/" + id + "/status", { method: "PATCH", body: JSON.stringify({ status }) });
    load();
  }

  return (
    <div>
      <div className="page-title">
        <h1>Incidents</h1>
        <div className="sub">Detected security incidents</div>
      </div>
      <div className="card">
        {loading ? (
          <div className="empty">Loading...</div>
        ) : incidents.length === 0 ? (
          <div className="empty">No incidents</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Detected</th><th>Server</th><th>IP</th><th>Risk</th><th>Attempts</th><th>Status</th><th>Actions</th></tr>
              </thead>
              <tbody>
                {incidents.map((i) => (
                  <tr key={i.id}>
                    <td className="mono">{fmtTime(i.detected_at)}</td>
                    <td className="mono">{i.server_hostname || "-"}</td>
                    <td className="mono">{i.source_ip || "-"}</td>
                    <td>{riskChip(i.risk_level)}</td>
                    <td className="mono">{i.failed_attempts}</td>
                    <td><Chip kind={i.status === "OPEN" ? "error" : "success"}>{i.status}</Chip></td>
                    <td>
                      {i.status === "OPEN" ? (
                        <button className="btn ghost sm" onClick={() => setStatus(i.id, "RESOLVED")}>Resolve</button>
                      ) : (
                        <button className="btn ghost sm" onClick={() => setStatus(i.id, "OPEN")}>Reopen</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

/* ---------- Users ---------- */
function Users() {
  const [user, setUser] = useState(null);
  useEffect(() => {
    const t = getToken();
    if (t) setUser(decodeToken(t));
  }, []);
  return (
    <div>
      <div className="page-title">
        <h1>Users</h1>
        <div className="sub">Access control</div>
      </div>
      <div className="card">
        <table>
          <thead><tr><th>Username</th><th>Role</th></tr></thead>
          <tbody>
            {user && (
              <tr>
                <td>{user.username}</td>
                <td><Chip kind="info">{user.role}</Chip></td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------- App ---------- */
const PAGES = [
  { key: "dashboard", label: "Dashboard", icon: "▦" },
  { key: "servers", label: "Servers", icon: "▣" },
  { key: "logs", label: "Logs", icon: "≡" },
  { key: "incidents", label: "Incidents", icon: "⚠" },
  { key: "users", label: "Users", icon: "◉" },
];

function App() {
  const [authed, setAuthed] = useState(!!getToken());
  const [page, setPage] = useState("dashboard");

  // This dashboard is admin-only (Servers/Logs/Incidents are org-wide views).
  // Regular self-registered users belong on /get-key instead.
  useEffect(() => {
    const t = getToken();
    if (t) {
      const payload = decodeToken(t);
      if (!payload || payload.role !== "admin") {
        window.location.href = "/get-key";
      }
    }
  }, []);

  function handleLogin(user) {
    if (user.role !== "admin") {
      window.location.href = "/get-key";
      return;
    }
    setAuthed(true);
  }
  function handleLogout() { setToken(null); setAuthed(false); }

  if (!authed) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">SSH Monitor</div>
        {PAGES.map((p) => (
          <div key={p.key} className={"nav-item" + (page === p.key ? " active" : "")} onClick={() => setPage(p.key)}>
            <span>{p.icon}</span> {p.label}
          </div>
        ))}
        <div style={{ flex: 1 }} />
        <div className="nav-item" onClick={handleLogout}>⏻ Logout</div>
      </aside>
      <main className="main">
        {page === "dashboard" && <Dashboard />}
        {page === "servers" && <Servers />}
        {page === "logs" && <Logs />}
        {page === "incidents" && <Incidents />}
        {page === "users" && <Users />}
      </main>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
