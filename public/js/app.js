const { useState, useEffect, useCallback, useRef } = React;

const TOKEN_KEY = "ssh_monitor_token";

// OAuth callback redirects to /app#token=...; store it and clean the URL.
(function () {
  const m = /[#&]token=([^&]+)/.exec(location.hash);
  if (m) {
    localStorage.setItem(TOKEN_KEY, decodeURIComponent(m[1]));
    history.replaceState(null, "", location.pathname + location.search);
  }
})();

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
  // SQLite datetime('now') is UTC but has no zone suffix; mark it as UTC.
  const d = new Date(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s) ? s.replace(" ", "T") + "Z" : s);
  if (isNaN(d)) return s;
  return d.toLocaleString();
}

function ThemeToggle({ floating }) {
  const [theme, setTheme] = useState(window.currentTheme());
  return (
    <button
      type="button"
      className={"theme-toggle" + (floating ? " floating" : "")}
      onClick={() => setTheme(window.toggleTheme())}
      aria-label="Toggle light / dark mode"
    >
      {theme === "dark" ? "☀ Light mode" : "☾ Dark mode"}
    </button>
  );
}

/* ---------- Login / Register ---------- */
function Captcha({ cfg, onChange }) {
  const boxRef = useRef(null);
  useEffect(() => {
    if (!cfg.turnstileSiteKey) return;
    let id;
    function render() {
      if (boxRef.current && window.turnstile && id === undefined) {
        id = window.turnstile.render(boxRef.current, {
          sitekey: cfg.turnstileSiteKey,
          callback: (t) => onChange({ captcha_token: t }),
          "expired-callback": () => onChange({ captcha_token: "" }),
        });
      }
    }
    if (window.turnstile) render();
    else {
      const s = document.createElement("script");
      s.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
      s.async = true;
      s.onload = render;
      document.head.appendChild(s);
    }
    return () => { if (id !== undefined && window.turnstile) window.turnstile.remove(id); };
  }, [cfg.turnstileSiteKey]);

  if (cfg.turnstileSiteKey) return <div className="field" ref={boxRef} />;
  if (!cfg.challenge) return null;
  return (
    <div className="field">
      <label>I'm not a robot: {cfg.challenge.question}</label>
      <input className="input" inputMode="numeric" placeholder="Answer"
        onChange={(e) => onChange({ captcha_token: cfg.challenge.token, captcha_answer: e.target.value })} />
    </div>
  );
}

function Login({ onLogin }) {
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [captcha, setCaptcha] = useState({});
  const [cfg, setCfg] = useState({ providers: [] });
  const [error, setError] = useState(() => {
    const m = /error=([^&]+)/.exec(location.hash);
    return m ? decodeURIComponent(m[1]) : "";
  });
  const [loading, setLoading] = useState(false);

  async function loadConfig() {
    try { setCfg(await api("/api/auth/config")); setCaptcha({}); } catch (e) {}
  }
  useEffect(() => { loadConfig(); }, []);

  async function submit(e) {
    e.preventDefault();
    setError("");
    if (mode === "register" && password !== confirm) {
      setError("Passwords do not match");
      return;
    }
    setLoading(true);
    try {
      const body = mode === "register"
        ? { username, email, password, confirm_password: confirm, ...captcha }
        : { username, password };
      const data = await api("/api/auth/" + mode, { method: "POST", body: JSON.stringify(body) });
      setToken(data.token);
      onLogin(data.user);
    } catch (err) {
      setError(err.message);
      if (mode === "register") loadConfig(); // challenges are single-use
    } finally {
      setLoading(false);
    }
  }

  function switchMode(m) { setMode(m); setError(""); loadConfig(); }
  const oauthLabel = { google: "Google", github: "GitHub" };

  return (
    <div className="login-wrap">
      <ThemeToggle floating />
      <form className="login-card" onSubmit={submit}>
        <h1>SSH Monitor</h1>
        <div className="sub">
          {new URLSearchParams(location.search).get("next") === "/get-key"
            ? "Sign in or register to get your API key"
            : "Security monitoring system"}
        </div>
        {error && <div className="error-banner">{error}</div>}
        <div className="field">
          <label>Username</label>
          <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
        </div>
        {mode === "register" && (
          <div className="field">
            <label>Email (optional)</label>
            <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
        )}
        <div className="field">
          <label>Password</label>
          <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        {mode === "register" && (
          <>
            <div className="field">
              <label>Confirm password</label>
              <input className="input" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
            </div>
            <Captcha key={cfg.challenge ? cfg.challenge.token : "ts"} cfg={cfg} onChange={setCaptcha} />
          </>
        )}
        <button className="btn primary" style={{ width: "100%" }} disabled={loading}>
          {loading ? "Please wait..." : mode === "login" ? "Sign In" : "Create Account"}
        </button>
        {cfg.providers.length > 0 && (
          <div style={{ marginTop: 16, display: "flex", flexDirection: "column", gap: 8 }}>
            <div style={{ textAlign: "center", fontSize: 12, color: "var(--text-muted)" }}>or</div>
            {cfg.providers.map((p) => (
              <a key={p} className="btn" style={{ width: "100%", textAlign: "center", boxSizing: "border-box" }}
                href={API_CONFIG.BACKEND_URL + "/api/auth/oauth/" + p}>
                {mode === "login" ? "Sign in" : "Sign up"} with {oauthLabel[p]}
              </a>
            ))}
          </div>
        )}
        <div style={{ marginTop: 16, textAlign: "center", fontSize: 13, color: "var(--text-muted)" }}>
          {mode === "login" ? (
            <>No account? <a href="#" onClick={(e) => { e.preventDefault(); switchMode("register"); }}>Register</a></>
          ) : (
            <>Already have an account? <a href="#" onClick={(e) => { e.preventDefault(); switchMode("login"); }}>Sign in</a></>
          )}
        </div>
      </form>
    </div>
  );
}

/* ---------- Analytics helpers ---------- */
const ATTACK_LABEL = {
  brute_force: "Brute force",
  brute_force_success: "Login after many failures",
  password_spraying: "Password spraying",
  credential_stuffing: "Credential stuffing",
  compromised_account: "Compromised account reuse",
  username_enumeration: "Username enumeration",
  ssh_scanning: "SSH scanning",
  abnormal_burst: "Abnormal burst",
  new_source_login: "Login from new source",
  cross_host: "Cross-host campaign",
  post_compromise: "Post-compromise activity",
};

// Status colors always travel with an icon + label (never color alone)
const RISK_META = [
  { key: "CRITICAL", icon: "✖", color: "var(--status-critical)" },
  { key: "HIGH", icon: "▲", color: "var(--status-serious)" },
  { key: "MEDIUM", icon: "●", color: "var(--status-warning)" },
  { key: "LOW", icon: "✓", color: "var(--status-good)" },
];
const SEVERITIES = [
  { key: "info", label: "Info", color: "var(--viz-ord-1)" },
  { key: "low", label: "Low", color: "var(--viz-ord-2)" },
  { key: "warning", label: "Warning", color: "var(--viz-ord-3)" },
  { key: "high", label: "High", color: "var(--viz-ord-4)" },
];
const RANGE_LABEL = { "24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days", all: "All time" };
const PREV_LABEL = { "24h": "previous 24h", "7d": "previous 7 days", "30d": "previous 30 days" };

function fmtNum(n) {
  if (n == null) return "-";
  if (Math.abs(n) >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, "") + "M";
  if (Math.abs(n) >= 1e4) return (n / 1e3).toFixed(1).replace(/\.0$/, "") + "K";
  return n.toLocaleString();
}
function pct(part, total) {
  return total ? ((part / total) * 100).toFixed(1) + "%" : "0%";
}
function niceStep(raw) {
  if (raw <= 1) return 1;
  const exp = Math.pow(10, Math.floor(Math.log10(raw)));
  const f = raw / exp;
  // 2.5 only from tens up, so tick values stay whole numbers (they are event counts)
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 && exp >= 10 ? 2.5 : f <= 5 ? 5 : 10) * exp;
}
function bucketLabel(t, bucketMs, long) {
  const d = new Date(t);
  const hm = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const day = d.toLocaleDateString([], { day: "numeric", month: "short" });
  if (bucketMs < 86400000) return long ? `${day} ${hm}` : bucketMs <= 3600000 ? hm : `${day} ${hm}`;
  return day;
}

function useWidth(ref) {
  const [w, setW] = useState(0);
  useEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver((entries) => setW(entries[0].contentRect.width));
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return w;
}

// Tooltip anchored inside the nearest .viz-card; works for mouse and keyboard focus
function useTip() {
  const [tip, setTip] = useState(null);
  function show(e, content) {
    const card = e.currentTarget.closest(".viz-card");
    if (!card) return;
    const r = card.getBoundingClientRect();
    let px, py;
    if (e.type.startsWith("mouse") || e.type.startsWith("pointer")) { px = e.clientX; py = e.clientY; }
    else { const b = e.currentTarget.getBoundingClientRect(); px = b.left + b.width / 2; py = b.top; }
    setTip({ x: Math.max(90, Math.min(r.width - 90, px - r.left)), y: Math.max(40, py - r.top), content });
  }
  const node = tip && <div className="viz-tip" style={{ left: tip.x, top: tip.y }}>{tip.content}</div>;
  return [node, show, () => setTip(null)];
}

function ChartCard({ title, sub, className, table, children }) {
  const [view, setView] = useState("chart");
  return (
    <section className={"card viz-card " + (className || "")}>
      <div className="viz-head">
        <div>
          <h3>{title}</h3>
          {sub && <div className="sub">{sub}</div>}
        </div>
        {table && (
          <div className="viz-toggle" role="group" aria-label={title + " view"}>
            <button type="button" className={view === "chart" ? "on" : ""} aria-pressed={view === "chart"} onClick={() => setView("chart")}>Chart</button>
            <button type="button" className={view === "table" ? "on" : ""} aria-pressed={view === "table"} onClick={() => setView("table")}>Table</button>
          </div>
        )}
      </div>
      {view === "table" && table ? <VizTable {...table} /> : children}
    </section>
  );
}

function VizTable({ columns, rows }) {
  if (!rows.length) return <div className="viz-empty">No data for this filter</div>;
  return (
    <div className="table-wrap">
      <table className="viz-table">
        <thead><tr>{columns.map((c) => <th key={c.key} style={c.num ? { textAlign: "right" } : null}>{c.label}</th>)}</tr></thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>{columns.map((c) => <td key={c.key} className={c.num ? "num" : c.mono ? "mono" : ""}>{c.num ? fmtNum(r[c.key]) : r[c.key]}</td>)}</tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ---------- Chart primitives ---------- */
function Sparkline({ values }) {
  const w = 96, h = 40, pad = 5;
  if (values.length < 2) return null;
  const max = Math.max(1, ...values);
  const x = (i) => pad + (i * (w - pad * 2)) / (values.length - 1);
  const y = (v) => h - pad - (v / max) * (h - pad * 2);
  const pts = values.map((v, i) => `${x(i)},${y(v)}`);
  const n = values.length - 1;
  return (
    <svg className="k-spark" width={w} height={h} viewBox={`0 0 ${w} ${h}`} aria-hidden="true">
      <polyline points={pts.slice(0, n).join(" ")} fill="none" stroke="var(--viz-spark)" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
      <polyline points={pts.slice(n - 1).join(" ")} fill="none" stroke="var(--viz-1)" strokeWidth="2" strokeLinecap="round" />
      <circle cx={x(n)} cy={y(values[n])} r="4" fill="var(--viz-1)" stroke="var(--surface)" strokeWidth="2" />
    </svg>
  );
}

function arcPath(cx, cy, r0, r1, a0, a1) {
  a1 = Math.min(a1, a0 + Math.PI * 2 - 0.0001);
  const large = a1 - a0 > Math.PI ? 1 : 0;
  const p = (r, a) => [cx + r * Math.sin(a), cy - r * Math.cos(a)];
  const [x0, y0] = p(r1, a0), [x1, y1] = p(r1, a1), [x2, y2] = p(r0, a1), [x3, y3] = p(r0, a0);
  return `M${x0},${y0} A${r1},${r1} 0 ${large} 1 ${x1},${y1} L${x2},${y2} A${r0},${r0} 0 ${large} 0 ${x3},${y3} Z`;
}

function Donut({ data, centerLabel }) {
  const [tip, show, hide] = useTip();
  const [active, setActive] = useState(null);
  const total = data.reduce((s, d) => s + d.value, 0);
  const size = 140, c = size / 2;
  let a = 0;
  const arcs = data.filter((d) => d.value > 0).map((d) => {
    const a0 = a; a += (d.value / total) * Math.PI * 2;
    return { ...d, a0, a1: a };
  });
  const tipFor = (d) => (
    <>
      <div className="r"><span className="sw" style={{ background: d.color }} />{d.label}<b>{fmtNum(d.value)}</b></div>
      <div className="t">{pct(d.value, total)} of {fmtNum(total)}</div>
    </>
  );
  if (!total) return <div className="viz-empty">No events for this filter</div>;
  return (
    <div className="donut-wrap">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`${centerLabel}: ${data.map((d) => `${d.label} ${d.value}`).join(", ")}`}>
        {arcs.map((d) => (
          <path key={d.key} d={arcPath(c, c, 46, 66, d.a0, d.a1)} fill={d.color} stroke="var(--surface)" strokeWidth="2"
            opacity={active && active !== d.key ? 0.4 : 1} style={{ transition: "opacity 150ms" }}
            onMouseMove={(e) => { setActive(d.key); show(e, tipFor(d)); }} onMouseLeave={() => { setActive(null); hide(); }} />
        ))}
        <text x={c} y={c - 2} textAnchor="middle" fontSize="20" fontWeight="700" fill="var(--text)">{fmtNum(total)}</text>
        <text x={c} y={c + 16} textAnchor="middle" fontSize="11" fill="var(--text-muted)">{centerLabel}</text>
      </svg>
      <div className="legend">
        {data.map((d) => (
          <div key={d.key} className={"li" + (active && active !== d.key ? " dim" : "")} tabIndex={0}
            onMouseEnter={() => setActive(d.key)} onMouseLeave={() => setActive(null)}
            onFocus={(e) => { setActive(d.key); show(e, tipFor(d)); }} onBlur={() => { setActive(null); hide(); }}>
            <span className="sw" style={{ background: d.color }} />
            <span className="lbl">{d.label}</span>
            <span className="v">{fmtNum(d.value)}</span>
            <span className="p">{pct(d.value, total)}</span>
          </div>
        ))}
      </div>
      {tip}
    </div>
  );
}

function HBars({ data, color, unit, onSelect, empty }) {
  const [tip, show, hide] = useTip();
  const max = Math.max(1, ...data.map((d) => d.value));
  if (!data.length) return <div className="viz-empty">{empty || "Nothing to show"}</div>;
  return (
    <div className="hbars">
      {data.map((d) => {
        const content = (
          <>
            <div className="r"><span className="sw" style={{ background: color }} />{d.label}<b>{fmtNum(d.value)} {unit}</b></div>
            {d.meta && <div className="t">{d.meta}</div>}
            {onSelect && <div className="t">Click to analyze</div>}
          </>
        );
        return (
          <div key={d.key} className="hbar" tabIndex={0} role={onSelect ? "button" : undefined}
            style={onSelect ? { cursor: "pointer" } : null}
            onClick={onSelect ? () => onSelect(d) : undefined}
            onKeyDown={onSelect ? (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSelect(d); } } : undefined}
            onMouseMove={(e) => show(e, content)} onMouseLeave={hide} onFocus={(e) => show(e, content)} onBlur={hide}>
            <div className="top"><span className={"lbl" + (d.mono ? " mono" : "")}>{d.label}</span><span className="v">{fmtNum(d.value)}</span></div>
            <div className="track"><div className="fill" style={{ width: `${Math.max(2, (d.value / max) * 100)}%`, background: color }} /></div>
          </div>
        );
      })}
      {tip}
    </div>
  );
}

function LineChart({ points, series, bucketMs }) {
  const ref = useRef(null);
  const width = useWidth(ref);
  const [hover, setHover] = useState(null);
  const W = Math.max(300, width || 600), H = 240, padL = 40, padR = 52, padT = 14, padB = 28;
  const n = points.length;
  const step = niceStep(Math.max(1, ...series.flatMap((s) => points.map((p) => p[s.key]))) / 4);
  const max = step * 4;
  const x = (i) => padL + (n <= 1 ? (W - padL - padR) / 2 : (i * (W - padL - padR)) / (n - 1));
  const y = (v) => padT + (H - padT - padB) * (1 - v / max);
  const path = (key) => points.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(p[key]).toFixed(1)}`).join("");
  const labelEvery = Math.max(1, Math.ceil(n / Math.max(2, Math.floor((W - padL - padR) / 90))));

  function onMove(e) {
    const r = e.currentTarget.getBoundingClientRect();
    const px = ((e.clientX - r.left) / r.width) * W;
    const i = n <= 1 ? 0 : Math.round(((px - padL) / (W - padL - padR)) * (n - 1));
    setHover(Math.max(0, Math.min(n - 1, i)));
  }

  const ends = series.map((s) => ({ ...s, v: n ? points[n - 1][s.key] : 0 }));
  const endsCollide = ends.length > 1 && Math.abs(y(ends[0].v) - y(ends[1].v)) < 14;
  const hp = hover != null ? points[hover] : null;

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <div className="line-legend" aria-hidden="true">
        {series.map((s) => <span key={s.key}><span className="sw line" style={{ background: s.color }} />{s.label}</span>)}
      </div>
      <svg className="linechart" width="100%" height={H} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img"
        aria-label={`${series.map((s) => s.label).join(" and ")} over time`}
        onMouseMove={onMove} onMouseLeave={() => setHover(null)}>
        {[0, 1, 2, 3, 4].map((k) => (
          <g key={k}>
            <line x1={padL} x2={W - padR} y1={y(step * k)} y2={y(step * k)} stroke={k === 0 ? "var(--viz-axis)" : "var(--viz-grid)"} strokeWidth="1" />
            <text x={padL - 8} y={y(step * k) + 4} textAnchor="end" fontSize="11" fill="var(--viz-muted)" style={{ fontVariantNumeric: "tabular-nums" }}>{fmtNum(step * k)}</text>
          </g>
        ))}
        {points.map((p, i) => i === n - 1 || (i % labelEvery === 0 && n - 1 - i >= labelEvery * 0.75) ? (
          <text key={i} x={x(i)} y={H - 8} textAnchor="middle" fontSize="11" fill="var(--viz-muted)">{bucketLabel(p.t, bucketMs)}</text>
        ) : null)}
        {series.map((s) => (
          <g key={s.key}>
            <path d={`${path(s.key)}L${x(n - 1)},${y(0)}L${x(0)},${y(0)}Z`} fill={s.color} opacity="0.08" />
            <path d={path(s.key)} fill="none" stroke={s.color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
          </g>
        ))}
        {!endsCollide && ends.map((s) => (
          <g key={s.key}>
            <circle cx={x(n - 1)} cy={y(s.v)} r="4" fill={s.color} stroke="var(--surface)" strokeWidth="2" />
            <text x={x(n - 1) + 8} y={y(s.v) + 4} fontSize="11" fontWeight="600" fill="var(--text)">{fmtNum(s.v)}</text>
          </g>
        ))}
        {hp && (
          <g>
            <line x1={x(hover)} x2={x(hover)} y1={padT} y2={H - padB} stroke="var(--viz-axis)" strokeWidth="1" />
            {series.map((s) => <circle key={s.key} cx={x(hover)} cy={y(hp[s.key])} r="4" fill={s.color} stroke="var(--surface)" strokeWidth="2" />)}
          </g>
        )}
      </svg>
      {hp && (
        <div className="viz-tip" style={{ left: `${(x(hover) / W) * 100}%`, top: 24 + Math.min(...series.map((s) => y(hp[s.key]))) }}>
          <div className="t">{bucketLabel(hp.t, bucketMs, true)} – {bucketLabel(hp.t + bucketMs, bucketMs, true)}</div>
          {series.map((s) => <div key={s.key} className="r"><span className="sw line" style={{ background: s.color }} />{s.label}<b>{fmtNum(hp[s.key])}</b></div>)}
        </div>
      )}
    </div>
  );
}

function RiskRows({ data }) {
  const [tip, show, hide] = useTip();
  const total = RISK_META.reduce((s, r) => s + (data[r.key] || 0), 0);
  if (!total) return <div className="viz-empty">No incidents in this period</div>;
  return (
    <div className="risk-rows">
      {RISK_META.map((r) => {
        const v = data[r.key] || 0;
        const content = <div className="r"><span className="sw" style={{ background: r.color }} />{r.key}<b>{v} · {pct(v, total)}</b></div>;
        return (
          <div key={r.key} className="risk-row" tabIndex={0} onMouseMove={(e) => show(e, content)} onMouseLeave={hide} onFocus={(e) => show(e, content)} onBlur={hide}>
            <span className="rl"><i style={{ color: r.color }} aria-hidden="true">{r.icon}</i>{r.key}</span>
            <span className="bar"><span style={{ width: `${(v / total) * 100}%`, background: r.color }} /></span>
            <span className="n">{v}</span>
            <span className="p">{pct(v, total)}</span>
          </div>
        );
      })}
      {tip}
    </div>
  );
}

/* ---------- IP analysis drawer ---------- */
function AnalysisModal({ ip, onClose }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => {
    api("/api/analysis/ip/" + encodeURIComponent(ip)).then(setData).catch((e) => setError(e.message));
    const esc = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", esc);
    return () => window.removeEventListener("keydown", esc);
  }, [ip]);
  const meta = data && RISK_META.find((r) => r.key === data.verdict.risk);
  return (
    <div className="modal-back" onClick={onClose}>
      <aside className="modal-panel" onClick={(e) => e.stopPropagation()} role="dialog" aria-label={"Analysis of " + ip}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <div className="sub" style={{ fontSize: 12, color: "var(--text-muted)", fontWeight: 600 }}>SOURCE IP ANALYSIS</div>
            <h2 style={{ fontFamily: "var(--font-mono)" }}>{ip}</h2>
          </div>
          <button className="btn ghost" onClick={onClose} aria-label="Close">✕</button>
        </div>
        {error && <div className="error-banner">{error}</div>}
        {!data && !error && <div className="empty">Analyzing…</div>}
        {data && (
          <>
            <div className="verdict" style={{ "--vc": meta ? meta.color : undefined }}>
              <div className="vr"><span style={{ color: meta && meta.color }} aria-hidden="true">{meta && meta.icon}</span>{data.verdict.risk} · Assessment</div>
              <div className="vt">{data.verdict.text}</div>
            </div>
            <div className="mini-stats">
              <div className="card"><div className="l">Events (24h)</div><div className="v">{fmtNum(data.events)}</div></div>
              <div className="card"><div className="l">Servers</div><div className="v">{data.hosts.length}</div></div>
              <div className="card"><div className="l">Accounts tried</div><div className="v">{data.users.length}</div></div>
            </div>
            {data.sequence.length > 0 && (
              <div>
                <h4 style={{ marginBottom: 8 }}>Attack sequence</h4>
                <div className="seq">
                  {data.sequence.map((s, i) => (
                    <React.Fragment key={i}>
                      {i > 0 && <span className="arrow">→</span>}
                      <span className="ph">{s.phase}<small>×{s.count}</small></span>
                    </React.Fragment>
                  ))}
                </div>
              </div>
            )}
            {data.hosts.length > 0 && (
              <div><h4 style={{ marginBottom: 8 }}>Targeted servers</h4><div className="seq">{data.hosts.map((h) => <span key={h} className="ph mono">{h}</span>)}</div></div>
            )}
            {data.users.length > 0 && (
              <div><h4 style={{ marginBottom: 8 }}>Accounts</h4><div className="seq">{data.users.map((u) => <span key={u.user} className="ph">{u.user}<small>×{u.count}</small></span>)}</div></div>
            )}
            {data.incidents.length > 0 && (
              <div>
                <h4 style={{ marginBottom: 8 }}>Detected patterns</h4>
                <div className="card" style={{ padding: "4px 8px" }}>
                  <table className="viz-table">
                    <tbody>
                      {data.incidents.map((i) => (
                        <tr key={i.id}>
                          <td>{riskChip(i.risk_level)}</td>
                          <td><b>{ATTACK_LABEL[i.attack_type] || i.attack_type}</b><div style={{ color: "var(--text-muted)", fontSize: 12 }}>{i.description}</div></td>
                          <td className="mono">{i.server_hostname}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
            {data.timeline.length > 0 && (
              <div>
                <h4 style={{ marginBottom: 8 }}>Timeline (latest {data.timeline.length})</h4>
                <div className="timeline">
                  {[...data.timeline].reverse().map((e, i) => (
                    <div key={i} className="ev">
                      <span className="mono">{fmtTime(e.time)}</span>
                      <span className="dot" />
                      <span><b>{EVENT_LABEL[e.type] || e.type}</b>{e.user ? ` · ${e.user}` : ""}{e.host ? <span style={{ color: "var(--text-muted)" }}> @ {e.host}</span> : null}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </aside>
    </div>
  );
}

/* ---------- Dashboard ---------- */
const KPIS = [
  { key: "total", label: "Total events", up: null },
  { key: "failed", label: "Failed logins", up: "bad" },
  { key: "success", label: "Successful logins", up: null },
  { key: "attackers", label: "Attacker IPs", up: "bad" },
];
const DEFAULT_FILTERS = { range: "24h", server_id: "", severity: "", event_type: "" };

function Delta({ cur, prev, up, range }) {
  if (prev == null) return <span>{RANGE_LABEL[range]}</span>;
  if (!prev) return <span>{cur ? <b>new</b> : "no change"} vs {PREV_LABEL[range]}</span>;
  const d = ((cur - prev) / prev) * 100;
  const cls = !up || Math.abs(d) < 0.05 ? "" : (d > 0) === (up === "good") ? "good" : "bad";
  return <span><b className={cls}>{d > 0 ? "▲" : d < 0 ? "▼" : ""} {Math.abs(d).toFixed(1)}%</b> vs {PREV_LABEL[range]}</span>;
}

function Dashboard() {
  const [filters, setFilters] = useState(DEFAULT_FILTERS);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [analyze, setAnalyze] = useState(null);

  const load = useCallback(() => {
    setLoading(true);
    const q = new URLSearchParams(Object.entries(filters).filter(([, v]) => v));
    api("/api/dashboard/analytics?" + q.toString())
      .then((d) => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [filters]);
  useEffect(() => {
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, [load]);

  const set = (k) => (e) => setFilters((f) => ({ ...f, [k]: e.target.value }));
  const cur = data ? data.kpis.current : {};
  const prev = data && data.kpis.previous;
  const series = data ? data.series : [];
  const other = Math.max(0, (cur.total || 0) - (cur.failed || 0) - (cur.success || 0));
  const riskMap = data ? Object.fromEntries(data.incidents.byRisk.map((r) => [r.key, r.count])) : {};
  const sevMap = data ? Object.fromEntries(data.bySeverity.map((r) => [r.key, r.count])) : {};

  return (
    <div>
      <div className="page-title">
        <h1>Dashboard</h1>
        <div className="sub">SSH security analytics · {RANGE_LABEL[filters.range]} · auto-refresh 30s</div>
      </div>
      <div className="dash">
        <aside className="card dash-filters" aria-label="Filters">
          <h3><span aria-hidden="true">⚲</span> Filter</h3>
          <div>
            <label htmlFor="f-range">Time range</label>
            <select id="f-range" className="input" value={filters.range} onChange={set("range")}>
              {Object.entries(RANGE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </div>
          <div>
            <label htmlFor="f-server">Server</label>
            <select id="f-server" className="input" value={filters.server_id} onChange={set("server_id")}>
              <option value="">All servers</option>
              {(data ? data.servers : []).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
          </div>
          <div>
            <label htmlFor="f-sev">Severity</label>
            <select id="f-sev" className="input" value={filters.severity} onChange={set("severity")}>
              <option value="">All</option>
              {SEVERITIES.map((s) => <option key={s.key} value={s.key}>{s.label}</option>)}
            </select>
          </div>
          <div>
            <label htmlFor="f-type">Event type</label>
            <select id="f-type" className="input" value={filters.event_type} onChange={set("event_type")}>
              <option value="">All</option>
              {Object.entries(EVENT_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </div>
          <button className="btn primary" style={{ width: "100%" }} onClick={() => setFilters(DEFAULT_FILTERS)}>Reset filter</button>
          <div className="meta">{data ? `${data.servers.length} server(s) in scope` : ""}</div>
        </aside>

        <div className={"dash-main" + (loading && data ? " loading" : "")}>
          <div className="kpi-row">
            {KPIS.map((k) => (
              <div key={k.key} className="card kpi">
                <div className="k-label">{k.label}</div>
                <div className="k-value">{data ? fmtNum(cur[k.key]) : "–"}</div>
                <div className="k-delta">{data && <Delta cur={cur[k.key]} prev={prev && prev[k.key]} up={k.up} range={data.range} />}</div>
                {data && <Sparkline values={series.map((p) => p[k.key])} />}
              </div>
            ))}
          </div>

          <div className="viz-grid">
            <ChartCard className="span-4" title="Login outcomes" sub="Share of all SSH events"
              table={{ columns: [{ key: "label", label: "Outcome" }, { key: "value", label: "Events", num: true }],
                rows: [{ label: "Successful", value: cur.success || 0 }, { label: "Failed", value: cur.failed || 0 }, { label: "Other", value: other }] }}>
              <Donut centerLabel="events" data={[
                { key: "success", label: "Successful", value: cur.success || 0, color: "var(--viz-1)" },
                { key: "failed", label: "Failed", value: cur.failed || 0, color: "var(--viz-2)" },
                { key: "other", label: "Other", value: other, color: "var(--viz-3)" },
              ]} />
            </ChartCard>

            <ChartCard className="span-4" title="Events by type"
              table={{ columns: [{ key: "label", label: "Event" }, { key: "value", label: "Count", num: true }],
                rows: (data ? data.byType : []).map((r) => ({ label: EVENT_LABEL[r.key] || r.key, value: r.count })) }}>
              <HBars color="var(--viz-1)" unit="events" data={(data ? data.byType : []).map((r) => ({ key: r.key, label: EVENT_LABEL[r.key] || r.key, value: r.count }))} />
            </ChartCard>

            <ChartCard className="span-4" title="Top attacker IPs" sub="Failed attempts · click to analyze"
              table={{ columns: [{ key: "ip", label: "IP", mono: true }, { key: "failed", label: "Failed", num: true }, { key: "success", label: "Success", num: true }, { key: "hosts", label: "Servers", num: true }],
                rows: data ? data.topIps : [] }}>
              <HBars color="var(--viz-2)" unit="failed" empty="No attacking IPs" onSelect={(d) => setAnalyze(d.key)}
                data={(data ? data.topIps : []).map((r) => ({ key: r.ip, label: r.ip, mono: true, value: r.failed,
                  meta: `${r.hosts} server(s) · ${r.success} successful login(s)` }))} />
            </ChartCard>

            <ChartCard className="span-4" title="Events by severity"
              table={{ columns: [{ key: "label", label: "Severity" }, { key: "value", label: "Events", num: true }],
                rows: SEVERITIES.map((s) => ({ label: s.label, value: sevMap[s.key] || 0 })) }}>
              <Donut centerLabel="events" data={SEVERITIES.map((s) => ({ ...s, value: sevMap[s.key] || 0 }))} />
            </ChartCard>

            <ChartCard className="span-8" title="Activity over time" sub="Failed vs successful logins"
              table={{ columns: [{ key: "time", label: "Period" }, { key: "failed", label: "Failed", num: true }, { key: "success", label: "Successful", num: true }],
                rows: series.map((p) => ({ time: bucketLabel(p.t, data.bucketMs, true), failed: p.failed, success: p.success })) }}>
              {data && <LineChart points={series} bucketMs={data.bucketMs} series={[
                { key: "failed", label: "Failed", color: "var(--viz-2)" },
                { key: "success", label: "Successful", color: "var(--viz-1)" },
              ]} />}
            </ChartCard>

            <ChartCard className="span-4" title="Incidents by attack type"
              table={{ columns: [{ key: "label", label: "Attack type" }, { key: "value", label: "Incidents", num: true }],
                rows: (data ? data.incidents.byAttack : []).map((r) => ({ label: ATTACK_LABEL[r.key] || r.key, value: r.count })) }}>
              <HBars color="var(--viz-1)" unit="incidents" empty="No incidents in this period"
                data={(data ? data.incidents.byAttack : []).map((r) => ({ key: r.key, label: ATTACK_LABEL[r.key] || r.key, value: r.count }))} />
            </ChartCard>

            <ChartCard className="span-4" title="Top targeted accounts" sub="Usernames in failed attempts"
              table={{ columns: [{ key: "user", label: "Username" }, { key: "count", label: "Attempts", num: true }, { key: "invalid", label: "Non-existent", num: true }],
                rows: data ? data.topUsers : [] }}>
              <HBars color="var(--viz-2)" unit="attempts" empty="No failed attempts"
                data={(data ? data.topUsers : []).map((r) => ({ key: r.user, label: r.user, value: r.count,
                  meta: r.invalid ? `${r.invalid} as non-existent user` : "existing account" }))} />
            </ChartCard>

            <ChartCard className="span-4" title="Incident risk" sub={data ? `${data.incidents.open} open incident(s)` : ""}
              table={{ columns: [{ key: "label", label: "Risk" }, { key: "value", label: "Incidents", num: true }],
                rows: RISK_META.map((r) => ({ label: r.key, value: riskMap[r.key] || 0 })) }}>
              <RiskRows data={riskMap} />
            </ChartCard>

            <section className="card viz-card span-12">
              <div className="viz-head"><div><h3>Attack incidents</h3><div className="sub">Highest risk first · open incidents on top</div></div></div>
              {!data || !data.incidents.recent.length ? (
                <div className="viz-empty">No incidents in this period</div>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>Last seen</th><th>Attack pattern</th><th>Server</th><th>Source</th><th>Account</th><th>Risk</th><th>Status</th><th></th></tr></thead>
                    <tbody>
                      {data.incidents.recent.map((i) => (
                        <tr key={i.id}>
                          <td className="mono">{fmtTime(i.last_seen || i.detected_at)}</td>
                          <td style={{ minWidth: 220 }}><b>{ATTACK_LABEL[i.attack_type] || i.attack_type}</b><div style={{ color: "var(--text-muted)", fontSize: 12, maxWidth: 400 }}>{i.description}</div></td>
                          <td className="mono">{i.server_hostname || "-"}</td>
                          <td className="mono">{i.source_ip || "-"}</td>
                          <td>{i.username || "-"}</td>
                          <td>{riskChip(i.risk_level)}</td>
                          <td><Chip kind={i.status === "OPEN" ? "error" : "success"}>{i.status}</Chip></td>
                          <td>{i.source_ip && <button className="btn ghost sm" onClick={() => setAnalyze(i.source_ip)}>Analyze</button>}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          </div>
        </div>
      </div>
      {analyze && <AnalysisModal ip={analyze} onClose={() => setAnalyze(null)} />}
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
  const t = getToken();
  const isAdmin = !!t && (decodeToken(t) || {}).role === "admin";

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
                <tr><th>Name</th>{isAdmin && <th>Owner</th>}<th>Hostname</th><th>IP</th><th>Status</th><th>API Key</th><th>Logs</th><th>Incidents</th><th>Actions</th></tr>
              </thead>
              <tbody>
                {servers.map((s) => (
                  <tr key={s.id}>
                    <td>{s.name}</td>
                    {isAdmin && <td>{s.owner || "-"}</td>}
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
  const [analyze, setAnalyze] = useState(null);

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
                <tr><th>Detected</th><th>Attack pattern</th><th>Server</th><th>Source</th><th>Account</th><th>Risk</th><th>Attempts</th><th>Status</th><th>Actions</th></tr>
              </thead>
              <tbody>
                {incidents.map((i) => (
                  <tr key={i.id}>
                    <td className="mono">{fmtTime(i.detected_at)}</td>
                    <td style={{ minWidth: 280 }}><b>{ATTACK_LABEL[i.attack_type] || i.attack_type || "-"}</b><div style={{ color: "var(--text-muted)", fontSize: 12, maxWidth: 420 }}>{i.description}</div></td>
                    <td className="mono">{i.server_hostname || "-"}</td>
                    <td className="mono">{i.source_ip || "-"}</td>
                    <td>{i.username || "-"}</td>
                    <td>{riskChip(i.risk_level)}</td>
                    <td className="mono">{i.failed_attempts}</td>
                    <td><Chip kind={i.status === "OPEN" ? "error" : "success"}>{i.status}</Chip></td>
                    <td style={{ whiteSpace: "nowrap" }}>
                      {i.source_ip && <button className="btn ghost sm" onClick={() => setAnalyze(i.source_ip)}>Analyze</button>}
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
      {analyze && <AnalysisModal ip={analyze} onClose={() => setAnalyze(null)} />}
    </div>
  );
}

/* ---------- Users ---------- */
function Users() {
  const [users, setUsers] = useState([]);
  useEffect(() => {
    api("/api/users").then(setUsers).catch(() => {});
  }, []);
  return (
    <div>
      <div className="page-title">
        <h1>Users</h1>
        <div className="sub">All accounts</div>
      </div>
      <div className="card">
        <table>
          <thead><tr><th>Username</th><th>Role</th><th>Servers</th></tr></thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>{u.username}</td>
                <td><Chip kind={u.role === "admin" ? "info" : "muted"}>{u.role}</Chip></td>
                <td className="mono">{u.server_count}</td>
              </tr>
            ))}
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
  const [role, setRole] = useState(() => {
    const t = getToken();
    const payload = t && decodeToken(t);
    return payload ? payload.role : null;
  });
  const [page, setPage] = useState("dashboard");
  const isAdmin = role === "admin";
  const pages = PAGES.filter((p) => p.key !== "users" || isAdmin);

  function handleLogin(user) {
    // Only this fixed path is honored, so ?next= can't be abused as an open redirect.
    if (new URLSearchParams(location.search).get("next") === "/get-key") {
      location.href = "/get-key";
      return;
    }
    setRole(user.role);
    setAuthed(true);
  }
  function handleLogout() { setToken(null); setAuthed(false); setRole(null); setPage("dashboard"); }

  if (!authed) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <a className="brand" href="/" style={{ textDecoration: "none" }}>SSH Monitor</a>
        <div className="role-badge">
          <span className="dot" />
          <span><strong>{isAdmin ? "Admin" : "User"}</strong> · {isAdmin ? "all users" : "my monitor"}</span>
        </div>
        <div className="nav-label">Menu</div>
        {pages.map((p) => (
          <div key={p.key} className={"nav-item" + (page === p.key ? " active" : "")} onClick={() => setPage(p.key)}>
            <span>{p.icon}</span> {p.label}
          </div>
        ))}
        <div className="nav-item" onClick={() => { window.location.href = "/get-key"; }}><span>⚿</span> Get Key</div>
        <div className="spacer" style={{ flex: 1 }} />
        <div className="sidebar-foot">
          <ThemeToggle />
          <div className="nav-item" onClick={handleLogout}><span>⏻</span> Logout</div>
        </div>
      </aside>
      <main className="main">
        {page === "dashboard" && <Dashboard />}
        {page === "servers" && <Servers />}
        {page === "logs" && <Logs />}
        {page === "incidents" && <Incidents />}
        {page === "users" && isAdmin && <Users />}
      </main>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
