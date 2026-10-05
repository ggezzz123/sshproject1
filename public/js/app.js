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

// Banner text from an OAuth / email-verification redirect (/app#verified=1), shown once on the next screen.
const FLASH = (() => {
  if (/[#&]verified=1/.test(location.hash)) {
    history.replaceState(null, "", location.pathname + location.search);
    return "ยืนยันอีเมลเรียบร้อยแล้ว ขอบคุณครับ";
  }
  return "";
})();

// Password-reset token from the emailed link (/app#reset=...)
const RESET_TOKEN = (() => {
  const m = /[#&]reset=([^&]+)/.exec(location.hash);
  if (!m) return "";
  history.replaceState(null, "", location.pathname + location.search);
  return decodeURIComponent(m[1]);
})();

function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}
function setToken(t) {
  if (t) localStorage.setItem(TOKEN_KEY, t);
  else localStorage.removeItem(TOKEN_KEY);
}
function decodeToken(t) {
  // base64url + UTF-8, so non-English usernames (e.g. Thai) decode correctly
  try {
    const bin = atob(t.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"));
    return JSON.parse(decodeURIComponent(Array.from(bin, (c) => "%" + c.charCodeAt(0).toString(16).padStart(2, "0")).join("")));
  } catch (e) { return null; }
}

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  const token = getToken();
  if (token) headers["Authorization"] = "Bearer " + token;
  const res = await fetch(path, { ...opts, headers });
  if (res.status === 401) {
    setToken(null);
    throw new Error("กรุณาล็อกอินใหม่");
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
  ssh_login_success: "ล็อกอินสำเร็จ",
  ssh_login_failed: "ล็อกอินไม่สำเร็จ",
  ssh_invalid_user: "ไม่มีชื่อผู้ใช้นี้",
  sudo_command: "ใช้คำสั่ง sudo",
  session_closed: "ปิดเซสชัน",
  connection_closed_preauth: "ตัดการเชื่อมต่อก่อนล็อกอิน",
};

function Chip({ kind, children }) {
  return <span className={"chip " + (kind || "muted")}>{children}</span>;
}

const RISK_TH = { CRITICAL: "วิกฤต", HIGH: "สูง", MEDIUM: "ปานกลาง", LOW: "ต่ำ" };
const STATUS_TH = { OPEN: "เปิดอยู่", RESOLVED: "แก้ไขแล้ว", CLOSED: "ปิดแล้ว" };
const SEVERITY_TH = { info: "ข้อมูล", low: "ต่ำ", warning: "เตือน", high: "สูง", critical: "วิกฤต" };
function riskChip(level) {
  const map = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low" };
  return <Chip kind={map[level] || "muted"}>{RISK_TH[level] || level}</Chip>;
}

function fmtTime(s) {
  if (!s) return "-";
  // SQLite datetime('now') is UTC but has no zone suffix; mark it as UTC.
  const d = new Date(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s) ? s.replace(" ", "T") + "Z" : s);
  if (isNaN(d)) return s;
  return d.toLocaleString("th-TH");
}

function ThemeToggle({ floating }) {
  const [theme, setTheme] = useState(window.currentTheme());
  return (
    <button
      type="button"
      className={"theme-toggle" + (floating ? " floating" : "")}
      onClick={() => setTheme(window.toggleTheme())}
      aria-label="สลับโหมดสว่าง / มืด"
    >
      {theme === "dark" ? "☀ โหมดสว่าง" : "☾ โหมดมืด"}
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
      <label>ยืนยันว่าไม่ใช่บอท: {cfg.challenge.question}</label>
      <input className="input" inputMode="numeric" placeholder="คำตอบ"
        onChange={(e) => onChange({ captcha_token: cfg.challenge.token, captcha_answer: e.target.value })} />
    </div>
  );
}

function Login({ onLogin, resetToken, onResetDone }) {
  const [mode, setMode] = useState(resetToken ? "reset" : "login");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [identifier, setIdentifier] = useState("");
  const [captcha, setCaptcha] = useState({});
  const [cfg, setCfg] = useState({ providers: [] });
  const [info, setInfo] = useState("");
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
    setInfo("");
    if ((mode === "register" || mode === "reset") && password !== confirm) {
      setError("รหัสผ่านทั้งสองช่องไม่ตรงกัน");
      return;
    }
    setLoading(true);
    try {
      if (mode === "forgot") {
        const d = await api("/api/auth/forgot-password", { method: "POST", body: JSON.stringify({ identifier }) });
        setInfo(d.mail_configured
          ? "ถ้ามีบัญชีที่ใช้อีเมลหรือชื่อผู้ใช้นี้ ระบบได้ส่งลิงก์รีเซ็ตไปแล้ว กรุณาตรวจกล่องจดหมาย (และโฟลเดอร์สแปม)"
          : "เซิร์ฟเวอร์นี้ยังไม่ได้ตั้งค่าการส่งอีเมล จึงส่งลิงก์รีเซ็ตไม่ได้ กรุณาติดต่อผู้ดูแลระบบ");
        return;
      }
      if (mode === "reset") {
        const d = await api("/api/auth/reset-password", { method: "POST",
          body: JSON.stringify({ token: resetToken, new_password: password, confirm_password: confirm }) });
        setPassword(""); setConfirm(""); setUsername(d.username || "");
        setMode("login");
        setInfo("เปลี่ยนรหัสผ่านแล้ว กรุณาล็อกอินด้วยรหัสผ่านใหม่");
        onResetDone && onResetDone();
        return;
      }
      const body = mode === "register"
        ? { username, email, password, confirm_password: confirm, ...captcha }
        : { username, password };
      const data = await api("/api/auth/" + mode, { method: "POST", body: JSON.stringify(body) });
      setToken(data.token);
      onLogin(data.user);
    } catch (err) {
      setError(err.message === "กรุณาล็อกอินใหม่" && mode === "login" ? "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" : err.message);
      if (mode === "register") loadConfig(); // challenges are single-use
    } finally {
      setLoading(false);
    }
  }

  function switchMode(m) { setMode(m); setError(""); setInfo(""); loadConfig(); }
  const link = (m, text) => <a href="#" onClick={(e) => { e.preventDefault(); switchMode(m); }}>{text}</a>;
  const oauthLabel = { google: "Google", github: "GitHub" };
  const title = { login: "เข้าสู่ระบบ", register: "สมัครสมาชิก", forgot: "ส่งลิงก์รีเซ็ตรหัสผ่าน", reset: "ตั้งรหัสผ่านใหม่" }[mode];

  return (
    <div className="login-wrap">
      <ThemeToggle floating />
      <form className="login-card" onSubmit={submit}>
        <h1>SSH Monitor</h1>
        <div className="sub">
          {mode === "forgot" ? "ลืมรหัสผ่าน? เราจะส่งลิงก์รีเซ็ตไปทางอีเมล"
            : mode === "reset" ? "ตั้งรหัสผ่านใหม่"
            : new URLSearchParams(location.search).get("next") === "/get-key"
            ? "เข้าสู่ระบบหรือสมัครสมาชิกเพื่อรับ API key"
            : "ระบบเฝ้าระวังความปลอดภัย SSH"}
        </div>
        {info && <div className="ok-banner">{info}</div>}
        {error && <div className="error-banner">{error}</div>}
        {mode === "forgot" && (
          <div className="field">
            <label>อีเมลหรือชื่อผู้ใช้</label>
            <input className="input" value={identifier} onChange={(e) => setIdentifier(e.target.value)} autoFocus required />
          </div>
        )}
        {(mode === "login" || mode === "register") && (
          <div className="field">
            <label>ชื่อผู้ใช้</label>
            <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
          </div>
        )}
        {mode === "register" && (
          <div className="field">
            <label>อีเมล (ไม่บังคับ แต่ต้องมีถ้าจะรีเซ็ตรหัสผ่านเมื่อลืม)</label>
            <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
        )}
        {mode !== "forgot" && (
          <div className="field">
            <label style={{ display: "flex", justifyContent: "space-between" }}>
              <span>{mode === "reset" ? "รหัสผ่านใหม่ (อย่างน้อย 6 ตัวอักษร)" : "รหัสผ่าน"}</span>
              {mode === "login" && <span style={{ fontWeight: 400 }}>{link("forgot", "ลืมรหัสผ่าน?")}</span>}
            </label>
            <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus={mode === "reset"} />
          </div>
        )}
        {(mode === "register" || mode === "reset") && (
          <div className="field">
            <label>ยืนยันรหัสผ่าน</label>
            <input className="input" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
          </div>
        )}
        {mode === "register" && <Captcha key={cfg.challenge ? cfg.challenge.token : "ts"} cfg={cfg} onChange={setCaptcha} />}
        <button className="btn primary" style={{ width: "100%" }} disabled={loading}>
          {loading ? "กรุณารอสักครู่..." : title}
        </button>
        {(mode === "login" || mode === "register") && cfg.providers.length > 0 && (
          <div style={{ marginTop: 16, display: "flex", flexDirection: "column", gap: 8 }}>
            <div style={{ textAlign: "center", fontSize: 12, color: "var(--text-muted)" }}>หรือ</div>
            {cfg.providers.map((p) => (
              <a key={p} className="btn" style={{ width: "100%", textAlign: "center", boxSizing: "border-box" }}
                href={"/api/auth/oauth/" + p}>
                {mode === "login" ? "เข้าสู่ระบบ" : "สมัคร"}ด้วย {oauthLabel[p]}
              </a>
            ))}
          </div>
        )}
        <div style={{ marginTop: 16, textAlign: "center", fontSize: 13, color: "var(--text-muted)" }}>
          {mode === "login" ? <>ยังไม่มีบัญชี? {link("register", "สมัครสมาชิก")}</>
            : mode === "register" ? <>มีบัญชีอยู่แล้ว? {link("login", "เข้าสู่ระบบ")}</>
            : <>{link("login", "กลับไปหน้าเข้าสู่ระบบ")}</>}
        </div>
      </form>
    </div>
  );
}

/* ---------- Analytics helpers ---------- */
// Incident content (attack names, descriptions, analysis) stays in English on purpose
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
  { key: "info", label: "ข้อมูล", color: "var(--viz-ord-1)" },
  { key: "low", label: "ต่ำ", color: "var(--viz-ord-2)" },
  { key: "warning", label: "เตือน", color: "var(--viz-ord-3)" },
  { key: "high", label: "สูง", color: "var(--viz-ord-4)" },
];
const RANGE_LABEL = { "24h": "24 ชั่วโมงล่าสุด", "7d": "7 วันล่าสุด", "30d": "30 วันล่าสุด", all: "ทั้งหมด" };
const PREV_LABEL = { "24h": "24 ชม. ก่อนหน้า", "7d": "7 วันก่อนหน้า", "30d": "30 วันก่อนหน้า" };

const regionNames = (() => {
  try { return new Intl.DisplayNames(["th"], { type: "region" }); } catch (e) { return null; }
})();
function countryName(code) {
  try { return (regionNames && regionNames.of(code)) || code; } catch (e) { return code; }
}

function fmtNum(n) {
  if (n == null) return "-";
  if (Math.abs(n) >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, "") + "M";
  if (Math.abs(n) >= 1e4) return (n / 1e3).toFixed(1).replace(/\.0$/, "") + "K";
  return n.toLocaleString("th-TH");
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
  const hm = d.toLocaleTimeString("th-TH", { hour: "2-digit", minute: "2-digit" });
  const day = d.toLocaleDateString("th-TH", { day: "numeric", month: "short" });
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
          <div className="viz-toggle" role="group" aria-label={"มุมมอง " + title}>
            <button type="button" className={view === "chart" ? "on" : ""} aria-pressed={view === "chart"} onClick={() => setView("chart")}>กราฟ</button>
            <button type="button" className={view === "table" ? "on" : ""} aria-pressed={view === "table"} onClick={() => setView("table")}>ตาราง</button>
          </div>
        )}
      </div>
      {view === "table" && table ? <VizTable {...table} /> : children}
    </section>
  );
}

function VizTable({ columns, rows }) {
  if (!rows.length) return <div className="viz-empty">ไม่มีข้อมูลตามตัวกรองนี้</div>;
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
      <div className="t">{pct(d.value, total)} จาก {fmtNum(total)}</div>
    </>
  );
  if (!total) return <div className="viz-empty">ไม่มีเหตุการณ์ตามตัวกรองนี้</div>;
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

function HBars({ data, color, unit, onSelect, empty, hint }) {
  const [tip, show, hide] = useTip();
  const max = Math.max(1, ...data.map((d) => d.value));
  if (!data.length) return <div className="viz-empty">{empty || "ไม่มีข้อมูล"}</div>;
  return (
    <div className="hbars">
      {data.map((d) => {
        const content = (
          <>
            <div className="r"><span className="sw" style={{ background: color }} />{d.label}<b>{fmtNum(d.value)} {unit}</b></div>
            {d.meta && <div className="t">{d.meta}</div>}
            {onSelect && <div className="t">{hint || "คลิกเพื่อวิเคราะห์"}</div>}
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
        aria-label={`${series.map((s) => s.label).join(" และ ")} ตามเวลา`}
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
  if (!total) return <div className="viz-empty">ไม่มีเหตุการณ์ในช่วงนี้</div>;
  return (
    <div className="risk-rows">
      {RISK_META.map((r) => {
        const v = data[r.key] || 0;
        const content = <div className="r"><span className="sw" style={{ background: r.color }} />{RISK_TH[r.key]}<b>{v} · {pct(v, total)}</b></div>;
        return (
          <div key={r.key} className="risk-row" tabIndex={0} onMouseMove={(e) => show(e, content)} onMouseLeave={hide} onFocus={(e) => show(e, content)} onBlur={hide}>
            <span className="rl"><i style={{ color: r.color }} aria-hidden="true">{r.icon}</i>{RISK_TH[r.key]}</span>
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
      <aside className="modal-panel" onClick={(e) => e.stopPropagation()} role="dialog" aria-label={"ผลวิเคราะห์ " + ip}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <div className="sub" style={{ fontSize: 12, color: "var(--text-muted)", fontWeight: 600 }}>วิเคราะห์ IP ต้นทาง</div>
            <h2 style={{ fontFamily: "var(--font-mono)" }}>{ip}</h2>
          </div>
          <button className="btn ghost" onClick={onClose} aria-label="ปิด">✕</button>
        </div>
        {error && <div className="error-banner">{error}</div>}
        {!data && !error && <div className="empty">กำลังวิเคราะห์…</div>}
        {data && (
          <>
            <div className="verdict" style={{ "--vc": meta ? meta.color : undefined }}>
              <div className="vr"><span style={{ color: meta && meta.color }} aria-hidden="true">{meta && meta.icon}</span>{RISK_TH[data.verdict.risk] || data.verdict.risk} · ผลการประเมิน</div>
              <div className="vt">{data.verdict.text}</div>
            </div>
            <div className="mini-stats">
              <div className="card"><div className="l">เหตุการณ์ (24 ชม.)</div><div className="v">{fmtNum(data.events)}</div></div>
              <div className="card"><div className="l">เซิร์ฟเวอร์</div><div className="v">{data.hosts.length}</div></div>
              <div className="card"><div className="l">บัญชีที่ถูกลอง</div><div className="v">{data.users.length}</div></div>
            </div>
            {data.sequence.length > 0 && (
              <div>
                <h4 style={{ marginBottom: 8 }}>ลำดับการโจมตี</h4>
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
              <div><h4 style={{ marginBottom: 8 }}>เซิร์ฟเวอร์ที่ถูกโจมตี</h4><div className="seq">{data.hosts.map((h) => <span key={h} className="ph mono">{h}</span>)}</div></div>
            )}
            {data.users.length > 0 && (
              <div><h4 style={{ marginBottom: 8 }}>บัญชี</h4><div className="seq">{data.users.map((u) => <span key={u.user} className="ph">{u.user}<small>×{u.count}</small></span>)}</div></div>
            )}
            {data.incidents.length > 0 && (
              <div>
                <h4 style={{ marginBottom: 8 }}>รูปแบบที่ตรวจพบ</h4>
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
                <h4 style={{ marginBottom: 8 }}>ไทม์ไลน์ ({data.timeline.length} รายการล่าสุด)</h4>
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
  { key: "total", label: "เหตุการณ์ทั้งหมด", up: null },
  { key: "failed", label: "ล็อกอินไม่สำเร็จ", up: "bad" },
  { key: "success", label: "ล็อกอินสำเร็จ", up: null },
  { key: "attackers", label: "IP ผู้โจมตี", up: "bad" },
];
const DEFAULT_FILTERS = { range: "24h", server_id: "", severity: "", event_type: "" };

function Delta({ cur, prev, up, range }) {
  if (prev == null) return <span>{RANGE_LABEL[range]}</span>;
  if (!prev) return <span>{cur ? <b>ใหม่</b> : "ไม่เปลี่ยนแปลง"} เทียบกับ {PREV_LABEL[range]}</span>;
  const d = ((cur - prev) / prev) * 100;
  const cls = !up || Math.abs(d) < 0.05 ? "" : (d > 0) === (up === "good") ? "good" : "bad";
  return <span><b className={cls}>{d > 0 ? "▲" : d < 0 ? "▼" : ""} {Math.abs(d).toFixed(1)}%</b> เทียบกับ {PREV_LABEL[range]}</span>;
}

function Dashboard() {
  const [filters, setFilters] = useState(DEFAULT_FILTERS);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [analyze, setAnalyze] = useState(null);
  const [country, setCountry] = useState("");

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
        <h1>แดชบอร์ด</h1>
        <div className="sub">วิเคราะห์ความปลอดภัย SSH · {RANGE_LABEL[filters.range]} · อัปเดตอัตโนมัติทุก 30 วินาที</div>
      </div>
      <div className="dash">
        <aside className="card dash-filters" aria-label="ตัวกรอง">
          <h3><span aria-hidden="true">⚲</span> ตัวกรอง</h3>
          <div>
            <label htmlFor="f-range">ช่วงเวลา</label>
            <select id="f-range" className="input" value={filters.range} onChange={set("range")}>
              {Object.entries(RANGE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </div>
          <div>
            <label htmlFor="f-server">เซิร์ฟเวอร์</label>
            <select id="f-server" className="input" value={filters.server_id} onChange={set("server_id")}>
              <option value="">ทุกเซิร์ฟเวอร์</option>
              {(data ? data.servers : []).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
          </div>
          <div>
            <label htmlFor="f-sev">ความรุนแรง</label>
            <select id="f-sev" className="input" value={filters.severity} onChange={set("severity")}>
              <option value="">ทั้งหมด</option>
              {SEVERITIES.map((s) => <option key={s.key} value={s.key}>{s.label}</option>)}
            </select>
          </div>
          <div>
            <label htmlFor="f-type">ประเภทเหตุการณ์</label>
            <select id="f-type" className="input" value={filters.event_type} onChange={set("event_type")}>
              <option value="">ทั้งหมด</option>
              {Object.entries(EVENT_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </div>
          <button className="btn primary" style={{ width: "100%" }} onClick={() => setFilters(DEFAULT_FILTERS)}>ล้างตัวกรอง</button>
          <div className="meta">{data ? `ครอบคลุม ${data.servers.length} เซิร์ฟเวอร์` : ""}</div>
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
            <ChartCard className="span-4" title="ผลการล็อกอิน" sub="สัดส่วนจากเหตุการณ์ SSH ทั้งหมด"
              table={{ columns: [{ key: "label", label: "ผลลัพธ์" }, { key: "value", label: "เหตุการณ์", num: true }],
                rows: [{ label: "สำเร็จ", value: cur.success || 0 }, { label: "ไม่สำเร็จ", value: cur.failed || 0 }, { label: "อื่น ๆ", value: other }] }}>
              <Donut centerLabel="เหตุการณ์" data={[
                { key: "success", label: "สำเร็จ", value: cur.success || 0, color: "var(--viz-1)" },
                { key: "failed", label: "ไม่สำเร็จ", value: cur.failed || 0, color: "var(--viz-2)" },
                { key: "other", label: "อื่น ๆ", value: other, color: "var(--viz-3)" },
              ]} />
            </ChartCard>

            <ChartCard className="span-4" title="เหตุการณ์ตามประเภท"
              table={{ columns: [{ key: "label", label: "เหตุการณ์" }, { key: "value", label: "จำนวน", num: true }],
                rows: (data ? data.byType : []).map((r) => ({ label: EVENT_LABEL[r.key] || r.key, value: r.count })) }}>
              <HBars color="var(--viz-1)" unit="ครั้ง" data={(data ? data.byType : []).map((r) => ({ key: r.key, label: EVENT_LABEL[r.key] || r.key, value: r.count }))} />
            </ChartCard>

            <ChartCard className="span-4" title="IP ที่โจมตีมากที่สุด" sub="จำนวนครั้งที่ล็อกอินผิด · คลิกเพื่อวิเคราะห์"
              table={{ columns: [{ key: "ip", label: "IP", mono: true }, { key: "failed", label: "ไม่สำเร็จ", num: true }, { key: "success", label: "สำเร็จ", num: true }, { key: "hosts", label: "เซิร์ฟเวอร์", num: true }],
                rows: data ? data.topIps : [] }}>
              <HBars color="var(--viz-2)" unit="ครั้ง" empty="ไม่มี IP ที่โจมตี" onSelect={(d) => setAnalyze(d.key)}
                data={(data ? data.topIps : []).map((r) => ({ key: r.ip, label: r.ip, mono: true, value: r.failed,
                  meta: `${r.hosts} เซิร์ฟเวอร์ · ล็อกอินสำเร็จ ${r.success} ครั้ง` }))} />
            </ChartCard>

            <ChartCard className="span-4" title="เหตุการณ์ตามความรุนแรง"
              table={{ columns: [{ key: "label", label: "ความรุนแรง" }, { key: "value", label: "เหตุการณ์", num: true }],
                rows: SEVERITIES.map((s) => ({ label: s.label, value: sevMap[s.key] || 0 })) }}>
              <Donut centerLabel="เหตุการณ์" data={SEVERITIES.map((s) => ({ ...s, value: sevMap[s.key] || 0 }))} />
            </ChartCard>

            <ChartCard className="span-8" title="กิจกรรมตามช่วงเวลา" sub="ล็อกอินไม่สำเร็จเทียบกับสำเร็จ"
              table={{ columns: [{ key: "time", label: "ช่วงเวลา" }, { key: "failed", label: "ไม่สำเร็จ", num: true }, { key: "success", label: "สำเร็จ", num: true }],
                rows: series.map((p) => ({ time: bucketLabel(p.t, data.bucketMs, true), failed: p.failed, success: p.success })) }}>
              {data && <LineChart points={series} bucketMs={data.bucketMs} series={[
                { key: "failed", label: "ไม่สำเร็จ", color: "var(--viz-2)" },
                { key: "success", label: "สำเร็จ", color: "var(--viz-1)" },
              ]} />}
            </ChartCard>

            <ChartCard className="span-4" title="เหตุการณ์ตามประเภทการโจมตี"
              table={{ columns: [{ key: "label", label: "ประเภทการโจมตี" }, { key: "value", label: "จำนวน", num: true }],
                rows: (data ? data.incidents.byAttack : []).map((r) => ({ label: ATTACK_LABEL[r.key] || r.key, value: r.count })) }}>
              <HBars color="var(--viz-1)" unit="ครั้ง" empty="ไม่มีเหตุการณ์ในช่วงนี้"
                data={(data ? data.incidents.byAttack : []).map((r) => ({ key: r.key, label: ATTACK_LABEL[r.key] || r.key, value: r.count }))} />
            </ChartCard>

            <ChartCard className="span-4" title="บัญชีที่ถูกโจมตีมากที่สุด" sub="ชื่อผู้ใช้ที่ถูกลองล็อกอินผิด"
              table={{ columns: [{ key: "user", label: "ชื่อผู้ใช้" }, { key: "count", label: "จำนวนครั้ง", num: true }, { key: "invalid", label: "ไม่มีในระบบ", num: true }],
                rows: data ? data.topUsers : [] }}>
              <HBars color="var(--viz-2)" unit="ครั้ง" empty="ไม่มีการล็อกอินผิด"
                data={(data ? data.topUsers : []).map((r) => ({ key: r.user, label: r.user, value: r.count,
                  meta: r.invalid ? `${r.invalid} ครั้งเป็นชื่อที่ไม่มีในระบบ` : "บัญชีที่มีอยู่จริง" }))} />
            </ChartCard>

            <ChartCard className="span-4" title="ระดับความเสี่ยง" sub={data ? `เปิดอยู่ ${data.incidents.open} เหตุการณ์` : ""}
              table={{ columns: [{ key: "label", label: "ความเสี่ยง" }, { key: "value", label: "จำนวน", num: true }],
                rows: RISK_META.map((r) => ({ label: RISK_TH[r.key], value: riskMap[r.key] || 0 })) }}>
              <RiskRows data={riskMap} />
            </ChartCard>

            <section className="card viz-card span-12">
              <div className="viz-head">
                <div><h3>การโจมตีแยกตามประเทศ</h3><div className="sub">จำนวนครั้งที่ล็อกอินผิดตามประเทศของ IP ต้นทาง · ลากลูกโลกเพื่อหมุน</div></div>
              </div>
              <div className="globe-row">
                <div className="globe-main"><AttackGlobe rows={data ? data.byCountry : []} selected={country} onSelect={setCountry} /></div>
                <div className="globe-side">
                  <HBars color="var(--text-muted)" unit="ครั้ง" empty="ไม่มีการโจมตีที่ระบุประเทศได้ในช่วงนี้"
                    onSelect={(d) => setCountry(d.key)} hint="คลิกเพื่อดูบนลูกโลก"
                    data={(data ? data.byCountry : []).slice(0, 10).map((r) => ({ key: r.code, label: `${countryName(r.code)} (${r.code})`, value: r.failed,
                      meta: `${r.ips} IP · ${r.hosts} เซิร์ฟเวอร์` }))} />
                </div>
              </div>
            </section>

            <section className="card viz-card span-12">
              <div className="viz-head"><div><h3>เหตุการณ์การโจมตี</h3><div className="sub">เรียงจากความเสี่ยงสูงสุด · เหตุการณ์ที่เปิดอยู่แสดงก่อน</div></div></div>
              {!data || !data.incidents.recent.length ? (
                <div className="viz-empty">ไม่มีเหตุการณ์ในช่วงนี้</div>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>พบล่าสุด</th><th>รูปแบบการโจมตี</th><th>เซิร์ฟเวอร์</th><th>ต้นทาง</th><th>บัญชี</th><th>ความเสี่ยง</th><th>สถานะ</th><th></th></tr></thead>
                    <tbody>
                      {data.incidents.recent.map((i) => (
                        <tr key={i.id}>
                          <td className="mono">{fmtTime(i.last_seen || i.detected_at)}</td>
                          <td style={{ minWidth: 220 }}><b>{ATTACK_LABEL[i.attack_type] || i.attack_type}</b><div style={{ color: "var(--text-muted)", fontSize: 12, maxWidth: 400 }}>{i.description}</div></td>
                          <td className="mono">{i.server_hostname || "-"}</td>
                          <td className="mono">{i.source_ip || "-"}</td>
                          <td>{i.username || "-"}</td>
                          <td>{riskChip(i.risk_level)}</td>
                          <td><Chip kind={i.status === "OPEN" ? "error" : "success"}>{STATUS_TH[i.status] || i.status}</Chip></td>
                          <td>{i.source_ip && <button className="btn ghost sm" onClick={() => setAnalyze(i.source_ip)}>วิเคราะห์</button>}</td>
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

  async function regenerate(s) {
    if (!confirm(`สร้าง API key ใหม่ให้ "${s.name}"? key เดิมจะใช้ไม่ได้ทันที ต้องแก้ key ใน agent ของเครื่องนั้นด้วย`)) return;
    try { await api("/api/servers/" + s.id + "/regenerate-key", { method: "POST" }); load(); } catch (e) { setError(e.message); }
  }

  async function remove(s) {
    if (!confirm(`ลบเซิร์ฟเวอร์ "${s.name}"?\n\nAPI key ของเครื่องนี้จะใช้ไม่ได้ และ log กับเหตุการณ์ทั้งหมดของเครื่องนี้จะถูกลบถาวร`)) return;
    try { await api("/api/servers/" + s.id, { method: "DELETE" }); load(); } catch (e) { setError(e.message); }
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
        <h1>เซิร์ฟเวอร์</h1>
        <div className="sub">ลงทะเบียนเซิร์ฟเวอร์ SSH เพื่อรับ API key</div>
      </div>

      <div className="card" style={{ marginBottom: 24 }}>
        <h4 style={{ marginBottom: 12 }}>เพิ่มเซิร์ฟเวอร์</h4>
        {error && <div className="error-banner">{error}</div>}
        <form onSubmit={createServer} className="toolbar">
          <input className="input" placeholder="ชื่อเซิร์ฟเวอร์" value={name} onChange={(e) => setName(e.target.value)} required />
          <input className="input" placeholder="Hostname (ไม่บังคับ)" value={hostname} onChange={(e) => setHostname(e.target.value)} />
          <input className="input" placeholder="IP (ไม่บังคับ)" value={ip} onChange={(e) => setIp(e.target.value)} />
          <button className="btn primary" disabled={creating}>{creating ? "กำลังสร้าง..." : "เพิ่มเซิร์ฟเวอร์"}</button>
        </form>
      </div>

      <div className="card">
        {loading ? (
          <div className="empty">กำลังโหลด...</div>
        ) : servers.length === 0 ? (
          <div className="empty">ยังไม่มีเซิร์ฟเวอร์</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>ชื่อ</th>{isAdmin && <th>เจ้าของ</th>}<th>Hostname</th><th>IP</th><th>สถานะ</th><th>API Key</th><th>Log</th><th>เหตุการณ์</th><th>จัดการ</th></tr>
              </thead>
              <tbody>
                {servers.map((s) => (
                  <tr key={s.id}>
                    <td>{s.name} {s.is_test ? <Chip kind="info">ทดสอบ</Chip> : null}</td>
                    {isAdmin && <td>{s.owner || "-"}</td>}
                    <td className="mono">{s.hostname || "-"}</td>
                    <td className="mono">{s.ip_address || "-"}</td>
                    <td><Chip kind={s.status === "online" ? "success" : "muted"}>{s.status === "online" ? "ออนไลน์" : "ออฟไลน์"}</Chip></td>
                    <td className="mono" style={{ maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={s.api_key}>{s.api_key || "-"}</td>
                    <td className="mono">{s.log_count}</td>
                    <td className="mono">{s.open_incidents}</td>
                    <td style={{ whiteSpace: "nowrap" }}>
                      <button className="btn ghost sm" onClick={() => copyKey(s.api_key, s.id)}>{copied === s.id ? "คัดลอกแล้ว!" : "คัดลอก key"}</button>
                      <button className="btn ghost sm" onClick={() => regenerate(s)}>สร้าง key ใหม่</button>
                      <button className="btn ghost sm danger" onClick={() => remove(s)}>ลบ</button>
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
        <h1>Log</h1>
        <div className="sub">ทั้งหมด {fmtNum(total)} เหตุการณ์</div>
      </div>
      <div className="toolbar">
        <select className="input" value={eventType} onChange={(e) => setEventType(e.target.value)}>
          <option value="">ทุกเหตุการณ์</option>
          {Object.entries(EVENT_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <input className="input" placeholder="กรองด้วย IP" value={sourceIp} onChange={(e) => setSourceIp(e.target.value)} />
        <button className="btn secondary sm" onClick={load}>รีเฟรช</button>
      </div>
      <div className="card">
        {loading ? (
          <div className="empty">กำลังโหลด...</div>
        ) : logs.length === 0 ? (
          <div className="empty">ไม่มี log</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>เวลา</th><th>เซิร์ฟเวอร์</th><th>เหตุการณ์</th><th>ผู้ใช้</th><th>IP</th><th>ความรุนแรง</th></tr>
              </thead>
              <tbody>
                {logs.map((l) => (
                  <tr key={l.id}>
                    <td className="mono">{fmtTime(l.event_time)}</td>
                    <td className="mono">{l.server_hostname || "-"}</td>
                    <td>{EVENT_LABEL[l.event_type] || l.event_type}</td>
                    <td>{l.username || "-"}</td>
                    <td className="mono">{l.source_ip || "-"}</td>
                    <td><Chip kind={SEVERITY_CHIP[l.severity] || "muted"}>{SEVERITY_TH[l.severity] || l.severity}</Chip></td>
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
        <h1>เหตุการณ์</h1>
        <div className="sub">เหตุการณ์ด้านความปลอดภัยที่ตรวจพบ</div>
      </div>
      <div className="card">
        {loading ? (
          <div className="empty">กำลังโหลด...</div>
        ) : incidents.length === 0 ? (
          <div className="empty">ไม่มีเหตุการณ์</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>ตรวจพบเมื่อ</th><th>รูปแบบการโจมตี</th><th>เซิร์ฟเวอร์</th><th>ต้นทาง</th><th>บัญชี</th><th>ความเสี่ยง</th><th>จำนวนครั้ง</th><th>สถานะ</th><th>จัดการ</th></tr>
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
                    <td><Chip kind={i.status === "OPEN" ? "error" : "success"}>{STATUS_TH[i.status] || i.status}</Chip></td>
                    <td style={{ whiteSpace: "nowrap" }}>
                      {i.source_ip && <button className="btn ghost sm" onClick={() => setAnalyze(i.source_ip)}>วิเคราะห์</button>}
                      {i.status === "OPEN" ? (
                        <button className="btn ghost sm" onClick={() => setStatus(i.id, "RESOLVED")}>แก้ไขแล้ว</button>
                      ) : (
                        <button className="btn ghost sm" onClick={() => setStatus(i.id, "OPEN")}>เปิดใหม่</button>
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
        <h1>ผู้ใช้</h1>
        <div className="sub">บัญชีทั้งหมด</div>
      </div>
      <div className="card">
        <table>
          <thead><tr><th>ชื่อผู้ใช้</th><th>บทบาท</th><th>เซิร์ฟเวอร์</th></tr></thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>{u.username}</td>
                <td><Chip kind={u.role === "admin" ? "info" : "muted"}>{u.role === "admin" ? "ผู้ดูแลระบบ" : "ผู้ใช้"}</Chip></td>
                <td className="mono">{u.server_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------- 3D attack globe (globe.gl, loaded on first use) ---------- */
const GLOBE_SRC = "https://unpkg.com/globe.gl@2.46.2/dist/globe.gl.min.js";
let globeAssets = null;
function loadGlobeAssets() {
  if (!globeAssets) {
    const lib = window.Globe ? Promise.resolve() : new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = GLOBE_SRC;
      s.onload = resolve;
      s.onerror = () => reject(new Error("โหลดไลบรารีลูกโลก 3D ไม่สำเร็จ"));
      document.head.appendChild(s);
    });
    const geo = fetch("/data/countries.geojson").then((r) => {
      if (!r.ok) throw new Error("โหลดแผนที่ประเทศไม่สำเร็จ");
      return r.json();
    });
    globeAssets = Promise.all([lib, geo]).then(([, g]) => g).catch((e) => { globeAssets = null; throw e; });
  }
  return globeAssets;
}

function cssVar(name, fallback) {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
}

// Center of the biggest ring of a country, used to turn the globe towards it
function featureCenter(f) {
  const polys = f.geometry.type === "Polygon" ? [f.geometry.coordinates] : f.geometry.coordinates;
  let best = null;
  for (const p of polys) {
    const ring = p[0];
    let minX = 180, maxX = -180, minY = 90, maxY = -90;
    for (const [x, y] of ring) { minX = Math.min(minX, x); maxX = Math.max(maxX, x); minY = Math.min(minY, y); maxY = Math.max(maxY, y); }
    const area = (maxX - minX) * (maxY - minY);
    if (!best || area > best.area) best = { area, lng: (minX + maxX) / 2, lat: (minY + maxY) / 2 };
  }
  return best || { lat: 0, lng: 0 };
}

function AttackGlobe({ rows, selected, onSelect }) {
  const boxRef = useRef(null);
  const globeRef = useRef(null);
  const geoRef = useRef(null);
  const hoverRef = useRef(null);
  const statsRef = useRef({ byCode: new Map(), max: 1 });
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;
  const [error, setError] = useState("");
  const [ready, setReady] = useState(false);
  const [spin, setSpin] = useState(true);
  const width = useWidth(boxRef);

  // Visual encoding: the world is black & white; countries that attacked turn red (deeper = more attempts)
  const paint = useCallback(() => {
    const g = globeRef.current;
    if (!g) return;
    const { byCode, max } = statsRef.current;
    // Fixed black & white world (same in light and dark theme); red is used for attacking countries only
    const mix = (t) => {
      // #ef4444 (red) -> #7f1d1d (deep red)
      const from = [239, 68, 68], to = [127, 29, 29];
      return `rgb(${from.map((c, i) => Math.round(c + (to[i] - c) * t)).join(",")})`;
    };
    const level = (f) => {
      const r = byCode.get(f.properties.iso);
      return r ? Math.log1p(r.failed) / Math.log1p(max) : -1;
    };
    g.globeMaterial().color.set("#7a7a7a");
    g.atmosphereColor("#ffffff");
    g.polygonCapColor((f) => {
      const l = level(f);
      return l >= 0 ? mix(l) : "#ffffff";
    })
      .polygonSideColor((f) => (level(f) >= 0 ? "#7f1d1d" : "rgba(60, 60, 60, 0.6)"))
      .polygonStrokeColor(() => "#3a3a3a")
      .polygonAltitude((f) => (f === hoverRef.current ? 0.08 : 0.006 + 0.06 * Math.max(0, level(f))))
      .polygonLabel((f) => {
        const r = byCode.get(f.properties.iso);
        const name = f.properties.name;
        return `<div style="background:rgba(15,17,22,.92);color:#fff;padding:8px 10px;border-radius:6px;font:12px Inter,sans-serif;line-height:1.5">
          <b>${countryName(f.properties.iso) || name}</b>${r ? `<br>ล็อกอินผิด ${fmtNum(r.failed)} ครั้ง<br>${r.ips} IP · ${r.hosts} เซิร์ฟเวอร์` : "<br>ไม่มีการโจมตี"}</div>`;
      });
  }, []);

  // Create the globe once
  useEffect(() => {
    let dead = false;
    loadGlobeAssets()
      .then((geo) => {
        if (dead || !boxRef.current) return;
        geoRef.current = geo;
        const g = window.Globe()(boxRef.current)
          .backgroundColor("rgba(0,0,0,0)")
          .showAtmosphere(true)
          .atmosphereAltitude(0.15)
          .polygonsData(geo.features)
          .polygonsTransitionDuration(300)
          .onPolygonHover((f) => {
            hoverRef.current = f;
            boxRef.current && (boxRef.current.style.cursor = f ? "pointer" : "grab");
            paint();
          })
          .onPolygonClick((f) => onSelectRef.current(f.properties.iso));
        const c = g.controls();
        c.autoRotate = true;
        c.autoRotateSpeed = 0.6;
        c.minDistance = 130;
        c.maxDistance = 600;
        g.pointOfView({ lat: 15, lng: 100, altitude: 2.2 });
        globeRef.current = g;
        paint();
        setReady(true);
      })
      .catch((e) => !dead && setError(e.message));
    return () => {
      dead = true;
      const g = globeRef.current;
      if (g) { g.pauseAnimation(); g._destructor && g._destructor(); }
      globeRef.current = null;
    };
  }, [paint]);

  // New data -> repaint
  useEffect(() => {
    statsRef.current = { byCode: new Map(rows.map((r) => [r.code, r])), max: Math.max(1, ...rows.map((r) => r.failed)) };
    paint();
  }, [rows, ready, paint]);

  // Follow the container size
  useEffect(() => {
    const g = globeRef.current;
    if (g && width) g.width(width).height(Math.min(520, Math.max(300, width * 0.6)));
  }, [width, ready]);

  useEffect(() => {
    if (globeRef.current) globeRef.current.controls().autoRotate = spin;
  }, [spin, ready]);

  // Turn towards the selected country
  useEffect(() => {
    const g = globeRef.current;
    if (!g || !selected || !geoRef.current) return;
    const f = geoRef.current.features.find((x) => x.properties.iso === selected);
    if (!f) return;
    setSpin(false);
    g.pointOfView({ ...featureCenter(f), altitude: 1.6 }, 1000);
  }, [selected, ready]);

  return (
    <div style={{ position: "relative" }}>
      {error ? (
        <div className="viz-empty">{error} เบราว์เซอร์อาจไม่รองรับ WebGL</div>
      ) : (
        <>
          <div ref={boxRef} style={{ width: "100%", minHeight: 300, cursor: "grab", touchAction: "none" }} aria-label="ลูกโลก 3D แสดงประเทศที่โจมตี" />
          {!ready && <div className="viz-empty" style={{ position: "absolute", inset: 0 }}>กำลังโหลดลูกโลก...</div>}
          {ready && (
            <div style={{ position: "absolute", top: 8, right: 8, display: "flex", gap: 6 }}>
              <button type="button" className="btn ghost sm" onClick={() => setSpin((s) => !s)}>{spin ? "หยุดหมุน" : "หมุน"}</button>
              <button type="button" className="btn ghost sm" onClick={() => { onSelect(""); setSpin(true); globeRef.current.pointOfView({ lat: 15, lng: 100, altitude: 2.2 }, 800); }}>รีเซ็ต</button>
            </div>
          )}
          {ready && (
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 6 }}>
              ลากเพื่อหมุน · เลื่อนเมาส์เพื่อซูม · ชี้ที่ประเทศเพื่อดูรายละเอียด · คลิกประเทศ (หรือรายการด้านข้าง) เพื่อซูมไปที่ประเทศนั้น
            </div>
          )}
        </>
      )}
    </div>
  );
}

/* ---------- LINE alerts (Profile) ---------- */
function LineCard({ isAdmin }) {
  const [st, setSt] = useState(null);
  const [code, setCode] = useState(null); // { code, until }
  const [msg, setMsg] = useState({ ok: "", err: "" });
  const [busy, setBusy] = useState("");
  const [left, setLeft] = useState(0);

  const load = useCallback(() => api("/api/profile/line").then(setSt).catch((e) => setMsg({ ok: "", err: e.message })), []);
  useEffect(() => { load(); }, [load]);

  // While a code is shown: count down and check every 3s whether the bot received it
  useEffect(() => {
    if (!code) return;
    const tick = setInterval(() => {
      const s = Math.max(0, Math.round((code.until - Date.now()) / 1000));
      setLeft(s);
      if (!s) setCode(null);
    }, 1000);
    const poll = setInterval(() => {
      api("/api/profile/line").then((d) => {
        setSt(d);
        if (d.linked) { setCode(null); setMsg({ ok: "เชื่อม LINE สำเร็จ ต่อไปการแจ้งเตือนของเซิร์ฟเวอร์คุณจะส่งเข้า LINE", err: "" }); }
      }).catch(() => {});
    }, 3000);
    return () => { clearInterval(tick); clearInterval(poll); };
  }, [code]);

  async function run(name, fn) {
    setBusy(name); setMsg({ ok: "", err: "" });
    try { await fn(); } catch (e) { setMsg({ ok: "", err: e.message }); } finally { setBusy(""); }
  }
  const startLink = () => run("link", async () => {
    const d = await api("/api/profile/line/link", { method: "POST" });
    setSt(d); setCode({ code: d.code, until: Date.now() + d.expires_in * 1000 }); setLeft(d.expires_in);
  });
  const test = () => run("test", async () => {
    await api("/api/profile/line/test", { method: "POST" });
    setMsg({ ok: "ส่งข้อความทดสอบแล้ว ลองเปิด LINE ดู", err: "" });
  });
  const unlink = () => {
    if (!confirm("ยกเลิกการเชื่อม LINE? จะไม่ได้รับแจ้งเตือนทาง LINE อีก")) return;
    run("unlink", async () => { await api("/api/profile/line", { method: "DELETE" }); await load(); setMsg({ ok: "ยกเลิกการเชื่อม LINE แล้ว", err: "" }); });
  };

  const bot = st && st.bot;
  return (
    <section className="card">
      <h4 style={{ marginBottom: 8 }}><span className="line-dot" aria-hidden="true">LINE</span> แจ้งเตือนทาง LINE</h4>
      <div style={{ color: "var(--text-muted)", fontSize: 14, marginBottom: 14 }}>
        รับแจ้งเตือนเข้า LINE ทันทีเมื่อเซิร์ฟเวอร์ของคุณถูกโจมตี (ระดับความเสี่ยงสูงขึ้นไป)
      </div>
      {msg.ok && <div className="ok-banner">{msg.ok}</div>}
      {msg.err && <div className="error-banner">{msg.err}</div>}
      {!st ? <div className="empty">กำลังโหลด...</div> : !st.configured ? (
        <div style={{ fontSize: 14, color: "var(--text-muted)" }}>
          ผู้ดูแลระบบยังไม่ได้ตั้งค่าบอท LINE
          {isAdmin && <> — ใส่ <span className="mono">LINE_CHANNEL_ACCESS_TOKEN</span> และ <span className="mono">LINE_CHANNEL_SECRET</span> ใน <span className="mono">.env</span> แล้วรีสตาร์ทเว็บ (ดูขั้นตอนใน README)</>}
        </div>
      ) : st.linked ? (
        <div>
          <div style={{ marginBottom: 14, fontSize: 14 }}><Chip kind="success">เชื่อมแล้ว</Chip> {bot && <span style={{ color: "var(--text-muted)" }}>กับบอท {bot.name}</span>}</div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button className="btn secondary sm" disabled={!!busy} onClick={test}>{busy === "test" ? "กำลังส่ง..." : "ส่งข้อความทดสอบ"}</button>
            <button className="btn ghost sm danger" disabled={!!busy} onClick={unlink}>ยกเลิกการเชื่อม</button>
          </div>
        </div>
      ) : code ? (
        <ol className="line-steps">
          <li>เพิ่มเพื่อนบอท {bot ? <b>{bot.name}</b> : "SSH Monitor"}
            {bot && bot.addUrl && <> — <a href={bot.addUrl} target="_blank" rel="noopener noreferrer">กดเพิ่มเพื่อน</a></>}
            {bot && bot.lineId && <div className="hint">หรือค้นหา LINE ID <span className="mono">{bot.lineId}</span></div>}
          </li>
          <li>ส่งรหัสนี้ในแชทกับบอท
            <div className="line-code mono">{code.code}</div>
            <div className="hint">รหัสหมดอายุใน {Math.floor(left / 60)}:{String(left % 60).padStart(2, "0")} นาที · หน้านี้จะอัปเดตเองเมื่อเชื่อมสำเร็จ</div>
          </li>
        </ol>
      ) : (
        <button className="btn primary" disabled={!!busy} onClick={startLink}>{busy === "link" ? "กำลังสร้างรหัส..." : "เชื่อม LINE"}</button>
      )}
    </section>
  );
}

/* ---------- Profile ---------- */
function Avatar({ name, src, large }) {
  const cls = "avatar" + (large ? " lg" : "");
  return src
    ? <img className={cls} src={src} alt="" />
    : <span className={cls} aria-hidden="true">{(name || "?").charAt(0).toUpperCase()}</span>;
}

// Center-crop to a square and shrink to 256x256 JPEG in the browser, so uploads stay small (~20-40 KB)
function resizeAvatar(file) {
  return new Promise((resolve, reject) => {
    if (!/^image\//.test(file.type)) return reject(new Error("กรุณาเลือกไฟล์รูปภาพ"));
    if (file.size > 15 * 1024 * 1024) return reject(new Error("รูปใหญ่เกินไป (สูงสุด 15 MB)"));
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      const size = 256;
      const side = Math.min(img.naturalWidth, img.naturalHeight);
      const c = document.createElement("canvas");
      c.width = c.height = size;
      const ctx = c.getContext("2d");
      ctx.fillStyle = "#fff";
      ctx.fillRect(0, 0, size, size);
      ctx.drawImage(img, (img.naturalWidth - side) / 2, (img.naturalHeight - side) / 2, side, side, 0, 0, size, size);
      URL.revokeObjectURL(url);
      resolve(c.toDataURL("image/jpeg", 0.85));
    };
    img.onerror = () => { URL.revokeObjectURL(url); reject(new Error("อ่านไฟล์รูปนี้ไม่ได้")); };
    img.src = url;
  });
}

function deviceOf(ua) {
  if (!ua) return "ไม่ทราบอุปกรณ์";
  const browser = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Firefox\//.test(ua) ? "Firefox"
    : /Chrome\//.test(ua) ? "Chrome" : /Version\/.*Safari/.test(ua) ? "Safari" : /curl\//.test(ua) ? "curl" : "Browser";
  const os = /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android" : /iPhone|iPad|iPod/.test(ua) ? "iOS"
    : /Mac OS X|Macintosh/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${browser} บน ${os}` : browser;
}
const METHOD_LABEL = { password: "รหัสผ่าน", register: "สมัครสมาชิก", google: "Google", github: "GitHub" };

function LoginHistory() {
  const [rows, setRows] = useState(null);
  useEffect(() => { api("/api/profile/logins").then(setRows).catch(() => setRows([])); }, []);
  const failed = rows ? rows.filter((r) => !r.success).length : 0;
  return (
    <section className="card" style={{ gridColumn: "1 / -1" }}>
      <h4 style={{ marginBottom: 8 }}>ประวัติการเข้าสู่ระบบ</h4>
      <div style={{ color: "var(--text-muted)", fontSize: 14, marginBottom: 14 }}>
        การเข้าสู่ระบบ {rows ? rows.length : ""} ครั้งล่าสุด ถ้าเห็นรายการที่ไม่ใช่คุณ ให้เปลี่ยนรหัสผ่านและออกจากระบบอุปกรณ์อื่นทันที
        {failed > 0 && <> มี<b style={{ color: "var(--red-text)" }}> การใส่รหัสผิด {failed} ครั้ง</b></>}
      </div>
      {!rows ? <div className="empty">กำลังโหลด...</div> : !rows.length ? <div className="empty">ยังไม่มีประวัติการเข้าสู่ระบบ</div> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>เวลา</th><th>ผลลัพธ์</th><th>วิธี</th><th>IP</th><th>ประเทศ</th><th>อุปกรณ์</th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td className="mono">{fmtTime(r.created_at)}</td>
                  <td><Chip kind={r.success ? "success" : "error"}>{r.success ? "สำเร็จ" : "ไม่สำเร็จ"}</Chip></td>
                  <td>{METHOD_LABEL[r.method] || r.method}</td>
                  <td className="mono">{r.ip_address || "-"}</td>
                  <td>{r.country && r.country !== "??" ? countryName(r.country) : "-"}</td>
                  <td title={r.user_agent || ""}>{deviceOf(r.user_agent)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function Profile({ onToken, onDeleted, flash, onProfile }) {
  const [p, setP] = useState(null);
  const [notice, setNotice] = useState({ ok: flash || "", err: "" });
  const [email, setEmail] = useState("");
  const [emailPw, setEmailPw] = useState("");
  const [pw, setPw] = useState({ cur: "", next: "", confirm: "" });
  const [delPw, setDelPw] = useState("");
  const [busy, setBusy] = useState("");

  const load = useCallback(() => {
    api("/api/profile").then((d) => { setP(d); setEmail(d.email || ""); onProfile && onProfile(d); }).catch((e) => setNotice({ ok: "", err: e.message }));
  }, []);
  useEffect(() => { load(); }, [load]);

  const ok = (m) => setNotice({ ok: m, err: "" });
  const bad = (m) => setNotice({ ok: "", err: m });
  async function run(name, fn) {
    setBusy(name);
    setNotice({ ok: "", err: "" });
    try { await fn(); } catch (e) { bad(e.message); } finally { setBusy(""); }
  }

  const mailNote = (sent) => sent ? "ส่งอีเมลยืนยันแล้ว กรุณากดลิงก์ในอีเมล" :
    "บันทึกอีเมลแล้ว แต่เซิร์ฟเวอร์ยังไม่ได้ตั้งค่าการส่งอีเมล (SMTP) จึงส่งอีเมลยืนยันไม่ได้ กรุณาติดต่อผู้ดูแลระบบ";

  const saveEmail = (e) => { e.preventDefault(); run("email", async () => {
    const d = await api("/api/profile/email", { method: "PATCH", body: JSON.stringify({ email, current_password: emailPw }) });
    setP(d); setEmailPw(""); ok(mailNote(d.verification_sent));
  }); };
  const resend = () => run("resend", async () => {
    const d = await api("/api/profile/email/verify-request", { method: "POST" });
    ok(mailNote(d.verification_sent));
  });
  const fileRef = useRef(null);
  const pickAvatar = (e) => {
    const file = e.target.files && e.target.files[0];
    e.target.value = "";
    if (!file) return;
    run("avatar", async () => {
      const image = await resizeAvatar(file);
      const d = await api("/api/profile/avatar", { method: "PUT", body: JSON.stringify({ image }) });
      setP(d); onProfile && onProfile(d);
      ok("เปลี่ยนรูปโปรไฟล์แล้ว");
    });
  };
  const removeAvatar = () => run("avatar", async () => {
    const d = await api("/api/profile/avatar", { method: "DELETE" });
    setP(d); onProfile && onProfile(d);
    ok("ลบรูปโปรไฟล์แล้ว");
  });
  const savePw = (e) => { e.preventDefault(); run("pw", async () => {
    const d = await api("/api/profile/password", { method: "POST",
      body: JSON.stringify({ current_password: pw.cur, new_password: pw.next, confirm_password: pw.confirm }) });
    setToken(d.token); onToken();
    setPw({ cur: "", next: "", confirm: "" });
    ok("เปลี่ยนรหัสผ่านแล้ว อุปกรณ์อื่นถูกออกจากระบบแล้ว");
  }); };
  const signOutAll = () => run("all", async () => {
    const d = await api("/api/profile/logout-everywhere", { method: "POST" });
    setToken(d.token); onToken();
    ok("ออกจากระบบอุปกรณ์อื่นทั้งหมดแล้ว");
  });
  const del = (e) => { e.preventDefault();
    if (!confirm("ลบบัญชีพร้อมเซิร์ฟเวอร์ log และเหตุการณ์ทั้งหมดของคุณ? การลบนี้ย้อนกลับไม่ได้")) return;
    run("del", async () => {
      await api("/api/profile", { method: "DELETE", body: JSON.stringify(p.has_password ? { password: delPw } : { confirm_username: delPw }) });
      onDeleted();
    });
  };

  if (!p) return <div className="empty">{notice.err || "กำลังโหลด..."}</div>;
  const providerLabel = p.provider === "local" ? "ชื่อผู้ใช้และรหัสผ่าน" : p.provider === "google" ? "Google" : "GitHub";

  return (
    <div>
      <div className="page-title profile-head">
        <button type="button" className="avatar-edit" onClick={() => fileRef.current.click()} disabled={busy === "avatar"}
          title="เปลี่ยนรูปโปรไฟล์" aria-label="เปลี่ยนรูปโปรไฟล์">
          <Avatar name={p.username} src={p.avatar} large />
          <span className="avatar-cam" aria-hidden="true">{busy === "avatar" ? "…" : "✎"}</span>
        </button>
        <input ref={fileRef} type="file" accept="image/png,image/jpeg,image/webp,image/gif" onChange={pickAvatar} hidden />
        <div>
          <h1>{p.username}</h1>
          <div className="sub">{p.email || "ยังไม่มีอีเมล"} · {p.role === "admin" ? "ผู้ดูแลระบบ" : "ผู้ใช้"} · บัญชี อีเมล และความปลอดภัยของคุณ</div>
          <div style={{ marginTop: 8, display: "flex", gap: 6 }}>
            <button type="button" className="btn secondary sm" disabled={busy === "avatar"} onClick={() => fileRef.current.click()}>
              {p.avatar ? "เปลี่ยนรูป" : "อัปโหลดรูป"}
            </button>
            {p.avatar && <button type="button" className="btn ghost sm" disabled={busy === "avatar"} onClick={removeAvatar}>ลบรูป</button>}
          </div>
        </div>
      </div>
      {notice.ok && <div className="ok-banner">{notice.ok}</div>}
      {notice.err && <div className="error-banner">{notice.err}</div>}
      <div className="profile-grid">
        <section className="card">
          <h4 style={{ marginBottom: 14 }}>บัญชี</h4>
          <dl className="kv" style={{ margin: 0 }}>
            <dt>ชื่อผู้ใช้</dt><dd>{p.username}</dd>
            <dt>บทบาท</dt><dd><Chip kind={p.role === "admin" ? "info" : "muted"}>{p.role === "admin" ? "ผู้ดูแลระบบ" : "ผู้ใช้"}</Chip></dd>
            <dt>วิธีเข้าสู่ระบบ</dt><dd>{providerLabel}</dd>
            <dt>สมัครเมื่อ</dt><dd>{p.created_at ? fmtTime(p.created_at) : "-"}</dd>
            <dt>เข้าระบบล่าสุด</dt><dd>{p.last_login_at ? fmtTime(p.last_login_at) : "-"}</dd>
            <dt>เซิร์ฟเวอร์</dt><dd>{p.servers} <a href="/get-key" style={{ marginLeft: 8 }}>จัดการ key</a></dd>
          </dl>
        </section>

        <section className="card">
          <h4 style={{ marginBottom: 14 }}>อีเมล</h4>
          <div style={{ marginBottom: 14, fontSize: 14 }}>
            {p.email ? <>{p.email} <Chip kind={p.email_verified ? "success" : "warning"}>{p.email_verified ? "ยืนยันแล้ว" : "ยังไม่ยืนยัน"}</Chip></> : "ยังไม่ได้ตั้งอีเมล"}
            {p.email && !p.email_verified && (
              <button type="button" className="btn ghost sm" style={{ marginLeft: 8 }} disabled={busy === "resend"} onClick={resend}>ส่งอีเมลยืนยันอีกครั้ง</button>
            )}
          </div>
          <form onSubmit={saveEmail}>
            <div className="field">
              <label>{p.email ? "อีเมลใหม่" : "อีเมล"}</label>
              <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
            </div>
            {p.has_password && (
              <div className="field">
                <label>รหัสผ่านปัจจุบัน</label>
                <input className="input" type="password" value={emailPw} onChange={(e) => setEmailPw(e.target.value)} required />
              </div>
            )}
            <button className="btn primary" disabled={busy === "email"}>{busy === "email" ? "กำลังบันทึก..." : "บันทึกอีเมล"}</button>
          </form>
        </section>

        <LineCard isAdmin={p.role === "admin"} />

        <section className="card">
          <h4 style={{ marginBottom: 14 }}>รหัสผ่าน</h4>
          {p.has_password ? (
            <form onSubmit={savePw}>
              <div className="field"><label>รหัสผ่านปัจจุบัน</label>
                <input className="input" type="password" value={pw.cur} onChange={(e) => setPw({ ...pw, cur: e.target.value })} required /></div>
              <div className="field"><label>รหัสผ่านใหม่ (อย่างน้อย 6 ตัวอักษร)</label>
                <input className="input" type="password" value={pw.next} onChange={(e) => setPw({ ...pw, next: e.target.value })} required /></div>
              <div className="field"><label>ยืนยันรหัสผ่านใหม่</label>
                <input className="input" type="password" value={pw.confirm} onChange={(e) => setPw({ ...pw, confirm: e.target.value })} required /></div>
              <button className="btn primary" disabled={busy === "pw"}>{busy === "pw" ? "กำลังบันทึก..." : "เปลี่ยนรหัสผ่าน"}</button>
            </form>
          ) : (
            <div style={{ color: "var(--text-muted)", fontSize: 14 }}>บัญชีนี้เข้าสู่ระบบด้วย {providerLabel} จึงไม่มีรหัสผ่านให้เปลี่ยน</div>
          )}
        </section>

        <section className="card">
          <h4 style={{ marginBottom: 8 }}>อุปกรณ์ที่ล็อกอินอยู่</h4>
          <div style={{ color: "var(--text-muted)", fontSize: 14, marginBottom: 14 }}>ออกจากระบบทุกเบราว์เซอร์และอุปกรณ์อื่นที่ล็อกอินอยู่ ยกเว้นเครื่องนี้</div>
          <button className="btn secondary" disabled={busy === "all"} onClick={signOutAll}>ออกจากระบบอุปกรณ์อื่น</button>
        </section>

        <LoginHistory />

        {p.role !== "admin" && (
          <section className="card" style={{ boxShadow: "inset 3px 0 0 var(--red)" }}>
            <h4 style={{ marginBottom: 8, color: "var(--red-text)" }}>ลบบัญชี</h4>
            <div style={{ color: "var(--text-muted)", fontSize: 14, marginBottom: 14 }}>ลบบัญชี เซิร์ฟเวอร์ และ log กับเหตุการณ์ทั้งหมดของคุณอย่างถาวร</div>
            <form onSubmit={del}>
              <div className="field">
                <label>{p.has_password ? "ใส่รหัสผ่านเพื่อยืนยัน" : "พิมพ์ชื่อผู้ใช้เพื่อยืนยัน"}</label>
                <input className="input" type={p.has_password ? "password" : "text"} value={delPw} onChange={(e) => setDelPw(e.target.value)} required />
              </div>
              <button className="btn primary" disabled={busy === "del"}>ลบบัญชีของฉัน</button>
            </form>
          </section>
        )}
      </div>
    </div>
  );
}

/* ---------- Attack test (simulator) ---------- */
function AttackTest({ go }) {
  const [info, setInfo] = useState(null);
  const [alerts, setAlerts] = useState(false);
  const [busy, setBusy] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const load = useCallback(() => {
    api("/api/simulate").then(setInfo).catch((e) => setError(e.message));
  }, []);
  useEffect(() => { load(); }, [load]);

  async function simulate(name) {
    setBusy(name); setError(""); setResult(null);
    try {
      const d = await api("/api/simulate", { method: "POST", body: JSON.stringify({ scenario: name, alerts }) });
      setResult({ ...d, name });
      setInfo((i) => ({ ...i, servers: d.servers }));
    } catch (e) { setError(e.message); } finally { setBusy(""); }
  }
  async function clearAll() {
    if (!confirm("ลบเซิร์ฟเวอร์ทดสอบ พร้อม log และเหตุการณ์ที่จำลองไว้ทั้งหมด?")) return;
    setBusy("clear"); setError("");
    try { await api("/api/simulate", { method: "DELETE" }); setResult(null); load(); } catch (e) { setError(e.message); } finally { setBusy(""); }
  }

  const servers = info ? info.servers : [];
  const totals = servers.reduce((t, s) => ({ logs: t.logs + s.logs, incidents: t.incidents + s.incidents }), { logs: 0, incidents: 0 });
  const label = (name) => ((info && info.scenarios.find((s) => s.name === name)) || {}).label || name;

  return (
    <div>
      <div className="page-title">
        <h1>ทดสอบการโจมตี</h1>
        <div className="sub">จำลองการโจมตี SSH เพื่อทดสอบว่าระบบตรวจจับและแจ้งเตือนได้ถูกต้อง</div>
      </div>
      {error && <div className="error-banner">{error}</div>}

      <div className="card sim-intro">
        <div>
          <p>ข้อมูลจำลองจะถูกส่งเข้า <b>เซิร์ฟเวอร์ทดสอบ</b> ของคุณเท่านั้น (<span className="mono">ทดสอบ-1</span>, <span className="mono">ทดสอบ-2</span> ระบบสร้างให้เอง) ไม่ปนกับเซิร์ฟเวอร์จริง
            IP ผู้โจมตีเป็นช่วงที่สงวนไว้สำหรับเอกสาร (RFC 5737) จึงไม่ใช่เครื่องของใครจริง ส่วนประเทศบนลูกโลกเป็นค่าสมมติ</p>
          <label className="sim-check">
            <input type="checkbox" checked={alerts} onChange={(e) => setAlerts(e.target.checked)} />
            ส่งแจ้งเตือนจริงด้วย (LINE / Discord / Slack / Telegram ที่ตั้งไว้) ข้อความจะขึ้นต้นด้วย [TEST]
          </label>
          <div className="sim-stats">
            {servers.length
              ? <>ข้อมูลทดสอบตอนนี้: {fmtNum(totals.logs)} log · {fmtNum(totals.incidents)} เหตุการณ์ ใน {servers.length} เซิร์ฟเวอร์ทดสอบ</>
              : <>ยังไม่มีข้อมูลทดสอบ</>}
          </div>
        </div>
        <div className="sim-actions">
          <button className="btn primary" disabled={!!busy || !info} onClick={() => simulate("all")}>
            {busy === "all" ? "กำลังจำลอง..." : "⚡ จำลองทุกสถานการณ์"}
          </button>
          <button className="btn ghost sm danger" disabled={!!busy || !servers.length} onClick={clearAll}>
            {busy === "clear" ? "กำลังลบ..." : "ลบข้อมูลทดสอบทั้งหมด"}
          </button>
        </div>
      </div>

      {result && (
        <section className="card sim-result">
          <div className="viz-head">
            <div>
              <h3>ผลการจำลอง: {result.name === "all" ? "ทุกสถานการณ์" : label(result.name)}</h3>
              <div className="sub">ส่ง {fmtNum(result.events)} เหตุการณ์ · ตรวจพบ {result.incidents.length} เหตุการณ์ความปลอดภัย</div>
            </div>
            {go && <button className="btn secondary sm" onClick={() => go("dashboard")}>ดูบนแดชบอร์ด →</button>}
          </div>
          {!result.incidents.length ? (
            <div className="viz-empty">ไม่พบการโจมตี {result.name === "baseline" ? "(ถูกต้อง: การใช้งานปกติต้องไม่เกิดเหตุการณ์)" : ""}</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>ความเสี่ยง</th><th>รูปแบบการโจมตี</th><th>เซิร์ฟเวอร์</th><th>ต้นทาง</th></tr></thead>
                <tbody>
                  {result.incidents.map((i) => (
                    <tr key={i.id}>
                      <td>{riskChip(i.risk_level)}</td>
                      <td style={{ minWidth: 260 }}><b>{ATTACK_LABEL[i.attack_type] || i.attack_type}</b><div style={{ color: "var(--text-muted)", fontSize: 12 }}>{i.description}</div></td>
                      <td className="mono">{i.server_name}</td>
                      <td className="mono">{i.source_ip || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      <div className="sim-grid">
        {(info ? info.scenarios : []).map((s, n) => (
          <div key={s.name} className="card sim-card">
            <div className="sim-n">{n + 1}</div>
            <h4>{s.label}</h4>
            <p>{s.desc}</p>
            <div className="sim-expect"><span>ผลที่ควรได้</span>{s.expect}</div>
            <button className="btn secondary sm" disabled={!!busy} onClick={() => simulate(s.name)}>
              {busy === s.name ? "กำลังจำลอง..." : "จำลอง"}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------- App ---------- */
const PAGES = [
  { key: "dashboard", label: "แดชบอร์ด", icon: "▦" },
  { key: "servers", label: "เซิร์ฟเวอร์", icon: "▣" },
  { key: "logs", label: "Log", icon: "≡" },
  { key: "incidents", label: "เหตุการณ์", icon: "⚠" },
  { key: "simulate", label: "ทดสอบการโจมตี", icon: "⚡" },
  { key: "users", label: "ผู้ใช้", icon: "◉" },
];

function App() {
  const [authed, setAuthed] = useState(!!getToken());
  const [role, setRole] = useState(() => {
    const t = getToken();
    const payload = t && decodeToken(t);
    return payload ? payload.role : null;
  });
  const [page, setPage] = useState(FLASH ? "profile" : "dashboard");
  const [resetToken, setResetToken] = useState(RESET_TOKEN);
  const isAdmin = role === "admin";
  const username = ((authed && decodeToken(getToken() || "")) || {}).username || "";
  const [me, setMe] = useState(null);
  useEffect(() => {
    if (authed) api("/api/profile").then(setMe).catch(() => {});
    else setMe(null);
  }, [authed]);
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
  function refreshAuth() {
    const t = getToken();
    const payload = t && decodeToken(t);
    setRole(payload ? payload.role : null);
    setAuthed(!!t);
  }
  function handleLogout() { setToken(null); setAuthed(false); setRole(null); setPage("dashboard"); }

  if (resetToken || !authed) {
    // A reset link always shows the reset form; afterwards every session is signed out (server-side too)
    return <Login onLogin={handleLogin} resetToken={resetToken}
      onResetDone={() => { setResetToken(""); setToken(null); setAuthed(false); setRole(null); }} />;
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <a className="brand" href="/" style={{ textDecoration: "none" }}>SSH Monitor</a>
        <div className="role-badge">
          <span className="dot" />
          <span><strong>{isAdmin ? "ผู้ดูแลระบบ" : "ผู้ใช้"}</strong> · {isAdmin ? "เห็นทุกบัญชี" : "เฉพาะของฉัน"}</span>
        </div>
        <div className="nav-label">เมนู</div>
        {pages.map((p) => (
          <div key={p.key} className={"nav-item" + (page === p.key ? " active" : "")} onClick={() => setPage(p.key)}>
            <span>{p.icon}</span> {p.label}
          </div>
        ))}
        <div className="nav-item" onClick={() => { window.location.href = "/get-key"; }}><span>⚿</span> รับ API Key</div>
        <div className="spacer" style={{ flex: 1 }} />
        <div className="sidebar-foot">
          <ThemeToggle />
          <div className="nav-item" onClick={handleLogout}><span>⏻</span> ออกจากระบบ</div>
        </div>
      </aside>
      <main className="main">
        <button type="button" className={"user-chip" + (page === "profile" ? " active" : "")} onClick={() => setPage("profile")}
          title="โปรไฟล์ของคุณ" aria-label={`เปิดโปรไฟล์ของ ${username}`}>
          <span className="who"><b>{username}</b><span>{isAdmin ? "ผู้ดูแลระบบ" : "ผู้ใช้"} · โปรไฟล์</span></span>
          <Avatar name={username} src={me && me.avatar} />
        </button>
        {page === "dashboard" && <Dashboard />}
        {page === "servers" && <Servers />}
        {page === "logs" && <Logs />}
        {page === "incidents" && <Incidents />}
        {page === "simulate" && <AttackTest go={setPage} />}
        {page === "users" && isAdmin && <Users />}
        {page === "profile" && <Profile onToken={refreshAuth} onDeleted={handleLogout} flash={FLASH} onProfile={setMe} />}
      </main>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
