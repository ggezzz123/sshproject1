# SSH Monitor

เฝ้าดูการ login SSH ของทุกเซิร์ฟเวอร์ในหน้า dashboard เดียว และแจ้งเตือนเมื่อมีคนพยายามโจมตี

มี **agent** ตัวเล็ก ๆ รันอยู่บนเซิร์ฟเวอร์ Linux แต่ละเครื่อง คอยอ่าน `/var/log/auth.log` แล้วส่งเหตุการณ์มาที่ **เว็บแอป** นี้ เว็บแอปจะเก็บข้อมูล รัน **detection engine** (brute force, password spraying, บัญชีที่ถูกยึด ฯลฯ) แสดงผลบน dashboard แบบ real-time และส่งแจ้งเตือนไป LINE / Discord / Slack / Telegram / webhook ได้

```
 เซิร์ฟเวอร์ Linux                       เว็บแอปนี้ (Node.js, Fly.io)                    เครื่องของคุณ (ไม่บังคับ)
┌───────────────┐   HTTPS + API key   ┌─────────────────────────────────┐   Tailscale   ┌────────────────────┐
│ agent (Python) │ ─────────────────▶ │ Express API + React dashboard    │ ────────────▶ │ Oracle DB           │
│ อ่าน auth.log  │                    │ detection engine + การแจ้งเตือน  │  สำเนาข้อมูล   │ (ดูด้วย SQL Developer)│
└───────────────┘                     │ SQLite (ฐานข้อมูลหลัก)           │  การสมัคร      └────────────────────┘
                                      └─────────────────────────────────┘
```

## ฟีเจอร์

- **Dashboard แบบ real-time**: การ login สำเร็จ/ล้มเหลวของแต่ละเซิร์ฟเวอร์ IP และ user พร้อมกราฟและระดับความเสี่ยง
- **ตรวจจับการโจมตี**: brute force, credential stuffing, password spraying, username enumeration, SSH scanning, burst ผิดปกติ, login จากแหล่งใหม่, บัญชีที่ถูกยึด, โจมตีข้ามเครื่อง, กิจกรรมหลังถูกยึด ดู [Detection engine](#detection-engine)
- **ติดตั้ง agent ได้ในคำสั่งเดียว** และมีหน้าขอ API key ด้วยตัวเอง (`/get-key`)
- **หลายผู้ใช้**: แต่ละบัญชีเห็นเฉพาะเซิร์ฟเวอร์ของตัวเอง ส่วน admin เห็นทั้งหมด
- **หน้าโปรไฟล์**: เปลี่ยนอีเมล ยืนยันอีเมล เปลี่ยนรหัสผ่าน ออกจากระบบทุกอุปกรณ์ และลบบัญชี
- **แผนที่ประเทศผู้โจมตี**: ดูว่าประเทศไหนพยายาม login เข้ามามากที่สุด (ลูกโลก 3D หมุนได้บน Dashboard)
- **สมัครสมาชิกพร้อมป้องกันบอท**: ยืนยันรหัสผ่าน, ตรวจว่าไม่ใช่บอท, และสมัครด้วย Google / GitHub
- **แจ้งเตือน** ไป LINE, Discord, Slack, Telegram หรือ webhook ทั่วไป
- **สำเนาไป Oracle (ไม่บังคับ)**: ข้อมูลการสมัครใหม่จะถูกคัดลอกไปเก็บที่ Oracle บนเครื่องของคุณเอง เปิดดูด้วย Oracle SQL Developer ได้

## โครงสร้างโปรเจกต์

| ไฟล์/โฟลเดอร์ | หน้าที่ |
|---|---|
| `server.js` | แอป Express: ต่อ route ต่าง ๆ ให้บริการหน้าเว็บและตัวติดตั้ง agent |
| `db.js` | schema และ migration ของ SQLite (`node:sqlite`) |
| `routes/` | API: `authRoutes` (login / สมัคร / OAuth), `agentRoutes` (รับ log), `serverRoutes`, `logRoutes`, `incidentRoutes`, `dashboardRoutes`, `profileRoutes` |
| `detectionEngine.js`, `analysisEngine.js` | คำนวณระดับความเสี่ยงและตรวจรูปแบบการโจมตี |
| `notifier.js` | ส่งแจ้งเตือน incident |
| `geo.js` | แปลง IP เป็นประเทศ (ฐานข้อมูล offline `geoip-country`) |
| `mailer.js`, `routes/profileRoutes.js` | ส่งอีเมล และ API ของหน้าโปรไฟล์ |
| `oracleSync.js` | คัดลอกข้อมูลการสมัครไป Oracle (ไม่บังคับ) |
| `middleware/auth.js` | ยืนยันตัวตนด้วย JWT (dashboard) และ API key (agent) |
| `public/` | หน้าเว็บ: landing page (`index.html`), dashboard (`app.html` + `js/app.js` ใช้ React ผ่าน CDN ไม่ต้อง build), หน้าขอ key (`get-key.html`) |
| `agent/` | `agentssh_v2.py` (agent) และ `install.sh` (ตัวติดตั้ง) |
| `tools/simulate.js` | สร้างทราฟฟิกโจมตีปลอมไว้ทดสอบ |
| `Dockerfile`, `start.sh`, `fly.toml` | deploy ขึ้น Fly.io (พร้อม Tailscale) |

## เริ่มใช้งาน (รันบนเครื่อง)

ต้องใช้ **Node.js 22.13 ขึ้นไป** (ใช้ `node:sqlite` ที่มาพร้อม Node)

```bash
npm install
cp .env.example .env     # ตั้งค่า JWT_SECRET, ADMIN_PASSWORD ฯลฯ
npm start
```

เปิด http://localhost:5000 แล้วล็อกอินด้วยบัญชี admin ที่ตั้งใน `.env` (ค่าเริ่มต้นคือ `admin` / `admin123` **ต้องเปลี่ยนก่อนเปิดใช้งานจริง**)

รัน `node tools/simulate.js` (จะถามหา URL และ API key) เพื่อส่งการโจมตีปลอมให้ dashboard มีข้อมูลดู ควรใช้ key ของเซิร์ฟเวอร์ทดสอบโดยเฉพาะ และใช้ `--list` เพื่อดูรายการสถานการณ์ที่มี

## เชื่อมเซิร์ฟเวอร์เข้าระบบ

1. เปิดหน้า `/get-key` บนเว็บแอป ล็อกอิน (หรือสมัครสมาชิก) ใส่ชื่อเซิร์ฟเวอร์ แล้วกด **Generate Key**
2. บนเซิร์ฟเวอร์ Linux รันตัวติดตั้ง (จะติดตั้ง Python + venv ดาวน์โหลด agent และตั้งเป็น service ให้):

   ```bash
   curl -sSL https://<โดเมนของคุณ>/install.sh | sudo MONITOR_API_KEY=<API_KEY> bash -s -- https://<โดเมนของคุณ>/api/logs
   ```

   ถ้าไม่ใส่ `MONITOR_API_KEY` ตัวติดตั้งจะถามหา key (พิมพ์แล้วไม่แสดงตัวอักษร) การส่ง key เป็น argument ในบรรทัดคำสั่งยังใช้ได้ แต่ key จะค้างอยู่ใน shell history และ `ps` จึงไม่แนะนำ
3. เซิร์ฟเวอร์จะขึ้นสถานะ **online** หลังมีเหตุการณ์ SSH login ครั้งแรก จัดการ service ด้วย `systemctl status|restart ssh-monitor`

ค่าตั้งของ agent อยู่ที่ `/opt/ssh-monitor/.env` (อ่านได้เฉพาะ root): `MONITOR_API_URL`, `MONITOR_API_KEY`, `BATCH_SIZE`, `SEND_INTERVAL` ฯลฯ

> ข้อควรระวัง: `curl | sudo bash` จะรันสิ่งที่เซิร์ฟเวอร์ส่งมาด้วยสิทธิ์ root ใช้กับเซิร์ฟเวอร์ของคุณเองเท่านั้น และควรดาวน์โหลด `install.sh` มาอ่านก่อนรันก็ได้

## บัญชีและการสมัครสมาชิก

- **Username + รหัสผ่าน**: ฟอร์มสมัครต้องกรอกรหัสผ่านสองครั้ง และผ่านการตรวจว่าไม่ใช่บอท:
  - ค่าเริ่มต้นเป็นโจทย์บวกเลขที่เซิร์ฟเวอร์เซ็นกำกับ ใช้ได้ครั้งเดียว หมดอายุใน 5 นาที (ไม่ต้องตั้งค่าอะไร)
  - หรือใช้ **Cloudflare Turnstile** ถ้าตั้ง `TURNSTILE_SITE_KEY` และ `TURNSTILE_SECRET`
- **Google / GitHub**: ปุ่มจะโผล่เองเมื่อตั้ง client id/secret แล้ว ให้สร้าง OAuth app ที่แต่ละเจ้า โดยใช้ callback URL ดังนี้
  - `<PUBLIC_URL>/api/auth/oauth/google/callback`
  - `<PUBLIC_URL>/api/auth/oauth/github/callback`

  บัญชีที่สมัครผ่าน OAuth จะล็อกอินด้วยรหัสผ่านไม่ได้
- ทุกการสมัครถูกเก็บในตาราง `users` และบันทึกใน `registrations` (วิธีสมัคร, IP, user agent, เวลา)
- Role: `user` เห็นเฉพาะเซิร์ฟเวอร์ log และ incident ของตัวเอง ส่วน `admin` เห็นทั้งหมด (บัญชีที่มาจาก `ADMIN_USERNAME` / `ADMIN_PASSWORD`)

## หน้าโปรไฟล์

เมนู **Profile** ใช้ได้กับทุกบัญชี:

- ดูข้อมูลบัญชี (วิธีล็อกอิน, วันที่สมัคร, ล็อกอินล่าสุด, จำนวนเซิร์ฟเวอร์)
- **เปลี่ยนอีเมล** (ต้องใส่รหัสผ่านปัจจุบัน) อีเมลใหม่จะเป็น "not verified" จนกว่าจะกดลิงก์ในอีเมลยืนยัน ลิงก์อายุ 24 ชั่วโมง ขอส่งใหม่ได้ทุก 1 นาที
- **เปลี่ยนรหัสผ่าน** (ต้องใส่รหัสเดิม และยืนยันรหัสใหม่) อุปกรณ์อื่นจะถูกออกจากระบบอัตโนมัติ
- **Sign out other devices** ออกจากระบบทุกอุปกรณ์ยกเว้นเครื่องนี้
- **ประวัติการล็อกอิน** 100 ครั้งล่าสุด: เวลา ผลลัพธ์ (สำเร็จ/รหัสผิด) วิธีล็อกอิน IP ประเทศ และอุปกรณ์/เบราว์เซอร์ (เก็บในตาราง `logins`)
- **ลบบัญชี** (ลบเซิร์ฟเวอร์ log และ incident ของบัญชีนั้นด้วย; บัญชี admin ลบเองไม่ได้)

**ลืมรหัสผ่าน**: กด "Forgot password?" ที่หน้าล็อกอิน ใส่อีเมลหรือ username ระบบจะส่งลิงก์รีเซ็ต (อายุ 1 ชั่วโมง ใช้ได้ครั้งเดียว) ไปที่อีเมลของบัญชี หลังตั้งรหัสใหม่ทุกอุปกรณ์จะถูกออกจากระบบ ใช้ได้เฉพาะบัญชีที่มีอีเมล

บัญชี Google/GitHub ไม่มีรหัสผ่านให้เปลี่ยน และอีเมลที่ผู้ให้บริการยืนยันแล้วจะถือว่า verified ทันที

การส่งอีเมลต้องตั้ง `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` ถ้าไม่ตั้ง ระบบจะไม่ส่งอีเมลจริง และพิมพ์ลิงก์ยืนยันไว้ใน log ของเซิร์ฟเวอร์แทน (ใช้ทดสอบได้)

## ประเทศของผู้โจมตี

ทุก log ที่เข้ามาจะถูกแปลง IP ต้นทางเป็นประเทศ (offline ด้วย `geoip-country` ไม่ต้องเรียกบริการภายนอก) แล้วเก็บในคอลัมน์ `ssh_logs.country` ส่วน log เก่าจะถูกเติมให้ตอนเริ่มเซิร์ฟเวอร์ครั้งแรก ดูได้ที่การ์ด "Attacks by country" บน Dashboard: ลูกโลก 3D (`globe.gl`) ที่ลากหมุน/ซูมได้ ประเทศยิ่งโจมตีมากยิ่งสีเข้มและนูนสูง ชี้เมาส์เพื่อดูรายละเอียด และรายการ 10 อันดับที่คลิกแล้วลูกโลกจะหมุนไปหาประเทศนั้น IP ภายในองค์กร (เช่น `10.x`, `192.168.x`) และ IP ที่ไม่รู้ประเทศจะไม่ถูกนับ ฐานข้อมูลประเทศอัปเดตตามเวอร์ชันของแพ็กเกจ `geoip-country` จึงอาจคลาดเคลื่อนเล็กน้อย

## การตั้งค่า

ตั้งค่าทั้งหมดผ่าน environment variable (ดูตัวอย่างใน `.env.example`)

| ตัวแปร | ใช้ทำอะไร |
|---|---|
| `PORT`, `HOST` | ที่อยู่ที่เปิดรับ (ค่าเริ่มต้น `5000`, `0.0.0.0`) |
| `JWT_SECRET` | ความลับสำหรับ token ล็อกอินและโจทย์ป้องกันบอท **ต้องตั้งเป็นค่าสุ่มยาว ๆ** |
| `ADMIN_USERNAME`, `ADMIN_PASSWORD` | บัญชี admin ที่สร้างตอนรันครั้งแรก |
| `VALID_API_KEYS` | API key แบบคงที่ของ agent เพิ่มเติม (ไม่บังคับ คั่นด้วยคอมมา) ปกติใช้ key ของแต่ละเซิร์ฟเวอร์จาก `/get-key` |
| `DB_PATH` | ไฟล์ SQLite (ค่าเริ่มต้น `./data/ssh-monitor.db`) |
| `TRUST_PROXY` | ตั้งเป็น `1` เมื่ออยู่หลัง reverse proxy ตัวเดียว เพื่อให้ได้ IP จริงของผู้ใช้ |
| `PUBLIC_URL` | URL สาธารณะของเว็บ ใช้ทำ callback ของ OAuth |
| `TURNSTILE_SITE_KEY`, `TURNSTILE_SECRET` | ใช้ Cloudflare Turnstile แทนโจทย์ในตัว |
| `GOOGLE_CLIENT_ID/SECRET`, `GITHUB_CLIENT_ID/SECRET` | เปิดการสมัครด้วย Google / GitHub |
| `ALERT_MIN_RISK` | ความเสี่ยงต่ำสุดที่จะส่งแจ้งเตือน (`LOW`..`CRITICAL` ค่าเริ่มต้น `HIGH`) |
| `LINE_*`, `DISCORD_WEBHOOK_URL`, `SLACK_WEBHOOK_URL`, `TELEGRAM_*`, `WEBHOOK_URL` | ช่องทางแจ้งเตือน (ตั้งช่องไหนก็ใช้ช่องนั้น) |
| `LOG_TZ_OFFSET`, `ALERT_TZ` | เขตเวลาของ log และกฎ login นอกเวลาทำการ |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` | ส่งอีเมลยืนยัน (ไม่ตั้งก็ได้) |
| `ORACLE_USER`, `ORACLE_PASSWORD`, `ORACLE_CONNECT_STRING` | เปิดการคัดลอกข้อมูลไป Oracle |
| `TS_AUTHKEY` | auth key ของ Tailscale (ตอน deploy บน Fly.io) |

## รันบนเครื่อง Windows ของตัวเอง + Tailscale Funnel (ฟรี)

ตอนนี้ระบบรันบนเครื่อง Windows และเปิดให้อินเทอร์เน็ตเข้าผ่าน **Tailscale Funnel** ที่ `https://ssh-monitor.tail634b6e.ts.net`

1. ตั้ง `.env`: `HOST=127.0.0.1` (รับเฉพาะในเครื่อง), `TRUST_PROXY=1`, `PUBLIC_URL=https://<ชื่อเครื่อง>.<tailnet>.ts.net` และ `JWT_SECRET` ที่สุ่มยาว ๆ
2. ให้เว็บเริ่มเองทุกครั้งที่ล็อกอิน Windows และรีสตาร์ทเองถ้าแครช:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\windows\install-autostart.ps1
   ```
   log อยู่ที่ `data\server.log` (รอบก่อนหน้า `data\server.prev.log`, ประวัติรีสตาร์ท `data\restarts.log`)
3. เปิด Funnel ครั้งเดียว (ค่าจะคงอยู่แม้รีบูต): `tailscale funnel --bg 5000` ปิดด้วย `tailscale funnel --https=443 off`
4. ปิด sleep ของเครื่อง: `powercfg /change standby-timeout-ac 0`
5. สำรองฐานข้อมูลอัตโนมัติทุกวันตี 3 (เก็บ 14 ชุดล่าสุด):
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\windows\install-backup.ps1
   ```
   ไฟล์สำรองไปอยู่ที่ OneDrive (`OneDrive\SSH-Monitor-backups`) ถ้ามี จึงออกนอกเครื่องด้วย ไม่งั้นอยู่ที่ `data\backups` เปลี่ยนที่เก็บได้ด้วย `BACKUP_DIR` และจำนวนด้วย `BACKUP_KEEP` ใน `.env` สำรองเองได้ทันทีด้วย `node scripts/backup.js`
   กู้คืน: หยุดเว็บ แล้วคัดลอกไฟล์สำรองมาทับ `data\ssh-monitor.db` (ลบ `ssh-monitor.db-wal` และ `-shm` เดิมทิ้งก่อน)

task "SSH Monitor" ตรวจทุก 1 นาทีและเปิดเว็บใหม่เองถ้าหยุดไป (เว็บไม่สนใจ Ctrl+C ที่หลงมา หยุดเว็บตั้งใจด้วย `Stop-Process`) ล็อกอินผิด 10 ครั้งจาก IP เดียวต้องรอ 15 นาที

เว็บใช้ได้เฉพาะตอนเครื่องเปิดอยู่ ถ้าเครื่องปิด agent จะส่ง log ไม่ได้ในช่วงนั้น

## Deploy บน Fly.io

```bash
fly volumes create data --region ams --size 1     # พื้นที่เก็บ SQLite ถาวร ทำครั้งเดียว
fly secrets set JWT_SECRET=... ADMIN_PASSWORD=...
fly deploy
```

`fly.toml` mount volume ไว้ที่ `/data` และตั้ง `DB_PATH=/data/ssh-monitor.db` ถ้าไม่มี volume ฐานข้อมูลจะหายทุกครั้งที่ deploy

## ไม่บังคับ: คัดลอกข้อมูลการสมัครไป Oracle บนเครื่องคุณ

ข้อมูลการสมัครจะถูกบันทึกลง SQLite ก่อนเสมอ ถ้าตั้งค่าไว้ จะถูกคัดลอกไป Oracle ที่รันบนเครื่องคุณด้วย เพื่อเปิดดูใน Oracle SQL Developer ถ้าเครื่องคุณปิดอยู่ เว็บยังทำงานปกติ (ข้ามการคัดลอกและบันทึกไว้ใน log และจะไม่ส่งย้อนหลังให้)

1. **บนเครื่องคุณ**: ติดตั้ง Oracle Database XE และ Tailscale ใน SQL Developer เชื่อมด้วย `system` ที่ service `XEPDB1` แล้วรัน:
   ```sql
   CREATE USER ssh_monitor IDENTIFIED BY "<รหัสผ่าน>" QUOTA UNLIMITED ON USERS;
   GRANT CREATE SESSION, CREATE TABLE TO ssh_monitor;
   ```
2. **Windows Firewall** (PowerShell แบบ Administrator) เปิดพอร์ต 1521 ให้เฉพาะเครือข่าย Tailscale:
   ```powershell
   New-NetFirewallRule -DisplayName "Oracle 1521 Tailscale" -Direction Inbound -Protocol TCP -LocalPort 1521 -RemoteAddress 100.64.0.0/10 -Action Allow
   ```
3. **Tailscale**: สร้าง auth key แบบ *reusable + ephemeral* แล้วตั้งค่า
   ```bash
   fly secrets set TS_AUTHKEY=tskey-auth-...
   fly secrets set ORACLE_USER=ssh_monitor ORACLE_PASSWORD="<รหัสผ่าน>" \
                   ORACLE_CONNECT_STRING=<Tailscale IP ของเครื่องคุณ>:1521/XEPDB1
   ```
   หา IP ของเครื่องคุณด้วย `tailscale ip -4`
4. ดู `fly logs` ควรเห็น `[tailscale] connected` และ `[oracle] connected, tables ready` จากนั้นตาราง `APP_USERS` และ `APP_REGISTRATIONS` จะปรากฏใน connection `ssh_monitor` password hash จะไม่ถูกคัดลอกไปด้วย

## API

Endpoint ของ agent ใช้ `Authorization: Bearer <API key>` ส่วน endpoint ของ dashboard ใช้ JWT ที่ได้จากการล็อกอิน

| Endpoint | การยืนยันตัวตน | หน้าที่ |
|---|---|---|
| `POST /api/logs` | API key | รับ log จาก agent |
| `GET /api/auth/config` | - | ตัวเลือกตอนสมัคร (โจทย์ป้องกันบอท, provider OAuth ที่เปิดอยู่) |
| `POST /api/auth/login`, `POST /api/auth/register` | - | ยืนยันตัวตน (ได้ JWT กลับมา) |
| `GET /api/auth/oauth/:provider` (+ `/callback`) | - | ล็อกอิน Google / GitHub |
| `GET /api/my-servers`, `POST /api/servers`, `POST /api/servers/:id/regenerate-key`, `DELETE /api/servers/:id` | JWT | จัดการเซิร์ฟเวอร์และ key ของตัวเอง |
| `GET /api/servers`, `/api/logs`, `/api/incidents`, `/api/dashboard/analytics` (รวม `byCountry`), `/api/analysis/ip/:ip` | JWT | ข้อมูล เฉพาะเซิร์ฟเวอร์ของตัวเอง (admin เห็นทั้งหมด) |
| `PATCH /api/incidents/:id/status` | JWT | ปิด / เปิด incident ใหม่ |
| `GET /api/users` | JWT (admin) | รายชื่อบัญชี |
| `GET /api/profile`, `PATCH /api/profile/email`, `POST /api/profile/email/verify-request`, `POST /api/profile/password`, `POST /api/profile/logout-everywhere`, `DELETE /api/profile` | JWT | โปรไฟล์ของตัวเอง |
| `GET /api/auth/verify-email?token=` | - | ลิงก์ยืนยันอีเมลจากในอีเมล |
| `POST /api/auth/forgot-password`, `POST /api/auth/reset-password` | - | ลืมรหัสผ่าน / ตั้งรหัสใหม่จากลิงก์ในอีเมล |
| `GET /api/profile/logins` | JWT | ประวัติการล็อกอินของตัวเอง |

## Detection engine

จำนวนครั้งที่ login ผิดจาก IP เดียวกันในช่วง 10 นาที กำหนดระดับความเสี่ยงพื้นฐาน:

| login ผิด (ครั้ง) | ความเสี่ยง |
|---|---|
| < 5 | LOW |
| >= 5 | MEDIUM |
| >= 20 | HIGH |
| >= 50 | CRITICAL |
| เดารหัสหลายครั้งแล้ว login สำเร็จ | CRITICAL |

นอกจากนี้ `analysisEngine.js` ยังสร้าง incident ประเภท `brute_force`, `brute_force_success`, `credential_stuffing`, `password_spraying`, `username_enumeration`, `ssh_scanning`, `abnormal_burst`, `new_source_login`, `compromised_account`, `cross_host` และ `post_compromise` incident ที่ระดับตั้งแต่ `ALERT_MIN_RISK` ขึ้นไปจะถูกส่งไปยังช่องทางแจ้งเตือนที่ตั้งไว้

## เทคโนโลยีที่ใช้

Node.js + Express, SQLite (`node:sqlite`), Oracle แบบไม่บังคับ (`oracledb` โหมด thin), React 18 ผ่าน CDN (ไม่ต้อง build), agent เขียนด้วย Python (`watchdog`, `requests`)
