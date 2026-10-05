import os
import time
import json
import glob
import socket
import logging
from logging.handlers import RotatingFileHandler
import requests
from datetime import datetime, timedelta
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
import re

# ตัวแปรเก็บเวลาที่อัปเดตค่า .env ล่าสุด
last_env_refresh = 0
ENV_REFRESH_INTERVAL = 3600  # รีเฟรชทุก 1 ชั่วโมง (ลดการเรียกใช้บ่อยครั้ง)

def load_env_file(path=".env"):
    if not os.path.exists(path):
        # ถ้า env ถูกส่งมาแล้ว (เช่น ผ่าน Docker / systemd) ให้ข้ามโหมด interactive
        if os.getenv("MONITOR_API_KEY"):
            return
        # ถ้าไม่มีไฟล์ .env ให้เข้าสู่โหมดตั้งค่า
        print("\n[!] Configuration not found.")
        api_key = input("Enter MONITOR API KEY: ").strip()
        
        with open(path, "w", encoding="utf-8") as f:
            # ใช้ web server เป็นค่า default ไม่ต้องให้ผู้ใช้กรอก URL อีก
            f.write("MONITOR_API_URL=http://localhost:5000/api/logs\n")
            f.write(f"MONITOR_API_KEY={api_key}\n")
            f.write("LOG_PATH=/var/log\n")
            f.write("LOG_DIR=/opt/ssh-monitor/logs\n")
        print(f"[+] Configuration saved to {path}\n")
    
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ[key] = value  # ใช้ setdefaultเป็น set เพื่อให้สามารถอัพเดทได้


def refresh_env():
    global last_env_refresh, MONITOR_API_URL, MONITOR_API_KEY, LOG_PATH, LOG_DIR, LOG_FILE
    current_time = time.time()
    # ตรวจสอบเวลาที่ผ่านมาจากครั้งก่อน refresh ถ้ามากกว่า 60 วินาที ให้ refresh ใหม่
    if current_time - last_env_refresh > ENV_REFRESH_INTERVAL:
        load_env_file()
        # อัพเดทตัวแปร global จากไฟล์ .env ที่โหลดใหม่
        MONITOR_API_URL = os.getenv("MONITOR_API_URL", "http://localhost:5000/api/logs")
        MONITOR_API_KEY = os.getenv("MONITOR_API_KEY", "")
        LOG_PATH = os.getenv("LOG_PATH", "/var/log")
        LOG_DIR = os.getenv("LOG_DIR", "/opt/ssh-monitor/logs")
        LOG_FILE = os.getenv("LOG_FILE", "auth.log")
        last_env_refresh = current_time


load_env_file()
last_env_refresh = time.time()  # เริ่มนับเวลาจากเริ่มรัน

# อ่านค่าเริ่มต้นจาก .env
MONITOR_API_URL = os.getenv("MONITOR_API_URL", "http://localhost:5000/api/logs")
MONITOR_API_KEY = os.getenv("MONITOR_API_KEY", "")
LOG_PATH = os.getenv("LOG_PATH", "/var/log")
LOG_DIR = os.getenv("LOG_DIR", "/opt/ssh-monitor/logs")
LOG_FILE = os.getenv("LOG_FILE", "auth.log")
LOG_MAX_SIZE_MB = int(os.getenv("LOG_MAX_SIZE_MB", "10"))
LOG_BACKUP_KEEP = int(os.getenv("LOG_BACKUP_KEEP", "5"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "10"))
SEND_INTERVAL = int(os.getenv("SEND_INTERVAL", "30"))
SSL_VERIFY = os.getenv("SSL_VERIFY", "true").strip().lower() in ("1", "true", "yes", "on")


def setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)
    os.chmod(LOG_DIR, 0o755)
    logger = logging.getLogger("ssh-monitor-agent")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        file_handler = RotatingFileHandler(
            os.path.join(LOG_DIR, "agent.log"),
            maxBytes=LOG_MAX_SIZE_MB * 1024 * 1024,
            backupCount=LOG_BACKUP_KEEP,
            encoding="utf-8",
        )
        error_handler = RotatingFileHandler(
            os.path.join(LOG_DIR, "agent_error.log"),
            maxBytes=LOG_MAX_SIZE_MB * 1024 * 1024,
            backupCount=LOG_BACKUP_KEEP,
            encoding="utf-8",
        )
        formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        file_handler.setFormatter(formatter)
        error_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)
        error_handler.setLevel(logging.ERROR)
        logger.addHandler(file_handler)
        logger.addHandler(error_handler)
        logger.addHandler(logging.StreamHandler())
    return logger


LOGGER = setup_logging()


class SSHLogMonitor(PatternMatchingEventHandler):
    def __init__(self, watch_dir, api_url=None, api_key=None):
        super().__init__(patterns=[LOG_FILE], ignore_directories=True, case_sensitive=False)
        self.file_positions = {}
        # ใช้ค่าจากตัวแปร Global ที่อัพเดทได้
        self.api_url = api_url or MONITOR_API_URL
        self.api_key = api_key or MONITOR_API_KEY
        self.batch_logs = []
        self.last_send_time = time.time()
        target_file = os.path.join(watch_dir, LOG_FILE)
        if os.path.exists(target_file):
            self.file_positions[target_file] = os.path.getsize(target_file)
            LOGGER.info("Tracking %s from position %s", target_file, self.file_positions[target_file])

    def on_modified(self, event):
        filepath = event.src_path
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                default_pos = os.path.getsize(filepath) if filepath not in self.file_positions else 0
                last_pos = self.file_positions.get(filepath, default_pos)
                f.seek(last_pos)
                new_lines = f.readlines()
                self.file_positions[filepath] = f.tell()
        except Exception as e:
            LOGGER.error("Failed to read log file %s: %s", filepath, e)
            return

        for line in new_lines:
            line = line.strip()
            if not line:
                continue
            log_data = self.parse_log_line(line)
            if log_data:
                self.batch_logs.append(log_data)
                self.print_log_event(log_data)

        if len(self.batch_logs) >= BATCH_SIZE or (time.time() - self.last_send_time) > SEND_INTERVAL:
            self.send_logs_to_server()

    def parse_log_line(self, line):
        log_data = None
        ts = self.line_timestamp(line)
        if "sudo" in line and "COMMAND=" in line:
            match = re.search(r"sudo(?:\[\d+\])?:\s+(\S+)\s*:.*?COMMAND=(.*)$", line)
            if match:
                log_data = {"timestamp": ts, "event_type": "sudo_command", "username": match.group(1), "severity": "info", "message": "sudo " + match.group(2).strip()}
        elif "sshd" in line and "Accepted password" in line:
            match = re.search(r"^(\S+)\s+.*?sshd.*?Accepted password for (\S+) from (\S+) port (\d+)", line)
            if match:
                log_data = {"timestamp": ts, "event_type": "ssh_login_success", "auth_method": "password", "username": match.group(2), "ip_address": match.group(3), "port": match.group(4), "severity": "info"}
        elif "sshd" in line and "Accepted publickey" in line:
            match = re.search(r"^(\S+)\s+.*?Accepted publickey for (\S+) from (\S+) port (\d+)", line)
            if match:
                log_data = {"timestamp": ts, "event_type": "ssh_login_success", "auth_method": "publickey", "username": match.group(2), "ip_address": match.group(3), "port": match.group(4), "severity": "info"}
        elif "sshd" in line and "Failed password" in line:
            match = re.search(r"^(\S+)\s+.*?Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)", line)
            if match:
                log_data = {"timestamp": ts, "event_type": "ssh_login_failed", "auth_method": "password", "username": match.group(2), "ip_address": match.group(3), "port": match.group(4), "severity": "warning"}
        elif "sshd" in line and "Invalid user" in line:
            match = re.search(r"^(\S+)\s+.*?Invalid user (\S+) from (\S+) port (\d+)", line)
            if match:
                log_data = {"timestamp": ts, "event_type": "ssh_invalid_user", "auth_method": "unknown", "username": match.group(2), "ip_address": match.group(3), "port": match.group(4), "severity": "high"}
        elif "sshd" in line and "session closed" in line:
            match = re.search(r"^(\S+)\s+.*?session closed for user (\S+)", line)
            if match:
                log_data = {"timestamp": ts, "event_type": "session_closed", "username": match.group(2), "severity": "info"}
        elif "sshd" in line and "Connection closed by" in line and "preauth" in line:
            match = re.search(r"^(\S+)\s+.*?Connection closed by.*?(\d+\.\d+\.\d+\.\d+) port (\d+)", line)
            if match:
                log_data = {"timestamp": ts, "event_type": "connection_closed_preauth", "ip_address": match.group(2), "port": match.group(3), "severity": "low"}
        return log_data

    ISO_TS = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
    SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})")

    def line_timestamp(self, line):
        """Full ISO-8601 timestamp WITH timezone offset, for both rsyslog formats."""
        now = datetime.now().astimezone()
        m = self.ISO_TS.match(line)
        if m:
            raw = m.group(1).replace("Z", "+00:00")
            # Python < 3.11 only accepts up to 6 fractional digits and needs a colon in the offset
            raw = re.sub(r"(\.\d{6})\d+", r"\1", raw)
            raw = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", raw)
            try:
                dt = datetime.fromisoformat(raw)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=now.tzinfo)
                return dt.isoformat()
            except ValueError:
                pass
        m = self.SYSLOG_TS.match(line)
        if m:
            try:
                dt = datetime.strptime(f"{now.year} {m.group(1)} {m.group(2)} {m.group(3)}", "%Y %b %d %H:%M:%S")
                dt = dt.replace(tzinfo=now.tzinfo)
                if dt > now + timedelta(days=1):  # Dec log line read in January
                    dt = dt.replace(year=now.year - 1)
                return dt.isoformat()
            except ValueError:
                pass
        return now.isoformat()

    def print_log_event(self, log_data):
        event_type = log_data.get("event_type", "unknown")
        timestamp = log_data.get("timestamp", "N/A")
        if event_type == "ssh_login_success":
            LOGGER.info("[SSH LOGIN] %s | User: %s | IP: %s | Auth: %s", timestamp, log_data.get("username"), log_data.get("ip_address"), log_data.get("auth_method"))
        elif event_type == "ssh_login_failed":
            LOGGER.warning("[FAILED LOGIN] %s | User: %s | IP: %s", timestamp, log_data.get("username"), log_data.get("ip_address"))
        elif event_type == "ssh_invalid_user":
            LOGGER.warning("[INVALID USER] %s | User: %s | IP: %s", timestamp, log_data.get("username"), log_data.get("ip_address"))
        else:
            LOGGER.info("[%s] %s | %s", event_type.upper(), timestamp, log_data)

    def _rotate_if_needed(self, filepath):
        if os.path.exists(filepath) and os.path.getsize(filepath) >= LOG_MAX_SIZE_MB * 1024 * 1024:
            stem, ext = os.path.splitext(filepath)
            backup_name = f"{stem}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}{ext}"
            os.rename(filepath, backup_name)
            LOGGER.info("Rotated %s to %s", filepath, backup_name)
            self._cleanup_old_backups(filepath)

    def _cleanup_old_backups(self, filepath):
        stem, ext = os.path.splitext(filepath)
        backups = sorted(glob.glob(f"{stem}_*{ext}"), reverse=True)
        for old in backups[LOG_BACKUP_KEEP:]:
            os.remove(old)
            LOGGER.info("Removed old backup: %s", old)

    def save_all_logs(self):
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
            all_log_file = os.path.join(LOG_DIR, "all_logs.jsonl")
            self._rotate_if_needed(all_log_file)
            with open(all_log_file, "a", encoding="utf-8") as f:
                for log in self.batch_logs:
                    f.write(json.dumps(log, ensure_ascii=False) + "\n")
            LOGGER.info("Saved all logs to %s", all_log_file)
        except Exception as e:
            LOGGER.error("Could not save all logs: %s", e)

    def save_failed_logs(self):
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
            failed_log_file = os.path.join(LOG_DIR, "failed_logs.jsonl")
            self._rotate_if_needed(failed_log_file)
            with open(failed_log_file, "a", encoding="utf-8") as f:
                for log in self.batch_logs:
                    f.write(json.dumps(log, ensure_ascii=False) + "\n")
            LOGGER.error("Saved failed logs to %s", failed_log_file)
            self.batch_logs = []
        except Exception as e:
            LOGGER.error("Could not save failed logs: %s", e)

    def retry_failed_logs(self):
        failed_log_file = os.path.join(LOG_DIR, "failed_logs.jsonl")
        if not os.path.exists(failed_log_file):
            return

        try:
            with open(failed_log_file, "r", encoding="utf-8") as f:
                failed_logs = [json.loads(line) for line in f if line.strip()]

            if not failed_logs:
                return

            payload = {"hostname": socket.gethostname(), "agent_version": "2.0", "timestamp": datetime.now().isoformat(), "logs": failed_logs}
            headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"}
            LOGGER.info("Retrying %d failed logs to %s", len(failed_logs), self.api_url)
            response = requests.post(self.api_url, json=payload, headers=headers, timeout=10, verify=SSL_VERIFY)
            if response.status_code == 200:
                LOGGER.info("Retry successful for %d logs", len(failed_logs))
                os.remove(failed_log_file)
            else:
                LOGGER.error("Retry failed with status %s: %s", response.status_code, response.text)
        except Exception as e:
            LOGGER.error("Failed to retry logs: %s", e)

    def send_logs_to_server(self):
        if not self.batch_logs:
            return
        try:
            payload = {"hostname": socket.gethostname(), "agent_version": "2.0", "timestamp": datetime.now().isoformat(), "logs": self.batch_logs}
            headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"}
            LOGGER.info("Sending %d logs to %s", len(self.batch_logs), self.api_url)
            self.save_all_logs()
            response = requests.post(self.api_url, json=payload, headers=headers, timeout=10, verify=SSL_VERIFY)
            if response.status_code == 200:
                LOGGER.info("Sent %d logs successfully", len(self.batch_logs))
                self.batch_logs = []
            else:
                LOGGER.error("Server returned %s: %s", response.status_code, response.text)
                self.save_failed_logs()
            self.last_send_time = time.time()
        except requests.exceptions.RequestException as e:
            LOGGER.error("Failed to send logs: %s", e)
            self.save_failed_logs()


def validate_api_connection(api_url, api_key):
    try:
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
        test_payload = {"hostname": socket.gethostname(), "agent_version": "2.0", "timestamp": datetime.now().isoformat(), "logs": []}
        response = requests.post(api_url, json=test_payload, headers=headers, timeout=10, verify=SSL_VERIFY)
        if response.status_code != 200:
            LOGGER.error("API Connection Test Failed: %s - %s", response.status_code, response.text)
            return False
        return True
    except Exception as e:
        LOGGER.error("API Connection Test Failed: %s", e)
        return False


def main():
    print("=" * 70)
    print("SSH Log Monitor Agent v2.0")
    print("=" * 70)
    print(f"Watching: {LOG_PATH}")
    print(f"API Endpoint: {MONITOR_API_URL}")
    print(f"Log storage: {LOG_DIR}")
    print("⚠️  ต้องรันพร้อมสิทธิ์ Admin (sudo) เพื่อบันทึก Log ได้")
    print("=" * 70)
    print("💡 เริ่มใช้งาน:")
    print("   1. Config ถูกบันทึกไว้ที่: .env")
    print("   2. แก้ไข config ได้ตลอดด้วยคำสั่ง:")
    print("      sudo nano .env")
    print("      จากนั้นรีสตาร์ท service:")
    print("      sudo systemctl restart ssh-monitor")
    print("   3. ดูสถานะ service:")
    print("      sudo systemctl status ssh-monitor")
    print("   4. ดู Log แบบ real-time:")
    print("      sudo journalctl -u ssh-monitor.service -f")
    print("=" * 70)

    if not validate_api_connection(MONITOR_API_URL, MONITOR_API_KEY):
        LOGGER.warning("⚠️ API Connection Warning: Check that the Monitor Server is running. The agent will continue monitoring and retry sending logs later.")
    else:
        LOGGER.info("✅ API Connection successful")

    event_handler = SSHLogMonitor(LOG_PATH)
    observer = Observer()
    observer.schedule(event_handler, path=LOG_PATH, recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
            # รีเฟรชค่า .env เป็นระยะ (ทุก 60 วินาที)
            refresh_env()
            if event_handler.batch_logs and (time.time() - event_handler.last_send_time) > SEND_INTERVAL:
                event_handler.send_logs_to_server()
            # Retry failed logs every 5 minutes
            if (time.time() - event_handler.last_send_time) > 300:
                event_handler.retry_failed_logs()
                event_handler.last_send_time = time.time()
    except KeyboardInterrupt:
        LOGGER.info("Stopping agent...")
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()