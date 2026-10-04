#!/bin/bash
# SSH Log Monitor Agent - cross-distro installer
# Usage:
#   curl -sSL https://<monitor-host>/install.sh | sudo bash -s -- <API_URL> <API_KEY>
#   e.g. curl -sSL https://monitor.example.com/install.sh | sudo bash -s -- https://monitor.example.com/api/logs my-secret-key
set -e

INSTALL_DIR="/opt/ssh-monitor"
AGENT_PATH="$INSTALL_DIR/src/agent/agentssh_v2.py"
ENV_FILE="$INSTALL_DIR/.env"
SERVICE_NAME="ssh-monitor"

API_URL="${1:-}"
API_KEY="${2:-}"

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)."
    exit 1
fi

if [ -z "$API_URL" ]; then
    echo "Usage: install.sh <API_URL> [API_KEY]"
    echo "Example: install.sh https://monitor.example.com/api/logs"
    exit 1
fi

# Derive base URL (strip trailing /api/logs) to download the agent from the same server
BASE_URL="${API_URL%/api/logs}"

echo "==> SSH Log Monitor Agent installer"
echo "    API URL : $API_URL"
echo "    Base URL: $BASE_URL"

# Prompt for API key if not provided
if [ -z "$API_KEY" ]; then
    echo ""
    echo "    No API key provided."
    echo "    Get your API key at: $BASE_URL/get-key"
    echo "    (register your server, then copy the key back here)"
    echo ""
    # stdin is the piped script under `curl | bash`, so prompt on the terminal
    read -r -p "    Enter API key: " API_KEY < /dev/tty
    if [ -z "$API_KEY" ]; then
        echo "API key is required."
        exit 1
    fi
fi

# --- Detect distro / package manager ---
detect_pkg() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            debian|ubuntu|linuxmint|raspbian) echo "apt";;
            rhel|centos|fedora|rocky|almalinux|ol) echo "dnf";;
            alpine) echo "apk";;
            opensuse*|sles) echo "zypper";;
            arch|manjaro) echo "pacman";;
            *) echo "unknown";;
        esac
    else
        echo "unknown"
    fi
}

PKG="$(detect_pkg)"
echo "    Detected package manager: $PKG"

install_python_venv() {
    case "$PKG" in
        apt)    apt-get update -qq && apt-get install -y -qq python3 python3-venv python3-pip;;
        dnf)    dnf install -y -q python3 python3-pip;;
        apk)    apk add --no-cache python3 py3-pip;;
        zypper) zypper --non-interactive install python3 python3-pip;;
        pacman) pacman -S --noconfirm python python-pip;;
        *)      echo "Unsupported distro. Install python3 + venv manually, then re-run."; exit 1;;
    esac
}

# --- Install python + venv if missing ---
if ! command -v python3 >/dev/null 2>&1; then
    echo "==> Installing python3..."
    install_python_venv
fi
if ! python3 -m venv --help >/dev/null 2>&1; then
    echo "==> Installing python3-venv..."
    install_python_venv
fi

# --- Prepare install dir ---
mkdir -p "$INSTALL_DIR/logs"
mkdir -p "$INSTALL_DIR/src/agent"

# --- Download agent from monitor server ---
echo "==> Downloading agent from $BASE_URL/agent/agentssh_v2.py"
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$BASE_URL/agent/agentssh_v2.py" -o "$AGENT_PATH"
elif command -v wget >/dev/null 2>&1; then
    wget -q "$BASE_URL/agent/agentssh_v2.py" -O "$AGENT_PATH"
else
    echo "Neither curl nor wget found. Install one and re-run."
    exit 1
fi

# --- Create venv + install deps ---
echo "==> Creating virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --disable-pip-version-check watchdog==3.0.0 requests==2.31.0

# --- Write .env ---
cat > "$ENV_FILE" << EOF
MONITOR_API_URL=$API_URL
MONITOR_API_KEY=$API_KEY
LOG_PATH=/var/log
LOG_DIR=$INSTALL_DIR/logs
LOG_MAX_SIZE_MB=10
LOG_BACKUP_KEEP=5
BATCH_SIZE=10
SEND_INTERVAL=30
SSL_VERIFY=true
EOF
echo "==> Configuration saved to $ENV_FILE"

# --- Install service ---
install_systemd() {
    cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=SSH Log Monitor Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python $AGENT_PATH
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"
}

install_initd() {
    cat > "/etc/init.d/$SERVICE_NAME" << EOF
#!/bin/sh
### BEGIN INIT INFO
# Provides:          $SERVICE_NAME
# Required-Start:    \$network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
### END INIT INFO
case "\$1" in
    start)  nohup $INSTALL_DIR/venv/bin/python $AGENT_PATH >/dev/null 2>&1 & ;;
    stop)   pkill -f "$AGENT_PATH" ;;
    restart) pkill -f "$AGENT_PATH"; nohup $INSTALL_DIR/venv/bin/python $AGENT_PATH >/dev/null 2>&1 & ;;
    status) pgrep -f "$AGENT_PATH" >/dev/null && echo "running" || echo "stopped" ;;
esac
EOF
    chmod +x "/etc/init.d/$SERVICE_NAME"
    "/etc/init.d/$SERVICE_NAME" start
}

if command -v systemctl >/dev/null 2>&1; then
    echo "==> Installing systemd service..."
    install_systemd
else
    echo "==> Installing init.d service..."
    install_initd
fi

echo ""
echo "==> Installation complete!"
echo "    Service : $SERVICE_NAME"
echo "    Config  : $ENV_FILE"
echo "    Logs    : $INSTALL_DIR/logs"
echo ""
echo "    Manage : systemctl {status|restart} $SERVICE_NAME   (or /etc/init.d/$SERVICE_NAME {status|restart})"
