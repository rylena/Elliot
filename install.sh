#!/bin/bash

set -e

echo "=========================================="
echo "  Elliot Installation Script"
echo "  AI-Powered Linux Command Companion"
echo "=========================================="
echo ""

if [ "$EUID" -eq 0 ]; then 
    echo "Error: Please do not run this script as root or with sudo."
    echo "The script will ask for sudo password when needed."
    exit 1
fi

INSTALL_DIR="$HOME/.elliot"
REPO_URL="https://github.com/rylena/Elliot.git"

echo "Installation directory: $INSTALL_DIR"
echo ""

if ! command -v git >/dev/null 2>&1; then
    echo "Git is not installed."
    read -p "Would you like to install Git? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo apt update
        sudo apt install -y git
    else
        echo "Git is required. Exiting."
        exit 1
    fi
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3 is not installed."
    read -p "Would you like to install Python 3? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo apt update
        sudo apt install -y python3 python3-venv python3-pip
    else
        echo "Python 3 is required. Exiting."
        exit 1
    fi
fi

echo "✓ Prerequisites installed"
echo ""

if [ -d "$INSTALL_DIR" ]; then
    echo "Elliot directory already exists."
    read -p "Would you like to update it? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Updating Elliot..."
        cd "$INSTALL_DIR"
        git pull
    else
        echo "Using existing installation."
    fi
else
    echo "Cloning Elliot repository..."
    git clone "$REPO_URL" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"
echo "✓ Repository ready"
echo ""

SETUP_CONFIG=true
if [ -f "$INSTALL_DIR/.env" ]; then
    echo "Configuration file already exists."
    read -p "Do you want to reconfigure the API key? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        SETUP_CONFIG=false
        echo "Using existing configuration."
    fi
fi

if [ "$SETUP_CONFIG" = "true" ]; then
    echo "=========================================="
    echo "  Configuration Required"
    echo "=========================================="
    echo ""
    echo "Please enter your Gemini API key."
    echo "Get one at: https://aistudio.google.com/app/apikey"
    echo ""
    echo "Please enter your Gemini API key."
    echo "Get one at: https://aistudio.google.com/app/apikey"
    echo ""
    read -p "Gemini API Key: " api_key
    
    if [ -z "$api_key" ]; then
        echo "Error: API key cannot be empty."
        exit 1
    fi

    echo ""
    read -p "Enter port to host Elliot on [5000]: " port_choice
    port_choice=${port_choice:-5000}
    
    cat > "$INSTALL_DIR/.env" <<EOF
GEMINI_API_KEY=$api_key
GEMINI_MODEL=gemini-2.0-flash
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
FLASK_ENV=production
SUDO_PASSWORD=
PORT=$port_choice
EOF
    
    echo "✓ Configuration file created"
fi

echo ""

if [ ! -d "$INSTALL_DIR/.venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv "$INSTALL_DIR/.venv"
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

echo ""

echo "Installing dependencies..."
source "$INSTALL_DIR/.venv/bin/activate"
pip install --upgrade pip -q
pip install -r "$INSTALL_DIR/requirements.txt" -q
echo "✓ Dependencies installed"
echo ""

CURRENT_USER=$(whoami)
SERVICE_FILE="/etc/systemd/system/elliot.service"

echo "Creating systemd service..."
sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=Elliot - AI-Powered Linux Command Companion
After=network.target

[Service]
Type=simple
User=$CURRENT_USER
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/.venv/bin:/usr/local/bin:/usr/bin:/bin"
EnvironmentFile=$INSTALL_DIR/.env
ExecStart=/bin/bash -c 'source $INSTALL_DIR/.env && $INSTALL_DIR/.venv/bin/gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:${PORT:-5000} --timeout 120 app:app'
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

echo "✓ Systemd service created"
echo ""

echo "Enabling and starting Elliot service..."
sudo systemctl daemon-reload
sudo systemctl enable elliot.service
sudo systemctl start elliot.service

echo ""
echo "=========================================="
echo "  Installation Complete!"
echo "=========================================="
echo ""
echo "Elliot is now running as a system service."
echo ""
echo "Installation location: $INSTALL_DIR"
echo ""
echo "Service commands:"
echo "  Status:  sudo systemctl status elliot"
echo "  Stop:    sudo systemctl stop elliot"
echo "  Start:   sudo systemctl start elliot"
echo "  Restart: sudo systemctl restart elliot"
echo "  Logs:    sudo journalctl -u elliot -f"
echo ""
echo "Access Elliot at: http://localhost:5000"
echo ""

sleep 2
if sudo systemctl is-active --quiet elliot; then
    echo "✓ Service is running successfully!"
else
    echo "⚠ Warning: Service may not be running. Check status with:"
    echo "  sudo systemctl status elliot"
fi

echo ""
echo "To uninstall Elliot, run:"
echo "  sudo systemctl stop elliot && sudo systemctl disable elliot"
echo "  sudo rm /etc/systemd/system/elliot.service"
echo "  rm -rf $INSTALL_DIR"
echo ""
