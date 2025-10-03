#!/bin/bash

# Ensure Python 3 is installed
if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3 is not installed. Please install Python 3 and rerun this script."
    echo "On Debian/Ubuntu: sudo apt update && sudo apt install -y python3 python3-venv python3-pip"
    exit 1
fi

export GEMINI_API_KEY="AIzaSyCJKWDJeusZ6EcdWy97uTejsoGA0X1QMgQ"
export GEMINI_MODEL="gemini-2.0-flash"
export SUDO_PASSWORD=""

# Create venv if it doesn't exist
if [ ! -d ".venv" ]; then
    python3 -m venv .venv || { echo "Failed to create virtual environment"; exit 1; }
fi

# Activate venv
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

# Install requirements if present
if [ -f "requirements.txt" ]; then
    python -m pip install --upgrade pip
    pip install -r requirements.txt || { echo "Failed to install dependencies"; exit 1; }
fi

python3 app.py
