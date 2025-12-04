#!/bin/bash

if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3 is not installed. Please install Python 3 and rerun this script."
    echo "On Debian/Ubuntu: sudo apt update && sudo apt install -y python3 python3-venv python3-pip"
    exit 1
fi

if [ -f ".env" ]; then
    echo "Loading environment variables from .env file..."
    export $(grep -v '^#' .env | xargs)
else
    echo "Warning: .env file not found. Please create one from env.template"
    echo "Copy env.template to .env and fill in your API key:"
    echo "  cp env.template .env"
    echo ""
fi

if [ -z "$GEMINI_API_KEY" ]; then
    echo "Warning: GEMINI_API_KEY is not set."
    echo "You can set it in .env or configure providers via the Web UI Settings."
fi

export GEMINI_MODEL="${GEMINI_MODEL:-gemini-2.0-flash}"
export SUDO_PASSWORD="${SUDO_PASSWORD:-}"
export FLASK_ENV="${FLASK_ENV:-production}"

if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv || { echo "Failed to create virtual environment"; exit 1; }
fi

if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

if [ -f "requirements.txt" ]; then
    echo "Installing dependencies..."
    python -m pip install --upgrade pip -q
    pip install -r requirements.txt -q || { echo "Failed to install dependencies"; exit 1; }
fi

MODE="${1:-production}"

if [ "$MODE" = "dev" ] || [ "$MODE" = "development" ]; then
    echo "Starting Elliot in DEVELOPMENT mode..."
    export FLASK_ENV=development
    python3 app.py
elif [ "$MODE" = "production" ] || [ "$MODE" = "prod" ]; then
    echo "Starting Elliot in PRODUCTION mode..."
    export FLASK_ENV=production
    PORT="${PORT:-5000}"
    gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:$PORT --timeout 120 app:app
else
    echo "Usage: ./run.sh [production|dev]"
    echo "  production (default): Run with gunicorn for production deployment"
    echo "  dev: Run with Flask development server"
    exit 1
fi