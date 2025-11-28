#!/bin/bash

# Check if Python 3 is installed
if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3 is not installed. Please install Python 3 and rerun this script."
    echo "On Debian/Ubuntu: sudo apt update && sudo apt install -y python3 python3-venv python3-pip"
    exit 1
fi

# Load environment variables from .env file if it exists
if [ -f ".env" ]; then
    echo "Loading environment variables from .env file..."
    export $(grep -v '^#' .env | xargs)
else
    echo "Warning: .env file not found. Please create one from env.template"
    echo "Copy env.template to .env and fill in your API key:"
    echo "  cp env.template .env"
    echo ""
fi

# Check if GEMINI_API_KEY is set
if [ -z "$GEMINI_API_KEY" ]; then
    echo "Error: GEMINI_API_KEY is not set."
    echo "Please create a .env file with your API key or export it:"
    echo "  export GEMINI_API_KEY='your-api-key-here'"
    exit 1
fi

# Set defaults for optional variables
export GEMINI_MODEL="${GEMINI_MODEL:-gemini-2.0-flash}"
export SUDO_PASSWORD="${SUDO_PASSWORD:-}"
export FLASK_ENV="${FLASK_ENV:-production}"

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv || { echo "Failed to create virtual environment"; exit 1; }
fi

# Activate virtual environment
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

# Install/update dependencies
if [ -f "requirements.txt" ]; then
    echo "Installing dependencies..."
    python -m pip install --upgrade pip -q
    pip install -r requirements.txt -q || { echo "Failed to install dependencies"; exit 1; }
fi

# Determine mode (production or development)
MODE="${1:-production}"

if [ "$MODE" = "dev" ] || [ "$MODE" = "development" ]; then
    echo "Starting Elliot in DEVELOPMENT mode..."
    export FLASK_ENV=development
    python3 app.py
elif [ "$MODE" = "production" ] || [ "$MODE" = "prod" ]; then
    echo "Starting Elliot in PRODUCTION mode..."
    export FLASK_ENV=production
    # Use gunicorn with eventlet worker for WebSocket support
    # -w 1: Single worker (required for pty/terminal management)
    # -k eventlet: Async worker class for WebSocket support
    # --bind 0.0.0.0:5000: Listen on all interfaces, port 5000
    # --timeout 120: Increase timeout for long-running terminal commands
    gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:5000 --timeout 120 app:app
else
    echo "Usage: ./run.sh [production|dev]"
    echo "  production (default): Run with gunicorn for production deployment"
    echo "  dev: Run with Flask development server"
    exit 1
fi
