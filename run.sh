#!/bin/bash

# Set environment variables
export GEMINI_API_KEY=GOOGLE_API_KEY
export GEMINI_MODEL=gemini-2.0-flash
export SUDO_PASSWORD=SUDO_PASSWORD

# Activate virtual environment if it exists
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

# Run the Flask app
python app.py
