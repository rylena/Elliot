#!/bin/bash

export GEMINI_API_KEY="YOUR_GEMINI_API_KEY_HERE"
export GEMINI_MODEL="gemini-2.0-flash"
export SUDO_PASSWORD=""

if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

python app.py
