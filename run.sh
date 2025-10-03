#!/bin/bash

<<<<<<< HEAD
# Set environment variables
export GEMINI_API_KEY=GOOGLE_API_KEY
export GEMINI_MODEL=gemini-2.0-flash
export SUDO_PASSWORD=SUDO_PASSWORD

# Activate virtual environment if it exists
=======
export GEMINI_API_KEY="YOUR_GEMINI_API_KEY_HERE"
export GEMINI_MODEL="gemini-2.0-flash"
export SUDO_PASSWORD=""

>>>>>>> a649ff1 (fixing all the bugs)
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

<<<<<<< HEAD
# Run the Flask app
=======
>>>>>>> a649ff1 (fixing all the bugs)
python app.py
