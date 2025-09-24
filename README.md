# Elliot - Terminal Assistant

## Quick Start

1. Create venv and install deps:
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Set environment variables (create `.env` or export):
- GEMINI_API_KEY: your Gemini API key
- GEMINI_MODEL (optional): defaults to `gemini-1.5-flash`

3. Run:
```
GEMINI_API_KEY=YOUR_KEY python Elliot/app.py
```

Or use the helper script:
```
bash run.sh
```

App runs at http://127.0.0.1:5000 
