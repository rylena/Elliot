# Elliot – AI-Powered Linux Command Companion

Elliot is a tool that acts as a bridge between natural language and Linux terminal commands.  
It allows you to type what you want in plain English and automatically translates that into the correct command, making the command line easier and more intuitive to use.

---

## What is Elliot?

Elliot is designed to make working with the Linux terminal simpler. Instead of memorizing complex commands, you can describe what you want to do in normal language, and Elliot will understand your request, generate the right command, and run it directly in your terminal.

---

## Features

- **Natural language to command:** Type what you want to do in English, and Elliot turns it into a valid Linux command.  
- **Direct execution:** Commands are executed automatically in the terminal through the web interface.  
- **AI understanding:** Elliot uses advanced language models to interpret what you mean.  
- **Simple web interface:** Access everything from a clean and minimal web interface in your browser.
- **Production ready:** Deploy with gunicorn for stable, production-grade performance.

---

## Installation and Setup

### Prerequisites

- Python 3.7 or higher (installer can install this for you)
- A Gemini API key (get one at https://aistudio.google.com/app/apikey)

### One-Line Installation (Recommended)

Install and set up Elliot as a system service with a single command:

```bash
curl -fsSL https://raw.githubusercontent.com/rylena/Elliot/main/install.sh | bash
```

The installer will:
- Install Git and Python if needed (will ask for confirmation)
- Clone the repository to `~/.elliot`
- Prompt you for your Gemini API key
- Set up a virtual environment and install dependencies
- Create a systemd service that runs in the background
- Start Elliot automatically (and on every boot)

After installation, Elliot will be accessible at `http://localhost:5000`

**Service Management:**
```bash
sudo systemctl status elliot   # Check status
sudo systemctl stop elliot     # Stop service
sudo systemctl start elliot    # Start service
sudo systemctl restart elliot  # Restart service
sudo journalctl -u elliot -f   # View logs
```

**Uninstall:**
```bash
sudo systemctl stop elliot && sudo systemctl disable elliot
sudo rm /etc/systemd/system/elliot.service
rm -rf ~/.elliot
```

### Manual Installation

For development or custom setup:

```bash
# 1. Clone the repository
git clone https://github.com/rylena/Elliot.git
cd Elliot

# 2. Create environment configuration
cp env.template .env

# 3. Edit .env and add your Gemini API key
nano .env

# 4. Start the application
chmod +x ./run.sh
./run.sh production  # or ./run.sh dev for development mode
```

---

## Configuration

### Environment Variables

Create a `.env` file in the project root with the following variables:

```bash
# Required
GEMINI_API_KEY=your_gemini_api_key_here

# Optional
GEMINI_MODEL=gemini-2.0-flash        # AI model to use
SECRET_KEY=your_secret_key_here       # Flask session secret (auto-generated if not set)
FLASK_ENV=production                  # Environment mode
SUDO_PASSWORD=                        # For automated sudo commands (optional)
```

### Running Modes

**Production Mode (Recommended for deployment):**
```bash
./run.sh production
# or simply
./run.sh
```

**Development Mode (For testing and debugging):**
```bash
./run.sh dev
```

---

## Deployment

### Local Deployment

Follow the Quick Start instructions above. The application runs on `http://localhost:5000` by default.

### Server Deployment

For deploying on a remote server:

1. **Set up the application** following the Quick Start steps
2. **Configure firewall** to allow access to port 5000
3. **Run in production mode**: `./run.sh production`
4. **Optional**: Use a reverse proxy (nginx/Apache) for HTTPS and domain mapping
5. **Optional**: Set up as a systemd service for auto-start on boot

### Production Best Practices

- Generate a strong `SECRET_KEY` for production:
  ```bash
  python -c "import secrets; print(secrets.token_hex(32))"
  ```
- Use a reverse proxy (nginx) for HTTPS
- Set up proper firewall rules
- Monitor logs and resource usage
- Keep dependencies updated

---

## Usage

1. Open your browser and navigate to `http://localhost:5000`
2. Type natural language commands in the chat interface
3. Elliot will translate and execute them in the terminal
4. View real-time terminal output and AI responses

---

## Troubleshooting

**API Key Error:**
- Ensure your `.env` file exists and contains a valid `GEMINI_API_KEY`

**Port Already in Use:**
- Change the port in `run.sh` by modifying the `--bind` parameter

**Dependencies Installation Failed:**
- Ensure you have Python 3.7+ and pip installed
- Try manually: `pip install -r requirements.txt`

---

## License

See LICENSE file for details.
