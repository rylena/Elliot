# Elliot - AI Terminal Assistant

Elliot is an intelligent AI-powered terminal assistant that combines the power of natural language processing with direct terminal command execution. Built with Flask, LangChain, and Ollama, Elliot provides a modern web-based terminal interface with AI assistance.

## Features

- **AI-Powered Assistance**: Get help with terminal commands, explanations, and programming tasks
- **Direct Command Execution**: Execute Linux commands directly through the web interface
- **File System Navigation**: Browse directories and view file contents
- **Modern Terminal UI**: Clean, responsive interface with syntax highlighting
- **Real-time Command Output**: See command results instantly with proper formatting
- **Safety Features**: Command timeout protection and error handling

## Prerequisites

1. **Python 3.8+**
2. **Ollama** installed and running locally
3. **Phi model** pulled in Ollama: `ollama pull phi:latest`

## Installation

1. Clone or navigate to the Elliot directory:
```bash
cd Elliot
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Ensure Ollama is running:
```bash
ollama serve
```

4. Pull the required model:
```bash
ollama pull phi:latest
```

## Usage

1. Start the application:
```bash
python app.py
```

2. Open your browser and navigate to:
```
http://localhost:5000
```

3. Start interacting with Elliot!

## How to Use

### AI Chat
- Ask questions about terminal commands
- Get explanations for complex operations
- Request help with programming tasks
- Ask for system information

### Command Execution
- Type commands directly (e.g., `ls`, `pwd`, `cat file.txt`)
- View real-time command output
- Navigate the file system with `cd`
- Execute any Linux command safely

### Quick Actions
- **Clear**: Clear the terminal output
- **PWD**: Show current working directory
- **LS**: List files in current directory

## Supported Commands

The interface automatically detects and executes common Linux commands:
- File operations: `ls`, `cd`, `cat`, `mkdir`, `rm`, `cp`, `mv`
- System info: `pwd`, `echo`, `whoami`
- Text processing: `grep`, `find`
- And many more!

## Security Features

- Command timeout (30 seconds)
- Safe command execution with proper error handling
- Input validation and sanitization
- Directory traversal protection

## Customization

You can modify the AI behavior by editing the `SYSTEM_PROMPT` in `app.py` to change Elliot's personality and capabilities.

## Troubleshooting

- **Ollama not running**: Make sure Ollama is installed and the service is running
- **Model not found**: Run `ollama pull phi:latest` to download the required model
- **Permission errors**: Ensure the application has proper permissions to execute commands

## License

This project is open source and available under the MIT License. 
