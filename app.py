from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
from langchain_community.llms import Ollama
from langchain_core.prompts import ChatPromptTemplate
import subprocess
import os
import json
import re
import pty
import select
import threading
import time
import signal
import fcntl
import termios
import struct
import PyPDF2
import io
import pexpect

app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, cors_allowed_origins="*")

llm = Ollama(model="phi:latest")

def get_enhanced_system_prompt():
    """Get enhanced system prompt with PDF knowledge"""
    base_prompt = """
You are Elliot, a terminal assistant. When asked to perform actions, respond with ONLY the command to run.

COMMON LINUX COMMANDS:

File Operations:
- "make a file called test" → touch test
- "create directory called folder" → mkdir folder
- "list files" → ls -la
- "show directory contents" → ls -la
- "find largest file" → ls -lah | sort -k5 -hr | head -2 | tail -1
- "find smallest file" → ls -lah | sort -k5 -h | head -2 | tail -1
- "find files containing text" → find . -type f -exec grep -l "text" {} \;
- "search for filename" → find . -name "*filename*"
- "copy file1 to file2" → cp file1 file2
- "move file1 to file2" → mv file1 file2
- "delete file" → rm file
- "remove directory" → rm -rf directory

System Info:
- "current directory" → pwd
- "who am i" → whoami
- "system info" → uname -a
- "disk usage" → df -h
- "memory usage" → free -h
- "process list" → ps aux

Text Processing:
- "show file contents" → cat filename
- "show last 10 lines" → tail -10 filename
- "show first 10 lines" → head -10 filename
- "grep for pattern" → grep "pattern" filename
- "count lines" → wc -l filename

Network Commands:
- "scan localhost" → nmap 127.0.0.1
- "scan 192.168.1.1" → nmap 192.168.1.1
- "ping host" → ping hostname
- "check port 80" → telnet hostname 80

NMAP COMMANDS:
- "ping scan 192.168.1.1" → nmap -sn 192.168.1.1
- "scan subnet 192.168.1.0" → nmap -sn 192.168.1.0/24
- "scan specific ports 80,443,22" → nmap -p 80,443,22 [target]
- "scan all ports" → nmap -p- [target]
- "fast scan" → nmap -F [target]
- "stealth scan" → nmap -sS [target]
- "detect services" → nmap -sV [target]
- "detect os" → nmap -O [target]
- "aggressive scan" → nmap -A [target]
- "vulnerability scan" → nmap --script=vuln [target]
"""
    
    # Add PDF knowledge if available
    if LINUX_COMMANDS_KNOWLEDGE:
        base_prompt += f"""

ADDITIONAL LINUX COMMANDS FROM HANDBOOK:
{LINUX_COMMANDS_KNOWLEDGE[:2000]}  # Limit to first 2000 chars to avoid token limits
"""
    
    base_prompt += "\nIMPORTANT: Return ONLY the command, no explanations, no quotes, no extra text."
    return base_prompt

class TerminalManager:
    def __init__(self):
        self.terminals = {}
        self.ai_mode = False
        self.output_buffer = {}  # Store output for each session
    
    def create_terminal(self, session_id):
        """Create a new terminal session"""
        try:
            # Create a new PTY (pseudo-terminal)
            master, slave = pty.openpty()
            
            # Start bash shell
            pid = os.fork()
            if pid == 0:
                # Child process
                os.close(master)
                os.dup2(slave, 0)
                os.dup2(slave, 1)
                os.dup2(slave, 2)
                os.execvp('bash', ['bash'])
            else:
                # Parent process
                os.close(slave)
                
                # Set non-blocking mode
                fcntl.fcntl(master, fcntl.F_SETFL, os.O_NONBLOCK)
                
                self.terminals[session_id] = {
                    'master': master,
                    'pid': pid,
                    'buffer': '',
                    'output': ''  # Store terminal output
                }
                
                # Start reading thread
                threading.Thread(target=self._read_terminal, args=(session_id,), daemon=True).start()
                
                return True
        except Exception as e:
            print(f"Error creating terminal: {e}")
            return False
    
    def _read_terminal(self, session_id):
        """Read from terminal and send to client"""
        terminal = self.terminals.get(session_id)
        if not terminal:
            return
        
        master = terminal['master']
        
        while session_id in self.terminals:
            try:
                # Check if there's data to read
                ready, _, _ = select.select([master], [], [], 0.1)
                if ready:
                    data = os.read(master, 1024)
                    if data:
                        output_data = data.decode('utf-8', errors='ignore')
                        # Store output for AI analysis
                        terminal['output'] += output_data
                        # Keep only last 10KB of output
                        if len(terminal['output']) > 10240:
                            terminal['output'] = terminal['output'][-10240:]
                        
                        # Send data to client
                        socketio.emit('terminal_output', {
                            'data': output_data,
                            'session_id': session_id
                        }, room=session_id)
            except Exception as e:
                print(f"Error reading terminal: {e}")
                break
        
        # Clean up
        if session_id in self.terminals:
            self._cleanup_terminal(session_id)
    
    def write_to_terminal(self, session_id, data):
        """Write data to terminal"""
        terminal = self.terminals.get(session_id)
        if terminal:
            try:
                print(f"Writing to terminal {session_id}: {data.encode('utf-8')}")  # Debug log
                result = os.write(terminal['master'], data.encode('utf-8'))
                print(f"Write result: {result}")  # Debug log
                return True
            except Exception as e:
                print(f"Error writing to terminal: {e}")
                import traceback
                traceback.print_exc()  # Print full error traceback
        else:
            print(f"No terminal found for session {session_id}")  # Debug log
        return False
    
    def get_output(self, session_id):
        """Get the current terminal output for AI analysis"""
        terminal = self.terminals.get(session_id)
        if terminal:
            return terminal.get('output', '')
        return ''
    
    def clear_output(self, session_id):
        """Clear the output buffer"""
        terminal = self.terminals.get(session_id)
        if terminal:
            terminal['output'] = ''
    
    def _cleanup_terminal(self, session_id):
        """Clean up terminal session"""
        terminal = self.terminals.get(session_id)
        if terminal:
            try:
                os.close(terminal['master'])
                os.kill(terminal['pid'], signal.SIGTERM)
            except:
                pass
            del self.terminals[session_id]
    
    def cleanup_all(self):
        """Clean up all terminals"""
        for session_id in list(self.terminals.keys()):
            self._cleanup_terminal(session_id)

terminal_manager = TerminalManager()

def parse_and_execute_command(user_message):
    """Parse user message and determine if a command should be executed"""
    
    # Common action patterns that should trigger command execution
    action_patterns = [
        r'make\s+(?:a\s+)?(?:file|txt|text)\s+(?:called\s+)?([^\s]+)',
        r'create\s+(?:a\s+)?(?:file|txt|text)\s+(?:called\s+)?([^\s]+)',
        r'create\s+(?:a\s+)?directory\s+(?:called\s+)?([^\s]+)',
        r'make\s+(?:a\s+)?directory\s+(?:called\s+)?([^\s]+)',
        r'new\s+(?:file|directory)\s+(?:called\s+)?([^\s]+)',
        r'show\s+(?:me\s+)?(?:the\s+)?contents?\s+(?:of\s+)?(?:this\s+)?directory',
        r'list\s+(?:the\s+)?files?\s+(?:in\s+)?(?:this\s+)?directory',
        r'what\s+(?:is\s+)?(?:in\s+)?(?:my\s+)?(?:current\s+)?directory',
        r'delete\s+(?:the\s+)?(?:file\s+)?([^\s]+)',
        r'remove\s+(?:the\s+)?(?:file\s+)?([^\s]+)',
        r'copy\s+([^\s]+)\s+to\s+([^\s]+)',
        r'move\s+([^\s]+)\s+to\s+([^\s]+)',
        r'rename\s+([^\s]+)\s+to\s+([^\s]+)',
        r'change\s+directory\s+to\s+([^\s]+)',
        r'go\s+to\s+(?:directory\s+)?([^\s]+)',
        r'cd\s+([^\s]+)',
        r'what\s+(?:is\s+)?(?:my\s+)?(?:current\s+)?(?:working\s+)?directory',
        r'pwd',
        r'where\s+am\s+i',
        # Nmap patterns
        r'scan\s+(?:my\s+)?(?:localhost|127\.0\.0\.1|network|host)',
        r'check\s+(?:what\s+)?(?:ports?\s+)?(?:are\s+)?open',
        r'nmap\s+scan',
        r'network\s+scan',
        r'port\s+scan',
        r'security\s+scan',
        r'find\s+(?:open\s+)?ports?',
        r'detect\s+(?:services|os)',
        r'quick\s+scan',
        r'stealth\s+scan',
        r'udp\s+scan',
        r'run\s+(?:a\s+)?nmap\s+scan\s+(?:on\s+)?([^\s]+)',
        r'scan\s+([^\s]+)',
        # New comprehensive nmap patterns
        r'ping\s+scan',
        r'subnet\s+scan',
        r'host\s+discovery',
        r'specific\s+ports?',
        r'all\s+ports?',
        r'fast\s+scan',
        r'tcp\s+connect\s+scan',
        r'ack\s+scan',
        r'null\s+scan',
        r'service\s+detection',
        r'version\s+detection',
        r'os\s+detection',
        r'aggressive\s+scan',
        r'vulnerability\s+scan',
        r'default\s+scripts?',
        r'http\s+title\s+scan',
        r'save\s+to\s+file',
        r'xml\s+output',
        r'decoy\s+scan',
        r'fragment\s+packets?',
        r'slow\s+scan',
        r'stealth\s+mode',
        r'evasion\s+techniques?',
        r'find\s+(?:the\s+)?(?:largest|biggest|smallest)\s+file',
        r'find\s+(?:files?|directories?)\s+(?:with|containing)\s+([^\s]+)',
        r'search\s+for\s+([^\s]+)',
        r'locate\s+([^\s]+)',
        r'find\s+([^\s]+)',
    ]
    
    user_message_lower = user_message.lower()
    
    # Check for action patterns
    for pattern in action_patterns:
        match = re.search(pattern, user_message_lower)
        if match:
            return True, match.groups()
    
    # Check for direct commands
    if any(cmd in user_message_lower for cmd in ['ls', 'pwd', 'mkdir', 'touch', 'rm', 'cp', 'mv', 'cat', 'echo', 'nmap']):
        return True, []
    
    return False, []

def is_safe_nmap_command(command):
    """Check if nmap command is safe (now allows all targets)"""
    # Removed safety restrictions - allow all nmap commands
    return True

def extract_pdf_content(pdf_path):
    """Extract text content from PDF file"""
    try:
        content = ""
        with open(pdf_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            for page in pdf_reader.pages:
                content += page.extract_text() + "\n"
        return content
    except Exception as e:
        print(f"Error reading PDF: {e}")
        return ""

def load_linux_commands_knowledge():
    """Load Linux commands knowledge from PDF"""
    pdf_path = os.path.join(os.path.dirname(__file__), 'linux-commands-handbook.pdf')
    if os.path.exists(pdf_path):
        print("Loading Linux commands from PDF...")
        pdf_content = extract_pdf_content(pdf_path)
        if pdf_content:
            # Extract key command patterns from PDF
            commands_knowledge = extract_commands_from_pdf(pdf_content)
            return commands_knowledge
    return ""

def extract_commands_from_pdf(pdf_content):
    """Extract and structure command knowledge from PDF content"""
    # Look for common command patterns in the PDF
    command_patterns = []
    
    # Common Linux command patterns to look for
    command_keywords = [
        'ls', 'cd', 'pwd', 'mkdir', 'rmdir', 'rm', 'cp', 'mv', 'touch', 'cat', 'head', 'tail',
        'grep', 'find', 'sort', 'uniq', 'wc', 'echo', 'printf', 'nano', 'vim', 'chmod', 'chown',
        'ps', 'top', 'kill', 'df', 'du', 'free', 'uname', 'whoami', 'id', 'su', 'sudo',
        'nmap', 'ping', 'telnet', 'ssh', 'scp', 'wget', 'curl', 'tar', 'gzip', 'gunzip'
    ]
    
    # Extract lines that contain commands
    lines = pdf_content.split('\n')
    for line in lines:
        line = line.strip()
        if any(keyword in line.lower() for keyword in command_keywords):
            # Clean up the line and add to patterns
            cleaned_line = re.sub(r'\s+', ' ', line)
            if len(cleaned_line) > 5 and len(cleaned_line) < 200:
                command_patterns.append(cleaned_line)
    
    # Limit to most relevant patterns
    return "\n".join(command_patterns[:100])  # Limit to 100 most relevant patterns

# Load Linux commands knowledge at startup
LINUX_COMMANDS_KNOWLEDGE = load_linux_commands_knowledge()
print(f"Loaded {len(LINUX_COMMANDS_KNOWLEDGE.split())} words of Linux command knowledge")

def run_zphisher_interactive(user_request, sudo_password='Rylen2009'):
    """Launch zphisher, read the menu, and select options based on user_request."""
    try:
        zphisher_path = os.path.expanduser('~/zphisher')
        if not os.path.exists(zphisher_path):
            return "Zphisher is not installed. Please run: git clone https://github.com/htr-tech/zphisher.git && cd zphisher && bash zphisher.sh"
        child = pexpect.spawn('bash zphisher.sh', cwd=zphisher_path, encoding='utf-8', timeout=30)
        output = ''
        while True:
            idx = child.expect([pexpect.EOF, pexpect.TIMEOUT, r'Select an option:|Select a port forwarding option:|Enter your choice:|\$|sudo password for', r'\n'])
            output += child.before
            if idx == 0:
                break  # EOF
            elif idx == 1:
                output += '\n[Timeout waiting for zphisher prompt]\n'
                break
            elif idx == 2:
                # Menu detected, parse and select option
                menu_text = child.before
                # Try to find the right option based on user_request
                option_number = parse_zphisher_menu_option(menu_text, user_request)
                if option_number:
                    child.sendline(str(option_number))
                else:
                    child.sendline('1')  # Default to first option
            elif idx == 3:
                # Sudo password prompt
                child.sendline(sudo_password)
            elif idx == 4:
                continue
        child.close()
        return output
    except Exception as e:
        return f"Error running zphisher: {e}"

def parse_zphisher_menu_option(menu_text, user_request):
    """Parse the zphisher menu and return the option number for the user_request."""
    # Simple keyword matching for common targets
    options = {
        'facebook': 1,
        'instagram': 2,
        'gmail': 3,
        'twitter': 4,
        'github': 5,
        'linkedin': 6,
        'wordpress': 7,
        'snapchat': 8,
        'spotify': 9,
        'netflix': 10,
        'paypal': 11,
        'steam': 12,
        'tiktok': 13,
        'yahoo': 14,
        'twitch': 15,
        'pinterest': 16,
        'reddit': 17,
        'custom': 99
    }
    for key, val in options.items():
        if key in user_request.lower():
            return val
    return None

@app.route('/api/chat', methods=['POST'])
def chat():
    data = request.get_json()
    user_message = data.get('message', '')
    session_id = data.get('session_id', 'default')
    
    if not user_message:
        return jsonify({'error': 'No message provided.'}), 400

    # Check if this is an action request that should execute a command
    should_execute, params = parse_and_execute_command(user_message)
    
    if should_execute:
        # Let the AI determine the appropriate command
        try:
            print(f"Invoking LLM for message: {user_message}")  # Debug log
            
            # Create a simple prompt without template formatting
            full_prompt = f"{get_enhanced_system_prompt()}\n\nUser request: {user_message}\n\nRespond with ONLY the command to execute:"
            
            response = llm.invoke(full_prompt)
            print(f"AI Response: {response}")  # Debug log
            
            if not response:
                print("No response from LLM")  # Debug log
                return jsonify({'response': "Sorry, I couldn't process that request. Please try again."})
            
            # Clean the response - should be just a command
            command = response.strip()
            
            # Remove any markdown formatting
            command = re.sub(r'```.*?```', '', command, flags=re.DOTALL)
            command = re.sub(r'^\$\s*', '', command)  # Remove leading $
            command = command.strip()
            
            print(f"After cleaning, command is: '{command}'")  # Debug log
            
            code_keywords = ['import ', 'def ', 'class ', 'print(', 'if __name__', 'while ', 'for ', 'try:', 'except:']
            is_code = any(keyword in command.lower() for keyword in code_keywords)
            print(f"Is code response: {is_code}")  # Debug log
            
            valid_command_keywords = ['ls', 'find', 'nmap', 'pwd', 'cd', 'mkdir', 'touch', 'rm', 'cp', 'mv', 'cat', 'echo', 'grep', 'sort', 'head', 'tail']
            is_valid_command = any(keyword in command.lower() for keyword in valid_command_keywords)
            print(f"Is valid command: {is_valid_command}")  # Debug log
            
            if is_code:
                print("Response looks like code, using fallback")  # Debug log
                # Use fallback command generation
                if 'nmap' in user_message.lower() or 'scan' in user_message.lower():
                    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', user_message)
                    if ip_match:
                        command = f"nmap {ip_match.group()}"
                    else:
                        command = "nmap 127.0.0.1"
                elif 'file' in user_message.lower() or 'create' in user_message.lower():
                    file_match = re.search(r'called\s+([^\s]+)', user_message)
                    if file_match:
                        command = f"touch {file_match.group(1)}"
                    else:
                        command = "touch file.txt"
                elif 'directory' in user_message.lower() or 'folder' in user_message.lower():
                    dir_match = re.search(r'called\s+([^\s]+)', user_message)
                    if dir_match:
                        command = f"mkdir {dir_match.group(1)}"
                    else:
                        command = "mkdir new_folder"
                elif 'list' in user_message.lower() or 'show' in user_message.lower():
                    command = "ls -la"
                elif 'pwd' in user_message.lower() or 'directory' in user_message.lower():
                    command = "pwd"
                elif 'find' in user_message.lower() or 'search' in user_message.lower():
                    if 'largest' in user_message.lower() or 'biggest' in user_message.lower():
                        command = "ls -lah | sort -k5 -hr | head -2 | tail -1"
                    elif 'smallest' in user_message.lower():
                        command = "ls -lah | sort -k5 -h | head -2 | tail -1"
                    elif 'containing' in user_message.lower():
                        search_match = re.search(r'containing\s+([^\s]+)', user_message)
                        if search_match:
                            search_term = search_match.group(1)
                            command = f"find . -type f -exec grep -l '{search_term}' {{}} \\;"
                        else:
                            command = "find . -type f"
                    else:
                        command = "find . -type f"
                elif 'search' in user_message.lower():
                    search_match = re.search(r'search\s+for\s+([^\s]+)', user_message)
                    if search_match:
                        search_term = search_match.group(1)
                        command = f"find . -name '*{search_term}*'"
                    else:
                        command = "find . -type f"
                else:
                    command = "echo 'Command not understood'"
            
            print(f"Cleaned command: {command}")  # Debug log
            
            if command and len(command) > 2 and not command.startswith('echo') and is_valid_command:
                print(f"Executing command: {command}")  # Debug log
                if terminal_manager.write_to_terminal(session_id, command + '\n'):
                    print(f"Command sent to terminal successfully")  # Debug log
                    return jsonify({
                        'response': f"Elliot executed: {command}",
                        'command_executed': True,
                        'command': command
                    })
                else:
                    print(f"Failed to send command to terminal")  # Debug log
                    return jsonify({
                        'response': f"Failed to execute: {command}",
                        'command_executed': False
                    })
            else:
                print(f"Invalid command or fallback triggered: {command}")  # Debug log
                return jsonify({'response': response})
        except Exception as e:
            print(f"Error in command execution: {e}")  # Debug log
            import traceback
            traceback.print_exc()  # Print full error traceback
            return jsonify({'error': f'Error processing request: {str(e)}'}), 500
    else:
        # Regular chat response
        try:
            full_prompt = f"{get_enhanced_system_prompt()}\n\nUser request: {user_message}\n\nRespond as a helpful Linux assistant."
            response = llm.invoke(full_prompt)
            filtered_response = '\n'.join(
                line for line in response.splitlines()
                if not line.strip().lower().startswith("think:")
            )
            return jsonify({'response': filtered_response.strip()})
        except Exception as e:
            print(f"Error in regular chat response: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'error': f'Error processing request: {str(e)}'}), 500

@app.route('/api/execute', methods=['POST'])
def execute_command():
    data = request.get_json()
    command = data.get('command', '')
    session_id = data.get('session_id', 'default')
    
    if not command:
        return jsonify({'error': 'No command provided.'}), 400
    
    # Execute in live terminal
    if terminal_manager.write_to_terminal(session_id, command + '\n'):
        return jsonify({'success': True, 'message': f"Command sent to terminal: {command}"})
    else:
        return jsonify({'success': False, 'message': "Failed to send command to terminal"})

@app.route('/api/pwd', methods=['GET'])
def get_current_directory():
    return jsonify({'pwd': os.getcwd()})

@app.route('/api/ls', methods=['GET'])
def list_directory():
    path = request.args.get('path', '.')
    try:
        items = os.listdir(path)
        return jsonify({'items': items, 'path': os.path.abspath(path)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze', methods=['POST'])
def analyze_output():
    """Analyze terminal output and provide AI insights"""
    data = request.get_json()
    session_id = data.get('session_id', 'default')
    user_question = data.get('question', 'What do you see in the output?')
    output = terminal_manager.get_output(session_id)
    if not output:
        return jsonify({'response': "No terminal output to analyze yet."})
    analysis_prompt = f"""
You are Elliot, an AI terminal assistant. Analyze the following terminal output and answer the user's question.

TERMINAL OUTPUT:
{output}

USER QUESTION: {user_question}

Provide a helpful analysis based on the terminal output. Focus on:
- What commands were executed
- What the results show
- Any errors or issues
- Recommendations or next steps

Keep your response concise and helpful.
"""
    try:
        full_prompt = f"{analysis_prompt}\n\nUser question: {user_question}\n"
        response = llm.invoke(full_prompt)
        return jsonify({'response': response.strip()})
    except Exception as e:
        print(f"Error in analyze_output: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Error analyzing output: {str(e)}'}), 500

@app.route('/api/refresh-knowledge', methods=['POST'])
def refresh_knowledge():
    """Refresh Linux commands knowledge from PDF"""
    global LINUX_COMMANDS_KNOWLEDGE
    try:
        LINUX_COMMANDS_KNOWLEDGE = load_linux_commands_knowledge()
        return jsonify({
            'success': True,
            'message': f'Refreshed knowledge with {len(LINUX_COMMANDS_KNOWLEDGE.split())} words'
        })
    except Exception as e:
        return jsonify({'error': f'Failed to refresh knowledge: {str(e)}'}), 500

@app.route('/api/knowledge-stats', methods=['GET'])
def knowledge_stats():
    """Get statistics about loaded knowledge"""
    return jsonify({
        'pdf_loaded': bool(LINUX_COMMANDS_KNOWLEDGE),
        'knowledge_words': len(LINUX_COMMANDS_KNOWLEDGE.split()) if LINUX_COMMANDS_KNOWLEDGE else 0,
        'knowledge_length': len(LINUX_COMMANDS_KNOWLEDGE) if LINUX_COMMANDS_KNOWLEDGE else 0
    })

@app.route('/api/test', methods=['GET'])
def test_llm():
    """Test if the LLM is working"""
    try:
        test_response = llm.invoke("Say 'Hello'")
        return jsonify({'status': 'success', 'response': test_response})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

# WebSocket events
@socketio.on('connect')
def handle_connect():
    session_id = request.sid
    print(f"Client connected: {session_id}")
    
    # Create terminal for this session
    if terminal_manager.create_terminal(session_id):
        emit('terminal_ready', {'session_id': session_id})
    else:
        emit('terminal_error', {'message': 'Failed to create terminal'})

@socketio.on('disconnect')
def handle_disconnect():
    session_id = request.sid
    print(f"Client disconnected: {session_id}")
    terminal_manager._cleanup_terminal(session_id)

@socketio.on('terminal_input')
def handle_terminal_input(data):
    session_id = request.sid
    user_input = data.get('input', '')
    
    if user_input:
        terminal_manager.write_to_terminal(session_id, user_input)

@socketio.on('ai_command')
def handle_ai_command(data):
    session_id = request.sid
    command = data.get('command', '')
    
    if command:
        terminal_manager.write_to_terminal(session_id, command + '\n')

if __name__ == '__main__':
    try:
        socketio.run(app, debug=True, host='0.0.0.0', port=5000)
    finally:
        terminal_manager.cleanup_all()
