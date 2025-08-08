from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
from langchain_community.llms import Ollama
from langchain_core.prompts import ChatPromptTemplate
import os
import pty
import fcntl
import select
import threading
import signal
import time
import re
import traceback
import pexpect

app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, cors_allowed_origins="*")

llm = Ollama(model="llama2:latest")

def get_enhanced_system_prompt():
    return """
You are Elliot, a terminal assistant. Respond with ONLY the command to run, nothing else.

EXACT COMMANDS TO USE:

File Operations:
- "find largest file" → ls -lah | sort -k5 -hr | head -1
- "find biggest file" → ls -lah | sort -k5 -hr | head -1
- "find smallest file" → ls -lah | sort -k5 -h | head -1
- "largest file" → ls -lah | sort -k5 -hr | head -1
- "biggest file" → ls -lah | sort -k5 -hr | head -1
- "list files" → ls -la
- "show directory contents" → ls -la
- "make a file called test" → touch test
- "create directory called folder" → mkdir folder
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
- "current time" → date
- "uptime" → uptime

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
- "check connectivity" → ping -c 4 hostname
- "trace route" → traceroute hostname
- "check DNS" → nslookup hostname

NMAP COMMANDS:
- "ping scan 192.168.1.1" → nmap -sn 192.168.1.1
- "scan subnet 192.168.1.0" → nmap -sn 192.168.1.0/24
- "scan specific ports 80,443,22" → nmap -p 80,443,22 [target]
- "scan all ports" → nmap -p- [target]
- "fast scan" → nmap -T4 -F [target]
- "quick scan" → nmap -T4 -F [target]
- "stealth scan" → nmap -sS [target]
- "detect services" → nmap -sV [target]
- "detect os" → nmap -O [target]
- "aggressive scan" → nmap -A [target]
- "vulnerability scan" → nmap --script=vuln [target]
- "comprehensive scan" → nmap -sS -sV -O -A -p- [target]
- "UDP scan" → nmap -sU [target]
- "version detection" → nmap -sV [target]
- "script scan" → nmap --script=default [target]
- "http scan" → nmap --script=http-title [target]
- "save to file" → nmap -oN output.txt [target]
- "XML output" → nmap -oX output.xml [target]
- "grepable output" → nmap -oG output.gnmap [target]
- "decoy scan" → nmap -D RND:10 [target]
- "fragment packets" → nmap -f [target]
- "slow scan" → nmap -T1 [target]
- "evasion techniques" → nmap -f -D RND:5 --mtu 16 [target]
- "run a fast nmap scan" → nmap -T4 -F [target]
- "run a quick nmap scan" → nmap -T4 -F [target]

ZPHISHER:
- "run zphisher" → cd ~/zphisher && bash zphisher.sh
- "start phishing" → cd ~/zphisher && bash zphisher.sh

Other Commands:
- "check system resources" → htop
- "monitor network" → iftop
- "check open ports" → netstat -tuln
- "check listening ports" → ss -tuln
- "check routing table" → route -n
- "check ARP table" → arp -a
- "check firewall status" → ufw status
- "check system logs" → journalctl -f
- "check disk space" → du -sh *
- "find large files" → find . -type f -size +100M
- "check file permissions" → ls -la
- "change file permissions" → chmod 755 filename
- "compress file" → gzip filename
- "extract archive" → tar -xzf filename.tar.gz
- "download file" → wget URL
- "curl request" → curl -I URL
- "check SSL certificate" → openssl s_client -connect host:port
- "generate SSH key" → ssh-keygen -t rsa -b 4096
- "check SSH connections" → ss | grep ssh

Application Commands:
- "open firefox" → firefox
- "open chrome" → google-chrome
- "open editor" → gedit
- "open nano" → nano
- "open vim" → vim
- "start firefox" → firefox
- "launch firefox" → firefox

Package Management:
- "install package" → sudo apt install [package]
- "remove package" → sudo apt remove [package]
- "update system" → sudo apt update && sudo apt upgrade
- "search package" → apt search [package]
- "list installed" → apt list --installed
- "clean cache" → sudo apt clean
- "autoremove" → sudo apt autoremove
- "fix broken" → sudo apt --fix-broken install
- "download app" → sudo apt install [app]
- "install software" → sudo apt install [software]
- "update packages" → sudo apt update
- "upgrade packages" → sudo apt upgrade

CRITICAL RULES:
- Return ONLY the command, no explanations, no quotes, no extra text
- Use EXACTLY the commands shown above
- For "find largest file" use: ls -lah | sort -k5 -hr | head -1
- For "find smallest file" use: ls -lah | sort -k5 -h | head -1
- Do NOT add /usr/bin/ prefix to commands
- Do NOT add extra spaces or characters
- Do NOT explain or reason about the command
- Do NOT add quotes around commands
- Do NOT add any prefixes like /usr/bin/, /bin/, etc.
- Use simple command names: ls, not /usr/bin/ls
- For "open firefox" return: firefox
- For "open chrome" return: google-chrome
- NEVER use Mac commands like /usr/bin/open
- NEVER use Windows commands
- ONLY use Linux commands
"""

ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

def strip_ansi(text: str) -> str:
    if not text:
        return text
    return ANSI_ESCAPE_RE.sub('', text)

class TerminalManager:
    def __init__(self):
        self.terminals = {}
        self.ai_mode = False
        self.output_buffer = {}
    
    def create_terminal(self, session_id):
        try:
            master, slave = pty.openpty()
            pid = os.fork()
            if pid == 0:
                os.close(master)
                os.dup2(slave, 0)
                os.dup2(slave, 1)
                os.dup2(slave, 2)
                os.execvp('bash', ['bash'])
            else:
                os.close(slave)
                fcntl.fcntl(master, fcntl.F_SETFL, os.O_NONBLOCK)
                self.terminals[session_id] = {
                    'master': master,
                    'pid': pid,
                    'buffer': '',
                    'output': ''
                }
                threading.Thread(target=self._read_terminal, args=(session_id,), daemon=True).start()
                return True
        except Exception as e:
            print(f"Error creating terminal: {e}")
            return False
    
    def _read_terminal(self, session_id):
        terminal = self.terminals.get(session_id)
        if not terminal:
            return
        master = terminal['master']
        while session_id in self.terminals:
            try:
                ready, _, _ = select.select([master], [], [], 0.1)
                if ready:
                    data = os.read(master, 1024)
                    if data:
                        output_data = data.decode(errors='ignore')
                        terminal['output'] += output_data
                        socketio.emit('terminal_output', {
                            'data': output_data,
                            'session_id': session_id
                        }, room=session_id)
            except Exception as e:
                print(f"Error reading terminal: {e}")
                break
        if session_id in self.terminals:
            self._cleanup_terminal(session_id)
    
    def write_to_terminal(self, session_id, data):
        terminal = self.terminals.get(session_id)
        if terminal:
            try:
                print(f"Writing to terminal {session_id}: {data.encode('utf-8')}")
                result = os.write(terminal['master'], data.encode('utf-8'))
                print(f"Write result: {result}")
                return True
            except Exception as e:
                print(f"Error writing to terminal: {e}")
                traceback.print_exc()
        else:
            print(f"No terminal found for session {session_id}")
        return False
    
    def get_output(self, session_id):
        terminal = self.terminals.get(session_id)
        if terminal:
            return terminal.get('output', '')
        return ''
    
    def clear_output(self, session_id):
        terminal = self.terminals.get(session_id)
        if terminal:
            terminal['output'] = ''
    
    def _cleanup_terminal(self, session_id):
        terminal = self.terminals.get(session_id)
        if terminal:
            try:
                os.close(terminal['master'])
                os.kill(terminal['pid'], signal.SIGTERM)
            except:
                pass
            del self.terminals[session_id]
    
    def cleanup_all(self):
        for session_id in list(self.terminals.keys()):
            self._cleanup_terminal(session_id)

    def get_output_cursor(self, session_id: str) -> int:
        terminal = self.terminals.get(session_id)
        if terminal:
            return len(terminal.get('output', ''))
        return 0

    def get_output_since(self, session_id: str, cursor: int) -> tuple[str, int]:
        terminal = self.terminals.get(session_id)
        if terminal:
            out = terminal.get('output', '')
            if cursor < 0:
                cursor = 0
            if cursor > len(out):
                cursor = len(out)
            return out[cursor:], len(out)
        return '', 0

terminal_manager = TerminalManager()

def parse_and_execute_command(user_message):
    user_message_lower = user_message.lower()
    non_command_patterns = [
        r'^(hi|hello|hey|goodbye|bye|thanks?|thank you)$',
        r'^(what is|what are|how does|explain|tell me about|describe)',
        r'^(can you help|help me|i need help)',
        r'^(who are you|what can you do|your name)',
    ]
    for pattern in non_command_patterns:
        if re.match(pattern, user_message_lower):
            return False, []
    return True, []

def is_safe_nmap_command(command):
    return True

def is_command_completed(output_text):
    if not output_text:
        return False
    prompt_patterns = [
        r'\$ $',
        r'# $',
        r'rylen@Laptop:.*\$ $',
        r'[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+:.*\$ $',
    ]
    for pattern in prompt_patterns:
        if re.search(pattern, output_text):
            return True
    return False

def handle_sudo_password(session_id, sudo_password='Rylen2009'):
    def check_and_input_password():
        max_wait = 10
        wait_time = 0
        check_interval = 0.5
        while wait_time < max_wait:
            time.sleep(check_interval)
            wait_time += check_interval
            try:
                current_output = terminal_manager.get_output(session_id)
                if '[sudo] password for' in current_output or 'Password:' in current_output:
                    print(f"Sudo password requested, inputting password for session {session_id}")
                    terminal_manager.write_to_terminal(session_id, sudo_password + '\n')
                    print(f"Sudo password sent for session {session_id}")
                    break
            except Exception as e:
                print(f"Error checking for sudo prompt: {e}")
                break
        time.sleep(2)
    threading.Thread(target=check_and_input_password, daemon=True).start()

def schedule_auto_analyze(session_id, command, start_cursor):
    def analyze_after_delay():
        max_wait = 30
        wait_time = 0
        check_interval = 0.5
        while wait_time < max_wait:
            time.sleep(check_interval)
            wait_time += check_interval
            try:
                current_output, current_cursor = terminal_manager.get_output_since(session_id, start_cursor)
                if is_command_completed(current_output):
                    time.sleep(2)
                    break
            except Exception as e:
                print(f"Error checking command completion: {e}")
                break
        try:
            new_output, current_cursor = terminal_manager.get_output_since(session_id, start_cursor)
            print(f"Analysis - Command: {command}, Output: {new_output}")
            if new_output.strip():
                clean_output = strip_ansi(new_output.strip())
                if clean_output.strip() == command.strip():
                    return
                if len(clean_output.strip()) < 10:
                    return
                analysis_prompt = f"""
You are Elliot, an AI terminal assistant. Analyze this terminal output and provide ONLY the key result.

TERMINAL OUTPUT:
{clean_output}

COMMAND EXECUTED: {command}

Provide ONLY the key finding (under 20 words). Focus on the actual data shown.
Examples:
- "Largest file: linux-commands-handbook.pdf (14M)"
- "3 files found"
- "Port 22 open"
- "Uptime: 5 days"
- "Command failed: firefox not found"
- "Error: No such file or directory"
- "Firefox launched successfully"
- "Application not found"

If the output shows file listings, identify the largest file by size.
If the output shows network scan results, identify open ports.
If the output shows system info, provide the key metric.
If the output shows an error, state what failed.
If the output shows application launch, confirm success.
"""
                response = llm.invoke(analysis_prompt)
                clean_response = response.strip()
                print(f"Analysis result: {clean_response}")  # Debug log
                
                socketio.emit('terminal_analysis', {
                    'command': command,
                    'analysis': clean_response,
                    'session_id': session_id
                }, room=session_id)
        except Exception as e:
            print(f"Error in auto-analysis: {e}")
            traceback.print_exc()
    threading.Thread(target=analyze_after_delay, daemon=True).start()

def run_zphisher_interactive(user_request, sudo_password='Rylen2009'):
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
                break
            elif idx == 1:
                output += '\n[Timeout waiting for zphisher prompt]\n'
                break
            elif idx == 2:
                menu_text = child.before
                option_number = parse_zphisher_menu_option(menu_text, user_request)
                if option_number:
                    child.sendline(str(option_number))
                else:
                    child.sendline('1')
            elif idx == 3:
                child.sendline(sudo_password)
            elif idx == 4:
                continue
        child.close()
        return output
    except Exception as e:
        return f"Error running zphisher: {e}"

def parse_zphisher_menu_option(menu_text, user_request):
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

def strip_code_fences(text: str) -> str:
    if not text:
        return text
    text = re.sub(r'```(?:bash|shell)?\s*\n?', '', text)
    text = re.sub(r'\n?```', '', text)
    text = re.sub(r'`([^`]+)`', r'\1', text)
    text = re.sub(r'^\$\s*', '', text)
    return text.strip()

def generate_smart_fallback_command(user_message: str) -> str:
    message_lower = user_message.lower()
    if any(word in message_lower for word in ['time', 'date', 'clock']):
        return "date"
    elif any(word in message_lower for word in ['uptime', 'how long']):
        return "uptime"
    elif any(word in message_lower for word in ['memory', 'ram', 'free']):
        return "free -h"
    elif any(word in message_lower for word in ['disk', 'space', 'storage']):
        return "df -h"
    elif any(word in message_lower for word in ['cpu', 'load', 'system']):
        return "top -bn1"
    elif any(word in message_lower for word in ['process', 'running', 'ps']):
        return "ps aux"
    elif any(word in message_lower for word in ['network', 'connections', 'ports']):
        return "netstat -tuln"
    elif any(word in message_lower for word in ['who', 'users', 'logged']):
        return "who"
    elif any(word in message_lower for word in ['kernel', 'version', 'uname']):
        return "uname -a"
    elif any(word in message_lower for word in ['file', 'create', 'make']):
        file_match = re.search(r'(?:called\s+)?([a-zA-Z0-9._-]+\.?[a-zA-Z0-9]*)', message_lower)
        if file_match:
            return f"touch {file_match.group(1)}"
        return "touch newfile.txt"
    elif any(word in message_lower for word in ['directory', 'folder', 'mkdir']):
        dir_match = re.search(r'(?:called\s+)?([a-zA-Z0-9._-]+)', message_lower)
        if dir_match:
            return f"mkdir {dir_match.group(1)}"
        return "mkdir newdir"
    elif any(word in message_lower for word in ['ping', 'connectivity']):
        host_match = re.search(r'\b([a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})?)\b', message_lower)
        if host_match:
            return f"ping -c 4 {host_match.group(1)}"
        return "ping -c 4 8.8.8.8"
    elif any(word in message_lower for word in ['dns', 'resolve', 'nslookup']):
        host_match = re.search(r'\b([a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})?)\b', message_lower)
        if host_match:
            return f"nslookup {host_match.group(1)}"
        return "nslookup google.com"
    return "echo 'Command not understood'"

def extract_command_from_response(raw_text: str) -> str:
    if not raw_text:
        return ''
    text = raw_text.strip()
    m = re.search(r"```(?:bash|shell)?\s*\n([\s\S]*?)\n```", text, re.IGNORECASE)
    if m:
        text = m.group(1).strip()
    else:
        m2 = re.search(r"```(?:bash|shell)?\s*([^`]+)```", text, re.IGNORECASE)
        if m2:
            text = m2.group(1).strip()
    for line in text.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        if candidate.startswith('$'):
            candidate = candidate.lstrip('$').strip()
        if candidate.lower().startswith('bash '):
            candidate = candidate[5:].strip()
        if candidate.startswith('/usr/bin/'):
            candidate = candidate[9:].strip()
        if candidate.startswith('/bin/'):
            candidate = candidate[5:].strip()
        if '/' in candidate and not candidate.startswith('./') and not candidate.startswith('../'):
            candidate = candidate.split('/')[-1]
        candidate = re.sub(r'\s+', ' ', candidate)
        if candidate:
            return candidate
    cleaned = text
    cleaned = cleaned.strip('`').strip()
    if cleaned.startswith('$'):
        cleaned = cleaned.lstrip('$').strip()
    if cleaned.lower().startswith('bash '):
        cleaned = cleaned[5:].strip()
    if cleaned.startswith('/usr/bin/'):
        cleaned = cleaned[9:].strip()
    cleaned = re.sub(r'\s+', ' ', cleaned)
    return cleaned

@app.route('/api/chat', methods=['POST'])
def chat():
    data = request.get_json()
    user_message = data.get('message', '')
    session_id = data.get('session_id', 'default')
    if not user_message:
        return jsonify({'error': 'No message provided'}), 400
    should_execute, params = parse_and_execute_command(user_message)
    if should_execute:
        try:
            print(f"Invoking LLM for message: {user_message}")
            full_prompt = f"{get_enhanced_system_prompt()}\n\nUser request: {user_message}\n\nRespond with ONLY the command to execute:"
            response = llm.invoke(full_prompt)
            print(f"AI Response: {response}")
            if not response:
                print("No response from LLM")
                return jsonify({'response': "Sorry, I couldn't process that request. Please try again."})
            command = extract_command_from_response(response)
            print(f"Extracted command: '{command}'")
            code_keywords = ['import ', 'def ', 'class ', 'print(', 'if __name__', 'while ', 'for ', 'try:', 'except:']
            is_code = any(keyword in command.lower() for keyword in code_keywords)
            print(f"Is code response: {is_code}")
            invalid_patterns = [
                r'^\s*$',
                r'^echo\s+["\']?command\s+not\s+understood["\']?$',
                r'^echo\s+["\']?sorry["\']?$',
                r'^echo\s+["\']?i\s+cannot["\']?$',
            ]
            is_invalid = any(re.match(pattern, command.lower()) for pattern in invalid_patterns)
            print(f"Is invalid command: {is_invalid}")
            if is_code:
                print("Response looks like code, using fallback")
                if 'nmap' in user_message.lower() or 'scan' in user_message.lower():
                    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', user_message)
                    hostname_match = re.search(r'\b(?:scan|nmap)\s+(?:on\s+)?([a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})?)', user_message)
                    target = None
                    if ip_match:
                        target = ip_match.group()
                    elif hostname_match:
                        target = hostname_match.group(1)
                    else:
                        target = "127.0.0.1"
                    if 'quick' in user_message.lower() or 'fast' in user_message.lower():
                        command = f"nmap -T4 -F {target}"
                    elif 'stealth' in user_message.lower() or 'syn' in user_message.lower():
                        command = f"nmap -sS {target}"
                    elif 'udp' in user_message.lower():
                        command = f"nmap -sU {target}"
                    elif 'comprehensive' in user_message.lower() or 'full' in user_message.lower() or 'all' in user_message.lower():
                        command = f"nmap -sS -sV -O -A -p- {target}"
                    elif 'vulnerability' in user_message.lower() or 'vuln' in user_message.lower():
                        command = f"nmap --script=vuln {target}"
                    elif 'service' in user_message.lower() or 'version' in user_message.lower():
                        command = f"nmap -sV {target}"
                    elif 'os' in user_message.lower() or 'operating system' in user_message.lower():
                        command = f"nmap -O {target}"
                    elif 'ping' in user_message.lower() or 'discovery' in user_message.lower():
                        command = f"nmap -sn {target}"
                    elif 'port' in user_message.lower():
                        port_match = re.search(r'port[s]?\s+(\d+(?:,\d+)*)', user_message)
                        if port_match:
                            ports = port_match.group(1)
                            command = f"nmap -p {ports} {target}"
                        else:
                            command = f"nmap -p 80,443,22,21,23,25,53,110,143,993,995 {target}"
                    else:
                        command = f"nmap {target}"
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
                        command = "ls -lah | sort -k5 -hr | head -1"
                    elif 'smallest' in user_message.lower():
                        command = "ls -lah | sort -k5 -h | head -1"
                    elif 'containing' in user_message.lower():
                        search_match = re.search(r'containing\s+([^\s]+)', user_message)
                        if search_match:
                            search_term = search_match.group(1)
                            command = f"find . -type f -exec grep -l '{search_term}' {{}} \\;"
                        else:
                            command = "find . -type f"
                    else:
                        command = "find . -type f"
                elif 'open' in user_message.lower():
                    if 'firefox' in user_message.lower():
                        command = "firefox"
                    elif 'chrome' in user_message.lower():
                        command = "google-chrome"
                    elif 'gedit' in user_message.lower() or 'editor' in user_message.lower():
                        command = "gedit"
                    elif 'nano' in user_message.lower():
                        command = "nano"
                    elif 'vim' in user_message.lower():
                        command = "vim"
                    else:
                        command = "echo 'Application not found'"
                elif 'install' in user_message.lower() or 'download' in user_message.lower():
                    package_match = re.search(r'(?:install|download)\s+(?:package\s+)?([a-zA-Z0-9_-]+)', user_message)
                    if package_match:
                        package_name = package_match.group(1)
                        command = f"sudo apt install {package_name}"
                    else:
                        command = "echo 'Please specify package name'"
                elif 'update' in user_message.lower() and ('system' in user_message.lower() or 'packages' in user_message.lower()):
                    command = "sudo apt update && sudo apt upgrade"
                elif 'remove' in user_message.lower() and 'package' in user_message.lower():
                    package_match = re.search(r'remove\s+package\s+([a-zA-Z0-9_-]+)', user_message)
                    if package_match:
                        package_name = package_match.group(1)
                        command = f"sudo apt remove {package_name}"
                    else:
                        command = "echo 'Please specify package name'"
                elif 'search' in user_message.lower():
                    search_match = re.search(r'search\s+for\s+([^\s]+)', user_message)
                    if search_match:
                        search_term = search_match.group(1)
                        command = f"find . -name '*{search_term}*'"
                    else:
                        command = "find . -type f"
                else:
                    command = generate_smart_fallback_command(user_message)
            print(f"Cleaned command: {command}")
            if command and len(command) > 2 and not is_invalid:
                print(f"Executing command: {command}")
                start_cursor = terminal_manager.get_output_cursor(session_id)
                if terminal_manager.write_to_terminal(session_id, command + '\n'):
                    print(f"Command sent to terminal successfully")
                    if command.strip().startswith('sudo'):
                        print(f"Sudo command detected, setting up password handling for session {session_id}")
                        handle_sudo_password(session_id)
                    schedule_auto_analyze(session_id, command, start_cursor)
                    return jsonify({
                        'response': "",
                        'command_executed': True,
                        'command': command
                    })
                else:
                    print(f"Failed to send command to terminal")
                    return jsonify({
                        'response': f"Failed to execute: {command}",
                        'command_executed': False
                    })
            else:
                print(f"Invalid command or fallback triggered: {command}")
                return jsonify({'response': response})
        except Exception as e:
            print(f"Error in command execution: {e}")
            traceback.print_exc()
            return jsonify({'error': f'Error processing request: {str(e)}'}), 500
    else:
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
            traceback.print_exc()
            return jsonify({'error': f'Error processing request: {str(e)}'}), 500

@app.route('/api/execute', methods=['POST'])
def execute_command():
    data = request.get_json()
    command = data.get('command', '')
    session_id = data.get('session_id', 'default')
    if not command:
        return jsonify({'error': 'No command provided.'}), 400
    if terminal_manager.write_to_terminal(session_id, command + '\n'):
        if command.strip().startswith('sudo'):
            print(f"Sudo command detected in execute endpoint, setting up password handling for session {session_id}")
            handle_sudo_password(session_id)
        start_cursor = terminal_manager.get_output_cursor(session_id)
        schedule_auto_analyze(session_id, command, start_cursor)
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
        files = os.listdir(path)
        return jsonify({'files': files})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze', methods=['POST'])
def analyze_output():
    data = request.get_json()
    session_id = data.get('session_id', 'default')
    user_question = data.get('question', 'What do you see in the output?')
    output = terminal_manager.get_output(session_id)
    if not output:
        return jsonify({'error': 'No output available'}), 400
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
        response = llm.invoke(analysis_prompt)
        return jsonify({'analysis': response.strip()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/test', methods=['GET'])
def test_llm():
    try:
        response = llm.invoke("Say hello world.")
        return jsonify({'llm_response': response.strip()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@socketio.on('connect')
def handle_connect():
    session_id = request.sid
    print(f"Client connected: {session_id}")
    if terminal_manager.create_terminal(session_id):
        emit('terminal_ready', {'session_id': session_id})
    else:
        emit('terminal_error', {'error': 'Failed to create terminal'})

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
