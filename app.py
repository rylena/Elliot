from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room
import os
import google.generativeai as genai
import pty
import fcntl
import select
import threading
import signal
import time
import re
import traceback
import json
import hashlib

app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, cors_allowed_origins="*")

GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
GEMINI_MODEL = os.environ.get('GEMINI_MODEL', 'gemini-2.0-flash')
if not GEMINI_API_KEY:
    raise RuntimeError('GEMINI_API_KEY is not set. Run via run.sh or export it in your environment.')
genai.configure(api_key=GEMINI_API_KEY)


class GeminiWrapper:
    def __init__(self, model_name: str = None):
        self.model_name = model_name or GEMINI_MODEL
        self.model = genai.GenerativeModel(self.model_name)

    def invoke(self, prompt: str) -> str:
        try:
            response = self.model.generate_content(prompt)
            return (response.text or "").strip()
        except Exception as e:
            print(f"Gemini invoke error: {e}")
            return ""


llm = GeminiWrapper()

chat_histories = {}
HISTORY_MAX_TURNS = 10
sid_to_client_id: dict[str, str] = {}


def build_history_prefix(session_id: str) -> str:
    history = chat_histories.get(session_id, [])[-HISTORY_MAX_TURNS:]
    if not history:
        return ""
    lines = []
    for turn in history:
        role = turn.get('role', 'user')
        content = turn.get('content', '')
        if not content:
            continue
        if role == 'user':
            lines.append(f"User: {content}")
        else:
            lines.append(f"Assistant: {content}")
    return "\n".join(lines)


def get_enhanced_system_prompt():
    return """
You are Elliot, a Linux terminal assistant.

Goal: Given a natural language request, output ONE Linux shell command that best accomplishes the task. Do not include explanations or extra text.

Constraints:
- Output ONLY the command (no quotes, no code fences, no commentary)
- Assume a Bash-compatible Linux environment
- Prefer simple, broadly available utilities
- Never output destructive commands unless explicitly requested
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
        self.waiting_for_menu_selection = {}
        self.last_user_question = {}
        self.handled_menus = {}
        self.last_menu_selection_time = {}

    def create_terminal(self, session_id):
        try:
            master, slave = pty.openpty()
            pid = os.fork()
            if pid == 0:
                os.close(master)
                os.dup2(slave, 0)
                os.dup2(slave, 1)
                os.dup2(slave, 2)
                try:
                    os.putenv('TERM', 'xterm-256color')
                    os.putenv('PS1', '\\[\\e[1;32m\\]\\u@\\h \\[\\e[1;34m\\]\\w\\[\\e[0m\\]\\$ ')
                except Exception:
                    pass
                os.execvp('bash', ['bash', '--noprofile', '--norc', '-i'])
            else:
                os.close(slave)
                fcntl.fcntl(master, fcntl.F_SETFL, os.O_NONBLOCK)
                self.terminals[session_id] = {
                    'master': master,
                    'pid': pid,
                    'buffer': '',
                    'output': '',
                    'last_menu_check': 0,
                    'menu_detected': False,
                    'menu_output_cursor': 0,
                    'last_output_length': 0,
                    'output_stable_since': 0
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
                        terminal['last_output_length'] = len(terminal['output'])
                        terminal['output_stable_since'] = 0
                        socketio.emit('terminal_output', {
                            'data': output_data,
                            'session_id': session_id
                        }, room=session_id)
                        
                        current_time = time.time()
                        if current_time - terminal.get('last_menu_check', 0) > 1.0:
                            terminal['last_menu_check'] = current_time
                            if not terminal.get('menu_detected', False) and not self.waiting_for_menu_selection.get(session_id):
                                self._check_for_menu(session_id)
                else:
                    current_time = time.time()
                    if terminal:
                        current_output_length = len(terminal.get('output', ''))
                        if current_output_length == terminal.get('last_output_length', 0):
                            if terminal.get('output_stable_since', 0) == 0:
                                terminal['output_stable_since'] = current_time
                            elif current_time - terminal.get('output_stable_since', 0) > 2.0:
                                if current_time - terminal.get('last_menu_check', 0) > 1.0:
                                    terminal['last_menu_check'] = current_time
                                    if not terminal.get('menu_detected', False) and not self.waiting_for_menu_selection.get(session_id):
                                        self._check_for_menu(session_id)
                        else:
                            terminal['last_output_length'] = current_output_length
                            terminal['output_stable_since'] = 0
            except Exception as e:
                print(f"Error reading terminal: {e}")
                break
        if session_id in self.terminals:
            self._cleanup_terminal(session_id)

    def write_to_terminal(self, session_id, data):
        terminal = self.terminals.get(session_id)
        if terminal:
            try:
                result = os.write(terminal['master'], data.encode('utf-8'))
                return True
            except Exception as e:
                print(f"Error writing to terminal: {e}")
                traceback.print_exc()
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
            except:
                pass
            try:
                os.kill(terminal['pid'], signal.SIGTERM)
            except:
                pass
        self.terminals.pop(session_id, None)

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

    def _check_for_menu(self, session_id):
        """Check if terminal output shows a menu or interactive prompt"""
        try:
            terminal = self.terminals.get(session_id)
            if not terminal:
                return
            
            if self.waiting_for_menu_selection.get(session_id):
                return
            
            output = self.get_output(session_id)
            if not output or len(output) < 50:
                return
            
            recent_output = output[-5000:]
            clean_output = strip_ansi(recent_output)
            
            last_200_chars = clean_output[-200:]
            has_prompt = is_command_completed(last_200_chars)
            
            if has_prompt:
                return
            
            menu_region = clean_output[-1500:]
            menu_hash = hashlib.md5(menu_region.encode()).hexdigest()
            handled_hashes = self.handled_menus.get(session_id, set())
            if menu_hash in handled_hashes:
                return
            
            last_selection_time = self.last_menu_selection_time.get(session_id, 0)
            if time.time() - last_selection_time < 1.0:
                return
            
            menu_indicators = [
                'select an option',
                'choose an option',
                'select option',
                'choose option',
                'press',
                'enter your choice',
                'select:',
                'choice:',
                'option',
                'menu',
            ]
            
            has_numbers = bool(re.search(r'\n\s*[0-9]+[\)\.\-\s:]+[A-Za-z]', clean_output, re.MULTILINE))
            has_indicators = any(indicator.lower() in clean_output.lower() for indicator in menu_indicators)
            
            has_menu_pattern = bool(
                re.search(r'\[[0-9]+\]', clean_output) or 
                re.search(r'\([0-9]+\)', clean_output) or
                re.search(r'^\s*[0-9]+[\.\)]\s+', clean_output, re.MULTILINE) or
                re.search(r'^\s*[0-9]+\s+[A-Z]', clean_output, re.MULTILINE)
            )
            
            output_stable_time = terminal.get('output_stable_since', 0)
            has_been_stable = output_stable_time > 0 and (time.time() - output_stable_time) > 3.0
            
            if has_numbers or has_indicators or has_menu_pattern or (has_been_stable and len(clean_output) > 100):
                terminal['menu_output_cursor'] = len(output)
                self._detect_and_handle_menu(session_id, clean_output, menu_hash)
        except Exception as e:
            print(f"Error checking for menu: {e}")

    def _detect_and_handle_menu(self, session_id, output_text, menu_hash=None):
        """Use LLM to detect menu and extract options"""
        try:
            terminal = self.terminals.get(session_id)
            if not terminal:
                return
            
            terminal['menu_detected'] = True
            self.waiting_for_menu_selection[session_id] = True
            
            if menu_hash:
                if session_id not in self.handled_menus:
                    self.handled_menus[session_id] = set()
                self.handled_menus[session_id].add(menu_hash)
            
            user_context = self.last_user_question.get(session_id, '')
            
            menu_prompt = f"""
You are analyzing terminal output to detect interactive menus.

OUTPUT:
{output_text[-2000:]}

TASK: Determine if this is an interactive menu/prompt requiring user input. If yes, extract:
1. All available options (numbered or labeled)
2. A brief description of what the menu is asking

Format your response as JSON:
{{
  "is_menu": true/false,
  "question": "What is the menu asking?",
  "options": [
    {{"value": "1", "label": "Option 1 description"}},
    {{"value": "2", "label": "Option 2 description"}}
  ]
}}

If it's not a menu, set "is_menu": false.

Return ONLY the JSON, no other text.
"""
            
            response = llm.invoke(menu_prompt)
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                try:
                    menu_data = json.loads(json_match.group(0))
                    if menu_data.get('is_menu') and menu_data.get('options'):
                        self._handle_menu_options(session_id, menu_data, user_context)
                        return
                except json.JSONDecodeError:
                    pass
            
            terminal['menu_detected'] = False
            self.waiting_for_menu_selection[session_id] = False
            
        except Exception as e:
            print(f"Error detecting menu: {e}")
            terminal = self.terminals.get(session_id)
            if terminal:
                terminal['menu_detected'] = False
            self.waiting_for_menu_selection[session_id] = False

    def _handle_menu_options(self, session_id, menu_data, user_context):
        """Handle menu options - always auto-select based on user's original request"""
        try:
            options = menu_data.get('options', [])
            question = menu_data.get('question', 'Select an option')
            
            if not options:
                terminal = self.terminals.get(session_id)
                if terminal:
                    terminal['menu_detected'] = False
                self.waiting_for_menu_selection[session_id] = False
                return
            
            history_prefix = build_history_prefix(session_id)
            
            auto_select_prompt = f"""
You are Elliot, a Linux terminal assistant. A menu has appeared and you need to automatically select the best option based on the user's original request.

USER'S ORIGINAL REQUEST: {user_context if user_context else "User is interacting with this application"}

CONVERSATION HISTORY:
{history_prefix}

MENU QUESTION: {question}

AVAILABLE OPTIONS:
{chr(10).join([f"{opt.get('value', '')}. {opt.get('label', '')}" for opt in options])}

TASK: Analyze the user's request and conversation history. Select the option that best matches what the user wants to accomplish. Be decisive - choose the most logical option even if not 100% certain.

Return ONLY the option value (just the number/letter, e.g., "1", "2", "a", etc.) with no explanation or additional text.
"""
            auto_response = llm.invoke(auto_select_prompt).strip()
            
            auto_response = re.sub(r'[^0-9a-zA-Z]', '', auto_response)
            
            valid_values = [str(opt.get('value', '')).strip() for opt in options]
            
            selected_option = None
            if auto_response in valid_values:
                selected_option = auto_response
            else:
                for val in valid_values:
                    if val.lower() == auto_response.lower():
                        selected_option = val
                        break
                
                if not selected_option:
                    num_match = re.search(r'(\d+)', auto_response)
                    if num_match:
                        num_str = num_match.group(1)
                        if num_str in valid_values:
                            selected_option = num_str
                    
                    if not selected_option and len(valid_values) > 0:
                        selected_option = valid_values[0]
            
            if selected_option:
                selected_label = next((opt.get('label', '') for opt in options if str(opt.get('value', '')).strip() == selected_option), '')
                socketio.emit('menu_auto_selected', {
                    'session_id': session_id,
                    'option': selected_option,
                    'label': selected_label
                }, room=session_id)
                
                self.write_to_terminal(session_id, selected_option + '\n')
                
                self.last_menu_selection_time[session_id] = time.time()
                
            terminal = self.terminals.get(session_id)
            if terminal:
                terminal['menu_detected'] = False
            self.waiting_for_menu_selection[session_id] = False
            
        except Exception as e:
            print(f"Error handling menu options: {e}")
            traceback.print_exc()
            terminal = self.terminals.get(session_id)
            if terminal:
                terminal['menu_detected'] = False
            self.waiting_for_menu_selection[session_id] = False


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


def is_command_completed(output_text):
    if not output_text:
        return False
    prompt_patterns = [
        r'\$ $',
        r'# $',
        r'[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+:.*\$ $',
    ]
    for pattern in prompt_patterns:
        if re.search(pattern, output_text):
            return True
    return False


def detect_command_failure(output_text, command):
    if not output_text:
        return False, "No output"
    
    error_patterns = [
        r'command not found',
        r'No such file or directory',
        r'Permission denied',
        r'Broken pipe',
        r'write failed',
        r'write error',
        r'cannot set terminal process group',
        r'no job control in this shell',
        r'bash: .*: command not found',
        r'Error:',
        r'error:',
        r'failed',
        r'Failed',
        r'not recognized as an internal or external command',
        r'usage: ',
        r'invalid option',
        r'unrecognized option',
        r'could not',
    ]
    
    for pattern in error_patterns:
        if re.search(pattern, output_text, re.IGNORECASE):
            return True, f"Error detected: {pattern}"
    
    clean_output = strip_ansi(output_text).strip()
    if len(clean_output) < 5 and command not in ['clear', 'cd']:
        return True, "Minimal output - possible failure"
    
    if clean_output.strip() == command.strip():
        return True, "Command echoed back - possible failure"
    
    return False, "Command appears successful"




def handle_sudo_password(session_id, sudo_password=None):
    if sudo_password is None:
        sudo_password = os.environ.get('SUDO_PASSWORD')
    if not sudo_password:
        return
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
                    terminal_manager.write_to_terminal(session_id, sudo_password + '\n')
                    break
            except Exception as e:
                break
        time.sleep(2)
    threading.Thread(target=check_and_input_password, daemon=True).start()


def schedule_auto_analyze(session_id, command, start_cursor, user_question: str = 'What do you see in the output?', retry_count: int = 0):
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
                break
        try:
            new_output, current_cursor = terminal_manager.get_output_since(session_id, start_cursor)
            if new_output.strip():
                clean_output = strip_ansi(new_output.strip())
                if clean_output.strip() == command.strip():
                    return
                if len(clean_output.strip()) < 10:
                    return
                failed, error_reason = detect_command_failure(clean_output, command)
                
                if failed and retry_count < 1:
                    corrected_command = generate_corrected_command(command, clean_output, user_question)
                    
                    if corrected_command != command:
                        socketio.emit('terminal_analysis', {
                            'command': command,
                            'analysis': f"Command failed ({error_reason}). Trying corrected version: {corrected_command}",
                            'session_id': session_id
                        }, room=session_id)
                        
                        new_start_cursor = terminal_manager.get_output_cursor(session_id)
                        if terminal_manager.write_to_terminal(session_id, corrected_command + '\n'):
                            if corrected_command.strip().startswith('sudo'):
                                handle_sudo_password(session_id)
                            schedule_auto_analyze(session_id, corrected_command, new_start_cursor, user_question, retry_count + 1)
                        return
                
                analysis_prompt = f"""
You are Elliot, a Linux terminal assistant.

Task: Read OUTPUT and answer USER QUESTION in a friendly, concise sentence. If the question is asking for a value/location
 Otherwise,   give one short sentence summarizing the result.

USER QUESTION: {user_question}
OUTPUT: {clean_output}
"""
                response = llm.invoke(analysis_prompt)
                clean_response = response.strip()
                socketio.emit('terminal_analysis', {
                    'command': command,
                    'analysis': clean_response,
                    'session_id': session_id
                }, room=session_id)
        except Exception as e:
            traceback.print_exc()
    threading.Thread(target=analyze_after_delay, daemon=True).start()


def strip_code_fences(text: str) -> str:
    if not text:
        return text
    text = re.sub(r'```(?:bash|shell)?\s*\n?', '', text)
    text = re.sub(r'\n?```', '', text)
    text = re.sub(r'`([^`]+)`', r'\1', text)
    text = re.sub(r'^\$\s*', '', text)
    return text.strip()


def validate_command(command: str) -> str:
    """Validate and fix common command issues"""
    if not command:
        return command
    
    command = command.strip()
    
    if command == 'cd':
        return 'cd ~'
    if command.startswith('cd ') and len(command.split()) == 2:
        return command
    
    return command


def generate_corrected_command(original_command: str, error_output: str, user_question: str) -> str:
    correction_prompt = f"""
You are Elliot, a Linux terminal assistant. The previous command failed. Generate a corrected version.

ORIGINAL COMMAND: {original_command}
ERROR OUTPUT: {error_output}
USER REQUEST: {user_question}

Generate a corrected command that will work. Common fixes:
- Use proper file paths
- Add missing flags or options
- Use alternative commands
- Fix syntax errors

Return ONLY the corrected command, no explanation.
"""
    
    try:
        response = llm.invoke(correction_prompt)
        corrected = extract_command_from_response(response)
        return corrected if corrected else original_command
    except Exception as e:
        print(f"Error generating corrected command: {e}")
        return original_command


def extract_command_from_response(raw_text: str) -> str:
    if not raw_text:
        return ''
    text = raw_text.strip()
    m = re.search(r"```(?:bash|shell)?\s*\n([\s\S]*?)\n```", text, re.IGNORECASE)
    if m:
        text = m.group(1).strip()
    for line in text.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        if candidate.startswith('$'):
            candidate = candidate.lstrip('$').strip()
        candidate = re.sub(r'\s+', ' ', candidate)
        if candidate:
            return validate_command(candidate)
    return validate_command(text.strip())


@app.route('/api/chat', methods=['POST'])
def chat():
    data = request.get_json()
    user_message = data.get('message', '')
    session_id = data.get('session_id', 'default')
    if not user_message:
        return jsonify({'error': 'No message provided'}), 400

    chat_histories.setdefault(session_id, []).append({'role': 'user', 'content': user_message})

    should_execute, params = parse_and_execute_command(user_message)
    if should_execute:
        try:
            history_prefix = build_history_prefix(session_id)
            full_prompt = f"{get_enhanced_system_prompt()}\n\n{history_prefix}\nUser: {user_message}\n\nReturn ONLY the command to execute:"
            response = llm.invoke(full_prompt)
            if not response:
                command = "echo 'Command not understood'"
                assistant_text = command
            else:
                command = extract_command_from_response(response)
                assistant_text = command or response

            chat_histories.setdefault(session_id, []).append({'role': 'assistant', 'content': assistant_text})

            if command and len(command) > 2:
                terminal_manager.last_user_question[session_id] = user_message
                terminal = terminal_manager.terminals.get(session_id)
                if terminal:
                    terminal['menu_detected'] = False
                    terminal['menu_output_cursor'] = 0
                terminal_manager.waiting_for_menu_selection[session_id] = False
                if session_id in terminal_manager.handled_menus:
                    terminal_manager.handled_menus[session_id].clear()
                terminal_manager.last_menu_selection_time[session_id] = 0
                start_cursor = terminal_manager.get_output_cursor(session_id)
                if terminal_manager.write_to_terminal(session_id, command + '\n'):
                    if command.strip().startswith('sudo'):
                        handle_sudo_password(session_id)
                    schedule_auto_analyze(session_id, command, start_cursor, user_message)
                    return jsonify({'response': "", 'command_executed': True, 'command': command})
                else:
                    return jsonify({'response': f"Failed to execute: {command}", 'command_executed': False})
            else:
                return jsonify({'response': response})
        except Exception as e:
            traceback.print_exc()
            return jsonify({'error': f'Error processing request: {str(e)}'}), 500
    else:
        try:
            history_prefix = build_history_prefix(session_id)
            full_prompt = f"{get_enhanced_system_prompt()}\n\n{history_prefix}\nUser: {user_message}\n\nRespond as a helpful Linux assistant. Keep responses short and direct - maximum 2-3 sentences."
            response = llm.invoke(full_prompt)
            filtered_response = '\n'.join(
                line for line in response.splitlines()
                if not line.strip().lower().startswith("think:")
            )
            chat_histories.setdefault(session_id, []).append({'role': 'assistant', 'content': filtered_response.strip()})
            return jsonify({'response': filtered_response.strip()})
        except Exception as e:
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
            handle_sudo_password(session_id)
        start_cursor = terminal_manager.get_output_cursor(session_id)
        schedule_auto_analyze(session_id, command, start_cursor, f"Execute: {command}")
        chat_histories.setdefault(session_id, []).append({'role': 'assistant', 'content': command})
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
You are Elliot, a Linux terminal assistant.

Task: Read OUTPUT and answer QUESTION in a friendly, concise sentence. If the question asks for a value/location (e.g., how much, what is, where, which, uptime), produce a natural answer like "Your uptime on this device is 3h 36m". Otherwise, give one short sentence summarizing the result.

OUTPUT: {output}
QUESTION: {user_question}
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
    emit('terminal_ready', {'session_id': request.sid})


@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    client_id = sid_to_client_id.pop(sid, None)


@socketio.on('register_client')
def handle_register_client(data):
    try:
        client_id = data.get('client_id') if isinstance(data, dict) else None
        if not client_id:
            emit('terminal_error', {'error': 'Missing client_id in register_client'})
            return
        join_room(client_id)
        sid_to_client_id[request.sid] = client_id
        if client_id not in terminal_manager.terminals:
            if not terminal_manager.create_terminal(client_id):
                emit('terminal_error', {'error': 'Failed to create terminal'})
                return
        emit('terminal_ready', {'session_id': client_id}, room=client_id)
        try:
            buffered = terminal_manager.get_output(client_id)
            if buffered:
                tail = buffered[-10000:]
                socketio.emit('terminal_output', {
                    'data': tail,
                    'session_id': client_id
                }, room=client_id)
        except Exception:
            pass
    except Exception as e:
        emit('terminal_error', {'error': f'Failed to register client: {str(e)}'})


@socketio.on('terminal_input')
def handle_terminal_input(data):
    sid = request.sid
    client_id = sid_to_client_id.get(sid, sid)
    user_input = data.get('input', '')
    if user_input:
        terminal_manager.write_to_terminal(client_id, user_input)


@socketio.on('ai_command')
def handle_ai_command(data):
    sid = request.sid
    client_id = sid_to_client_id.get(sid, sid)
    command = data.get('command', '')
    if command:
        terminal_manager.write_to_terminal(client_id, command + '\n')


@socketio.on('menu_select')
def handle_menu_selection(data):
    sid = request.sid
    client_id = sid_to_client_id.get(sid, sid)
    option = data.get('option', '')
    if option:
        terminal_manager.write_to_terminal(client_id, option + '\n')
        terminal = terminal_manager.terminals.get(client_id)
        if terminal:
            terminal['menu_detected'] = False
        terminal_manager.waiting_for_menu_selection[client_id] = False


if __name__ == '__main__':
    try:
        socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
    finally:
        terminal_manager.cleanup_all()
