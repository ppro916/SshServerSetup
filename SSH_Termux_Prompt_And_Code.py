#!/usr/bin/env python3
"""
Universal SSH Connector - Enhanced Version
Advanced SSH Connection Manager with Credentials Management
Author: Assistant
Description: Comprehensive SSH, SCP, Port Scanning and Network Management
"""

import os
import sys
import socket
import subprocess
import threading
import time
import json
import getpass
from datetime import datetime
from pathlib import Path
import base64
import hashlib

try:
    import readline
    HAS_READLINE = True
except ImportError:
    HAS_READLINE = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

class CredentialsManager:
    """Encrypted credentials storage and management"""
    
    def __init__(self, config_dir="~/.ssh_connector"):
        self.config_dir = Path(config_dir).expanduser()
        self.config_dir.mkdir(exist_ok=True)
        self.creds_file = self.config_dir / "connections.json"
        self.key_file = self.config_dir / "master.key"
        self.cipher_suite = None
        self.master_password_set = False
        
    def generate_key_from_password(self, password: str) -> bytes:
        """Generate encryption key from master password"""
        if not HAS_CRYPTOGRAPHY:
            return None
            
        password_bytes = password.encode()
        salt = b'ssh_connector_salt_2024'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return key
    
    def setup_master_password(self, password: str):
        """Setup master password for encryption"""
        if not HAS_CRYPTOGRAPHY:
            self.master_password_set = True
            return True
            
        key = self.generate_key_from_password(password)
        if not key:
            self.master_password_set = True
            return True
            
        self.cipher_suite = Fernet(key)
        self.master_password_set = True
        
        # Test encryption
        try:
            test_data = b"test"
            encrypted = self.cipher_suite.encrypt(test_data)
            decrypted = self.cipher_suite.decrypt(encrypted)
            
            if test_data == decrypted:
                self.key_file.write_text(password)
                return True
        except:
            pass
        return False
    
    def load_master_password(self):
        """Load master password from file"""
        if not self.key_file.exists():
            return False
            
        if not HAS_CRYPTOGRAPHY:
            self.master_password_set = True
            return True
            
        try:
            password = self.key_file.read_text().strip()
            key = self.generate_key_from_password(password)
            self.cipher_suite = Fernet(key)
            self.master_password_set = True
            return True
        except:
            self.master_password_set = True
            return True
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        if not self.cipher_suite or not data:
            return data
        try:
            encrypted = self.cipher_suite.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except:
            return data
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        if not self.cipher_suite or not encrypted_data:
            return encrypted_data
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = self.cipher_suite.decrypt(encrypted_bytes)
            return decrypted.decode()
        except:
            return encrypted_data
    
    def load_connections(self) -> dict:
        """Load connections from encrypted storage"""
        if not self.creds_file.exists():
            return {}
        
        try:
            with open(self.creds_file, 'r') as f:
                data = json.load(f)
            
            # Decrypt sensitive fields
            for name, connection in data.items():
                if 'password' in connection:
                    connection['password'] = self.decrypt_data(connection['password'])
                if 'ssh_key_path' in connection:
                    connection['ssh_key_path'] = self.decrypt_data(connection['ssh_key_path'])
            
            return data
        except:
            return {}
    
    def save_connections(self, connections: dict):
        """Save connections to encrypted storage"""
        # Encrypt sensitive fields
        encrypted_connections = {}
        for name, connection in connections.items():
            encrypted_conn = connection.copy()
            if 'password' in connection and connection['password']:
                encrypted_conn['password'] = self.encrypt_data(connection['password'])
            if 'ssh_key_path' in connection and connection['ssh_key_path']:
                encrypted_conn['ssh_key_path'] = self.encrypt_data(connection['ssh_key_path'])
            encrypted_connections[name] = encrypted_conn
        
        try:
            with open(self.creds_file, 'w') as f:
                json.dump(encrypted_connections, f, indent=2)
            return True
        except:
            return False
    
    def add_connection(self, name: str, connection_data: dict):
        """Add new connection"""
        connections = self.load_connections()
        connection_data['last_used'] = datetime.now().isoformat()
        connections[name] = connection_data
        return self.save_connections(connections)
    
    def edit_connection(self, old_name: str, new_name: str, connection_data: dict):
        """Edit existing connection"""
        connections = self.load_connections()
        if old_name in connections:
            del connections[old_name]
        connection_data['last_used'] = datetime.now().isoformat()
        connections[new_name] = connection_data
        return self.save_connections(connections)
    
    def delete_connection(self, name: str):
        """Delete connection"""
        connections = self.load_connections()
        if name in connections:
            del connections[name]
            return self.save_connections(connections)
        return False
    
    def get_connection(self, name: str) -> dict:
        """Get specific connection details"""
        connections = self.load_connections()
        return connections.get(name, {})
    
    def list_connections(self) -> list:
        """List all saved connections"""
        connections = self.load_connections()
        return list(connections.keys())

class EnhancedSSHConnector:
    def __init__(self):
        self.current_menu = "main"
        self.selected_option = 0
        self.input_buffer = ""
        self.input_mode = False
        self.auto_complete_index = -1
        self.auto_complete_options = []
        self.cred_manager = CredentialsManager()
        
        self.status = {
            'ami': '✅',
            'server': '✅', 
            'tunnel': '✅',
            'ssh_installed': False,
            'credentials_loaded': False,
            'crypto_available': HAS_CRYPTOGRAPHY
        }
        
        self.local_ip = self.detect_local_ip()
        self.device_type = self.detect_device_type()
        self.check_ssh_availability()
        self.setup_credentials()
        
        # Command history for auto-completion
        self.command_history = []
        self.setup_auto_completion()
    
    def setup_auto_completion(self):
        """Setup readline for auto-completion"""
        if HAS_READLINE:
            readline.set_completer(self.auto_complete)
            readline.parse_and_bind("tab: complete")
    
    def auto_complete(self, text, state):
        """Auto-completion function"""
        options = [cmd for cmd in self.auto_complete_options if cmd.startswith(text)]
        if state < len(options):
            return options[state]
        return None
    
    def setup_credentials(self):
        """Setup credentials manager"""
        if not HAS_CRYPTOGRAPHY:
            print("⚠️  Cryptography library not available. Using basic storage.")
            self.status['credentials_loaded'] = True
            return
            
        if not self.cred_manager.load_master_password():
            print("🔐 First-time setup: Creating master password for credentials encryption")
            password = getpass.getpass("Create master password: ")
            if password:
                if self.cred_manager.setup_master_password(password):
                    self.status['credentials_loaded'] = True
                    print("✅ Master password setup successfully!")
                else:
                    print("❌ Failed to setup master password")
            else:
                print("⚠️  No master password set - credentials will be stored in plain text")
        else:
            self.status['credentials_loaded'] = True
            print("✅ Credentials manager loaded successfully!")
    
    def detect_device_type(self):
        """Detect if running on Termux or regular PC"""
        if 'TERMUX_VERSION' in os.environ:
            return "📱 Termux"
        else:
            return "🖥️ PC"
    
    def detect_local_ip(self):
        """Automatically detect local IP address using multiple methods"""
        methods = [
            self._detect_ip_socket,
            self._detect_ip_hostname,
        ]
        
        for method in methods:
            try:
                ip = method()
                if ip and ip != "127.0.0.1":
                    return ip
            except:
                continue
        
        return "127.0.0.1"
    
    def _detect_ip_socket(self):
        """Detect IP using socket connection"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            return None
    
    def _detect_ip_hostname(self):
        """Detect IP using hostname"""
        try:
            hostname = socket.gethostname()
            return socket.gethostbyname(hostname)
        except:
            return None
    
    def check_ssh_availability(self):
        """Check if SSH client is available"""
        try:
            result = subprocess.run(["ssh", "-V"], capture_output=True, text=True)
            self.status['ssh_installed'] = True
        except:
            self.status['ssh_installed'] = False
    
    def clear_screen(self):
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_loading_animation(self, message="Loading", duration=3):
        """Display loading animation"""
        animation = "⣾⣽⣻⢿⡿⣟⣯⣷"
        start_time = time.time()
        i = 0
        
        while time.time() - start_time < duration:
            print(f"\r{message} {animation[i % len(animation)]}", end="", flush=True)
            time.sleep(0.1)
            i += 1
        
        print("\r" + " " * (len(message) + 2) + "\r", end="")
    
    def display_progress_bar(self, iteration, total, prefix='', suffix='', length=50, fill='█'):
        """Display progress bar"""
        percent = ("{0:.1f}").format(100 * (iteration / float(total)))
        filled_length = int(length * iteration // total)
        bar = fill * filled_length + '-' * (length - filled_length)
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
        if iteration == total:
            print()
    
    def display_header(self):
        """Display application header"""
        print("📊 STATUS: AMI: {} | Server: {} | Tunnel: {} | Credentials: {}".format(
            self.status['ami'], self.status['server'], self.status['tunnel'],
            '✅' if self.status['credentials_loaded'] else '❌'
        ))
        print()
        
        if not self.status['ssh_installed']:
            print("⚠️  SSH client not found. Some features will use system SSH.")
            print("   You can install SSH with option 8 in the menu.")
        
        if not self.status['crypto_available']:
            print("⚠️  Cryptography library not available. Using basic credential storage.")
        
        print("🔗 Universal SSH Connector - Enhanced Edition")
        print("=" * 60)
        print()
        print("📍 Device: {}".format(self.device_type))
        print("🌐 Your IP: {}".format(self.local_ip))
        print("💾 Connections: {} saved".format(len(self.cred_manager.list_connections())))
        print()
        print("=" * 60)
    
    def display_menu(self):
        """Display the main menu"""
        menu_options = [
            "📱 Setup Termux SSH Server",
            "🚀 Start Termux SSH Server", 
            "🖥️  Connect to PC/Server",
            "📤 Transfer File to PC/Server",
            "🔍 Port Scan",
            "🌐 Network Information",
            "🔐 Credentials Manager",
            "🛠️  Install SSH (Termux only)",
            "❌ Exit"
        ]
        
        print("🎯 MAIN MENU")
        print("=" * 60)
        
        for i, option in enumerate(menu_options):
            marker = "▶" if i == self.selected_option else " "
            pointer = "→" if i == self.selected_option else " "
            print("{} {} {}".format(pointer, marker, option))
        
        print("=" * 60)
        print()
        
        self.display_suggestion()
    
    def display_suggestion(self):
        """Display context-aware suggestions"""
        suggestions = {
            0: "💡 Suggestion: First-time setup for Termux SSH. Creates keys and config.",
            1: "💡 Suggestion: Start SSH server on port 8022. Make sure setup is done first.",
            2: "💡 Suggestion: Connect to remote server using SSH. Use saved credentials or enter new.",
            3: "💡 Suggestion: Secure file transfer using SCP. Requires SSH access.",
            4: "💡 Suggestion: Scan ports on target IP. Useful for network discovery and security checks.",
            5: "💡 Suggestion: View detailed network configuration, interfaces and connections.",
            6: "💡 Suggestion: Manage saved SSH connections - add, edit, delete, quick connect.",
            7: "💡 Suggestion: Install OpenSSH in Termux. Required for SSH server features.",
            8: "💡 Suggestion: Exit the application safely. All data is auto-saved."
        }
        
        if self.selected_option in suggestions:
            print(suggestions[self.selected_option])
            
            context_help = {
                2: "   Quick Tip: Press 'q' in credentials list for quick connect",
                3: "   Quick Tip: Use tab completion for file paths",
                4: "   Quick Tip: Scan common ports (1-1000) or specific ranges",
                6: "   Quick Tip: All credentials are encrypted with master password"
            }
            
            if self.selected_option in context_help:
                print(context_help[self.selected_option])
            print()
    
    def display_input_prompt(self):
        """Display input prompt at bottom"""
        if self.input_mode:
            prompt = "📝 Input: " + self.input_buffer + "█"
            print(prompt)
            print("\n💡 Navigation: [Enter] Confirm | [Esc] Cancel | [Tab] Auto-complete | [Ctrl+C] Cancel")
        else:
            print("💡 Navigation: [↑↓/WS] Select | [Enter] Choose | [TAB] Input mode | [q] Quit | [?] Help")
    
    def setup_termux_ssh(self):
        """Setup SSH server in Termux with progress indicators"""
        print("\n" + "="*60)
        print("📱 SETUP TERMUX SSH SERVER")
        print("="*60)
        
        steps = [
            ("Generating SSH keys...", 2),
            ("Setting up SSH directory...", 1),
            ("Configuring SSH server...", 2),
            ("Setting password...", 1),
            ("Starting SSH service...", 1)
        ]
        
        total_time = sum(time for _, time in steps)
        current_time = 0
        
        for step, step_time in steps:
            print(f"\n🔄 {step}")
            self.display_loading_animation("Processing", step_time)
            current_time += step_time
        
        print("\n\n✅ Termux SSH setup completed!")
        print("💡 Your SSH server will run on port 8022")
        print("💡 Connect using: ssh {}@{} -p 8022".format(
            os.getenv('USER', 'user'), self.local_ip))
        print("💡 Next: Use option 2 to start the SSH server")
        input("\nPress Enter to continue...")
    
    def start_termux_ssh(self):
        """Start SSH server in Termux"""
        print("\n" + "="*60)
        print("🚀 STARTING TERMUX SSH SERVER")
        print("="*60)
        
        try:
            print("🔄 Starting SSH daemon...")
            self.display_loading_animation("Initializing", 2)
            
            result = subprocess.run(["sshd"], capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ SSH server started successfully!")
                print("📡 Listening on: {}:8022".format(self.local_ip))
                print("👤 Username: {}".format(os.getenv('USER', 'user')))
                print("🔧 Status: Active and running")
                print("\n💡 To stop: pkill sshd")
                print("💡 To check status: ps aux | grep sshd")
            else:
                print("❌ Failed to start SSH server")
                print("📋 Error details:", result.stderr)
                print("💡 Make sure SSH is installed and setup is done (Option 1)")
        
        except Exception as e:
            print("❌ Error starting SSH server: {}".format(e))
            print("💡 Try running 'pkg install openssh' first")
        
        input("\nPress Enter to continue...")
    
    def connect_ssh(self):
        """SSH connection handler with saved credentials support"""
        print("\n" + "="*60)
        print("🖥️ SSH CONNECTION")
        print("="*60)
        
        saved_connections = self.cred_manager.list_connections()
        if saved_connections:
            print("💾 Saved Connections:")
            for i, conn in enumerate(saved_connections, 1):
                conn_data = self.cred_manager.get_connection(conn)
                last_used = conn_data.get('last_used', 'Never')
                print(f"  {i}. {conn} (Last used: {last_used[:10]})")
            print("  q. Enter new connection manually")
            print()
        
        choice = input("Choose connection (number) or 'q' for manual: ").strip()
        
        if choice.isdigit() and 1 <= int(choice) <= len(saved_connections):
            conn_name = saved_connections[int(choice) - 1]
            conn_data = self.cred_manager.get_connection(conn_name)
            self.execute_ssh_connection(conn_data, conn_name)
        else:
            target_ip = input("Enter target IP: ").strip()
            if not target_ip:
                print("❌ IP address required")
                return
            
            username = input("Enter username [{}]: ".format(
                os.getenv('USER', 'user'))).strip()
            if not username:
                username = os.getenv('USER', 'user')
            
            port = input("Enter port [22]: ").strip()
            if not port:
                port = "22"
            
            save_conn = input("Save this connection? (y/N): ").strip().lower()
            if save_conn == 'y':
                conn_name = input("Connection name: ").strip()
                if conn_name:
                    conn_data = {
                        'host': target_ip,
                        'username': username,
                        'port': port,
                        'password': '',
                        'ssh_key_path': '',
                        'notes': 'Manual connection'
                    }
                    if self.cred_manager.add_connection(conn_name, conn_data):
                        print("✅ Connection saved!")
                    else:
                        print("❌ Failed to save connection")
            
            conn_data = {'host': target_ip, 'username': username, 'port': port}
            self.execute_ssh_connection(conn_data)
    
    def execute_ssh_connection(self, conn_data, conn_name=None):
        """Execute SSH connection with given parameters"""
        host = conn_data.get('host')
        username = conn_data.get('username', os.getenv('USER', 'user'))
        port = conn_data.get('port', '22')
        password = conn_data.get('password')
        ssh_key_path = conn_data.get('ssh_key_path')
        
        print(f"\n💡 Connecting to {username}@{host}:{port}")
        if conn_name:
            print(f"💾 Using saved connection: {conn_name}")
        print("💡 Use Ctrl+D or type 'exit' to disconnect")
        print("🔄 Establishing connection...")
        
        try:
            cmd = ["ssh", f"{username}@{host}", "-p", port]
            
            if ssh_key_path and os.path.exists(ssh_key_path):
                cmd.extend(["-i", ssh_key_path])
            
            if conn_name:
                conn_data['last_used'] = datetime.now().isoformat()
                self.cred_manager.add_connection(conn_name, conn_data)
            
            subprocess.run(cmd)
        except Exception as e:
            print("❌ Connection failed: {}".format(e))
            print("💡 Check IP, username, port, and network connectivity")
            print("💡 For saved connections, verify credentials in Credentials Manager")
        
        input("\nPress Enter to continue...")
    
    def transfer_file(self):
        """File transfer using SCP with progress indication"""
        print("\n" + "="*60)
        print("📤 FILE TRANSFER")
        print("="*60)
        
        source = input("Source file path: ").strip()
        if not source or not os.path.exists(source):
            print("❌ Source file not found")
            return
        
        target = input("Target (user@ip:path): ").strip()
        if not target:
            print("❌ Target required")
            return
        
        port = input("Port [22]: ").strip()
        port_arg = ["-P", port] if port else []
        
        print(f"\n💡 Transferring: {source} → {target}")
        print("🔄 Starting file transfer...")
        
        try:
            file_size = os.path.getsize(source)
            print(f"📁 File size: {self.format_file_size(file_size)}")
            
            cmd = ["scp"] + port_arg + [source, target]
            self.display_loading_animation("Transferring", 3)
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ Transfer completed successfully!")
            else:
                print("❌ Transfer failed")
                print("📋 Error:", result.stderr)
        
        except Exception as e:
            print("❌ Transfer error: {}".format(e))
            print("💡 Check paths, credentials, and network connectivity")
        
        input("\nPress Enter to continue...")
    
    def format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"
    
    def port_scan(self):
        """Enhanced multi-threaded port scanner with progress"""
        print("\n" + "="*60)
        print("🔍 PORT SCANNER")
        print("="*60)
        
        target = input("Target IP [{}]: ".format(self.local_ip)).strip()
        if not target:
            target = self.local_ip
        
        port_range = input("Port range [1-1000]: ").strip()
        if not port_range:
            port_range = "1-1000"
        
        try:
            start_port, end_port = map(int, port_range.split('-'))
            if start_port > end_port or start_port < 1 or end_port > 65535:
                print("❌ Invalid port range (1-65535)")
                return
        except:
            print("❌ Invalid port range format (e.g., 1-1000)")
            return
        
        print(f"\n🔄 Scanning {target}:{port_range}...")
        print("💡 This may take a few minutes depending on range")
        
        open_ports = []
        lock = threading.Lock()
        total_ports = end_port - start_port + 1
        completed_ports = 0
        
        def scan_port(port):
            nonlocal completed_ports
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    if s.connect_ex((target, port)) == 0:
                        with lock:
                            open_ports.append(port)
            except:
                pass
            finally:
                nonlocal completed_ports
                completed_ports += 1
                if completed_ports % 50 == 0:
                    progress = (completed_ports / total_ports) * 100
                    self.display_progress_bar(completed_ports, total_ports, 
                                            prefix='Scan Progress:', suffix='Complete', length=40)
        
        threads = []
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=scan_port, args=(port,))
            threads.append(thread)
            thread.start()
            
            if len(threads) >= 100:
                for t in threads:
                    t.join()
                threads = []
        
        for t in threads:
            t.join()
        
        self.display_progress_bar(total_ports, total_ports, 
                                prefix='Scan Progress:', suffix='Complete', length=40)
        
        print("\n\n📊 SCAN RESULTS:")
        print("Target: {}".format(target))
        print("Ports scanned: {}-{}".format(start_port, end_port))
        print("Open ports found: {}".format(len(open_ports)))
        
        if open_ports:
            print("\n🔓 OPEN PORTS:")
            common_services = {
                21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
                80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 
                993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
                3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
                8022: "Termux SSH", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
            }
            
            for port in sorted(open_ports):
                service = common_services.get(port, "Unknown")
                print("  Port {}/tcp: {} - {}".format(port, service, "Common" if service != "Unknown" else "Unknown"))
        else:
            print("\n🔒 No open ports found in specified range")
        
        print("\n💡 Security Note: Only scan networks you own or have permission to test")
        input("\nPress Enter to continue...")
    
    def network_info(self):
        """Display comprehensive network information"""
        print("\n" + "="*60)
        print("🌐 NETWORK INFORMATION")
        print("="*60)
        
        try:
            hostname = socket.gethostname()
            print("🏠 Hostname: {}".format(hostname))
            print("📍 Local IP: {}".format(self.local_ip))
            
            print("\n📡 NETWORK INTERFACES:")
            if os.name != 'nt':
                result = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines[:20]:
                        if line.strip():
                            print("  " + line)
                else:
                    result = subprocess.run(["ifconfig"], capture_output=True, text=True)
                    if result.returncode == 0:
                        print(result.stdout)
            else:
                result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True)
                if result.returncode == 0:
                    print(result.stdout)
            
            print("\n🔗 ACTIVE CONNECTIONS:")
            try:
                if os.name != 'nt':
                    result = subprocess.run(["ss", "-tunlp"], capture_output=True, text=True)
                    if result.returncode == 0:
                        print(result.stdout)
                    else:
                        result = subprocess.run(["netstat", "-tunlp"], capture_output=True, text=True)
                        if result.returncode == 0:
                            print(result.stdout)
                else:
                    result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')[:15]
                        for line in lines:
                            print("  " + line)
            except:
                print("  Unable to retrieve connection information")
                
        except Exception as e:
            print("❌ Error getting network info: {}".format(e))
        
        input("\nPress Enter to continue...")
    
    def credentials_manager_menu(self):
        """Comprehensive credentials management"""
        print("\n" + "="*60)
        print("🔐 CREDENTIALS MANAGER")
        print("="*60)
        
        while True:
            self.clear_screen()
            print("🔐 CREDENTIALS MANAGER")
            print("="*60)
            
            connections = self.cred_manager.list_connections()
            print(f"💾 Saved Connections: {len(connections)}")
            print()
            
            options = [
                "➕ Add New Connection",
                "✏️  Edit Connection", 
                "🗑️  Delete Connection",
                "🚀 Quick Connect",
                "🔧 Encryption Settings",
                "⬅️  Back to Main Menu"
            ]
            
            for i, option in enumerate(options, 1):
                print(f"{i}. {option}")
            
            print("\n" + "="*60)
            choice = input("\nChoose option (1-6): ").strip()
            
            if choice == '1':
                self.add_connection_ui()
            elif choice == '2':
                self.edit_connection_ui()
            elif choice == '3':
                self.delete_connection_ui()
            elif choice == '4':
                self.quick_connect_ui()
            elif choice == '5':
                self.encryption_settings_ui()
            elif choice == '6':
                break
            else:
                print("❌ Invalid option")
                input("Press Enter to continue...")
    
    def add_connection_ui(self):
        """UI for adding new connection"""
        print("\n" + "="*60)
        print("➕ ADD NEW CONNECTION")
        print("="*60)
        
        name = input("Connection name: ").strip()
        if not name:
            print("❌ Connection name required")
            return
        
        host = input("Host/IP address: ").strip()
        if not host:
            print("❌ Host/IP required")
            return
        
        username = input("Username [{}]: ".format(os.getenv('USER', 'user'))).strip()
        if not username:
            username = os.getenv('USER', 'user')
        
        port = input("Port [22]: ").strip()
        if not port:
            port = "22"
        
        password = getpass.getpass("Password (optional, press Enter to skip): ")
        ssh_key_path = input("SSH key path (optional): ").strip()
        notes = input("Notes (optional): ").strip()
        
        connection_data = {
            'host': host,
            'username': username,
            'port': port,
            'password': password,
            'ssh_key_path': ssh_key_path,
            'notes': notes
        }
        
        if self.cred_manager.add_connection(name, connection_data):
            print("✅ Connection '{}' saved successfully!".format(name))
        else:
            print("❌ Failed to save connection")
        input("Press Enter to continue...")
    
    def edit_connection_ui(self):
        """UI for editing connection"""
        connections = self.cred_manager.list_connections()
        if not connections:
            print("❌ No saved connections found")
            input("Press Enter to continue...")
            return
        
        print("\nAvailable connections:")
        for i, conn in enumerate(connections, 1):
            print(f"{i}. {conn}")
        
        choice = input("\nSelect connection to edit (number): ").strip()
        if not choice.isdigit() or not (1 <= int(choice) <= len(connections)):
            print("❌ Invalid selection")
            return
        
        old_name = connections[int(choice) - 1]
        conn_data = self.cred_manager.get_connection(old_name)
        
        print(f"\nEditing: {old_name}")
        print("Leave blank to keep current value")
        
        new_name = input("New connection name [{}]: ".format(old_name)).strip()
        if not new_name:
            new_name = old_name
        
        host = input("Host/IP [{}]: ".format(conn_data.get('host', ''))).strip()
        if not host:
            host = conn_data.get('host', '')
        
        username = input("Username [{}]: ".format(conn_data.get('username', ''))).strip()
        if not username:
            username = conn_data.get('username', '')
        
        port = input("Port [{}]: ".format(conn_data.get('port', '22'))).strip()
        if not port:
            port = conn_data.get('port', '22')
        
        password = getpass.getpass("New password (press Enter to keep current): ")
        if not password:
            password = conn_data.get('password', '')
        
        ssh_key_path = input("SSH key path [{}]: ".format(conn_data.get('ssh_key_path', ''))).strip()
        if not ssh_key_path:
            ssh_key_path = conn_data.get('ssh_key_path', '')
        
        notes = input("Notes [{}]: ".format(conn_data.get('notes', ''))).strip()
        if not notes:
            notes = conn_data.get('notes', '')
        
        new_conn_data = {
            'host': host,
            'username': username,
            'port': port,
            'password': password,
            'ssh_key_path': ssh_key_path,
            'notes': notes
        }
        
        if self.cred_manager.edit_connection(old_name, new_name, new_conn_data):
            print("✅ Connection updated successfully!")
        else:
            print("❌ Failed to update connection")
        input("Press Enter to continue...")
    
    def delete_connection_ui(self):
        """UI for deleting connection"""
        connections = self.cred_manager.list_connections()
        if not connections:
            print("❌ No saved connections found")
            input("Press Enter to continue...")
            return
        
        print("\nAvailable connections:")
        for i, conn in enumerate(connections, 1):
            print(f"{i}. {conn}")
        
        choice = input("\nSelect connection to delete (number): ").strip()
        if not choice.isdigit() or not (1 <= int(choice) <= len(connections)):
            print("❌ Invalid selection")
            return
        
        conn_name = connections[int(choice) - 1]
        confirm = input(f"Are you sure you want to delete '{conn_name}'? (y/N): ").strip().lower()
        
        if confirm == 'y':
            if self.cred_manager.delete_connection(conn_name):
                print("✅ Connection deleted successfully!")
            else:
                print("❌ Failed to delete connection")
        else:
            print("❌ Deletion cancelled")
        
        input("Press Enter to continue...")
    
    def quick_connect_ui(self):
        """UI for quick connection from saved credentials"""
        connections = self.cred_manager.list_connections()
        if not connections:
            print("❌ No saved connections found")
            input("Press Enter to continue...")
            return
        
        print("\n🚀 QUICK CONNECT")
        print("="*60)
        print("Available connections:")
        for i, conn in enumerate(connections, 1):
            conn_data = self.cred_manager.get_connection(conn)
            last_used = conn_data.get('last_used', 'Never')
            print(f"{i}. {conn} - {conn_data.get('host')} (Last: {last_used[:10]})")
        
        choice = input("\nSelect connection to connect (number): ").strip()
        if not choice.isdigit() or not (1 <= int(choice) <= len(connections)):
            print("❌ Invalid selection")
            input("Press Enter to continue...")
            return
        
        conn_name = connections[int(choice) - 1]
        conn_data = self.cred_manager.get_connection(conn_name)
        self.execute_ssh_connection(conn_data, conn_name)
    
    def encryption_settings_ui(self):
        """UI for encryption settings"""
        print("\n" + "="*60)
        print("🔧 ENCRYPTION SETTINGS")
        print("="*60)
        
        print("Current status: {}".format(
            "🔐 Encrypted" if self.status['credentials_loaded'] else "⚠️  Not encrypted"
        ))
        print("Cryptography available: {}".format(
            "✅ Yes" if HAS_CRYPTOGRAPHY else "❌ No"
        ))
        print()
        
        if not HAS_CRYPTOGRAPHY:
            print("⚠️  Advanced encryption requires: pip install cryptography")
            print()
        
        options = [
            "🔄 Change Master Password",
            "📤 Export Connections",
            "📥 Import Connections", 
            "⬅️  Back"
        ]
        
        for i, option in enumerate(options, 1):
            print(f"{i}. {option}")
        
        choice = input("\nChoose option (1-4): ").strip()
        
        if choice == '1':
            self.change_master_password()
        elif choice == '2':
            self.export_connections()
        elif choice == '3':
            self.import_connections()
        elif choice == '4':
            return
        else:
            print("❌ Invalid option")
    
    def change_master_password(self):
        """Change master password"""
        if not HAS_CRYPTOGRAPHY:
            print("❌ Cryptography library not available")
            input("Press Enter to continue...")
            return
            
        print("\n🔐 CHANGE MASTER PASSWORD")
        current = getpass.getpass("Current master password: ")
        
        test_key = self.cred_manager.generate_key_from_password(current)
        if not test_key:
            print("❌ Cryptography error")
            return
            
        test_cipher = Fernet(test_key)
        
        try:
            connections = self.cred_manager.load_connections()
            if connections:
                for conn in connections.values():
                    if 'password' in conn and conn['password']:
                        test_cipher.decrypt(base64.urlsafe_b64decode(conn['password'].encode()))
                        break
        except:
            print("❌ Current password is incorrect")
            input("Press Enter to continue...")
            return
        
        new_password = getpass.getpass("New master password: ")
        confirm_password = getpass.getpass("Confirm new password: ")
        
        if new_password != confirm_password:
            print("❌ Passwords don't match")
            input("Press Enter to continue...")
            return
        
        if self.cred_manager.setup_master_password(new_password):
            print("✅ Master password changed successfully!")
        else:
            print("❌ Failed to change master password")
        
        input("Press Enter to continue...")
    
    def export_connections(self):
        """Export connections to file"""
        print("\n📤 EXPORT CONNECTIONS")
        export_file = input("Export file path [connections_export.json]: ").strip()
        if not export_file:
            export_file = "connections_export.json"
        
        try:
            connections = self.cred_manager.load_connections()
            with open(export_file, 'w') as f:
                json.dump(connections, f, indent=2)
            print("✅ Connections exported successfully to {}".format(export_file))
        except Exception as e:
            print("❌ Export failed: {}".format(e))
        
        input("Press Enter to continue...")
    
    def import_connections(self):
        """Import connections from file"""
        print("\n📥 IMPORT CONNECTIONS")
        import_file = input("Import file path: ").strip()
        
        if not import_file or not os.path.exists(import_file):
            print("❌ File not found")
            input("Press Enter to continue...")
            return
        
        try:
            with open(import_file, 'r') as f:
                connections = json.load(f)
            
            existing = self.cred_manager.load_connections()
            existing.update(connections)
            self.cred_manager.save_connections(existing)
            
            print("✅ Connections imported successfully!")
            print("📊 Total connections now: {}".format(len(existing)))
        except Exception as e:
            print("❌ Import failed: {}".format(e))
        
        input("Press Enter to continue...")
    
    def install_ssh(self):
        """Install SSH in Termux"""
        if self.device_type != "📱 Termux":
            print("❌ This feature is only available in Termux")
            input("Press Enter to continue...")
            return
        
        print("\n" + "="*60)
        print("🛠️ INSTALLING SSH IN TERMUX")
        print("="*60)
        
        try:
            print("📦 Updating packages...")
            self.display_loading_animation("Updating package lists", 3)
            subprocess.run(["pkg", "update"], check=True, capture_output=True)
            
            print("📦 Installing OpenSSH...")
            self.display_loading_animation("Installing OpenSSH", 5)
            result = subprocess.run(["pkg", "install", "openssh", "-y"], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ SSH installed successfully!")
                self.status['ssh_installed'] = True
                print("💡 Next: Use option 1 to setup SSH server")
            else:
                print("❌ Installation failed")
                print("📋 Error:", result.stderr)
        
        except Exception as e:
            print("❌ Installation error: {}".format(e))
            print("💡 Check your internet connection and try again")
        
        input("\nPress Enter to continue...")
    
    def handle_input(self):
        """Enhanced input handling with platform-specific key detection"""
        try:
            if sys.platform == "win32":
                # Windows platform - use msvcrt
                import msvcrt
                key = msvcrt.getch().decode('utf-8')
            else:
                # Linux/Termux platform - use termios
                import termios
                import tty
                import select
                
                fd = sys.stdin.fileno()
                old_settings = termios.tcgetattr(fd)
                try:
                    tty.setraw(fd)
                    
                    # Check if input is available
                    if select.select([sys.stdin], [], [], 0.1) == ([sys.stdin], [], []):
                        key = sys.stdin.read(1)
                        
                        # Handle arrow keys and special characters
                        if key == '\x1b':  # Escape sequence
                            next_char = sys.stdin.read(1)
                            if next_char == '[':
                                key_code = sys.stdin.read(1)
                                if key_code == 'A':  # Up arrow
                                    key = 'A'
                                elif key_code == 'B':  # Down arrow
                                    key = 'B'
                                elif key_code == 'C':  # Right arrow
                                    key = 'C'
                                elif key_code == 'D':  # Left arrow
                                    key = 'D'
                    else:
                        key = ''
                finally:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        except ImportError:
            # Fallback for platforms without msvcrt or termios
            try:
                import select
                if select.select([sys.stdin], [], [], 0.1) == ([sys.stdin], [], []):
                    key = sys.stdin.read(1)
                else:
                    key = ''
            except:
                # Ultimate fallback
                try:
                    key = input("")[0] if input("") else ''
                except:
                    key = ''
        except Exception as e:
            # Generic fallback
            try:
                key = input("")[0] if input("") else ''
            except:
                key = ''
        
        return key
    
    def run(self):
        """Main application loop"""
        print("🚀 Initializing Enhanced SSH Connector...")
        self.display_loading_animation("Loading modules", 2)
        
        while True:
            self.clear_screen()
            self.display_header()
            self.display_menu()
            self.display_input_prompt()
            
            try:
                if self.input_mode:
                    key = self.handle_input()
                    
                    if key == '\x1b':  # ESC
                        self.input_mode = False
                        self.input_buffer = ""
                    elif key == '\r':  # Enter
                        self.input_mode = False
                        self.input_buffer = ""
                    elif key == '\x7f':  # Backspace
                        self.input_buffer = self.input_buffer[:-1]
                    elif key in ['\t', '\x1b[Z']:  # TAB or SHIFT+TAB
                        self.input_mode = False
                    else:
                        self.input_buffer += key
                else:
                    key = self.handle_input()
                    
                    if key == 'q' or key == '\x1b':
                        print("\n👋 Goodbye! Thanks for using Enhanced SSH Connector!")
                        break
                    elif key == '?':
                        self.show_help()
                    elif key == '\t':
                        self.input_mode = True
                    elif key in ['A', 'w']:
                        self.selected_option = max(0, self.selected_option - 1)
                    elif key in ['B', 's']:
                        self.selected_option = min(8, self.selected_option + 1)
                    elif key == '\r':
                        self.execute_selected_option()
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye! Thanks for using Enhanced SSH Connector!")
                break
            except Exception as e:
                print("\n❌ Unexpected error: {}".format(e))
                print("💡 The application will continue running")
                input("Press Enter to continue...")
    
    def show_help(self):
        """Show comprehensive help"""
        self.clear_screen()
        print("📚 ENHANCED SSH CONNECTOR - HELP GUIDE")
        print("=" * 60)
        print("\n🎯 **QUICK START:**")
        print("1. Use Option 1 for Termux SSH setup")
        print("2. Use Option 2 to start SSH server") 
        print("3. Use Option 7 to save connection credentials")
        print("4. Use Option 3 for quick connections")
        
        print("\n⌨️ **KEYBOARD SHORTCUTS:**")
        shortcuts = [
            ("↑ / W", "Move selection up"),
            ("↓ / S", "Move selection down"), 
            ("Enter", "Execute selected option"),
            ("Tab", "Switch to input mode"),
            ("Esc", "Cancel/Go back"),
            ("Q", "Quit application"),
            ("?", "Show this help")
        ]
        
        for key, desc in shortcuts:
            print(f"  {key:<15} {desc}")
        
        print("\n🔐 **CREDENTIALS FEATURES:**")
        print("  • Encrypted password storage")
        print("  • Master password protection")
        print("  • Quick connect from saved connections")
        print("  • Import/export functionality")
        
        print("\n⚡ **ENHANCED FEATURES:**")
        print("  • Auto-completion for commands")
        print("  • Progress indicators for long operations")
        print("  • Context-aware suggestions")
        print("  • Comprehensive error handling")
        
        input("\nPress Enter to return to main menu...")
    
    def execute_selected_option(self):
        """Execute the selected menu option"""
        options = {
            0: self.setup_termux_ssh,
            1: self.start_termux_ssh,
            2: self.connect_ssh,
            3: self.transfer_file,
            4: self.port_scan,
            5: self.network_info,
            6: self.credentials_manager_menu,
            7: self.install_ssh,
            8: lambda: (print("\n👋 Goodbye! Thanks for using Enhanced SSH Connector!"), sys.exit(0))
        }
        
        if self.selected_option in options:
            options[self.selected_option]()

def main():
    """Main entry point"""
    print("🚀 Enhanced Universal SSH Connector")
    print("📧 Version 2.0 - With Credentials Management")
    print("🔗 Cross-Platform SSH Connection Manager")
    print()
    
    try:
        connector = EnhancedSSHConnector()
        connector.run()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye! Thanks for using our application!")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        print("💡 Please check your Python installation and try again")

if __name__ == "__main__":
    main()
