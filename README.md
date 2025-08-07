# clientask.py
Gathering Intelligence & Credentials

Browser cookies & passwords (Chrome, Firefox, Edge, etc.)

System (host, user, OS, domain)

Wi-Fi, VPN, RDP, email, database connection strings

Financial files (Excel, CSV, PDF, .docx documents, etc.)

Crypto wallet files (Bitcoin, Electrum, Exodus, Ethereum keystores)

Multimedia Collection & Keylogging

Periodic screenshots (PIL.ImageGrab)

Audio recording via sounddevice + FLAC encoding

Windows low-level keylogger hook (WH_KEYBOARD_LL)

Anti-Forensics & Evasion

Sandbox/debugger/VM detection (IsDebuggerPresent, CPUID check, registry, mouse movement)

Placeholder hollowing process, memory patching, obfuscated sleep

Turns off the real-time AV monitor (PowerShell)

Hide processes, deploy decoy (notepad.exe, calc.exe)

Persistence

Registry Run keys, RunOnce, Policies\Explorer\Run

Scheduled Task (XML via schtasks)

WMI event consumer binding (PowerShell script)

UAC bypass via hijack fodhelper.exe or runas

Encrypted Logging

Internal logs are AES-CFB encrypted to temporary files, with static keys

Read & cleanup logs function

Command-and-Control (C2) Loop

EncryptedCommunicator: AES session key + RSA public key for encrypted payload

Exfiltrator Data:

HTTPS POST to https://C2_DOMAIN:8443/api/v1/collect

Fallback DNS tunneling (base32 subdomain queries)

ICMP fallback (ping with payload in options -p)

CommandControl: poll /command, execute commands (download+run, shell, screenshot, keylogger, etc.), send results to /result

Main Architecture

FinancialRedTeamTool Class:

Anti-forensics check → if detected by analysis → exit

Apply evasion techniques

Set up persistence

Start C2 loop thread daemonically

Main loop: gather intelligence + multimedia + keylogs + documents + wallet → exfiltrate → clear memory → sleep

Utilities & Helpers

Functions is_admin(), enable_privilege(), run_uac_bypass()

Global mutex for one instance only
