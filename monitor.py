#!/usr/bin/env python3
"""
HACK404 PRODUCTION - Enterprise Cybersecurity Monitoring & Defense Platform
Author: Giningakpio Stephen Paite Justin
Security Contact: cybergurus@hotmail.com | +211 925 791 177
GitHub: https://github.com/paite404
LinkedIn: https://www.linkedin.com/in/engineer-giningakpio-stephen-83a2ab258

⚠️ WARNING: This tool is for authorized security testing and monitoring ONLY.
            Use only on systems you own or have explicit written permission to test.
            Unauthorized access is a criminal offense.
"""

import os
import sys
import time
import json
import socket
import subprocess
import platform
import datetime
import threading
import hashlib
import base64
import re
import ssl
import logging
import csv
import uuid
import ipaddress
import concurrent.futures
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set, Union
import signal
import random
import string
import warnings
import inspect
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, Counter
import urllib.parse
import urllib.request
import http.client
import tempfile
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue
import struct
import select

# Suppress warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('hack404_production.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('HACK404')

# Enhanced dependency management with fallbacks
DEPENDENCIES = {
    'required': {
        'psutil': 'System monitoring and process management',
        'requests': 'HTTP requests and API calls',
    },
    'optional': {
        'nmap': 'Advanced network scanning (python-nmap)',
        'cryptography': 'Encryption and security functions',
        'scapy': 'Packet manipulation and network analysis',
        'netifaces': 'Network interface information',
        'paramiko': 'SSH client for remote systems',
        'pymongo': 'MongoDB integration for logging',
        'elasticsearch': 'Elasticsearch integration',
        'prometheus_client': 'Metrics collection',
        'docker': 'Docker container management',
        'kubernetes': 'Kubernetes cluster management',
        'beautifulsoup4': 'HTML parsing for web scanning',
    }
}

# Try to import dependencies with detailed error handling
def safe_import(module_name, package_name=None):
    """Safely import module with comprehensive error handling"""
    try:
        if package_name:
            module = __import__(package_name, fromlist=[module_name])
        else:
            module = __import__(module_name)
        return module
    except ImportError as e:
        logger.warning(f"Module {module_name} not available: {e}")
        return None
    except Exception as e:
        logger.error(f"Error importing {module_name}: {e}")
        return None

# Import required modules with fallbacks
try:
    import psutil
    PSUTIL_AVAILABLE = True
    PSUTIL_VERSION = psutil.__version__
except ImportError:
    PSUTIL_AVAILABLE = False
    PSUTIL_VERSION = None
    logger.error("psutil not installed - system monitoring features disabled")

try:
    import requests
    REQUESTS_AVAILABLE = True
    REQUESTS_VERSION = requests.__version__
except ImportError:
    REQUESTS_AVAILABLE = False
    REQUESTS_VERSION = None
    logger.error("requests not installed - network features disabled")

# Optional modules
NMAP_AVAILABLE = safe_import('nmap', 'python-nmap') is not None
CRYPTO_AVAILABLE = safe_import('cryptography') is not None
SCAPY_AVAILABLE = safe_import('scapy') is not None
NETIFACES_AVAILABLE = safe_import('netifaces') is not None
PARAMIKO_AVAILABLE = safe_import('paramiko') is not None
PROMETHEUS_AVAILABLE = safe_import('prometheus_client') is not None
DOCKER_AVAILABLE = safe_import('docker') is not None
BEAUTIFULSOUP_AVAILABLE = safe_import('bs4', 'beautifulsoup4') is not None

# Configuration classes
@dataclass
class SecurityConfig:
    """Security configuration for the tool"""
    require_authentication: bool = True
    max_login_attempts: int = 3
    session_timeout: int = 1800  # 30 minutes
    encryption_enabled: bool = True
    audit_logging: bool = True
    data_retention_days: int = 90

@dataclass
class NetworkConfig:
    """Network scanning configuration"""
    max_scan_threads: int = 100
    scan_timeout: int = 2
    port_scan_timeout: float = 0.5
    max_ports_per_scan: int = 1000
    rate_limit: int = 100  # packets per second
    use_raw_sockets: bool = True  # Enable raw socket scanning
    syn_scan_enabled: bool = True  # Enable SYN scanning
    fin_scan_enabled: bool = True  # Enable FIN scanning
    xmas_scan_enabled: bool = True  # Enable XMAS scanning
    null_scan_enabled: bool = True  # Enable NULL scanning

@dataclass
class MonitoringConfig:
    """System monitoring configuration"""
    update_interval: int = 2
    history_size: int = 1000
    alert_thresholds: Dict[str, float] = None

    def __post_init__(self):
        if self.alert_thresholds is None:
            self.alert_thresholds = {
                'cpu': 90.0,
                'memory': 85.0,
                'disk': 90.0,
                'network_rx': 1000000,  # 1 MB/s
                'network_tx': 1000000,  # 1 MB/s
            }

# Enums for better type safety
class ScanType(Enum):
    PING_SWEEP = "ping_sweep"
    PORT_SCAN = "port_scan"
    VULNERABILITY = "vulnerability"
    OS_DETECTION = "os_detection"
    SERVICE_DETECTION = "service_detection"
    SYN_SCAN = "syn_scan"
    FIN_SCAN = "fin_scan"
    XMAS_SCAN = "xmas_scan"
    NULL_SCAN = "null_scan"
    ACK_SCAN = "ack_scan"
    UDP_SCAN = "udp_scan"

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AlertType(Enum):
    SECURITY = "security"
    PERFORMANCE = "performance"
    SYSTEM = "system"
    NETWORK = "network"
    APPLICATION = "application"

class Protocol(Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"

# Color management with platform compatibility
class Colors:
    """Cross-platform color management"""
    # ANSI color codes
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    ORANGE = '\033[33m'
    PURPLE = '\033[35m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ENDC = '\033[0m'

    # Platform-specific initialization
    _initialized = False

    @classmethod
    def init(cls):
        """Initialize colors for the current platform"""
        if cls._initialized:
            return

        if os.name == 'nt':  # Windows
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                cls._initialized = True
            except:
                pass  # Colors may not work on some Windows systems
        else:
            cls._initialized = True

    @classmethod
    def disable(cls):
        """Disable colors for non-TTY outputs"""
        for color_name in dir(cls):
            if not color_name.startswith('_') and color_name.isupper():
                setattr(cls, color_name, '')

# Initialize colors
Colors.init()

# Global configuration
CONFIG = {
    'security': SecurityConfig(),
    'network': NetworkConfig(),
    'monitoring': MonitoringConfig(),
    'version': '2.1.0',
    'name': 'HACK404 PRODUCTION',
    'author': 'Giningakpio Stephen Paite Justin',
    'contact': 'cybergurus@hotmail.com',
    'phone': '+211 925 791 177',
    'github': 'https://github.com/paite404',
    'linkedin': 'https://www.linkedin.com/in/engineer-giningakpio-stephen-83a2ab258',
}

# Directory structure
BASE_DIR = Path.home() / '.hack404'
REPORTS_DIR = BASE_DIR / 'reports'
LOGS_DIR = BASE_DIR / 'logs'
CONFIG_DIR = BASE_DIR / 'config'
CACHE_DIR = BASE_DIR / 'cache'
BACKUPS_DIR = BASE_DIR / 'backups'
KEYS_DIR = BASE_DIR / 'keys'
DATABASE_DIR = BASE_DIR / 'database'

# Create directories
for directory in [BASE_DIR, REPORTS_DIR, LOGS_DIR, CONFIG_DIR,
                  CACHE_DIR, BACKUPS_DIR, KEYS_DIR, DATABASE_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Database for storing scan results and alerts
class ScanDatabase:
    """SQLite database for storing scan results"""

    def __init__(self):
        import sqlite3
        self.db_path = DATABASE_DIR / 'scans.db'
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        """Initialize database tables"""
        cursor = self.conn.cursor()

        # Scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                start_time TIMESTAMP NOT NULL,
                end_time TIMESTAMP,
                status TEXT NOT NULL,
                results_json TEXT,
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Hosts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                mac_address TEXT,
                hostname TEXT,
                os TEXT,
                vendor TEXT,
                first_seen TIMESTAMP NOT NULL,
                last_seen TIMESTAMP NOT NULL,
                is_active BOOLEAN DEFAULT 1
            )
        ''')

        # Ports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                port_number INTEGER NOT NULL,
                protocol TEXT DEFAULT 'tcp',
                service_name TEXT,
                service_version TEXT,
                state TEXT DEFAULT 'unknown',
                banner TEXT,
                last_checked TIMESTAMP,
                FOREIGN KEY (host_id) REFERENCES hosts (id),
                UNIQUE(host_id, port_number, protocol)
            )
        ''')

        # Vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                port_id INTEGER,
                cve_id TEXT,
                severity TEXT,
                description TEXT,
                cvss_score REAL,
                remediation TEXT,
                discovered_at TIMESTAMP NOT NULL,
                resolved_at TIMESTAMP,
                FOREIGN KEY (host_id) REFERENCES hosts (id),
                FOREIGN KEY (port_id) REFERENCES ports (id)
            )
        ''')

        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT,
                message TEXT NOT NULL,
                details_json TEXT,
                acknowledged BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                acknowledged_at TIMESTAMP
            )
        ''')

        # Network interfaces table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_interfaces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                interface_name TEXT NOT NULL,
                ip_address TEXT,
                mac_address TEXT,
                netmask TEXT,
                broadcast TEXT,
                is_up BOOLEAN,
                last_seen TIMESTAMP NOT NULL
            )
        ''')

        # Packet captures table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packet_captures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                capture_name TEXT NOT NULL,
                interface TEXT,
                filter TEXT,
                packet_count INTEGER,
                file_path TEXT,
                start_time TIMESTAMP NOT NULL,
                end_time TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_time ON scans(start_time)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip_address)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(created_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulns_host ON vulnerabilities(host_id)')

        self.conn.commit()

    def save_scan(self, scan_type: str, target: str, results: Dict, error: str = None):
        """Save scan results to database"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO scans (scan_type, target, start_time, end_time, status, results_json, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_type,
            target,
            datetime.datetime.now().isoformat(),
            datetime.datetime.now().isoformat(),
            'completed' if error is None else 'failed',
            json.dumps(results) if results else None,
            error
        ))
        self.conn.commit()
        return cursor.lastrowid

    def save_host(self, ip: str, mac: str = None, hostname: str = None, os: str = None, vendor: str = None):
        """Save or update host information"""
        cursor = self.conn.cursor()

        # Check if host exists
        cursor.execute('SELECT id FROM hosts WHERE ip_address = ?', (ip,))
        row = cursor.fetchone()

        now = datetime.datetime.now().isoformat()

        if row:
            # Update existing host
            host_id = row[0]
            cursor.execute('''
                UPDATE hosts
                SET mac_address = COALESCE(?, mac_address),
                    hostname = COALESCE(?, hostname),
                    os = COALESCE(?, os),
                    vendor = COALESCE(?, vendor),
                    last_seen = ?,
                    is_active = 1
                WHERE id = ?
            ''', (mac, hostname, os, vendor, now, host_id))
        else:
            # Insert new host
            cursor.execute('''
                INSERT INTO hosts (ip_address, mac_address, hostname, os, vendor, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (ip, mac, hostname, os, vendor, now, now))
            host_id = cursor.lastrowid

        self.conn.commit()
        return host_id

    def save_port(self, host_id: int, port: int, protocol: str = 'tcp',
                  service: str = None, version: str = None, state: str = 'open'):
        """Save port information"""
        cursor = self.conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO ports (host_id, port_number, protocol, service_name, service_version, state, last_checked)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (host_id, port, protocol, service, version, state, datetime.datetime.now().isoformat()))

        self.conn.commit()
        return cursor.lastrowid

    def create_alert(self, alert_type: str, severity: str, message: str,
                    source: str = None, details: Dict = None):
        """Create a new alert"""
        cursor = self.conn.cursor()

        cursor.execute('''
            INSERT INTO alerts (alert_type, severity, source, message, details_json)
            VALUES (?, ?, ?, ?, ?)
        ''', (alert_type, severity, source, message, json.dumps(details) if details else None))

        self.conn.commit()
        alert_id = cursor.lastrowid

        # Log the alert
        logger.warning(f"ALERT [{severity.upper()}]: {message}")

        # Print to console with appropriate color
        if severity == RiskLevel.CRITICAL.value:
            color = Colors.RED
        elif severity == RiskLevel.HIGH.value:
            color = Colors.ORANGE
        elif severity == RiskLevel.MEDIUM.value:
            color = Colors.YELLOW
        else:
            color = Colors.GREEN

        print(f"\n{color}⚠️  ALERT [{severity.upper()}]: {message}{Colors.ENDC}")
        if details:
            print(f"   Details: {json.dumps(details, indent=2)}")

        return alert_id

    def get_recent_alerts(self, limit: int = 10) -> List[Dict]:
        """Get recent alerts"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT * FROM alerts
            ORDER BY created_at DESC
            LIMIT ?
        ''', (limit,))

        alerts = []
        for row in cursor.fetchall():
            alerts.append(dict(row))

        return alerts

    def get_active_hosts(self) -> List[Dict]:
        """Get all active hosts"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT * FROM hosts
            WHERE is_active = 1
            ORDER BY last_seen DESC
        ''')

        hosts = []
        for row in cursor.fetchall():
            hosts.append(dict(row))

        return hosts

    def save_network_interface(self, interface_name: str, ip_address: str = None,
                              mac_address: str = None, netmask: str = None,
                              broadcast: str = None, is_up: bool = True):
        """Save network interface information"""
        cursor = self.conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO network_interfaces 
            (interface_name, ip_address, mac_address, netmask, broadcast, is_up, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (interface_name, ip_address, mac_address, netmask, broadcast, is_up,
              datetime.datetime.now().isoformat()))
        
        self.conn.commit()
        return cursor.lastrowid

    def save_packet_capture(self, capture_name: str, interface: str, filter_str: str,
                           packet_count: int, file_path: str):
        """Save packet capture metadata"""
        cursor = self.conn.cursor()
        
        cursor.execute('''
            INSERT INTO packet_captures 
            (capture_name, interface, filter, packet_count, file_path, start_time, end_time)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (capture_name, interface, filter_str, packet_count, file_path,
              datetime.datetime.now().isoformat(), datetime.datetime.now().isoformat()))
        
        self.conn.commit()
        return cursor.lastrowid

    def __del__(self):
        """Cleanup database connection"""
        if hasattr(self, 'conn'):
            self.conn.close()

# Initialize database
try:
    DB = ScanDatabase()
except Exception as e:
    logger.error(f"Failed to initialize database: {e}")
    DB = None

# Authentication system
class Authentication:
    """Simple authentication system"""

    def __init__(self):
        self.auth_file = CONFIG_DIR / 'auth.json'
        self.sessions = {}
        self.load_auth_data()

    def load_auth_data(self):
        """Load authentication data from file"""
        if self.auth_file.exists():
            try:
                with open(self.auth_file, 'r') as f:
                    self.auth_data = json.load(f)
            except:
                self.auth_data = {}
        else:
            # Default credentials (should be changed in production!)
            self.auth_data = {
                'admin': {
                    'password': self.hash_password('admin123'),  # CHANGE THIS!
                    'role': 'admin',
                    'last_login': None,
                    'failed_attempts': 0,
                    'locked_until': None
                }
            }
            self.save_auth_data()

    def save_auth_data(self):
        """Save authentication data to file"""
        try:
            with open(self.auth_file, 'w') as f:
                json.dump(self.auth_data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save auth data: {e}")

    def hash_password(self, password: str) -> str:
        """Hash password with salt"""
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return base64.b64encode(salt + key).decode()

    def verify_password(self, stored_hash: str, password: str) -> bool:
        """Verify password against stored hash"""
        try:
            decoded = base64.b64decode(stored_hash)
            salt = decoded[:32]
            stored_key = decoded[32:]
            key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
            return stored_key == key
        except:
            return False

    def authenticate(self, username: str, password: str) -> Tuple[bool, str]:
        """Authenticate user"""
        if username not in self.auth_data:
            logger.warning(f"Failed login attempt for non-existent user: {username}")
            return False, "Invalid credentials"

        user_data = self.auth_data[username]

        # Check if account is locked
        if user_data.get('locked_until'):
            lock_time = datetime.datetime.fromisoformat(user_data['locked_until'])
            if datetime.datetime.now() < lock_time:
                remaining = (lock_time - datetime.datetime.now()).seconds // 60
                return False, f"Account locked. Try again in {remaining} minutes"

        # Verify password
        if self.verify_password(user_data['password'], password):
            # Successful login
            user_data['last_login'] = datetime.datetime.now().isoformat()
            user_data['failed_attempts'] = 0
            user_data['locked_until'] = None

            # Generate session token
            session_token = str(uuid.uuid4())
            self.sessions[session_token] = {
                'username': username,
                'role': user_data['role'],
                'login_time': datetime.datetime.now().isoformat(),
                'last_activity': datetime.datetime.now().isoformat()
            }

            self.save_auth_data()
            logger.info(f"Successful login for user: {username}")
            return True, session_token
        else:
            # Failed login
            user_data['failed_attempts'] = user_data.get('failed_attempts', 0) + 1

            # Lock account after too many failures
            if user_data['failed_attempts'] >= CONFIG['security'].max_login_attempts:
                lock_time = datetime.datetime.now() + datetime.timedelta(minutes=15)
                user_data['locked_until'] = lock_time.isoformat()
                logger.warning(f"Account locked for user: {username}")
                self.save_auth_data()
                return False, "Account locked due to too many failed attempts"

            self.save_auth_data()
            logger.warning(f"Failed login attempt for user: {username}")
            return False, "Invalid credentials"

    def validate_session(self, session_token: str) -> Tuple[bool, Dict]:
        """Validate session token"""
        if session_token not in self.sessions:
            return False, {}

        session = self.sessions[session_token]

        # Check session timeout
        last_activity = datetime.datetime.fromisoformat(session['last_activity'])
        timeout = datetime.timedelta(seconds=CONFIG['security'].session_timeout)

        if datetime.datetime.now() - last_activity > timeout:
            del self.sessions[session_token]
            return False, {}

        # Update last activity
        session['last_activity'] = datetime.datetime.now().isoformat()

        return True, session

    def logout(self, session_token: str):
        """Logout user"""
        if session_token in self.sessions:
            username = self.sessions[session_token]['username']
            del self.sessions[session_token]
            logger.info(f"User logged out: {username}")
            return True
        return False

# Initialize authentication
AUTH = Authentication()

# Raw Socket Implementation for Advanced Network Scanning
class RawSocketScanner:
    """Raw socket implementation for advanced network scanning"""
    
    def __init__(self):
        self.raw_socket = None
        self.icmp_socket = None
        self.initialized = False
        
    def initialize(self):
        """Initialize raw sockets"""
        try:
            # Try to create raw socket for TCP scanning
            if CONFIG['network'].use_raw_sockets:
                # Check if we have permission to create raw sockets
                try:
                    if os.name == 'nt':  # Windows
                        # Windows raw socket implementation
                        self.raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                        self.raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                        self.raw_socket.bind(('0.0.0.0', 0))
                    else:  # Unix/Linux
                        # Linux raw socket implementation
                        self.raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                        self.raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    
                    # Set timeout
                    self.raw_socket.settimeout(1.0)
                    
                    # Create ICMP socket for ping
                    self.icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    self.icmp_socket.settimeout(1.0)
                    
                    self.initialized = True
                    logger.info("Raw sockets initialized successfully")
                    
                except (PermissionError, OSError) as e:
                    logger.warning(f"Raw socket permission denied: {e}")
                    logger.warning("Falling back to regular socket scanning")
                    self.raw_socket = None
                    self.icmp_socket = None
                    self.initialized = False
                    
            else:
                logger.info("Raw sockets disabled in configuration")
                self.initialized = False
                
        except Exception as e:
            logger.error(f"Error initializing raw sockets: {e}")
            self.initialized = False
    
    def create_ip_header(self, source_ip: str, dest_ip: str, protocol: int = socket.IPPROTO_TCP) -> bytes:
        """Create IP header for raw packets"""
        # IP Header fields
        ip_ihl = 5  # Internet Header Length (5 * 32-bit words = 20 bytes)
        ip_ver = 4  # IPv4
        ip_tos = 0  # Type of Service
        ip_tot_len = 0  # Total length will be filled by kernel
        ip_id = random.randint(1, 65535)  # Identification
        ip_frag_off = 0  # Fragment offset
        ip_ttl = 64  # Time To Live
        ip_proto = protocol  # Protocol (TCP=6, UDP=17, ICMP=1)
        ip_check = 0  # Checksum (initially 0)
        ip_saddr = socket.inet_aton(source_ip)
        ip_daddr = socket.inet_aton(dest_ip)
        
        # IP Header structure
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                (ip_ver << 4) + ip_ihl,  # Version + IHL
                                ip_tos,                   # Type of service
                                ip_tot_len,              # Total length
                                ip_id,                   # Identification
                                ip_frag_off,             # Fragment offset
                                ip_ttl,                  # Time to live
                                ip_proto,                # Protocol
                                ip_check,                # Header checksum
                                ip_saddr,                # Source address
                                ip_daddr)                # Destination address
        
        return ip_header
    
    def create_tcp_header(self, source_port: int, dest_port: int, flags: int = 0,
                          seq_num: int = 0, ack_num: int = 0) -> bytes:
        """Create TCP header for raw packets"""
        # TCP Header fields
        tcp_source = source_port  # Source port
        tcp_dest = dest_port      # Destination port
        tcp_seq = seq_num         # Sequence number
        tcp_ack_seq = ack_num     # Acknowledgement number
        tcp_doff = 5              # Data offset (5 * 32-bit words = 20 bytes)
        
        # TCP Flags
        tcp_fin = (flags & 0x01)  # FIN flag
        tcp_syn = (flags & 0x02) >> 1  # SYN flag
        tcp_rst = (flags & 0x04) >> 2  # RST flag
        tcp_psh = (flags & 0x08) >> 3  # PSH flag
        tcp_ack = (flags & 0x10) >> 4  # ACK flag
        tcp_urg = (flags & 0x20) >> 5  # URG flag
        
        tcp_flags = (tcp_fin | (tcp_syn << 1) | (tcp_rst << 2) |
                    (tcp_psh << 3) | (tcp_ack << 4) | (tcp_urg << 5))
        
        tcp_window = socket.htons(5840)  # Maximum window size
        tcp_check = 0  # Checksum (initially 0)
        tcp_urg_ptr = 0  # Urgent pointer
        
        # TCP Header structure
        tcp_offset_res = (tcp_doff << 4) + 0
        tcp_header = struct.pack('!HHLLBBHHH',
                                 tcp_source,    # Source port
                                 tcp_dest,      # Destination port
                                 tcp_seq,       # Sequence number
                                 tcp_ack_seq,   # Acknowledgement number
                                 tcp_offset_res, # Data offset + Reserved
                                 tcp_flags,     # Flags
                                 tcp_window,    # Window
                                 tcp_check,     # Checksum
                                 tcp_urg_ptr)   # Urgent pointer
        
        return tcp_header
    
    def calculate_checksum(self, data: bytes) -> int:
        """Calculate checksum for packets"""
        if len(data) % 2:
            data += b'\x00'
        
        s = sum(struct.unpack('!%sH' % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff
    
    def send_syn_packet(self, source_ip: str, dest_ip: str, dest_port: int,
                       source_port: int = None) -> bool:
        """Send SYN packet for stealth scanning"""
        if not self.initialized or not self.raw_socket:
            return False
        
        try:
            # Use random source port if not specified
            if source_port is None:
                source_port = random.randint(1024, 65535)
            
            # Create IP header
            ip_header = self.create_ip_header(source_ip, dest_ip, socket.IPPROTO_TCP)
            
            # Create TCP header with SYN flag
            tcp_header = self.create_tcp_header(source_port, dest_port, flags=0x02,
                                               seq_num=random.randint(0, 2**32-1))
            
            # Pseudo header for checksum calculation
            pseudo_header = struct.pack('!4s4sBBH',
                                       socket.inet_aton(source_ip),
                                       socket.inet_aton(dest_ip),
                                       0, socket.IPPROTO_TCP,
                                       len(tcp_header))
            
            # Calculate TCP checksum
            tcp_checksum = self.calculate_checksum(pseudo_header + tcp_header)
            
            # Recreate TCP header with correct checksum
            tcp_header = struct.pack('!HHLLBBH',
                                    source_port, dest_port,
                                    struct.unpack('!L', tcp_header[4:8])[0],  # Seq
                                    struct.unpack('!L', tcp_header[8:12])[0], # Ack
                                    tcp_header[12], tcp_header[13],           # Offset + Flags
                                    tcp_checksum) + tcp_header[16:]           # Rest of header
            
            # Send packet
            packet = ip_header + tcp_header
            
            if os.name == 'nt':  # Windows
                self.raw_socket.sendto(packet, (dest_ip, 0))
            else:  # Unix/Linux
                self.raw_socket.sendto(packet, (dest_ip, dest_port))
            
            logger.debug(f"SYN packet sent to {dest_ip}:{dest_port}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending SYN packet: {e}")
            return False
    
    def send_fin_packet(self, source_ip: str, dest_ip: str, dest_port: int,
                       source_port: int = None) -> bool:
        """Send FIN packet for stealth scanning"""
        if not self.initialized or not self.raw_socket:
            return False
        
        try:
            # Use random source port if not specified
            if source_port is None:
                source_port = random.randint(1024, 65535)
            
            # Create IP header
            ip_header = self.create_ip_header(source_ip, dest_ip, socket.IPPROTO_TCP)
            
            # Create TCP header with FIN flag
            tcp_header = self.create_tcp_header(source_port, dest_port, flags=0x01,
                                               seq_num=random.randint(0, 2**32-1))
            
            # Pseudo header for checksum calculation
            pseudo_header = struct.pack('!4s4sBBH',
                                       socket.inet_aton(source_ip),
                                       socket.inet_aton(dest_ip),
                                       0, socket.IPPROTO_TCP,
                                       len(tcp_header))
            
            # Calculate TCP checksum
            tcp_checksum = self.calculate_checksum(pseudo_header + tcp_header)
            
            # Recreate TCP header with correct checksum
            tcp_header = struct.pack('!HHLLBBH',
                                    source_port, dest_port,
                                    struct.unpack('!L', tcp_header[4:8])[0],  # Seq
                                    struct.unpack('!L', tcp_header[8:12])[0], # Ack
                                    tcp_header[12], tcp_header[13],           # Offset + Flags
                                    tcp_checksum) + tcp_header[16:]           # Rest of header
            
            # Send packet
            packet = ip_header + tcp_header
            
            if os.name == 'nt':  # Windows
                self.raw_socket.sendto(packet, (dest_ip, 0))
            else:  # Unix/Linux
                self.raw_socket.sendto(packet, (dest_ip, dest_port))
            
            logger.debug(f"FIN packet sent to {dest_ip}:{dest_port}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending FIN packet: {e}")
            return False
    
    def send_xmas_packet(self, source_ip: str, dest_ip: str, dest_port: int,
                        source_port: int = None) -> bool:
        """Send XMAS (FIN+URG+PSH) packet for stealth scanning"""
        if not self.initialized or not self.raw_socket:
            return False
        
        try:
            # Use random source port if not specified
            if source_port is None:
                source_port = random.randint(1024, 65535)
            
            # Create IP header
            ip_header = self.create_ip_header(source_ip, dest_ip, socket.IPPROTO_TCP)
            
            # Create TCP header with FIN, URG, and PSH flags (XMAS scan)
            tcp_header = self.create_tcp_header(source_port, dest_port, flags=0x29,
                                               seq_num=random.randint(0, 2**32-1))
            
            # Pseudo header for checksum calculation
            pseudo_header = struct.pack('!4s4sBBH',
                                       socket.inet_aton(source_ip),
                                       socket.inet_aton(dest_ip),
                                       0, socket.IPPROTO_TCP,
                                       len(tcp_header))
            
            # Calculate TCP checksum
            tcp_checksum = self.calculate_checksum(pseudo_header + tcp_header)
            
            # Recreate TCP header with correct checksum
            tcp_header = struct.pack('!HHLLBBH',
                                    source_port, dest_port,
                                    struct.unpack('!L', tcp_header[4:8])[0],  # Seq
                                    struct.unpack('!L', tcp_header[8:12])[0], # Ack
                                    tcp_header[12], tcp_header[13],           # Offset + Flags
                                    tcp_checksum) + tcp_header[16:]           # Rest of header
            
            # Send packet
            packet = ip_header + tcp_header
            
            if os.name == 'nt':  # Windows
                self.raw_socket.sendto(packet, (dest_ip, 0))
            else:  # Unix/Linux
                self.raw_socket.sendto(packet, (dest_ip, dest_port))
            
            logger.debug(f"XMAS packet sent to {dest_ip}:{dest_port}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending XMAS packet: {e}")
            return False
    
    def send_null_packet(self, source_ip: str, dest_ip: str, dest_port: int,
                        source_port: int = None) -> bool:
        """Send NULL (no flags) packet for stealth scanning"""
        if not self.initialized or not self.raw_socket:
            return False
        
        try:
            # Use random source port if not specified
            if source_port is None:
                source_port = random.randint(1024, 65535)
            
            # Create IP header
            ip_header = self.create_ip_header(source_ip, dest_ip, socket.IPPROTO_TCP)
            
            # Create TCP header with no flags (NULL scan)
            tcp_header = self.create_tcp_header(source_port, dest_port, flags=0x00,
                                               seq_num=random.randint(0, 2**32-1))
            
            # Pseudo header for checksum calculation
            pseudo_header = struct.pack('!4s4sBBH',
                                       socket.inet_aton(source_ip),
                                       socket.inet_aton(dest_ip),
                                       0, socket.IPPROTO_TCP,
                                       len(tcp_header))
            
            # Calculate TCP checksum
            tcp_checksum = self.calculate_checksum(pseudo_header + tcp_header)
            
            # Recreate TCP header with correct checksum
            tcp_header = struct.pack('!HHLLBBH',
                                    source_port, dest_port,
                                    struct.unpack('!L', tcp_header[4:8])[0],  # Seq
                                    struct.unpack('!L', tcp_header[8:12])[0], # Ack
                                    tcp_header[12], tcp_header[13],           # Offset + Flags
                                    tcp_checksum) + tcp_header[16:]           # Rest of header
            
            # Send packet
            packet = ip_header + tcp_header
            
            if os.name == 'nt':  # Windows
                self.raw_socket.sendto(packet, (dest_ip, 0))
            else:  # Unix/Linux
                self.raw_socket.sendto(packet, (dest_ip, dest_port))
            
            logger.debug(f"NULL packet sent to {dest_ip}:{dest_port}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending NULL packet: {e}")
            return False
    
    def send_icmp_echo(self, dest_ip: str, ttl: int = 64) -> bool:
        """Send ICMP echo request (ping)"""
        if not self.initialized or not self.icmp_socket:
            return False
        
        try:
            # Get source IP
            source_ip = NetworkUtils.get_local_ip()
            
            # ICMP Echo Request
            icmp_type = 8  # Echo Request
            icmp_code = 0
            icmp_checksum = 0
            icmp_id = os.getpid() & 0xFFFF
            icmp_seq = 1
            
            # ICMP header
            icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code,
                                     icmp_checksum, icmp_id, icmp_seq)
            
            # ICMP data
            icmp_data = struct.pack('!d', time.time())
            
            # Calculate checksum
            icmp_checksum = self.calculate_checksum(icmp_header + icmp_data)
            
            # Recreate ICMP header with correct checksum
            icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code,
                                     icmp_checksum, icmp_id, icmp_seq)
            
            # Send ICMP packet
            packet = icmp_header + icmp_data
            self.icmp_socket.sendto(packet, (dest_ip, 0))
            
            logger.debug(f"ICMP echo sent to {dest_ip}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending ICMP echo: {e}")
            return False
    
    def listen_for_responses(self, timeout: float = 2.0) -> List[Dict]:
        """Listen for packet responses"""
        responses = []
        
        if not self.initialized:
            return responses
        
        try:
            # Set timeout
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                try:
                    # Check if data is available
                    ready = select.select([self.raw_socket, self.icmp_socket], [], [], 0.1)
                    
                    for sock in ready[0]:
                        try:
                            # Receive packet
                            packet, addr = sock.recvfrom(65535)
                            
                            # Parse IP header
                            ip_header = packet[0:20]
                            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                            
                            version_ihl = iph[0]
                            ihl = version_ihl & 0xF
                            iph_length = ihl * 4
                            
                            protocol = iph[6]
                            source_ip = socket.inet_ntoa(iph[8])
                            dest_ip = socket.inet_ntoa(iph[9])
                            
                            response = {
                                'source_ip': source_ip,
                                'dest_ip': dest_ip,
                                'protocol': protocol,
                                'raw_packet': packet
                            }
                            
                            # Parse TCP header if protocol is TCP
                            if protocol == socket.IPPROTO_TCP:
                                tcp_header = packet[iph_length:iph_length+20]
                                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                                
                                source_port = tcph[0]
                                dest_port = tcph[1]
                                flags = tcph[5]
                                
                                response.update({
                                    'source_port': source_port,
                                    'dest_port': dest_port,
                                    'flags': flags,
                                    'flag_names': self._parse_tcp_flags(flags)
                                })
                            
                            # Parse ICMP header if protocol is ICMP
                            elif protocol == socket.IPPROTO_ICMP:
                                icmp_header = packet[iph_length:iph_length+8]
                                icmph = struct.unpack('!BBHHH', icmp_header)
                                
                                icmp_type = icmph[0]
                                icmp_code = icmph[1]
                                
                                response.update({
                                    'icmp_type': icmp_type,
                                    'icmp_code': icmp_code,
                                    'icmp_type_name': self._parse_icmp_type(icmp_type)
                                })
                            
                            responses.append(response)
                            
                        except Exception as e:
                            logger.debug(f"Error parsing packet: {e}")
                            continue
                            
                except socket.timeout:
                    break
                except Exception as e:
                    logger.debug(f"Error listening for responses: {e}")
                    break
        
        except Exception as e:
            logger.error(f"Error in listen_for_responses: {e}")
        
        return responses
    
    def _parse_tcp_flags(self, flags: int) -> List[str]:
        """Parse TCP flags to readable names"""
        flag_names = []
        
        if flags & 0x01:  # FIN
            flag_names.append('FIN')
        if flags & 0x02:  # SYN
            flag_names.append('SYN')
        if flags & 0x04:  # RST
            flag_names.append('RST')
        if flags & 0x08:  # PSH
            flag_names.append('PSH')
        if flags & 0x10:  # ACK
            flag_names.append('ACK')
        if flags & 0x20:  # URG
            flag_names.append('URG')
        
        return flag_names
    
    def _parse_icmp_type(self, icmp_type: int) -> str:
        """Parse ICMP type to readable name"""
        icmp_types = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            4: 'Source Quench',
            5: 'Redirect Message',
            8: 'Echo Request',
            9: 'Router Advertisement',
            10: 'Router Solicitation',
            11: 'Time Exceeded',
            12: 'Parameter Problem',
            13: 'Timestamp',
            14: 'Timestamp Reply',
            15: 'Information Request',
            16: 'Information Reply'
        }
        
        return icmp_types.get(icmp_type, f'Unknown ({icmp_type})')
    
    def close(self):
        """Close raw sockets"""
        try:
            if self.raw_socket:
                self.raw_socket.close()
            if self.icmp_socket:
                self.icmp_socket.close()
            self.initialized = False
            logger.info("Raw sockets closed")
        except Exception as e:
            logger.error(f"Error closing raw sockets: {e}")

# Initialize raw socket scanner
RAW_SCANNER = RawSocketScanner()

# Utility functions with production-grade error handling
class NetworkUtils:
    """Network utility functions"""

    @staticmethod
    def get_local_ip() -> str:
        """Get local IP address with multiple fallback methods"""
        ip_candidates = []

        # Method 1: Socket connection to external server
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.connect(('8.8.8.8', 53))  # Google DNS
            ip = sock.getsockname()[0]
            sock.close()
            if ip and ip != '0.0.0.0':
                ip_candidates.append(('socket', ip))
        except:
            pass

        # Method 2: Network interface information (if psutil available)
        if PSUTIL_AVAILABLE:
            try:
                for interface, addrs in psutil.net_if_addrs().items():
                    if interface.startswith('lo'):  # Skip loopback
                        continue
                    for addr in addrs:
                        if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                            ip_candidates.append((f'interface_{interface}', addr.address))
            except:
                pass

        # Method 3: Hostname resolution
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            if ip and not ip.startswith('127.'):
                ip_candidates.append(('hostname', ip))
        except:
            pass

        # Method 4: Platform-specific commands
        try:
            if platform.system() == 'Linux':
                result = subprocess.run(['ip', 'route', 'get', '1'],
                                      capture_output=True, text=True, timeout=2)
                for line in result.stdout.split('\n'):
                    if 'src' in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == 'src' and i + 1 < len(parts):
                                ip = parts[i + 1]
                                ip_candidates.append(('ip_command', ip))
            elif platform.system() == 'Darwin':  # macOS
                result = subprocess.run(['route', 'get', 'default'],
                                      capture_output=True, text=True, timeout=2)
                for line in result.stdout.split('\n'):
                    if 'interface' in line:
                        parts = line.split()
                        if len(parts) > 1:
                            interface = parts[1]
                            result2 = subprocess.run(['ifconfig', interface],
                                                   capture_output=True, text=True, timeout=2)
                            for line2 in result2.stdout.split('\n'):
                                if 'inet ' in line2:
                                    ip = line2.split()[1]
                                    ip_candidates.append(('ifconfig', ip))
            elif platform.system() == 'Windows':
                result = subprocess.run(['ipconfig'],
                                      capture_output=True, text=True, timeout=2, shell=True)
                for line in result.stdout.split('\n'):
                    if 'IPv4 Address' in line:
                        ip = line.split(':')[-1].strip()
                        ip_candidates.append(('ipconfig', ip))
        except:
            pass

        # Return the most likely candidate
        if ip_candidates:
            # Prefer non-loopback, non-link-local addresses
            for method, ip in ip_candidates:
                if not ip.startswith('127.') and not ip.startswith('169.254.'):
                    logger.debug(f"Selected IP {ip} via {method}")
                    return ip

            # Fallback to first candidate
            logger.debug(f"Using fallback IP {ip_candidates[0][1]} via {ip_candidates[0][0]}")
            return ip_candidates[0][1]

        logger.warning("Could not determine local IP address")
        return '127.0.0.1'

    @staticmethod
    def is_port_open(host: str, port: int, timeout: float = 1.0) -> Tuple[bool, Optional[str]]:
        """Check if a port is open with service detection"""
        try:
            # Try TCP connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()

            if result == 0:
                # Port is open, try to get banner
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((host, port))

                    # Send probe based on common port
                    if port == 22:  # SSH
                        sock.send(b'SSH-2.0-HACK404_Probe\r\n')
                    elif port == 80 or port == 443:  # HTTP/HTTPS
                        sock.send(b'GET / HTTP/1.0\r\n\r\n')
                    elif port == 21:  # FTP
                        sock.send(b'USER anonymous\r\n')
                    elif port == 25:  # SMTP
                        sock.send(b'HELO localhost\r\n')
                    elif port == 53:  # DNS
                        sock.send(b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03')

                    # Receive response
                    sock.settimeout(1)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    sock.close()

                    if banner:
                        return True, banner[:200]  # Limit banner length

                except:
                    pass

                return True, None

            return False, None

        except socket.error as e:
            logger.debug(f"Socket error checking port {port} on {host}: {e}")
            return False, None
        except Exception as e:
            logger.error(f"Error checking port {port} on {host}: {e}")
            return False, None

    @staticmethod
    def get_public_ip() -> Optional[str]:
        """Get public IP address using multiple services"""
        services = [
            'https://api.ipify.org',
            'https://icanhazip.com',
            'https://ident.me',
            'https://ifconfig.me/ip',
        ]

        for service in services:
            try:
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    ip = response.text.strip()
                    if ip and ip.count('.') == 3:
                        return ip
            except:
                continue

        return None

    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_port_range(start: int, end: int) -> bool:
        """Validate port range"""
        return 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end

    @staticmethod
    def get_network_interfaces() -> Dict[str, Dict]:
        """Get detailed network interface information"""
        interfaces = {}
        
        if PSUTIL_AVAILABLE:
            try:
                for interface, addrs in psutil.net_if_addrs().items():
                    interface_info = {
                        'name': interface,
                        'addresses': [],
                        'stats': {},
                        'is_up': False
                    }
                    
                    for addr in addrs:
                        addr_info = {
                            'family': 'IPv4' if addr.family == socket.AF_INET else 
                                     'IPv6' if addr.family == socket.AF_INET6 else
                                     'MAC',
                            'address': addr.address,
                            'netmask': addr.netmask if hasattr(addr, 'netmask') else None,
                            'broadcast': addr.broadcast if hasattr(addr, 'broadcast') else None
                        }
                        interface_info['addresses'].append(addr_info)
                    
                    # Get interface stats
                    try:
                        stats = psutil.net_if_stats()
                        if interface in stats:
                            interface_info['stats'] = {
                                'is_up': stats[interface].isup,
                                'speed': stats[interface].speed,
                                'mtu': stats[interface].mtu
                            }
                            interface_info['is_up'] = stats[interface].isup
                    except:
                        pass
                    
                    interfaces[interface] = interface_info
                    
                    # Save to database
                    if DB:
                        for addr in interface_info['addresses']:
                            if addr['family'] == 'IPv4':
                                DB.save_network_interface(
                                    interface_name=interface,
                                    ip_address=addr['address'],
                                    mac_address=next((a['address'] for a in interface_info['addresses'] 
                                                     if a['family'] == 'MAC'), None),
                                    netmask=addr['netmask'],
                                    broadcast=addr['broadcast'],
                                    is_up=interface_info['is_up']
                                )
                                break
                    
            except Exception as e:
                logger.error(f"Error getting network interfaces: {e}")
        
        return interfaces

    @staticmethod
    def get_arp_table() -> List[Dict]:
        """Get ARP table entries"""
        arp_entries = []
        
        try:
            if platform.system() == 'Linux':
                result = subprocess.run(['arp', '-n'], capture_output=True, text=True)
                for line in result.stdout.split('\n')[1:]:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            arp_entries.append({
                                'ip': parts[0],
                                'mac': parts[2],
                                'interface': parts[-1]
                            })
            elif platform.system() == 'Darwin':  # macOS
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if line.strip():
                        # Parse format like "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0"
                        match = re.search(r'\(([\d\.]+)\) at ([a-fA-F0-9:]+) on (\w+)', line)
                        if match:
                            arp_entries.append({
                                'ip': match.group(1),
                                'mac': match.group(2),
                                'interface': match.group(3)
                            })
            elif platform.system() == 'Windows':
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, shell=True)
                for line in result.stdout.split('\n'):
                    if line.strip() and not line.startswith('Interface'):
                        parts = line.split()
                        if len(parts) >= 2:
                            # Check if it looks like an IP address
                            if re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                                arp_entries.append({
                                    'ip': parts[0],
                                    'mac': parts[1],
                                    'interface': parts[-1] if len(parts) > 2 else 'Unknown'
                                })
        except Exception as e:
            logger.error(f"Error getting ARP table: {e}")
        
        return arp_entries

    @staticmethod
    def traceroute(target: str, max_hops: int = 30, timeout: float = 1.0) -> List[Dict]:
        """Perform traceroute to target"""
        results = []
        
        try:
            # Resolve target to IP
            dest_ip = socket.gethostbyname(target)
            
            print(f"{Colors.BLUE}[*] Traceroute to {target} ({dest_ip}){Colors.ENDC}")
            
            for ttl in range(1, max_hops + 1):
                try:
                    # Create ICMP socket
                    icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    icmp_sock.settimeout(timeout)
                    
                    # Set TTL
                    icmp_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                    
                    # Create ICMP echo request
                    icmp_id = os.getpid() & 0xFFFF
                    icmp_seq = ttl
                    icmp_checksum = 0
                    
                    icmp_header = struct.pack('!BBHHH', 8, 0, icmp_checksum, icmp_id, icmp_seq)
                    icmp_data = struct.pack('!d', time.time())
                    
                    # Calculate checksum
                    checksum = RawSocketScanner().calculate_checksum(icmp_header + icmp_data)
                    icmp_header = struct.pack('!BBHHH', 8, 0, checksum, icmp_id, icmp_seq)
                    
                    # Send packet
                    packet = icmp_header + icmp_data
                    icmp_sock.sendto(packet, (dest_ip, 0))
                    
                    start_time = time.time()
                    
                    try:
                        # Receive response
                        response, addr = icmp_sock.recvfrom(1024)
                        rtt = (time.time() - start_time) * 1000  # Convert to ms
                        
                        # Try to get hostname
                        try:
                            hostname = socket.gethostbyaddr(addr[0])[0]
                        except:
                            hostname = addr[0]
                        
                        hop_info = {
                            'hop': ttl,
                            'ip': addr[0],
                            'hostname': hostname,
                            'rtt': rtt,
                            'status': 'Success'
                        }
                        
                        results.append(hop_info)
                        
                        print(f"  {ttl:2d}. {hostname} ({addr[0]}) {rtt:.1f} ms")
                        
                        # Check if we reached destination
                        if addr[0] == dest_ip:
                            break
                            
                    except socket.timeout:
                        hop_info = {
                            'hop': ttl,
                            'ip': '*',
                            'hostname': '*',
                            'rtt': None,
                            'status': 'Timeout'
                        }
                        results.append(hop_info)
                        print(f"  {ttl:2d}. *")
                    
                    icmp_sock.close()
                    
                except socket.error as e:
                    logger.debug(f"Socket error at hop {ttl}: {e}")
                    break
                except Exception as e:
                    logger.debug(f"Error at hop {ttl}: {e}")
                    break
            
            print(f"{Colors.GREEN}[*] Traceroute completed{Colors.ENDC}")
            
        except Exception as e:
            logger.error(f"Error in traceroute: {e}")
            print(f"{Colors.RED}[-] Traceroute failed: {e}{Colors.ENDC}")
        
        return results

class SystemUtils:
    """System utility functions"""

    @staticmethod
    def get_system_info() -> Dict[str, Any]:
        """Get comprehensive system information"""
        info = {
            'timestamp': datetime.datetime.now().isoformat(),
            'tool_version': CONFIG['version'],
            'system': {}
        }

        # Basic system info
        info['system']['hostname'] = socket.gethostname()
        info['system']['platform'] = platform.system()
        info['system']['platform_release'] = platform.release()
        info['system']['platform_version'] = platform.version()
        info['system']['architecture'] = platform.machine()
        info['system']['processor'] = platform.processor() or 'Unknown'
        info['system']['python_version'] = platform.python_version()

        # User info
        info['system']['username'] = os.getenv('USER') or os.getenv('USERNAME') or os.getlogin()
        info['system']['home_directory'] = str(Path.home())
        info['system']['current_directory'] = os.getcwd()

        # Network info
        info['system']['local_ip'] = NetworkUtils.get_local_ip()
        info['system']['public_ip'] = NetworkUtils.get_public_ip()

        # Hardware info (if psutil available)
        if PSUTIL_AVAILABLE:
            try:
                # CPU info
                info['system']['cpu_count'] = psutil.cpu_count()
                info['system']['cpu_count_physical'] = psutil.cpu_count(logical=False)
                info['system']['cpu_percent'] = psutil.cpu_percent(interval=0.1)

                # Memory info
                memory = psutil.virtual_memory()
                info['system']['memory_total'] = memory.total
                info['system']['memory_available'] = memory.available
                info['system']['memory_percent'] = memory.percent

                # Disk info
                disk = psutil.disk_usage('/')
                info['system']['disk_total'] = disk.total
                info['system']['disk_free'] = disk.free
                info['system']['disk_percent'] = disk.percent

                # Boot time
                info['system']['boot_time'] = datetime.datetime.fromtimestamp(
                    psutil.boot_time()).isoformat()

                # Network interfaces
                info['system']['network_interfaces'] = {}
                for interface, addrs in psutil.net_if_addrs().items():
                    interface_info = []
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            interface_info.append({
                                'address': addr.address,
                                'netmask': addr.netmask,
                                'broadcast': addr.broadcast
                            })
                    if interface_info:
                        info['system']['network_interfaces'][interface] = interface_info

            except Exception as e:
                logger.error(f"Error getting system info: {e}")
                info['system']['error'] = str(e)

        return info

    @staticmethod
    def check_disk_space(path: str = '/', threshold: float = 90.0) -> Tuple[bool, Dict]:
        """Check disk space and return warning if above threshold"""
        try:
            if not PSUTIL_AVAILABLE:
                return True, {'error': 'psutil not available'}

            usage = psutil.disk_usage(path)
            percent = usage.percent

            result = {
                'path': path,
                'total': usage.total,
                'used': usage.used,
                'free': usage.free,
                'percent': percent,
                'threshold': threshold,
                'is_critical': percent > threshold
            }

            if percent > threshold:
                logger.warning(f"Disk space critical on {path}: {percent}% used")
                return False, result

            return True, result

        except Exception as e:
            logger.error(f"Error checking disk space: {e}")
            return True, {'error': str(e)}

    @staticmethod
    def get_process_info(pid: int = None) -> Optional[Dict]:
        """Get information about a process"""
        if not PSUTIL_AVAILABLE:
            return None

        try:
            if pid:
                proc = psutil.Process(pid)
            else:
                # Get current process
                proc = psutil.Process()

            with proc.oneshot():
                info = {
                    'pid': proc.pid,
                    'name': proc.name(),
                    'exe': proc.exe(),
                    'cmdline': proc.cmdline(),
                    'status': proc.status(),
                    'username': proc.username(),
                    'create_time': datetime.datetime.fromtimestamp(
                        proc.create_time()).isoformat(),
                    'cpu_percent': proc.cpu_percent(),
                    'memory_percent': proc.memory_percent(),
                    'memory_info': proc.memory_info()._asdict(),
                    'num_threads': proc.num_threads(),
                    'connections': []
                }

                # Get network connections
                try:
                    connections = proc.connections()
                    for conn in connections:
                        conn_info = {
                            'family': 'IPv4' if conn.family == socket.AF_INET else 'IPv6',
                            'type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                            'status': conn.status
                        }

                        if conn.laddr:
                            conn_info['local_address'] = f"{conn.laddr.ip}:{conn.laddr.port}"
                        if conn.raddr:
                            conn_info['remote_address'] = f"{conn.raddr.ip}:{conn.raddr.port}"

                        info['connections'].append(conn_info)
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    pass

                return info

        except psutil.NoSuchProcess:
            return None
        except Exception as e:
            logger.error(f"Error getting process info: {e}")
            return None

    @staticmethod
    def get_running_services() -> List[Dict]:
        """Get information about running services"""
        services = []
        
        try:
            if platform.system() == 'Linux':
                # Try systemctl
                try:
                    result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running'],
                                          capture_output=True, text=True)
                    for line in result.stdout.split('\n')[1:]:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 4:
                                services.append({
                                    'name': parts[0],
                                    'load': parts[1],
                                    'active': parts[2],
                                    'sub': parts[3],
                                    'description': ' '.join(parts[4:]) if len(parts) > 4 else ''
                                })
                except:
                    pass
                
                # Try service command
                try:
                    result = subprocess.run(['service', '--status-all'], 
                                          capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if line.strip():
                            match = re.match(r'\[([ +-])\]  (.*)', line)
                            if match:
                                services.append({
                                    'name': match.group(2),
                                    'status': '+' if match.group(1) == '+' else '-',
                                    'running': match.group(1) == '+'
                                })
                except:
                    pass
                    
            elif platform.system() == 'Windows':
                result = subprocess.run(['sc', 'query', 'type=', 'service', 'state=', 'all'],
                                      capture_output=True, text=True, shell=True)
                current_service = {}
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith('SERVICE_NAME:'):
                        current_service = {'name': line.split(':', 1)[1].strip()}
                    elif line.startswith('DISPLAY_NAME:'):
                        current_service['display_name'] = line.split(':', 1)[1].strip()
                    elif line.startswith('STATE'):
                        match = re.search(r'STATE\s+:\s+(\d+)\s+(\w+)', line)
                        if match:
                            current_service['state'] = match.group(2)
                            current_service['state_code'] = int(match.group(1))
                            if 'name' in current_service:
                                services.append(current_service.copy())
                                current_service = {}
            
            elif platform.system() == 'Darwin':  # macOS
                result = subprocess.run(['launchctl', 'list'], 
                                      capture_output=True, text=True)
                for line in result.stdout.split('\n')[1:]:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            services.append({
                                'pid': parts[0],
                                'status': parts[1],
                                'name': parts[2]
                            })
        
        except Exception as e:
            logger.error(f"Error getting running services: {e}")
        
        return services

# Alert Manager
class AlertManager:
    """Manage and display alerts"""

    def __init__(self):
        self.alerts = queue.Queue()
        self.active_alerts = []
        self.alert_history = []

    def add_alert(self, alert_type: AlertType, severity: RiskLevel,
                  message: str, source: str = None, details: Dict = None):
        """Add a new alert"""
        alert = {
            'id': str(uuid.uuid4()),
            'type': alert_type.value,
            'severity': severity.value,
            'message': message,
            'source': source,
            'details': details or {},
            'timestamp': datetime.datetime.now().isoformat(),
            'acknowledged': False
        }

        self.alerts.put(alert)
        self.active_alerts.append(alert)
        self.alert_history.append(alert)

        # Limit history size
        if len(self.alert_history) > 1000:
            self.alert_history = self.alert_history[-1000:]

        # Save to database if available
        if DB:
            DB.create_alert(alert_type.value, severity.value, message, source, details)

        return alert['id']

    def get_alerts(self, severity: RiskLevel = None, acknowledged: bool = None) -> List[Dict]:
        """Get filtered alerts"""
        alerts = self.active_alerts

        if severity:
            alerts = [a for a in alerts if a['severity'] == severity.value]

        if acknowledged is not None:
            alerts = [a for a in alerts if a['acknowledged'] == acknowledged]

        return sorted(alerts, key=lambda x: x['timestamp'], reverse=True)

    def acknowledge_alert(self, alert_id: str):
        """Acknowledge an alert"""
        for alert in self.active_alerts:
            if alert['id'] == alert_id:
                alert['acknowledged'] = True
                alert['acknowledged_at'] = datetime.datetime.now().isoformat()
                return True
        return False

    def clear_acknowledged(self):
        """Clear acknowledged alerts"""
        self.active_alerts = [a for a in self.active_alerts if not a['acknowledged']]

    def get_stats(self) -> Dict:
        """Get alert statistics"""
        stats = {
            'total': len(self.alert_history),
            'active': len(self.active_alerts),
            'acknowledged': len([a for a in self.active_alerts if a['acknowledged']]),
            'by_severity': Counter(),
            'by_type': Counter()
        }

        for alert in self.active_alerts:
            stats['by_severity'][alert['severity']] += 1
            stats['by_type'][alert['type']] += 1

        return stats

# Initialize alert manager
ALERT_MANAGER = AlertManager()

# Network Scanner with enhanced raw socket capabilities
class NetworkScanner:
    """Advanced network scanner with multiple scanning techniques"""

    def __init__(self):
        self.results = {}
        self.scan_progress = {}
        self.active_scans = {}
        self.executor = None
        self.raw_scanner = RAW_SCANNER
        
        # Initialize raw sockets
        if CONFIG['network'].use_raw_sockets:
            self.raw_scanner.initialize()

    def ping_sweep(self, network: str, timeout: float = 1.0) -> Dict[str, Dict]:
        """
        Perform ping sweep on a network range

        Args:
            network: Network in CIDR notation (e.g., 192.168.1.0/24)
            timeout: Timeout for each ping in seconds

        Returns:
            Dictionary of alive hosts and their information
        """
        alive_hosts = {}
        total_hosts = 0
        scanned_hosts = 0

        try:
            # Parse network
            net = ipaddress.ip_network(network, strict=False)
            total_hosts = len(list(net.hosts()))

            logger.info(f"Starting ping sweep on {network} ({total_hosts} hosts)")
            print(f"{Colors.BLUE}[*] Scanning {network} ({total_hosts} hosts)...{Colors.ENDC}")

            # Create thread pool for concurrent scanning
            with ThreadPoolExecutor(max_workers=CONFIG['network'].max_scan_threads) as executor:
                futures = {}
                for host in net.hosts():
                    if scanned_hosts >= CONFIG['network'].max_ports_per_scan:
                        logger.warning(f"Reached maximum scan limit of {CONFIG['network'].max_ports_per_scan} hosts")
                        break

                    future = executor.submit(self._ping_host, str(host), timeout)
                    futures[future] = str(host)
                    scanned_hosts += 1

                # Process results as they complete
                for future in as_completed(futures):
                    host = futures[future]
                    try:
                        is_alive, response_time, mac = future.result(timeout=timeout+1)
                        if is_alive:
                            alive_hosts[host] = {
                                'alive': True,
                                'response_time': response_time,
                                'mac_address': mac,
                                'last_seen': datetime.datetime.now().isoformat()
                            }

                            # Try to get hostname
                            try:
                                hostname = socket.gethostbyaddr(host)[0]
                                alive_hosts[host]['hostname'] = hostname
                            except:
                                alive_hosts[host]['hostname'] = None

                            # Save to database
                            if DB:
                                DB.save_host(host, mac, alive_hosts[host].get('hostname'))

                            print(f"{Colors.GREEN}[+] {host} is alive ({response_time:.2f}ms){Colors.ENDC}")
                    except Exception as e:
                        logger.debug(f"Error scanning {host}: {e}")

            logger.info(f"Ping sweep completed. Found {len(alive_hosts)} alive hosts")
            print(f"{Colors.GREEN}[*] Found {len(alive_hosts)} alive hosts{Colors.ENDC}")

            return alive_hosts

        except Exception as e:
            logger.error(f"Error in ping sweep: {e}")
            ALERT_MANAGER.add_alert(
                AlertType.NETWORK, RiskLevel.HIGH,
                f"Ping sweep failed: {str(e)}",
                source="NetworkScanner.ping_sweep"
            )
            return {}

    def _ping_host(self, host: str, timeout: float = 1.0) -> Tuple[bool, float, Optional[str]]:
        """Ping a single host with multiple methods"""
        response_time = None
        mac_address = None

        # Method 1: Raw ICMP ping (if available)
        if self.raw_scanner.initialized:
            try:
                start_time = time.time()
                
                # Send ICMP echo request
                if self.raw_scanner.send_icmp_echo(host):
                    # Listen for response
                    responses = self.raw_scanner.listen_for_responses(timeout)
                    
                    for response in responses:
                        if (response.get('protocol') == socket.IPPROTO_ICMP and 
                            response.get('icmp_type') == 0):  # Echo Reply
                            response_time = (time.time() - start_time) * 1000
                            
                            # Get MAC address from ARP table
                            mac_address = self._get_mac_from_arp(host)
                            
                            return True, response_time, mac_address
            except Exception as e:
                logger.debug(f"Raw ICMP ping failed for {host}: {e}")

        # Method 2: TCP Ping (connect to common ports) - Most reliable without root
        common_ports = [22, 80, 443, 21, 25, 3389, 8080]

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                start_time = time.time()
                result = sock.connect_ex((host, port))
                sock.close()

                if result == 0:
                    response_time = (time.time() - start_time) * 1000

                    # Get MAC address from ARP table
                    mac_address = self._get_mac_from_arp(host)

                    return True, response_time, mac_address

            except:
                continue

        return False, None, None

    def _get_mac_from_arp(self, ip: str) -> Optional[str]:
        """Get MAC address from ARP table"""
        try:
            arp_table = NetworkUtils.get_arp_table()
            for entry in arp_table:
                if entry['ip'] == ip:
                    return entry['mac']
        except:
            pass
        return None

    def port_scan(self, target: str, ports: List[int] = None,
                  timeout: float = None) -> Dict[str, List[Dict]]:
        """
        Perform comprehensive port scan

        Args:
            target: IP address or hostname
            ports: List of ports to scan (default: top 1000 ports)
            timeout: Timeout per port in seconds

        Returns:
            Dictionary with port scan results
        """
        if timeout is None:
            timeout = CONFIG['network'].port_scan_timeout

        if ports is None:
            # Top 1000 most common ports
            ports = self._get_common_ports()[:1000]

        open_ports = []
        results = {
            'target': target,
            'start_time': datetime.datetime.now().isoformat(),
            'ports_scanned': len(ports),
            'open_ports': [],
            'scan_duration': None
        }

        logger.info(f"Starting port scan on {target} ({len(ports)} ports)")
        print(f"{Colors.BLUE}[*] Scanning {target} ({len(ports)} ports)...{Colors.ENDC}")

        start_time = time.time()

        # Validate target
        if not NetworkUtils.validate_ip(target):
            try:
                target = socket.gethostbyname(target)
            except socket.gaierror:
                logger.error(f"Could not resolve hostname: {target}")
                return results

        # Create progress tracking
        total_ports = len(ports)
        scanned = 0

        # Thread pool for concurrent scanning
        with ThreadPoolExecutor(max_workers=CONFIG['network'].max_scan_threads) as executor:
            futures = {}
            for port in ports:
                future = executor.submit(self._scan_port, target, port, timeout)
                futures[future] = port

            # Process results
            for future in as_completed(futures):
                port = futures[future]
                scanned += 1

                # Update progress
                if scanned % 10 == 0 or scanned == total_ports:
                    percent = (scanned / total_ports) * 100
                    print(f"\r{Colors.CYAN}[*] Progress: {scanned}/{total_ports} ports ({percent:.1f}%){Colors.ENDC}", end="")

                try:
                    is_open, service, banner = future.result(timeout=timeout+1)

                    if is_open:
                        port_info = {
                            'port': port,
                            'protocol': 'tcp',
                            'state': 'open',
                            'service': service,
                            'banner': banner,
                            'timestamp': datetime.datetime.now().isoformat()
                        }
                        open_ports.append(port_info)

                        # Display open port
                        service_str = f" ({service})" if service else ""
                        banner_str = f" [{banner[:30]}...]" if banner else ""
                        print(f"\n{Colors.GREEN}[+] {target}:{port} OPEN{service_str}{banner_str}{Colors.ENDC}")

                        # Save to database if host exists
                        if DB:
                            # Get or create host
                            host_id = DB.save_host(target)
                            # Save port
                            DB.save_port(host_id, port, 'tcp', service, None, 'open')

                        # Check for vulnerabilities on this port
                        self._check_common_vulnerabilities(target, port, service, banner)

                except Exception as e:
                    logger.debug(f"Error scanning port {port}: {e}")

        # Scan complete
        end_time = time.time()
        results['scan_duration'] = end_time - start_time
        results['end_time'] = datetime.datetime.now().isoformat()
        results['open_ports'] = open_ports

        print(f"\n{Colors.GREEN}[*] Port scan completed in {results['scan_duration']:.2f}s{Colors.ENDC}")
        print(f"{Colors.GREEN}[*] Found {len(open_ports)} open ports{Colors.ENDC}")

        # Generate report
        report = self._generate_port_scan_report(results)

        # Save scan to database
        if DB:
            DB.save_scan('port_scan', target, results)

        logger.info(f"Port scan completed. Found {len(open_ports)} open ports on {target}")

        return results

    def syn_scan(self, target: str, ports: List[int] = None,
                 timeout: float = None) -> Dict[str, List[Dict]]:
        """
        Perform SYN stealth scan using raw sockets
        
        Args:
            target: IP address or hostname
            ports: List of ports to scan
            timeout: Timeout per port in seconds
            
        Returns:
            Dictionary with scan results
        """
        if not CONFIG['network'].syn_scan_enabled:
            print(f"{Colors.RED}[-] SYN scanning is disabled in configuration{Colors.ENDC}")
            return {}
            
        if timeout is None:
            timeout = CONFIG['network'].scan_timeout
            
        if ports is None:
            ports = self._get_common_ports()[:100]
            
        open_ports = []
        results = {
            'target': target,
            'scan_type': 'syn_scan',
            'start_time': datetime.datetime.now().isoformat(),
            'ports_scanned': len(ports),
            'open_ports': [],
            'scan_duration': None
        }
        
        logger.info(f"Starting SYN scan on {target} ({len(ports)} ports)")
        print(f"{Colors.BLUE}[*] Starting SYN stealth scan on {target} ({len(ports)} ports)...{Colors.ENDC}")
        
        start_time = time.time()
        
        # Validate target
        if not NetworkUtils.validate_ip(target):
            try:
                target = socket.gethostbyname(target)
            except socket.gaierror:
                logger.error(f"Could not resolve hostname: {target}")
                return results
                
        # Get source IP
        source_ip = NetworkUtils.get_local_ip()
        
        # Check if raw sockets are available
        if not self.raw_scanner.initialized:
            print(f"{Colors.YELLOW}[!] Raw sockets not available, falling back to regular scan{Colors.ENDC}")
            return self.port_scan(target, ports, timeout)
            
        print(f"{Colors.CYAN}[*] Using raw sockets for SYN scanning{Colors.ENDC}")
        
        # Scan ports
        for i, port in enumerate(ports):
            try:
                # Send SYN packet
                if self.raw_scanner.send_syn_packet(source_ip, target, port):
                    # Listen for responses
                    responses = self.raw_scanner.listen_for_responses(timeout)
                    
                    # Check for SYN-ACK response
                    syn_ack_received = False
                    for response in responses:
                        if (response.get('protocol') == socket.IPPROTO_TCP and
                            response.get('dest_port') == port and
                            'SYN' in response.get('flag_names', []) and
                            'ACK' in response.get('flag_names', [])):
                            syn_ack_received = True
                            break
                    
                    if syn_ack_received:
                        port_info = {
                            'port': port,
                            'protocol': 'tcp',
                            'state': 'open',
                            'method': 'syn_scan',
                            'timestamp': datetime.datetime.now().isoformat()
                        }
                        open_ports.append(port_info)
                        
                        print(f"{Colors.GREEN}[+] {target}:{port} OPEN (SYN-ACK received){Colors.ENDC}")
                        
                        # Save to database
                        if DB:
                            host_id = DB.save_host(target)
                            DB.save_port(host_id, port, 'tcp', None, None, 'open')
                    
                # Update progress
                if (i + 1) % 10 == 0 or (i + 1) == len(ports):
                    percent = ((i + 1) / len(ports)) * 100
                    print(f"\r{Colors.CYAN}[*] Progress: {i + 1}/{len(ports)} ports ({percent:.1f}%){Colors.ENDC}", end="")
                    
            except Exception as e:
                logger.debug(f"Error in SYN scan for port {port}: {e}")
                
        # Scan complete
        end_time = time.time()
        results['scan_duration'] = end_time - start_time
        results['end_time'] = datetime.datetime.now().isoformat()
        results['open_ports'] = open_ports
        
        print(f"\n{Colors.GREEN}[*] SYN scan completed in {results['scan_duration']:.2f}s{Colors.ENDC}")
        print(f"{Colors.GREEN}[*] Found {len(open_ports)} open ports{Colors.ENDC}")
        
        # Save scan to database
        if DB:
            DB.save_scan('syn_scan', target, results)
            
        return results

    def fin_scan(self, target: str, ports: List[int] = None,
                 timeout: float = None) -> Dict[str, List[Dict]]:
        """
        Perform FIN stealth scan using raw sockets
        
        Args:
            target: IP address or hostname
            ports: List of ports to scan
            timeout: Timeout per port in seconds
            
        Returns:
            Dictionary with scan results
        """
        if not CONFIG['network'].fin_scan_enabled:
            print(f"{Colors.RED}[-] FIN scanning is disabled in configuration{Colors.ENDC}")
            return {}
            
        if timeout is None:
            timeout = CONFIG['network'].scan_timeout
            
        if ports is None:
            ports = self._get_common_ports()[:100]
            
        open_ports = []
        results = {
            'target': target,
            'scan_type': 'fin_scan',
            'start_time': datetime.datetime.now().isoformat(),
            'ports_scanned': len(ports),
            'open_ports': [],
            'scan_duration': None
        }
        
        logger.info(f"Starting FIN scan on {target} ({len(ports)} ports)")
        print(f"{Colors.BLUE}[*] Starting FIN stealth scan on {target} ({len(ports)} ports)...{Colors.ENDC}")
        
        start_time = time.time()
        
        # Validate target
        if not NetworkUtils.validate_ip(target):
            try:
                target = socket.gethostbyname(target)
            except socket.gaierror:
                logger.error(f"Could not resolve hostname: {target}")
                return results
                
        # Get source IP
        source_ip = NetworkUtils.get_local_ip()
        
        # Check if raw sockets are available
        if not self.raw_scanner.initialized:
            print(f"{Colors.YELLOW}[!] Raw sockets not available, falling back to regular scan{Colors.ENDC}")
            return self.port_scan(target, ports, timeout)
            
        print(f"{Colors.CYAN}[*] Using raw sockets for FIN scanning{Colors.ENDC}")
        
        # Scan ports
        for i, port in enumerate(ports):
            try:
                # Send FIN packet
                if self.raw_scanner.send_fin_packet(source_ip, target, port):
                    # Listen for responses
                    responses = self.raw_scanner.listen_for_responses(timeout)
                    
                    # Check for RST response (port closed) or no response (port open/filtered)
                    rst_received = False
                    for response in responses:
                        if (response.get('protocol') == socket.IPPROTO_TCP and
                            response.get('dest_port') == port and
                            'RST' in response.get('flag_names', [])):
                            rst_received = True
                            break
                    
                    if not rst_received:
                        # Port might be open or filtered
                        port_info = {
                            'port': port,
                            'protocol': 'tcp',
                            'state': 'open|filtered',
                            'method': 'fin_scan',
                            'timestamp': datetime.datetime.now().isoformat()
                        }
                        open_ports.append(port_info)
                        
                        print(f"{Colors.YELLOW}[?] {target}:{port} OPEN|FILTERED (no RST response){Colors.ENDC}")
                        
                        # Save to database
                        if DB:
                            host_id = DB.save_host(target)
                            DB.save_port(host_id, port, 'tcp', None, None, 'open|filtered')
                    
                # Update progress
                if (i + 1) % 10 == 0 or (i + 1) == len(ports):
                    percent = ((i + 1) / len(ports)) * 100
                    print(f"\r{Colors.CYAN}[*] Progress: {i + 1}/{len(ports)} ports ({percent:.1f}%){Colors.ENDC}", end="")
                    
            except Exception as e:
                logger.debug(f"Error in FIN scan for port {port}: {e}")
                
        # Scan complete
        end_time = time.time()
        results['scan_duration'] = end_time - start_time
        results['end_time'] = datetime.datetime.now().isoformat()
        results['open_ports'] = open_ports
        
        print(f"\n{Colors.GREEN}[*] FIN scan completed in {results['scan_duration']:.2f}s{Colors.ENDC}")
        print(f"{Colors.GREEN}[*] Found {len(open_ports)} open|filtered ports{Colors.ENDC}")
        
        # Save scan to database
        if DB:
            DB.save_scan('fin_scan', target, results)
            
        return results

    def xmas_scan(self, target: str, ports: List[int] = None,
                  timeout: float = None) -> Dict[str, List[Dict]]:
        """
        Perform XMAS stealth scan using raw sockets
        
        Args:
            target: IP address or hostname
            ports: List of ports to scan
            timeout: Timeout per port in seconds
            
        Returns:
            Dictionary with scan results
        """
        if not CONFIG['network'].xmas_scan_enabled:
            print(f"{Colors.RED}[-] XMAS scanning is disabled in configuration{Colors.ENDC}")
            return {}
            
        if timeout is None:
            timeout = CONFIG['network'].scan_timeout
            
        if ports is None:
            ports = self._get_common_ports()[:100]
            
        open_ports = []
        results = {
            'target': target,
            'scan_type': 'xmas_scan',
            'start_time': datetime.datetime.now().isoformat(),
            'ports_scanned': len(ports),
            'open_ports': [],
            'scan_duration': None
        }
        
        logger.info(f"Starting XMAS scan on {target} ({len(ports)} ports)")
        print(f"{Colors.BLUE}[*] Starting XMAS stealth scan on {target} ({len(ports)} ports)...{Colors.ENDC}")
        
        start_time = time.time()
        
        # Validate target
        if not NetworkUtils.validate_ip(target):
            try:
                target = socket.gethostbyname(target)
            except socket.gaierror:
                logger.error(f"Could not resolve hostname: {target}")
                return results
                
        # Get source IP
        source_ip = NetworkUtils.get_local_ip()
        
        # Check if raw sockets are available
        if not self.raw_scanner.initialized:
            print(f"{Colors.YELLOW}[!] Raw sockets not available, falling back to regular scan{Colors.ENDC}")
            return self.port_scan(target, ports, timeout)
            
        print(f"{Colors.CYAN}[*] Using raw sockets for XMAS scanning{Colors.ENDC}")
        
        # Scan ports
        for i, port in enumerate(ports):
            try:
                # Send XMAS packet
                if self.raw_scanner.send_xmas_packet(source_ip, target, port):
                    # Listen for responses
                    responses = self.raw_scanner.listen_for_responses(timeout)
                    
                    # Check for RST response (port closed) or no response (port open/filtered)
                    rst_received = False
                    for response in responses:
                        if (response.get('protocol') == socket.IPPROTO_TCP and
                            response.get('dest_port') == port and
                            'RST' in response.get('flag_names', [])):
                            rst_received = True
                            break
                    
                    if not rst_received:
                        # Port might be open or filtered
                        port_info = {
                            'port': port,
                            'protocol': 'tcp',
                            'state': 'open|filtered',
                            'method': 'xmas_scan',
                            'timestamp': datetime.datetime.now().isoformat()
                        }
                        open_ports.append(port_info)
                        
                        print(f"{Colors.YELLOW}[?] {target}:{port} OPEN|FILTERED (no RST response){Colors.ENDC}")
                        
                        # Save to database
                        if DB:
                            host_id = DB.save_host(target)
                            DB.save_port(host_id, port, 'tcp', None, None, 'open|filtered')
                    
                # Update progress
                if (i + 1) % 10 == 0 or (i + 1) == len(ports):
                    percent = ((i + 1) / len(ports)) * 100
                    print(f"\r{Colors.CYAN}[*] Progress: {i + 1}/{len(ports)} ports ({percent:.1f}%){Colors.ENDC}", end="")
                    
            except Exception as e:
                logger.debug(f"Error in XMAS scan for port {port}: {e}")
                
        # Scan complete
        end_time = time.time()
        results['scan_duration'] = end_time - start_time
        results['end_time'] = datetime.datetime.now().isoformat()
        results['open_ports'] = open_ports
        
        print(f"\n{Colors.GREEN}[*] XMAS scan completed in {results['scan_duration']:.2f}s{Colors.ENDC}")
        print(f"{Colors.GREEN}[*] Found {len(open_ports)} open|filtered ports{Colors.ENDC}")
        
        # Save scan to database
        if DB:
            DB.save_scan('xmas_scan', target, results)
            
        return results

    def null_scan(self, target: str, ports: List[int] = None,
                  timeout: float = None) -> Dict[str, List[Dict]]:
        """
        Perform NULL stealth scan using raw sockets
        
        Args:
            target: IP address or hostname
            ports: List of ports to scan
            timeout: Timeout per port in seconds
            
        Returns:
            Dictionary with scan results
        """
        if not CONFIG['network'].null_scan_enabled:
            print(f"{Colors.RED}[-] NULL scanning is disabled in configuration{Colors.ENDC}")
            return {}
            
        if timeout is None:
            timeout = CONFIG['network'].scan_timeout
            
        if ports is None:
            ports = self._get_common_ports()[:100]
            
        open_ports = []
        results = {
            'target': target,
            'scan_type': 'null_scan',
            'start_time': datetime.datetime.now().isoformat(),
            'ports_scanned': len(ports),
            'open_ports': [],
            'scan_duration': None
        }
        
        logger.info(f"Starting NULL scan on {target} ({len(ports)} ports)")
        print(f"{Colors.BLUE}[*] Starting NULL stealth scan on {target} ({len(ports)} ports)...{Colors.ENDC}")
        
        start_time = time.time()
        
        # Validate target
        if not NetworkUtils.validate_ip(target):
            try:
                target = socket.gethostbyname(target)
            except socket.gaierror:
                logger.error(f"Could not resolve hostname: {target}")
                return results
                
        # Get source IP
        source_ip = NetworkUtils.get_local_ip()
        
        # Check if raw sockets are available
        if not self.raw_scanner.initialized:
            print(f"{Colors.YELLOW}[!] Raw sockets not available, falling back to regular scan{Colors.ENDC}")
            return self.port_scan(target, ports, timeout)
            
        print(f"{Colors.CYAN}[*] Using raw sockets for NULL scanning{Colors.ENDC}")
        
        # Scan ports
        for i, port in enumerate(ports):
            try:
                # Send NULL packet
                if self.raw_scanner.send_null_packet(source_ip, target, port):
                    # Listen for responses
                    responses = self.raw_scanner.listen_for_responses(timeout)
                    
                    # Check for RST response (port closed) or no response (port open/filtered)
                    rst_received = False
                    for response in responses:
                        if (response.get('protocol') == socket.IPPROTO_TCP and
                            response.get('dest_port') == port and
                            'RST' in response.get('flag_names', [])):
                            rst_received = True
                            break
                    
                    if not rst_received:
                        # Port might be open or filtered
                        port_info = {
                            'port': port,
                            'protocol': 'tcp',
                            'state': 'open|filtered',
                            'method': 'null_scan',
                            'timestamp': datetime.datetime.now().isoformat()
                        }
                        open_ports.append(port_info)
                        
                        print(f"{Colors.YELLOW}[?] {target}:{port} OPEN|FILTERED (no RST response){Colors.ENDC}")
                        
                        # Save to database
                        if DB:
                            host_id = DB.save_host(target)
                            DB.save_port(host_id, port, 'tcp', None, None, 'open|filtered')
                    
                # Update progress
                if (i + 1) % 10 == 0 or (i + 1) == len(ports):
                    percent = ((i + 1) / len(ports)) * 100
                    print(f"\r{Colors.CYAN}[*] Progress: {i + 1}/{len(ports)} ports ({percent:.1f}%){Colors.ENDC}", end="")
                    
            except Exception as e:
                logger.debug(f"Error in NULL scan for port {port}: {e}")
                
        # Scan complete
        end_time = time.time()
        results['scan_duration'] = end_time - start_time
        results['end_time'] = datetime.datetime.now().isoformat()
        results['open_ports'] = open_ports
        
        print(f"\n{Colors.GREEN}[*] NULL scan completed in {results['scan_duration']:.2f}s{Colors.ENDC}")
        print(f"{Colors.GREEN}[*] Found {len(open_ports)} open|filtered ports{Colors.ENDC}")
        
        # Save scan to database
        if DB:
            DB.save_scan('null_scan', target, results)
            
        return results

    def udp_scan(self, target: str, ports: List[int] = None,
                 timeout: float = None) -> Dict[str, List[Dict]]:
        """
        Perform UDP port scan
        
        Args:
            target: IP address or hostname
            ports: List of ports to scan
            timeout: Timeout per port in seconds
            
        Returns:
            Dictionary with scan results
        """
        if timeout is None:
            timeout = CONFIG['network'].scan_timeout
            
        if ports is None:
            ports = [53, 67, 68, 69, 123, 137, 138, 139, 161, 162, 445, 514, 520, 631, 1434]
            
        open_ports = []
        results = {
            'target': target,
            'scan_type': 'udp_scan',
            'start_time': datetime.datetime.now().isoformat(),
            'ports_scanned': len(ports),
            'open_ports': [],
            'scan_duration': None
        }
        
        logger.info(f"Starting UDP scan on {target} ({len(ports)} ports)")
        print(f"{Colors.BLUE}[*] Starting UDP scan on {target} ({len(ports)} ports)...{Colors.ENDC}")
        
        start_time = time.time()
        
        # Validate target
        if not NetworkUtils.validate_ip(target):
            try:
                target = socket.gethostbyname(target)
            except socket.gaierror:
                logger.error(f"Could not resolve hostname: {target}")
                return results
        
        # Scan ports
        for i, port in enumerate(ports):
            try:
                # Create UDP socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                
                # Send empty packet
                sock.sendto(b'', (target, port))
                
                try:
                    # Try to receive response
                    data, addr = sock.recvfrom(1024)
                    
                    # If we get a response, port is open
                    port_info = {
                        'port': port,
                        'protocol': 'udp',
                        'state': 'open',
                        'response': data[:100].hex() if data else None,
                        'timestamp': datetime.datetime.now().isoformat()
                    }
                    open_ports.append(port_info)
                    
                    print(f"{Colors.GREEN}[+] {target}:{port}/udp OPEN{Colors.ENDC}")
                    
                    # Save to database
                    if DB:
                        host_id = DB.save_host(target)
                        DB.save_port(host_id, port, 'udp', None, None, 'open')
                        
                except socket.timeout:
                    # Port might be open or filtered (UDP is connectionless)
                    port_info = {
                        'port': port,
                        'protocol': 'udp',
                        'state': 'open|filtered',
                        'timestamp': datetime.datetime.now().isoformat()
                    }
                    open_ports.append(port_info)
                    
                    print(f"{Colors.YELLOW}[?] {target}:{port}/udp OPEN|FILTERED{Colors.ENDC}")
                    
                    # Save to database
                    if DB:
                        host_id = DB.save_host(target)
                        DB.save_port(host_id, port, 'udp', None, None, 'open|filtered')
                        
                except ConnectionRefusedError:
                    # Port is closed
                    pass
                    
                sock.close()
                
                # Update progress
                if (i + 1) % 5 == 0 or (i + 1) == len(ports):
                    percent = ((i + 1) / len(ports)) * 100
                    print(f"\r{Colors.CYAN}[*] Progress: {i + 1}/{len(ports)} ports ({percent:.1f}%){Colors.ENDC}", end="")
                    
            except Exception as e:
                logger.debug(f"Error in UDP scan for port {port}: {e}")
                
        # Scan complete
        end_time = time.time()
        results['scan_duration'] = end_time - start_time
        results['end_time'] = datetime.datetime.now().isoformat()
        results['open_ports'] = open_ports
        
        print(f"\n{Colors.GREEN}[*] UDP scan completed in {results['scan_duration']:.2f}s{Colors.ENDC}")
        print(f"{Colors.GREEN}[*] Found {len(open_ports)} open/open|filtered ports{Colors.ENDC}")
        
        # Save scan to database
        if DB:
            DB.save_scan('udp_scan', target, results)
            
        return results

    def _scan_port(self, host: str, port: int, timeout: float) -> Tuple[bool, Optional[str], Optional[str]]:
        """Scan a single port with service detection"""
        return NetworkUtils.is_port_open(host, port, timeout)

    def _get_common_ports(self) -> List[int]:
        """Return list of common ports"""
        return [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443
        ] + list(range(1, 1024))

    def _check_common_vulnerabilities(self, host: str, port: int, service: str, banner: str):
        """Check for common vulnerabilities based on port and service"""
        vulnerabilities = []

        # SSH vulnerabilities
        if port == 22 and 'SSH' in (service or ''):
            if banner and 'OpenSSH' in banner:
                version_match = re.search(r'OpenSSH_(\d+\.\d+)', banner)
                if version_match:
                    version = float(version_match.group(1))
                    if version < 7.0:
                        vulnerabilities.append({
                            'cve': 'CVE-2016-0777',
                            'severity': 'medium',
                            'description': 'OpenSSH client information disclosure',
                            'remediation': 'Upgrade OpenSSH to version 7.1 or later'
                        })

        # FTP vulnerabilities
        elif port == 21 and 'ftp' in (service or '').lower():
            vulnerabilities.append({
                'cve': 'Various',
                'severity': 'high',
                'description': 'FTP is an insecure protocol that transmits credentials in plain text',
                'remediation': 'Use SFTP or FTPS instead'
            })

        # SMB vulnerabilities
        elif port == 445 or port == 139:
            vulnerabilities.append({
                'cve': 'CVE-2017-0143-CVE-2017-0148',
                'severity': 'critical',
                'description': 'EternalBlue SMB vulnerability (used in WannaCry ransomware)',
                'remediation': 'Apply MS17-010 security update'
            })

        # Telnet vulnerabilities
        elif port == 23:
            vulnerabilities.append({
                'cve': 'Various',
                'severity': 'high',
                'description': 'Telnet transmits all data in plain text',
                'remediation': 'Disable telnet and use SSH instead'
            })

        # Create alerts for vulnerabilities
        for vuln in vulnerabilities:
            ALERT_MANAGER.add_alert(
                AlertType.SECURITY,
                RiskLevel(vuln['severity']),
                f"Potential vulnerability on {host}:{port} - {vuln['description']}",
                source="NetworkScanner.vulnerability_check",
                details=vuln
            )

            # Save to database
            if DB:
                host_id = DB.save_host(host)
                port_id = None

                # Get port ID
                cursor = DB.conn.cursor()
                cursor.execute(
                    "SELECT id FROM ports WHERE host_id = ? AND port_number = ?",
                    (host_id, port)
                )
                port_row = cursor.fetchone()
                if port_row:
                    port_id = port_row[0]

                # Save vulnerability
                cursor.execute('''
                    INSERT INTO vulnerabilities
                    (host_id, port_id, cve_id, severity, description, cvss_score, remediation, discovered_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    host_id, port_id, vuln.get('cve'), vuln['severity'],
                    vuln['description'], 0.0, vuln['remediation'],
                    datetime.datetime.now().isoformat()
                ))
                DB.conn.commit()

    def _generate_port_scan_report(self, results: Dict) -> str:
        """Generate a formatted report for port scan results"""
        report = []
        report.append("=" * 70)
        report.append("PORT SCAN REPORT")
        report.append("=" * 70)
        report.append(f"Target: {results['target']}")
        report.append(f"Scan started: {results['start_time']}")
        report.append(f"Scan duration: {results['scan_duration']:.2f} seconds")
        report.append(f"Ports scanned: {results['ports_scanned']}")
        report.append(f"Open ports found: {len(results['open_ports'])}")
        report.append("-" * 70)

        if results['open_ports']:
            report.append("OPEN PORTS:")
            report.append("-" * 70)
            for port_info in sorted(results['open_ports'], key=lambda x: x['port']):
                service = port_info.get('service', 'unknown')
                banner = port_info.get('banner', '')
                report.append(f"Port {port_info['port']}/tcp: {service}")
                if banner:
                    report.append(f"  Banner: {banner[:100]}...")
        else:
            report.append("No open ports found")

        report.append("=" * 70)

        report_text = "\n".join(report)

        # Save report to file
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = REPORTS_DIR / f"port_scan_{results['target']}_{timestamp}.txt"

        with open(report_file, 'w') as f:
            f.write(report_text)

        logger.info(f"Report saved to {report_file}")

        return report_text

    def comprehensive_scan(self, target: str) -> Dict:
        """
        Perform comprehensive scan including ping, ports, services, and vulnerabilities
        """
        logger.info(f"Starting comprehensive scan on {target}")
        print(f"{Colors.CYAN}[*] Starting comprehensive scan on {target}{Colors.ENDC}")

        results = {
            'target': target,
            'start_time': datetime.datetime.now().isoformat(),
            'phases': {}
        }

        # Phase 1: Host discovery
        print(f"{Colors.BLUE}[*] Phase 1: Host Discovery{Colors.ENDC}")
        if NetworkUtils.validate_ip(target):
            network = f"{target}/24"  # Assume /24 network
            alive_hosts = self.ping_sweep(network)
            results['phases']['host_discovery'] = alive_hosts
        else:
            # Single host
            try:
                ip = socket.gethostbyname(target)
                results['phases']['host_discovery'] = {
                    ip: {
                        'alive': True,
                        'hostname': target,
                        'last_seen': datetime.datetime.now().isoformat()
                    }
                }
            except:
                results['phases']['host_discovery'] = {}

        # Phase 2: Port scanning on discovered hosts
        print(f"\n{Colors.BLUE}[*] Phase 2: Port Scanning{Colors.ENDC}")
        results['phases']['port_scanning'] = {}

        for host, host_info in results['phases']['host_discovery'].items():
            if host_info.get('alive'):
                print(f"{Colors.CYAN}[*] Scanning ports on {host}{Colors.ENDC}")
                port_results = self.port_scan(host)
                results['phases']['port_scanning'][host] = port_results

        # Phase 3: Service detection and vulnerability assessment
        print(f"\n{Colors.BLUE}[*] Phase 3: Vulnerability Assessment{Colors.ENDC}")
        results['phases']['vulnerability_assessment'] = []

        for host, port_results in results['phases']['port_scanning'].items():
            for port_info in port_results.get('open_ports', []):
                # Additional service probing could go here
                pass

        results['end_time'] = datetime.datetime.now().isoformat()
        results['scan_duration'] = (
            datetime.datetime.fromisoformat(results['end_time']) -
            datetime.datetime.fromisoformat(results['start_time'])
        ).total_seconds()

        # Generate comprehensive report
        report = self._generate_comprehensive_report(results)

        # Save to database
        if DB:
            DB.save_scan('comprehensive', target, results)

        logger.info(f"Comprehensive scan completed for {target}")
        print(f"{Colors.GREEN}[*] Comprehensive scan completed{Colors.ENDC}")

        return results

    def _generate_comprehensive_report(self, results: Dict) -> str:
        """Generate comprehensive scan report"""
        report = []
        report.append("=" * 80)
        report.append("COMPREHENSIVE SECURITY SCAN REPORT")
        report.append("=" * 80)
        report.append(f"Target: {results['target']}")
        report.append(f"Scan started: {results['start_time']}")
        report.append(f"Scan completed: {results['end_time']}")
        report.append(f"Scan duration: {results['scan_duration']:.2f} seconds")
        report.append("=" * 80)

        # Host discovery section
        report.append("\nHOST DISCOVERY")
        report.append("-" * 80)
        alive_hosts = results['phases'].get('host_discovery', {})
        report.append(f"Alive hosts found: {len(alive_hosts)}")

        for host, info in alive_hosts.items():
            hostname = info.get('hostname', 'N/A')
            response_time = info.get('response_time', 'N/A')
            report.append(f"  {host} ({hostname}) - Response: {response_time}")

        # Port scanning section
        report.append("\nPORT SCANNING RESULTS")
        report.append("-" * 80)

        for host, scan_results in results['phases'].get('port_scanning', {}).items():
            open_ports = scan_results.get('open_ports', [])
            if open_ports:
                report.append(f"\n{host}:")
                for port_info in open_ports:
                    service = port_info.get('service', 'unknown')
                    report.append(f"  Port {port_info['port']}/tcp: {service}")

        # Vulnerability assessment section
        report.append("\nVULNERABILITY ASSESSMENT")
        report.append("-" * 80)

        # Get vulnerabilities from database
        if DB:
            cursor = DB.conn.cursor()
            cursor.execute('''
                SELECT v.severity, COUNT(*) as count
                FROM vulnerabilities v
                JOIN hosts h ON v.host_id = h.id
                WHERE h.ip_address = ? AND v.resolved_at IS NULL
                GROUP BY v.severity
            ''', (results['target'],))

            vuln_counts = cursor.fetchall()

            if vuln_counts:
                report.append("Potential vulnerabilities found:")
                for severity, count in vuln_counts:
                    report.append(f"  {severity.upper()}: {count}")
            else:
                report.append("No critical vulnerabilities detected")

        # Recommendations section
        report.append("\nSECURITY RECOMMENDATIONS")
        report.append("-" * 80)

        recommendations = []

        # Check for common insecure services
        for host, scan_results in results['phases'].get('port_scanning', {}).items():
            for port_info in scan_results.get('open_ports', []):
                port = port_info['port']

                if port == 21:
                    recommendations.append("Disable FTP (port 21) - use SFTP or FTPS instead")
                elif port == 23:
                    recommendations.append("Disable Telnet (port 23) - use SSH instead")
                elif port == 445 or port == 139:
                    recommendations.append("Ensure SMB (ports 139/445) is properly secured with latest patches")
                elif port == 3389:
                    recommendations.append("RDP (port 3389) should be protected with strong authentication")

        if recommendations:
            for i, rec in enumerate(set(recommendations), 1):
                report.append(f"{i}. {rec}")
        else:
            report.append("No specific recommendations at this time")

        report.append("\n" + "=" * 80)
        report.append(f"Report generated: {datetime.datetime.now().isoformat()}")
        report.append("=" * 80)

        report_text = "\n".join(report)

        # Save report to file
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = REPORTS_DIR / f"comprehensive_scan_{results['target']}_{timestamp}.txt"

        with open(report_file, 'w') as f:
            f.write(report_text)

        print(f"{Colors.GREEN}[*] Report saved to {report_file}{Colors.ENDC}")

        return report_text

    def packet_sniff(self, interface: str = None, filter_str: str = None,
                    packet_count: int = 100, timeout: int = 30) -> Dict:
        """
        Capture network packets
        
        Args:
            interface: Network interface to capture on
            filter_str: BPF filter string
            packet_count: Number of packets to capture
            timeout: Capture timeout in seconds
            
        Returns:
            Dictionary with capture results
        """
        try:
            # Check if we have permission for packet capture
            if platform.system() != 'Windows':
                # Check if we can create raw socket (requires root on Linux)
                try:
                    test_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                    test_socket.close()
                    can_capture = True
                except (PermissionError, OSError):
                    can_capture = False
                    print(f"{Colors.RED}[-] Permission denied for packet capture. Run with sudo/Admin.{Colors.ENDC}")
                    return {}
            else:
                # Windows packet capture requires WinPcap/Npcap
                can_capture = False
                print(f"{Colors.YELLOW}[!] Packet capture requires WinPcap/Npcap on Windows{Colors.ENDC}")
                return {}
            
            if not can_capture:
                return {}
                
            # Try to use scapy if available
            if SCAPY_AVAILABLE:
                from scapy.all import sniff, conf
                
                # Set interface
                if interface:
                    conf.iface = interface
                else:
                    # Use default interface
                    interface = conf.iface
                    
                print(f"{Colors.BLUE}[*] Capturing packets on {interface}...{Colors.ENDC}")
                print(f"{Colors.CYAN}[*] Filter: {filter_str or 'None'}{Colors.ENDC}")
                print(f"{Colors.CYAN}[*] Packet count: {packet_count}{Colors.ENDC}")
                print(f"{Colors.CYAN}[*] Timeout: {timeout} seconds{Colors.ENDC}")
                
                # Start capture
                packets = sniff(iface=interface, filter=filter_str, count=packet_count, timeout=timeout)
                
                # Analyze packets
                packet_stats = {
                    'total': len(packets),
                    'by_protocol': Counter(),
                    'source_ips': Counter(),
                    'dest_ips': Counter(),
                    'packets': []
                }
                
                for i, pkt in enumerate(packets):
                    packet_info = {
                        'number': i + 1,
                        'time': pkt.time,
                        'summary': pkt.summary()
                    }
                    
                    # Get protocol
                    if pkt.haslayer('IP'):
                        packet_info['src_ip'] = pkt['IP'].src
                        packet_info['dst_ip'] = pkt['IP'].dst
                        packet_stats['source_ips'][pkt['IP'].src] += 1
                        packet_stats['dest_ips'][pkt['IP'].dst] += 1
                        
                    if pkt.haslayer('TCP'):
                        packet_info['protocol'] = 'TCP'
                        packet_info['src_port'] = pkt['TCP'].sport
                        packet_info['dst_port'] = pkt['TCP'].dport
                        packet_stats['by_protocol']['TCP'] += 1
                    elif pkt.haslayer('UDP'):
                        packet_info['protocol'] = 'UDP'
                        packet_info['src_port'] = pkt['UDP'].sport
                        packet_info['dst_port'] = pkt['UDP'].dport
                        packet_stats['by_protocol']['UDP'] += 1
                    elif pkt.haslayer('ICMP'):
                        packet_info['protocol'] = 'ICMP'
                        packet_stats['by_protocol']['ICMP'] += 1
                    elif pkt.haslayer('ARP'):
                        packet_info['protocol'] = 'ARP'
                        packet_stats['by_protocol']['ARP'] += 1
                    else:
                        packet_info['protocol'] = 'Other'
                        packet_stats['by_protocol']['Other'] += 1
                    
                    packet_stats['packets'].append(packet_info)
                
                # Save capture to file
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                capture_file = REPORTS_DIR / f"packet_capture_{timestamp}.pcap"
                
                # Save as pcap
                from scapy.all import wrpcap
                wrpcap(str(capture_file), packets)
                
                # Save metadata to database
                if DB:
                    DB.save_packet_capture(
                        capture_name=f"Capture_{timestamp}",
                        interface=interface,
                        filter_str=filter_str or '',
                        packet_count=len(packets),
                        file_path=str(capture_file)
                    )
                
                print(f"{Colors.GREEN}[*] Captured {len(packets)} packets{Colors.ENDC}")
                print(f"{Colors.GREEN}[*] Capture saved to {capture_file}{Colors.ENDC}")
                
                # Display statistics
                print(f"\n{Colors.CYAN}=== CAPTURE STATISTICS ==={Colors.ENDC}")
                print(f"Total packets: {packet_stats['total']}")
                print(f"\nBy protocol:")
                for protocol, count in packet_stats['by_protocol'].items():
                    print(f"  {protocol}: {count}")
                
                print(f"\nTop source IPs:")
                for ip, count in packet_stats['source_ips'].most_common(5):
                    print(f"  {ip}: {count}")
                    
                print(f"\nTop destination IPs:")
                for ip, count in packet_stats['dest_ips'].most_common(5):
                    print(f"  {ip}: {count}")
                
                return packet_stats
                
            else:
                print(f"{Colors.YELLOW}[!] Scapy not installed. Install with: pip install scapy{Colors.ENDC}")
                return {}
                
        except ImportError:
            print(f"{Colors.YELLOW}[!] Scapy not installed. Install with: pip install scapy{Colors.ENDC}")
            return {}
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
            print(f"{Colors.RED}[-] Packet capture failed: {e}{Colors.ENDC}")
            return {}

    def close(self):
        """Close scanner resources"""
        try:
            self.raw_scanner.close()
            logger.info("Network scanner closed")
        except Exception as e:
            logger.error(f"Error closing network scanner: {e}")

# System Monitoring Component
class SystemMonitor:
    """Real-time system monitoring and alerting"""

    def __init__(self, update_interval: int = None):
        if update_interval is None:
            update_interval = CONFIG['monitoring'].update_interval

        self.update_interval = update_interval
        self.monitoring = False
        self.monitor_thread = None
        self.metrics_history = []
        self.max_history = CONFIG['monitoring'].history_size

    def start_monitoring(self):
        """Start system monitoring in background thread"""
        if self.monitoring:
            logger.warning("Monitoring already started")
            return

        self.monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="SystemMonitor"
        )
        self.monitor_thread.start()

        logger.info("System monitoring started")
        print(f"{Colors.GREEN}[*] System monitoring started{Colors.ENDC}")

    def stop_monitoring(self):
        """Stop system monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)

        logger.info("System monitoring stopped")
        print(f"{Colors.YELLOW}[*] System monitoring stopped{Colors.ENDC}")

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                metrics = self._collect_metrics()
                self._analyze_metrics(metrics)
                self._store_metrics(metrics)

                # Display real-time metrics (optional)
                if len(self.metrics_history) % 10 == 1:  # Update every 10 cycles
                    self._display_metrics(metrics)

            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                ALERT_MANAGER.add_alert(
                    AlertType.SYSTEM, RiskLevel.HIGH,
                    f"Monitoring error: {str(e)}",
                    source="SystemMonitor._monitor_loop"
                )

            time.sleep(self.update_interval)

    def _collect_metrics(self) -> Dict:
        """Collect system metrics"""
        metrics = {
            'timestamp': datetime.datetime.now().isoformat(),
            'cpu': {},
            'memory': {},
            'disk': {},
            'network': {},
            'processes': {}
        }

        if not PSUTIL_AVAILABLE:
            return metrics

        try:
            # CPU metrics
            metrics['cpu']['percent'] = psutil.cpu_percent(interval=0.1)
            metrics['cpu']['percent_per_core'] = psutil.cpu_percent(interval=0.1, percpu=True)
            metrics['cpu']['freq'] = psutil.cpu_freq().current if psutil.cpu_freq() else None
            metrics['cpu']['load'] = psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None

            # Memory metrics
            memory = psutil.virtual_memory()
            metrics['memory']['total'] = memory.total
            metrics['memory']['available'] = memory.available
            metrics['memory']['percent'] = memory.percent
            metrics['memory']['used'] = memory.used
            metrics['memory']['free'] = memory.free

            # Swap memory
            swap = psutil.swap_memory()
            metrics['memory']['swap_total'] = swap.total
            metrics['memory']['swap_used'] = swap.used
            metrics['memory']['swap_percent'] = swap.percent

            # Disk metrics
            partitions = []
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    partitions.append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent
                    })
                except:
                    continue
            metrics['disk']['partitions'] = partitions

            # Network metrics
            net_io = psutil.net_io_counters()
            metrics['network']['bytes_sent'] = net_io.bytes_sent
            metrics['network']['bytes_recv'] = net_io.bytes_recv
            metrics['network']['packets_sent'] = net_io.packets_sent
            metrics['network']['packets_recv'] = net_io.packets_recv

            # Network connections
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                conn_info = {
                    'fd': conn.fd,
                    'family': conn.family.name,
                    'type': conn.type.name,
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                }
                connections.append(conn_info)
            metrics['network']['connections'] = connections

            # Process metrics
            metrics['processes']['total'] = len(psutil.pids())

            # Top processes by CPU and memory
            top_cpu = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    info = proc.info
                    info['cpu_percent'] = info.get('cpu_percent', 0)
                    info['memory_percent'] = info.get('memory_percent', 0)
                    top_cpu.append(info)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            top_cpu.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
            metrics['processes']['top_cpu'] = top_cpu[:5]

        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
            metrics['error'] = str(e)

        return metrics

    def _analyze_metrics(self, metrics: Dict):
        """Analyze metrics and trigger alerts if thresholds exceeded"""
        if not metrics or 'error' in metrics:
            return

        thresholds = CONFIG['monitoring'].alert_thresholds

        # Check CPU usage
        cpu_percent = metrics['cpu'].get('percent', 0)
        if cpu_percent > thresholds['cpu']:
            ALERT_MANAGER.add_alert(
                AlertType.PERFORMANCE, RiskLevel.HIGH,
                f"High CPU usage: {cpu_percent:.1f}%",
                source="SystemMonitor.cpu",
                details={'value': cpu_percent, 'threshold': thresholds['cpu']}
            )

        # Check memory usage
        memory_percent = metrics['memory'].get('percent', 0)
        if memory_percent > thresholds['memory']:
            ALERT_MANAGER.add_alert(
                AlertType.PERFORMANCE, RiskLevel.HIGH,
                f"High memory usage: {memory_percent:.1f}%",
                source="SystemMonitor.memory",
                details={'value': memory_percent, 'threshold': thresholds['memory']}
            )

        # Check disk usage for each partition
        for partition in metrics['disk'].get('partitions', []):
            disk_percent = partition.get('percent', 0)
            if disk_percent > thresholds['disk']:
                ALERT_MANAGER.add_alert(
                    AlertType.PERFORMANCE, RiskLevel.MEDIUM,
                    f"High disk usage on {partition['mountpoint']}: {disk_percent:.1f}%",
                    source="SystemMonitor.disk",
                    details={
                        'mountpoint': partition['mountpoint'],
                        'value': disk_percent,
                        'threshold': thresholds['disk']
                    }
                )

        # Check for suspicious network connections
        suspicious_connections = []
        for conn in metrics['network'].get('connections', []):
            # Look for connections to known suspicious ports
            if conn.get('raddr'):
                try:
                    port = int(conn['raddr'].split(':')[-1])
                    if port in [4444, 31337, 6667, 6660, 6661]:  # Common malware ports
                        suspicious_connections.append(conn)
                except:
                    pass

        if suspicious_connections:
            ALERT_MANAGER.add_alert(
                AlertType.SECURITY, RiskLevel.HIGH,
                f"Suspicious network connections detected: {len(suspicious_connections)}",
                source="SystemMonitor.network",
                details={'connections': suspicious_connections}
            )

    def _store_metrics(self, metrics: Dict):
        """Store metrics in history"""
        self.metrics_history.append(metrics)

        # Limit history size
        if len(self.metrics_history) > self.max_history:
            self.metrics_history = self.metrics_history[-self.max_history:]

    def _display_metrics(self, metrics: Dict):
        """Display current metrics in console"""
        if not metrics or 'error' in metrics:
            return

        print(f"\n{Colors.CYAN}=== SYSTEM METRICS ==={Colors.ENDC}")
        print(f"Time: {datetime.datetime.now().strftime('%H:%M:%S')}")

        # CPU
        cpu_percent = metrics['cpu'].get('percent', 0)
        cpu_color = Colors.GREEN
        if cpu_percent > 80:
            cpu_color = Colors.RED
        elif cpu_percent > 60:
            cpu_color = Colors.YELLOW
        print(f"CPU: {cpu_color}{cpu_percent:.1f}%{Colors.ENDC}")

        # Memory
        memory_percent = metrics['memory'].get('percent', 0)
        memory_color = Colors.GREEN
        if memory_percent > 80:
            memory_color = Colors.RED
        elif memory_percent > 60:
            memory_color = Colors.YELLOW
        memory_used = metrics['memory'].get('used', 0) / (1024**3)  # Convert to GB
        memory_total = metrics['memory'].get('total', 0) / (1024**3)  # Convert to GB
        print(f"Memory: {memory_color}{memory_percent:.1f}%{Colors.ENDC} ({memory_used:.1f}/{memory_total:.1f} GB)")

        # Network
        bytes_sent = metrics['network'].get('bytes_sent', 0) / (1024**2)  # Convert to MB
        bytes_recv = metrics['network'].get('bytes_recv', 0) / (1024**2)  # Convert to MB
        print(f"Network: ↑{bytes_sent:.1f} MB ↓{bytes_recv:.1f} MB")

        # Processes
        total_procs = metrics['processes'].get('total', 0)
        print(f"Processes: {total_procs}")

        # Display top CPU process
        top_procs = metrics['processes'].get('top_cpu', [])
        if top_procs:
            print(f"Top process: {top_procs[0].get('name', 'N/A')} ({top_procs[0].get('cpu_percent', 0):.1f}%)")

        print(f"{Colors.CYAN}====================={Colors.ENDC}")

    def get_metrics_history(self, limit: int = 100) -> List[Dict]:
        """Get recent metrics history"""
        return self.metrics_history[-limit:] if self.metrics_history else []

    def get_metrics_summary(self) -> Dict:
        """Get summary statistics of recent metrics"""
        if not self.metrics_history:
            return {}

        recent_metrics = self.metrics_history[-100:]  # Last 100 samples

        summary = {
            'cpu': {
                'avg': sum(m['cpu'].get('percent', 0) for m in recent_metrics) / len(recent_metrics),
                'max': max(m['cpu'].get('percent', 0) for m in recent_metrics),
                'min': min(m['cpu'].get('percent', 0) for m in recent_metrics)
            },
            'memory': {
                'avg': sum(m['memory'].get('percent', 0) for m in recent_metrics) / len(recent_metrics),
                'max': max(m['memory'].get('percent', 0) for m in recent_metrics),
                'min': min(m['memory'].get('percent', 0) for m in recent_metrics)
            },
            'sample_count': len(recent_metrics),
            'time_range': {
                'start': recent_metrics[0]['timestamp'],
                'end': recent_metrics[-1]['timestamp']
            }
        }

        return summary

# Initialize system monitor
SYSTEM_MONITOR = SystemMonitor()

# Web Application Scanner Component
class WebScanner:
    """Web application security scanner"""

    def __init__(self):
        self.session = None
        self.vulnerabilities = []

    def scan_url(self, url: str, depth: int = 1) -> Dict:
        """
        Scan a web application for common vulnerabilities

        Args:
            url: Base URL to scan
            depth: Crawling depth (1 = only base URL, 2 = includes links, etc.)

        Returns:
            Scan results with discovered vulnerabilities
        """
        if not REQUESTS_AVAILABLE:
            logger.error("Requests library not available for web scanning")
            return {}

        results = {
            'url': url,
            'start_time': datetime.datetime.now().isoformat(),
            'vulnerabilities': [],
            'endpoints': [],
            'scan_duration': None
        }

        logger.info(f"Starting web scan for {url}")
        print(f"{Colors.BLUE}[*] Scanning web application: {url}{Colors.ENDC}")

        start_time = time.time()

        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        # Create session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; HACK404-Scanner/2.0)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })

        try:
            # Check if site is accessible
            response = self.session.get(url, timeout=10, allow_redirects=True)
            final_url = response.url
            results['final_url'] = final_url
            results['status_code'] = response.status_code
            results['headers'] = dict(response.headers)

            print(f"{Colors.GREEN}[+] Site accessible: {response.status_code}{Colors.ENDC}")

            # Perform security checks
            checks = [
                self._check_http_security_headers,
                self._check_information_disclosure,
                self._check_directory_listing,
                self._check_common_files,
                self._check_cors_misconfiguration,
                self._check_xss_vulnerabilities,
                self._check_sql_injection,
            ]

            for check in checks:
                try:
                    vulnerabilities = check(final_url, response)
                    if vulnerabilities:
                        results['vulnerabilities'].extend(vulnerabilities)

                        for vuln in vulnerabilities:
                            # Create alert for high severity vulnerabilities
                            if vuln.get('severity') in ['high', 'critical']:
                                ALERT_MANAGER.add_alert(
                                    AlertType.SECURITY,
                                    RiskLevel(vuln['severity']),
                                    f"Web vulnerability found: {vuln['title']}",
                                    source="WebScanner",
                                    details=vuln
                                )

                            # Display finding
                            severity_color = Colors.RED if vuln.get('severity') in ['high', 'critical'] else Colors.YELLOW
                            print(f"{severity_color}[!] {vuln['title']} - {vuln.get('severity', 'medium').upper()}{Colors.ENDC}")

                except Exception as e:
                    logger.error(f"Error in security check: {e}")

            # Crawl for more endpoints (basic crawling)
            if depth > 1:
                endpoints = self._crawl_links(final_url, response.text, depth - 1)
                results['endpoints'] = endpoints

            # Check for common admin panels
            admin_panels = self._check_admin_panels(final_url)
            if admin_panels:
                results['admin_panels'] = admin_panels
                print(f"{Colors.YELLOW}[!] Potential admin panels found{Colors.ENDC}")

        except requests.RequestException as e:
            logger.error(f"Error accessing {url}: {e}")
            results['error'] = str(e)
            print(f"{Colors.RED}[-] Error accessing {url}: {e}{Colors.ENDC}")

        except Exception as e:
            logger.error(f"Unexpected error scanning {url}: {e}")
            results['error'] = str(e)

        # Calculate duration
        end_time = time.time()
        results['scan_duration'] = end_time - start_time
        results['end_time'] = datetime.datetime.now().isoformat()

        # Generate report
        report = self._generate_web_scan_report(results)

        logger.info(f"Web scan completed for {url}. Found {len(results['vulnerabilities'])} vulnerabilities")
        print(f"{Colors.GREEN}[*] Web scan completed in {results['scan_duration']:.2f}s{Colors.ENDC}")

        return results

    def _check_http_security_headers(self, url: str, response: requests.Response) -> List[Dict]:
        """Check for missing security headers"""
        vulnerabilities = []
        required_headers = {
            'X-Frame-Options': 'Prevents clickjacking attacks',
            'X-Content-Type-Options': 'Prevents MIME type sniffing',
            'X-XSS-Protection': 'Enables XSS protection in older browsers',
            'Strict-Transport-Security': 'Enforces HTTPS',
            'Content-Security-Policy': 'Prevents XSS and other code injection attacks',
            'Referrer-Policy': 'Controls referrer information',
        }

        missing_headers = []
        for header, description in required_headers.items():
            if header not in response.headers:
                missing_headers.append(header)

        if missing_headers:
            vulnerabilities.append({
                'title': 'Missing security headers',
                'severity': 'medium',
                'description': f"Missing recommended HTTP security headers: {', '.join(missing_headers)}",
                'recommendation': 'Implement the missing security headers',
                'headers_missing': missing_headers,
                'url': url
            })

        return vulnerabilities

    def _check_information_disclosure(self, url: str, response: requests.Response) -> List[Dict]:
        """Check for information disclosure in headers and content"""
        vulnerabilities = []

        # Check for sensitive headers
        sensitive_patterns = [
            r'server:.*', r'x-powered-by:.*', r'x-aspnet-version:.*',
            r'x-aspnetmvc-version:.*', r'x-runtime:.*'
        ]

        for header_name, header_value in response.headers.items():
            for pattern in sensitive_patterns:
                if re.match(pattern, f'{header_name.lower()}:{header_value}', re.IGNORECASE):
                    vulnerabilities.append({
                        'title': 'Information disclosure in headers',
                        'severity': 'low',
                        'description': f'Sensitive information in header: {header_name}: {header_value}',
                        'recommendation': 'Remove or obfuscate server information in headers',
                        'url': url,
                        'header': header_name,
                        'value': header_value
                    })

        # Check for sensitive information in response body
        sensitive_info_patterns = [
            (r'(password|pwd|passwd|secret|key|token)=["\']?[^"\'\s]+["\']?', 'Credentials in source'),
            (r'sql.*error|syntax.*error|mysql.*error', 'Database errors'),
            (r'stack trace:|traceback|exception:|at .*\.java:|\.py", line', 'Debug information'),
        ]

        body = response.text.lower()
        for pattern, description in sensitive_info_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                vulnerabilities.append({
                    'title': f'Potential information disclosure: {description}',
                    'severity': 'medium',
                    'description': f'Found pattern indicating {description.lower()}',
                    'recommendation': 'Review error handling and ensure sensitive information is not exposed',
                    'url': url,
                    'pattern': pattern
                })

        return vulnerabilities

    def _check_common_files(self, url: str, response: requests.Response) -> List[Dict]:
        """Check for common sensitive files"""
        vulnerabilities = []
        
        common_files = [
            ('robots.txt', 'low', 'robots.txt file accessible'),
            ('.git/config', 'high', 'Git configuration exposed'),
            ('.env', 'critical', 'Environment file exposed'),
            ('wp-config.php', 'high', 'WordPress configuration exposed'),
            ('config.php', 'high', 'PHP configuration exposed'),
            ('backup.zip', 'medium', 'Backup file accessible'),
            ('dump.sql', 'critical', 'Database dump accessible'),
            ('.htaccess', 'low', '.htaccess file accessible'),
            ('phpinfo.php', 'medium', 'PHP info exposed'),
            ('crossdomain.xml', 'low', 'Cross-domain policy file'),
        ]
        
        base_url = url.rstrip('/')
        
        for file_path, severity, description in common_files:
            try:
                file_url = f"{base_url}/{file_path}"
                file_response = self.session.get(file_url, timeout=5)
                
                if file_response.status_code == 200:
                    content_type = file_response.headers.get('content-type', '')
                    
                    # Check for sensitive content patterns
                    sensitive_content = False
                    content_preview = file_response.text[:500]
                    
                    if 'env' in file_path.lower() and ('password' in content_preview.lower() or 
                                                      'secret' in content_preview.lower()):
                        sensitive_content = True
                    elif 'sql' in file_path.lower() and ('insert into' in content_preview.lower() or 
                                                         'create table' in content_preview.lower()):
                        sensitive_content = True
                    elif 'config' in file_path.lower() and ('db_' in content_preview.lower() or 
                                                           'database' in content_preview.lower()):
                        sensitive_content = True
                    
                    if sensitive_content or severity in ['high', 'critical']:
                        vulnerabilities.append({
                            'title': f'Sensitive file exposed: {file_path}',
                            'severity': severity,
                            'description': f'{description} found at {file_url}',
                            'recommendation': f'Restrict access to {file_path} or remove from web root',
                            'url': file_url,
                            'status_code': file_response.status_code,
                            'content_length': len(file_response.content)
                        })
                        
                        print(f"{Colors.RED if severity in ['high', 'critical'] else Colors.YELLOW}[!] Found sensitive file: {file_url}{Colors.ENDC}")
                        
            except requests.RequestException:
                continue
                
        return vulnerabilities

    def _check_directory_listing(self, url: str, response: requests.Response) -> List[Dict]:
        """Check if directory listing is enabled"""
        vulnerabilities = []
        
        # Test common directories
        test_directories = [
            ('images/', 'low'),
            ('css/', 'low'),
            ('js/', 'low'),
            ('uploads/', 'medium'),
            ('admin/', 'high'),
            ('backup/', 'critical'),
            ('logs/', 'critical'),
            ('tmp/', 'medium'),
        ]
        
        base_url = url.rstrip('/')
        
        for directory, severity in test_directories:
            try:
                dir_url = f"{base_url}/{directory}"
                dir_response = self.session.get(dir_url, timeout=5)
                
                # Check for directory listing indicators
                indicators = [
                    'Index of',
                    'Directory listing',
                    'Parent Directory',
                    '<title>Index of',
                    'Last modified',
                    'Size</th>',
                    'Name</th>'
                ]
                
                if dir_response.status_code == 200:
                    response_text = dir_response.text
                    if any(indicator in response_text for indicator in indicators):
                        vulnerabilities.append({
                            'title': f'Directory listing enabled: {directory}',
                            'severity': severity,
                            'description': f'Directory listing is enabled for {dir_url}',
                            'recommendation': 'Disable directory listing in web server configuration',
                            'url': dir_url,
                            'status_code': dir_response.status_code
                        })
                        
                        print(f"{Colors.YELLOW}[!] Directory listing enabled: {dir_url}{Colors.ENDC}")
                        
            except requests.RequestException:
                continue
                
        return vulnerabilities

    def _check_cors_misconfiguration(self, url: str, response: requests.Response) -> List[Dict]:
        """Check for CORS misconfigurations"""
        vulnerabilities = []
        
        # Check CORS headers
        cors_header = response.headers.get('Access-Control-Allow-Origin', '')
        
        if cors_header == '*':
            vulnerabilities.append({
                'title': 'CORS misconfiguration - Wildcard origin',
                'severity': 'high',
                'description': 'Access-Control-Allow-Origin header is set to wildcard (*)',
                'recommendation': 'Restrict CORS origins to specific trusted domains',
                'url': url,
                'header_value': cors_header
            })
            print(f"{Colors.RED}[!] CORS misconfiguration: Wildcard origin{Colors.ENDC}")
            
        # Check for missing CORS headers on API endpoints
        if 'api' in url.lower() or 'json' in response.headers.get('content-type', '').lower():
            if 'Access-Control-Allow-Origin' not in response.headers:
                vulnerabilities.append({
                    'title': 'Missing CORS headers on API endpoint',
                    'severity': 'medium',
                    'description': 'API endpoint lacks CORS headers',
                    'recommendation': 'Implement proper CORS headers for API endpoints',
                    'url': url
                })
                
        return vulnerabilities

    def _check_xss_vulnerabilities(self, url: str, response: requests.Response) -> List[Dict]:
        """Check for basic XSS vulnerabilities"""
        vulnerabilities = []
        
        # Look for reflected parameters
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        if query_params:
            # Test each parameter for reflection
            for param_name in query_params.keys():
                test_payload = f"HACK404_XSS_TEST_{random.randint(1000, 9999)}"
                test_url = self._build_test_url(url, param_name, test_payload)
                
                try:
                    test_response = self.session.get(test_url, timeout=5)
                    
                    # Check if payload is reflected in response
                    if test_payload in test_response.text:
                        # Check for proper escaping
                        escaped_payload = test_payload.replace('<', '&lt;').replace('>', '&gt;')
                        
                        if escaped_payload not in test_response.text:
                            vulnerabilities.append({
                                'title': f'Potential XSS vulnerability in parameter: {param_name}',
                                'severity': 'high',
                                'description': f'User input in parameter "{param_name}" is reflected without proper escaping',
                                'recommendation': 'Implement proper input validation and output encoding',
                                'url': test_url,
                                'parameter': param_name,
                                'payload': test_payload
                            })
                            
                            print(f"{Colors.RED}[!] Potential XSS in parameter: {param_name}{Colors.ENDC}")
                            
                except requests.RequestException:
                    continue
                    
        return vulnerabilities

    def _check_sql_injection(self, url: str, response: requests.Response) -> List[Dict]:
        """Check for basic SQL injection vulnerabilities"""
        vulnerabilities = []
        
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Common SQL injection test payloads
        test_payloads = [
            ("'", "SQL syntax error"),
            ("' OR '1'='1", "always true condition"),
            ("1' AND '1'='1", "conditional test"),
            ("' UNION SELECT null--", "union test"),
            ("' AND 1=CAST((SELECT version()) AS INT)--", "version extraction"),
        ]
        
        if query_params:
            for param_name in query_params.keys():
                for payload, description in test_payloads:
                    test_url = self._build_test_url(url, param_name, payload)
                    
                    try:
                        test_response = self.session.get(test_url, timeout=5)
                        response_text = test_response.text.lower()
                        
                        # Look for SQL error indicators
                        sql_error_indicators = [
                            'sql syntax',
                            'mysql_fetch',
                            'sqlite3',
                            'postgresql',
                            'odbc',
                            'ora-',
                            'microsoft ole db',
                            'syntax error',
                            'unclosed quotation',
                            'you have an error in your sql syntax',
                        ]
                        
                        for indicator in sql_error_indicators:
                            if indicator in response_text:
                                vulnerabilities.append({
                                    'title': f'Potential SQL injection in parameter: {param_name}',
                                    'severity': 'critical',
                                    'description': f'SQL error detected with payload: {description}',
                                    'recommendation': 'Use parameterized queries or prepared statements',
                                    'url': test_url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'error_indicator': indicator
                                })
                                
                                print(f"{Colors.RED}[!] Potential SQL Injection in parameter: {param_name}{Colors.ENDC}")
                                break  # Found an error, move to next parameter
                                
                    except requests.RequestException:
                        continue
                        
        return vulnerabilities

    def _check_admin_panels(self, url: str) -> List[str]:
        """Check for common admin panel locations"""
        admin_panels = []
        
        common_admin_paths = [
            'admin', 'administrator', 'wp-admin', 'login', 'admin/login',
            'admincp', 'admin_area', 'panel-administracion', 'management',
            'backend', 'secure', 'private', 'hidden', 'control',
            'admin123', 'adminarea', 'system', 'sysadmin', 'superuser'
        ]
        
        base_url = url.rstrip('/')
        
        for path in common_admin_paths:
            admin_url = f"{base_url}/{path}"
            
            try:
                response = self.session.get(admin_url, timeout=3)
                
                if response.status_code == 200:
                    # Check for login forms or admin indicators
                    response_text = response.text.lower()
                    
                    admin_indicators = [
                        '<form',
                        'password',
                        'username',
                        'login',
                        'admin',
                        'dashboard',
                        'control panel',
                        'manage',
                        'sign in'
                    ]
                    
                    if any(indicator in response_text for indicator in admin_indicators):
                        admin_panels.append({
                            'url': admin_url,
                            'status_code': response.status_code,
                            'title': self._extract_page_title(response.text)
                        })
                        
            except requests.RequestException:
                continue
                
        return admin_panels

    def _crawl_links(self, base_url: str, html_content: str, max_depth: int) -> List[str]:
        """Crawl links from HTML content"""
        endpoints = []
        
        if not BEAUTIFULSOUP_AVAILABLE:
            return endpoints
            
        try:
            from bs4 import BeautifulSoup
            
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Find all links
            for link in soup.find_all('a', href=True):
                href = link['href']
                
                # Resolve relative URLs
                absolute_url = urllib.parse.urljoin(base_url, href)
                
                # Filter to same domain
                if urllib.parse.urlparse(absolute_url).netloc == urllib.parse.urlparse(base_url).netloc:
                    endpoints.append(absolute_url)
                    
                    # Recursive crawl if depth allows
                    if max_depth > 0:
                        try:
                            response = self.session.get(absolute_url, timeout=3)
                            if response.status_code == 200:
                                sub_endpoints = self._crawl_links(base_url, response.text, max_depth - 1)
                                endpoints.extend(sub_endpoints)
                        except:
                            pass
                            
        except Exception as e:
            logger.error(f"Error crawling links: {e}")
            
        # Remove duplicates
        return list(set(endpoints))

    def _build_test_url(self, url: str, param_name: str, test_value: str) -> str:
        """Build a test URL with modified parameter"""
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Replace the parameter value
        query_params[param_name] = [test_value]
        
        # Rebuild URL
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        new_url = urllib.parse.urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query,
            parsed_url.fragment
        ))
        
        return new_url

    def _extract_page_title(self, html_content: str) -> str:
        """Extract page title from HTML"""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, 'html.parser')
            title_tag = soup.find('title')
            return title_tag.text.strip() if title_tag else 'No title'
        except:
            return 'No title'

    def _generate_web_scan_report(self, results: Dict) -> str:
        """Generate web scan report"""
        report = []
        
        report.append("=" * 80)
        report.append("WEB APPLICATION SECURITY SCAN REPORT")
        report.append("=" * 80)
        report.append(f"URL: {results.get('url', 'N/A')}")
        report.append(f"Final URL: {results.get('final_url', 'N/A')}")
        report.append(f"Status Code: {results.get('status_code', 'N/A')}")
        report.append(f"Scan started: {results.get('start_time', 'N/A')}")
        report.append(f"Scan duration: {results.get('scan_duration', 0):.2f} seconds")
        report.append(f"Vulnerabilities found: {len(results.get('vulnerabilities', []))}")
        report.append("=" * 80)
        
        # Vulnerabilities section
        if results.get('vulnerabilities'):
            report.append("\nVULNERABILITIES FOUND:")
            report.append("-" * 80)
            
            # Group by severity
            by_severity = defaultdict(list)
            for vuln in results['vulnerabilities']:
                by_severity[vuln.get('severity', 'unknown')].append(vuln)
            
            # Display in order of severity
            severity_order = ['critical', 'high', 'medium', 'low', 'unknown']
            
            for severity in severity_order:
                if severity in by_severity:
                    report.append(f"\n{severity.upper()} SEVERITY ({len(by_severity[severity])}):")
                    report.append("-" * 40)
                    
                    for i, vuln in enumerate(by_severity[severity], 1):
                        report.append(f"\n{i}. {vuln.get('title', 'Unknown')}")
                        report.append(f"   Description: {vuln.get('description', 'N/A')}")
                        report.append(f"   URL: {vuln.get('url', 'N/A')}")
                        if vuln.get('recommendation'):
                            report.append(f"   Recommendation: {vuln['recommendation']}")
        else:
            report.append("\nNo vulnerabilities found.")
            
        # Admin panels section
        if results.get('admin_panels'):
            report.append("\n\nPOTENTIAL ADMIN PANELS FOUND:")
            report.append("-" * 80)
            for admin in results['admin_panels']:
                report.append(f"- {admin.get('url')} (Status: {admin.get('status_code')})")
                
        # Endpoints section
        if results.get('endpoints'):
            report.append(f"\n\nDISCOVERED ENDPOINTS ({len(results['endpoints'])}):")
            report.append("-" * 80)
            for endpoint in results['endpoints'][:50]:  # Limit display
                report.append(f"- {endpoint}")
            if len(results['endpoints']) > 50:
                report.append(f"... and {len(results['endpoints']) - 50} more")
                
        # Headers section (brief)
        if results.get('headers'):
            report.append("\n\nSECURITY HEADERS:")
            report.append("-" * 80)
            security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 
                              'X-XSS-Protection', 'Strict-Transport-Security',
                              'Content-Security-Policy', 'Referrer-Policy']
            
            for header in security_headers:
                value = results['headers'].get(header, 'NOT SET')
                report.append(f"{header}: {value}")
                
        report.append("\n" + "=" * 80)
        report.append(f"Report generated: {datetime.datetime.now().isoformat()}")
        report.append("=" * 80)
        
        report_text = "\n".join(report)
        
        # Save report to file
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_url = results.get('url', 'scan').replace('://', '_').replace('/', '_').replace(':', '_')
        report_file = REPORTS_DIR / f"web_scan_{safe_url}_{timestamp}.txt"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_text)
            
        logger.info(f"Web scan report saved to {report_file}")
        
        return report_text

    def __del__(self):
        """Cleanup"""
        if self.session:
            self.session.close()

# Initialize web scanner
WEB_SCANNER = WebScanner()

# Real-time Packet Analyzer
class PacketAnalyzer:
    """Real-time packet analysis and intrusion detection"""
    
    def __init__(self):
        self.capturing = False
        self.capture_thread = None
        self.packet_buffer = []
        self.max_buffer_size = 1000
        self.signatures = self._load_intrusion_signatures()
        
    def _load_intrusion_signatures(self) -> List[Dict]:
        """Load intrusion detection signatures"""
        signatures = [
            # Network scanning signatures
            {
                'name': 'Port Scan',
                'pattern': r'flags=\.S\.',
                'protocol': 'TCP',
                'severity': 'medium',
                'description': 'Multiple SYN packets to different ports'
            },
            {
                'name': 'NMAP FIN Scan',
                'pattern': r'flags=\.F\.',
                'protocol': 'TCP',
                'severity': 'medium',
                'description': 'FIN scan commonly used by Nmap'
            },
            {
                'name': 'NMAP XMAS Scan',
                'pattern': r'flags=\.FPU\.',
                'protocol': 'TCP',
                'severity': 'medium',
                'description': 'XMAS scan (FIN, PSH, URG)'
            },
            {
                'name': 'NMAP NULL Scan',
                'pattern': r'flags=\.\.',
                'protocol': 'TCP',
                'severity': 'medium',
                'description': 'NULL scan (no flags set)'
            },
            
            # Malware/Exploit signatures
            {
                'name': 'EternalBlue Exploit',
                'pattern': r'SMB.*NT Trans.*MaxParameterCount',
                'protocol': 'TCP',
                'severity': 'critical',
                'description': 'EternalBlue SMB exploit attempt'
            },
            {
                'name': 'Meterpreter Beacon',
                'pattern': r'User-Agent:.*Meterpreter',
                'protocol': 'TCP',
                'severity': 'critical',
                'description': 'Metasploit Meterpreter traffic'
            },
            
            # Suspicious traffic patterns
            {
                'name': 'DNS Tunneling',
                'pattern': r'DNS.*TXT.*[a-zA-Z0-9+/=]{50,}',
                'protocol': 'UDP',
                'severity': 'high',
                'description': 'Potential DNS tunneling data exfiltration'
            },
            {
                'name': 'ICMP Tunnel',
                'pattern': r'ICMP.*Data.*[a-zA-Z0-9+/=]{20,}',
                'protocol': 'ICMP',
                'severity': 'high',
                'description': 'Potential ICMP tunneling'
            },
            
            # Web attacks
            {
                'name': 'SQL Injection Attempt',
                'pattern': r'(union.*select|select.*from|insert.*into|delete.*from)',
                'protocol': 'TCP',
                'severity': 'high',
                'description': 'SQL injection attempt in HTTP traffic'
            },
            {
                'name': 'XSS Attempt',
                'pattern': r'<script.*>|javascript:|onload=|onerror=',
                'protocol': 'TCP',
                'severity': 'high',
                'description': 'Cross-site scripting attempt'
            },
            
            # Reconnaissance
            {
                'name': 'Directory Traversal',
                'pattern': r'(\.\./|\.\.\\)',
                'protocol': 'TCP',
                'severity': 'medium',
                'description': 'Directory traversal attempt'
            },
            {
                'name': 'LFI/RFI Attempt',
                'pattern': r'(include=|require=|php://|http://|ftp://).*(\.\./|\.\.\\)',
                'protocol': 'TCP',
                'severity': 'high',
                'description': 'Local/Remote File Inclusion attempt'
            },
        ]
        
        return signatures
    
    def start_realtime_analysis(self, interface: str = None, filter_str: str = None):
        """Start real-time packet analysis"""
        if self.capturing:
            print(f"{Colors.YELLOW}[!] Already capturing packets{Colors.ENDC}")
            return
            
        if not SCAPY_AVAILABLE:
            print(f"{Colors.RED}[-] Scapy not installed. Required for packet analysis.{Colors.ENDC}")
            return
            
        print(f"{Colors.BLUE}[*] Starting real-time packet analysis...{Colors.ENDC}")
        
        self.capturing = True
        self.capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(interface, filter_str),
            daemon=True,
            name="PacketAnalyzer"
        )
        self.capture_thread.start()
        
        print(f"{Colors.GREEN}[*] Real-time analysis started{Colors.ENDC}")
        
    def stop_realtime_analysis(self):
        """Stop real-time packet analysis"""
        self.capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
            
        print(f"{Colors.YELLOW}[*] Real-time analysis stopped{Colors.ENDC}")
        
    def _capture_loop(self, interface: str, filter_str: str):
        """Main capture and analysis loop"""
        from scapy.all import sniff, conf
        
        try:
            # Configure interface
            if interface:
                conf.iface = interface
                
            # Start sniffing
            sniff(
                prn=self._analyze_packet,
                filter=filter_str,
                store=0,
                stop_filter=lambda x: not self.capturing
            )
            
        except Exception as e:
            logger.error(f"Error in capture loop: {e}")
            ALERT_MANAGER.add_alert(
                AlertType.NETWORK, RiskLevel.HIGH,
                f"Packet capture error: {str(e)}",
                source="PacketAnalyzer._capture_loop"
            )
            
    def _analyze_packet(self, packet):
        """Analyze individual packet for threats"""
        try:
            packet_info = self._extract_packet_info(packet)
            
            # Add to buffer
            self.packet_buffer.append(packet_info)
            if len(self.packet_buffer) > self.max_buffer_size:
                self.packet_buffer.pop(0)
                
            # Check for intrusion signatures
            threats = self._check_intrusion_signatures(packet_info, packet)
            
            # Generate alerts for threats
            for threat in threats:
                ALERT_MANAGER.add_alert(
                    AlertType.SECURITY,
                    RiskLevel(threat['severity']),
                    f"Intrusion detected: {threat['name']}",
                    source="PacketAnalyzer",
                    details=threat
                )
                
                print(f"{Colors.RED}[!] INTRUSION: {threat['name']} - {threat['description']}{Colors.ENDC}")
                
            # Detect scanning patterns
            self._detect_scanning_patterns()
            
        except Exception as e:
            logger.debug(f"Error analyzing packet: {e}")
            
    def _extract_packet_info(self, packet) -> Dict:
        """Extract relevant information from packet"""
        info = {
            'timestamp': datetime.datetime.now().isoformat(),
            'summary': packet.summary(),
            'layers': []
        }
        
        # Extract layer information
        layer = packet
        while layer:
            info['layers'].append(layer.name)
            layer = layer.payload
            
        # Extract IP information
        if packet.haslayer('IP'):
            info['src_ip'] = packet['IP'].src
            info['dst_ip'] = packet['IP'].dst
            info['protocol'] = packet['IP'].proto
            
        # Extract TCP information
        if packet.haslayer('TCP'):
            info['src_port'] = packet['TCP'].sport
            info['dst_port'] = packet['TCP'].dport
            info['flags'] = packet['TCP'].flags
            info['tcp_flags'] = str(packet['TCP'].flags)
            
        # Extract UDP information
        if packet.haslayer('UDP'):
            info['src_port'] = packet['UDP'].sport
            info['dst_port'] = packet['UDP'].dport
            
        # Extract HTTP information
        if packet.haslayer('TCP') and packet.haslayer('Raw'):
            try:
                payload = packet['Raw'].load.decode('utf-8', errors='ignore')
                if 'HTTP' in payload:
                    info['http'] = True
                    info['http_method'] = payload.split()[0] if payload.split() else None
                    info['http_host'] = self._extract_http_header(payload, 'Host')
                    info['http_user_agent'] = self._extract_http_header(payload, 'User-Agent')
                    info['http_referer'] = self._extract_http_header(payload, 'Referer')
            except:
                pass
                
        return info
        
    def _extract_http_header(self, payload: str, header: str) -> Optional[str]:
        """Extract HTTP header value"""
        lines = payload.split('\r\n')
        for line in lines:
            if line.lower().startswith(header.lower() + ':'):
                return line.split(':', 1)[1].strip()
        return None
        
    def _check_intrusion_signatures(self, packet_info: Dict, packet) -> List[Dict]:
        """Check packet against intrusion signatures"""
        threats = []
        
        for signature in self.signatures:
            try:
                # Check protocol match
                if signature['protocol'] == 'TCP' and 'TCP' not in packet_info.get('layers', []):
                    continue
                elif signature['protocol'] == 'UDP' and 'UDP' not in packet_info.get('layers', []):
                    continue
                elif signature['protocol'] == 'ICMP' and 'ICMP' not in packet_info.get('layers', []):
                    continue
                    
                # Check pattern match in summary or payload
                if re.search(signature['pattern'], packet_info.get('summary', ''), re.IGNORECASE):
                    threats.append(signature.copy())
                    
                # Check in payload if available
                elif packet.haslayer('Raw'):
                    try:
                        payload = packet['Raw'].load.decode('utf-8', errors='ignore')
                        if re.search(signature['pattern'], payload, re.IGNORECASE):
                            threats.append(signature.copy())
                    except:
                        pass
                        
            except Exception as e:
                logger.debug(f"Error checking signature {signature['name']}: {e}")
                
        return threats
        
    def _detect_scanning_patterns(self):
        """Detect network scanning patterns from packet buffer"""
        if len(self.packet_buffer) < 10:
            return
            
        # Analyze last 100 packets
        recent_packets = self.packet_buffer[-100:]
        
        # Count SYN packets by destination
        syn_packets = {}
        port_scan_candidates = {}
        
        for packet in recent_packets:
            src_ip = packet.get('src_ip')
            dst_ip = packet.get('dst_ip')
            dst_port = packet.get('dst_port')
            flags = packet.get('tcp_flags', '')
            
            if src_ip and dst_ip and dst_port and 'S' in flags and 'A' not in flags:
                key = f"{src_ip}->{dst_ip}"
                if key not in syn_packets:
                    syn_packets[key] = set()
                syn_packets[key].add(dst_port)
                
                # Check for port scan pattern
                if len(syn_packets[key]) > 10:  # More than 10 different ports
                    port_scan_candidates[key] = len(syn_packets[key])
                    
        # Alert for port scans
        for scan, port_count in port_scan_candidates.items():
            if scan not in self._recent_alerts:  # Prevent duplicate alerts
                ALERT_MANAGER.add_alert(
                    AlertType.SECURITY, RiskLevel.MEDIUM,
                    f"Port scan detected: {scan} ({port_count} ports)",
                    source="PacketAnalyzer.port_scan_detection",
                    details={'src_dst': scan, 'port_count': port_count}
                )
                self._recent_alerts.add(scan)
                
        # Clean old alerts
        current_time = time.time()
        self._recent_alerts = {alert for alert in self._recent_alerts 
                              if current_time - self._alert_times.get(alert, 0) < 300}
                              
    def get_packet_statistics(self) -> Dict:
        """Get packet analysis statistics"""
        if not self.packet_buffer:
            return {}
            
        stats = {
            'total_packets': len(self.packet_buffer),
            'by_protocol': Counter(),
            'top_source_ips': Counter(),
            'top_destination_ips': Counter(),
            'threats_detected': 0,
            'time_window': {
                'start': self.packet_buffer[0].get('timestamp') if self.packet_buffer else None,
                'end': self.packet_buffer[-1].get('timestamp') if self.packet_buffer else None
            }
        }
        
        for packet in self.packet_buffer:
            # Count protocols
            if 'TCP' in packet.get('layers', []):
                stats['by_protocol']['TCP'] += 1
            elif 'UDP' in packet.get('layers', []):
                stats['by_protocol']['UDP'] += 1
            elif 'ICMP' in packet.get('layers', []):
                stats['by_protocol']['ICMP'] += 1
            elif 'ARP' in packet.get('layers', []):
                stats['by_protocol']['ARP'] += 1
                
            # Count IPs
            if packet.get('src_ip'):
                stats['top_source_ips'][packet['src_ip']] += 1
            if packet.get('dst_ip'):
                stats['top_destination_ips'][packet['dst_ip']] += 1
                
        return stats
        
    def __init__(self):
        """Initialize packet analyzer"""
        self.capturing = False
        self.capture_thread = None
        self.packet_buffer = []
        self.max_buffer_size = 1000
        self.signatures = self._load_intrusion_signatures()
        self._recent_alerts = set()
        self._alert_times = {}

# Initialize packet analyzer
PACKET_ANALYZER = PacketAnalyzer()

# Log Analyzer Component
class LogAnalyzer:
    """System and application log analysis for security incidents"""
    
    def __init__(self):
        self.log_patterns = self._load_log_patterns()
        self.analysis_results = []
        
    def _load_log_patterns(self) -> List[Dict]:
        """Load log analysis patterns for security events"""
        patterns = [
            # Authentication failures
            {
                'name': 'Failed SSH Login',
                'pattern': r'Failed password|authentication failure|Invalid user',
                'severity': 'medium',
                'log_source': ['auth.log', 'secure', 'sshd'],
                'description': 'Failed SSH authentication attempt'
            },
            {
                'name': 'Brute Force Attempt',
                'pattern': r'(Failed password).*from.*(\d+\.\d+\.\d+\.\d+).*user=(\w+)',
                'severity': 'high',
                'log_source': ['auth.log', 'secure'],
                'description': 'Multiple failed login attempts from same IP'
            },
            
            # System events
            {
                'name': 'Root Login',
                'pattern': r'session opened for user root',
                'severity': 'medium',
                'log_source': ['auth.log', 'secure'],
                'description': 'Root user login detected'
            },
            {
                'name': 'Sudo Command',
                'pattern': r'sudo:.*COMMAND=',
                'severity': 'low',
                'log_source': ['auth.log', 'secure'],
                'description': 'Sudo command execution'
            },
            
            # Web server attacks
            {
                'name': 'SQL Injection Attempt',
                'pattern': r'(\?|&).*(union|select|insert|delete|drop).*',
                'severity': 'high',
                'log_source': ['access.log', 'error.log'],
                'description': 'Potential SQL injection in web request'
            },
            {
                'name': 'Directory Traversal',
                'pattern': r'\.\./|\.\.\\',
                'severity': 'medium',
                'log_source': ['access.log'],
                'description': 'Directory traversal attempt'
            },
            
            # Network attacks
            {
                'name': 'Port Scan Detected',
                'pattern': r'port scan|PortScan',
                'severity': 'medium',
                'log_source': ['kern.log', 'messages', 'firewall'],
                'description': 'Network port scan detected'
            },
            {
                'name': 'DoS Attack',
                'pattern': r'flood|DoS|DDoS|too many connections',
                'severity': 'high',
                'log_source': ['kern.log', 'messages'],
                'description': 'Denial of Service attack detected'
            },
            
            # File system events
            {
                'name': 'File Modification',
                'pattern': r'MODIFY.*\.(php|asp|jsp|py|sh)$',
                'severity': 'medium',
                'log_source': ['audit.log'],
                'description': 'Web application file modified'
            },
            {
                'name': 'Sensitive File Access',
                'pattern': r'OPEN.*(/etc/passwd|/etc/shadow|\.env|config\.)',
                'severity': 'high',
                'log_source': ['audit.log'],
                'description': 'Sensitive file accessed'
            },
            
            # Malware indicators
            {
                'name': 'Suspicious Process',
                'pattern': r'(miner|xmrig|minerd|backdoor|shell)',
                'severity': 'critical',
                'log_source': ['syslog', 'messages'],
                'description': 'Suspicious process execution'
            },
            {
                'name': 'Cryptocurrency Miner',
                'pattern': r'(crypto|mining|pool|stratum)',
                'severity': 'critical',
                'log_source': ['syslog'],
                'description': 'Potential cryptocurrency mining activity'
            },
        ]
        
        return patterns
        
    def analyze_log_file(self, log_file: str, realtime: bool = False) -> Dict:
        """
        Analyze log file for security events
        
        Args:
            log_file: Path to log file
            realtime: Monitor file in real-time
            
        Returns:
            Analysis results
        """
        results = {
            'log_file': log_file,
            'start_time': datetime.datetime.now().isoformat(),
            'events_found': [],
            'statistics': {},
            'scan_duration': None
        }
        
        if not os.path.exists(log_file):
            logger.error(f"Log file not found: {log_file}")
            return results
            
        logger.info(f"Analyzing log file: {log_file}")
        print(f"{Colors.BLUE}[*] Analyzing log file: {log_file}{Colors.ENDC}")
        
        start_time = time.time()
        
        try:
            if realtime:
                # Real-time log monitoring
                self._monitor_log_realtime(log_file)
            else:
                # One-time analysis
                events = self._analyze_log_content(log_file)
                results['events_found'] = events
                
                # Display findings
                if events:
                    print(f"\n{Colors.CYAN}=== LOG ANALYSIS FINDINGS ==={Colors.ENDC}")
                    for event in events:
                        severity_color = Colors.RED if event['severity'] in ['high', 'critical'] else Colors.YELLOW
                        print(f"{severity_color}[{event['severity'].upper()}] {event['name']}{Colors.ENDC}")
                        print(f"  Time: {event.get('timestamp', 'N/A')}")
                        print(f"  Description: {event['description']}")
                        if event.get('details'):
                            print(f"  Details: {event['details'][:100]}...")
                        print()
                        
                    # Create alerts for critical findings
                    for event in events:
                        if event['severity'] in ['high', 'critical']:
                            ALERT_MANAGER.add_alert(
                                AlertType.SECURITY,
                                RiskLevel(event['severity']),
                                f"Security event in logs: {event['name']}",
                                source="LogAnalyzer",
                                details=event
                            )
                else:
                    print(f"{Colors.GREEN}[*] No security events found in logs{Colors.ENDC}")
                    
        except Exception as e:
            logger.error(f"Error analyzing log file {log_file}: {e}")
            results['error'] = str(e)
            
        # Calculate duration
        end_time = time.time()
        results['scan_duration'] = end_time - start_time
        results['end_time'] = datetime.datetime.now().isoformat()
        
        return results
        
    def _analyze_log_content(self, log_file: str) -> List[Dict]:
        """Analyze log file content for security events"""
        events = []
        line_count = 0
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line_count += 1
                    
                    # Check each pattern
                    for pattern in self.log_patterns:
                        if re.search(pattern['pattern'], line, re.IGNORECASE):
                            # Extract timestamp if present
                            timestamp = self._extract_timestamp(line)
                            
                            event = {
                                'line_number': line_count,
                                'timestamp': timestamp,
                                'name': pattern['name'],
                                'severity': pattern['severity'],
                                'description': pattern['description'],
                                'pattern': pattern['pattern'],
                                'log_source': pattern.get('log_source', []),
                                'details': line.strip()[:500]  # Truncate long lines
                            }
                            
                            events.append(event)
                            break  # Only match first pattern per line
                            
        except Exception as e:
            logger.error(f"Error reading log file: {e}")
            
        return events
        
    def _extract_timestamp(self, log_line: str) -> Optional[str]:
        """Extract timestamp from log line"""
        # Common timestamp patterns
        timestamp_patterns = [
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',
            r'(\w{3} \d{2} \d{2}:\d{2}:\d{2})',
            r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})',
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, log_line)
            if match:
                return match.group(1)
                
        return None
        
    def _monitor_log_realtime(self, log_file: str):
        """Monitor log file in real-time for new events"""
        print(f"{Colors.BLUE}[*] Starting real-time log monitoring for {log_file}{Colors.ENDC}")
        print(f"{Colors.CYAN}[*] Press Ctrl+C to stop monitoring{Colors.ENDC}")
        
        try:
            # Get current file size
            last_size = os.path.getsize(log_file)
            
            while True:
                current_size = os.path.getsize(log_file)
                
                if current_size > last_size:
                    # Read new lines
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(last_size)
                        new_lines = f.read()
                        
                        for line in new_lines.split('\n'):
                            if line.strip():
                                self._process_log_line(line)
                                
                    last_size = current_size
                    
                time.sleep(1)  # Check every second
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] Log monitoring stopped{Colors.ENDC}")
        except Exception as e:
            logger.error(f"Error in real-time log monitoring: {e}")
            
    def _process_log_line(self, line: str):
        """Process individual log line in real-time"""
        for pattern in self.log_patterns:
            if re.search(pattern['pattern'], line, re.IGNORECASE):
                timestamp = self._extract_timestamp(line) or datetime.datetime.now().isoformat()
                
                event = {
                    'timestamp': timestamp,
                    'name': pattern['name'],
                    'severity': pattern['severity'],
                    'description': pattern['description'],
                    'details': line.strip()[:200]
                }
                
                # Display alert
                severity_color = Colors.RED if pattern['severity'] in ['high', 'critical'] else Colors.YELLOW
                print(f"\n{severity_color}[!] LOG ALERT [{pattern['severity'].upper()}]: {pattern['name']}{Colors.ENDC}")
                print(f"  Time: {timestamp}")
                print(f"  Event: {pattern['description']}")
                print(f"  Details: {line.strip()[:100]}...")
                
                # Add to alert manager
                ALERT_MANAGER.add_alert(
                    AlertType.SECURITY,
                    RiskLevel(pattern['severity']),
                    f"Log event: {pattern['name']}",
                    source="LogAnalyzer.realtime",
                    details=event
                )
                
                break
                
    def analyze_system_logs(self) -> Dict:
        """Analyze common system log files"""
        system_logs = []
        
        # Common log file locations
        log_dirs = ['/var/log', '/var/log/syslog', '/var/log/messages']
        
        for log_dir in log_dirs:
            if os.path.exists(log_dir):
                if os.path.isdir(log_dir):
                    # List log files in directory
                    try:
                        for log_file in os.listdir(log_dir):
                            if log_file.endswith('.log') or log_file in ['auth.log', 'secure', 'syslog', 'messages']:
                                full_path = os.path.join(log_dir, log_file)
                                system_logs.append(full_path)
                    except:
                        pass
                else:
                    # Single log file
                    system_logs.append(log_dir)
                    
        results = {
            'scan_time': datetime.datetime.now().isoformat(),
            'logs_analyzed': [],
            'total_events': 0
        }
        
        for log_file in system_logs[:10]:  # Limit to 10 files
            try:
                log_result = self.analyze_log_file(log_file)
                if log_result.get('events_found'):
                    results['logs_analyzed'].append({
                        'file': log_file,
                        'events': len(log_result['events_found']),
                        'critical_events': len([e for e in log_result['events_found'] if e['severity'] in ['high', 'critical']])
                    })
                    results['total_events'] += len(log_result['events_found'])
            except:
                continue
                
        return results
        
    def generate_log_report(self, results: Dict) -> str:
        """Generate log analysis report"""
        report = []
        
        report.append("=" * 80)
        report.append("LOG SECURITY ANALYSIS REPORT")
        report.append("=" * 80)
        report.append(f"Analysis time: {results.get('scan_time', 'N/A')}")
        report.append(f"Logs analyzed: {len(results.get('logs_analyzed', []))}")
        report.append(f"Total events found: {results.get('total_events', 0)}")
        report.append("=" * 80)
        
        if results.get('logs_analyzed'):
            report.append("\nLOG FILES ANALYZED:")
            report.append("-" * 80)
            
            for log_info in results['logs_analyzed']:
                report.append(f"\n{log_info['file']}:")
                report.append(f"  Total events: {log_info['events']}")
                report.append(f"  Critical events: {log_info['critical_events']}")
                
        # Get recent alerts from log analysis
        recent_log_alerts = []
        for alert in ALERT_MANAGER.get_alerts():
            if alert.get('source', '').startswith('LogAnalyzer'):
                recent_log_alerts.append(alert)
                
        if recent_log_alerts:
            report.append("\n\nRECENT LOG SECURITY ALERTS:")
            report.append("-" * 80)
            
            for alert in recent_log_alerts[:20]:  # Limit to 20 alerts
                report.append(f"\n[{alert.get('severity', 'UNKNOWN').upper()}] {alert.get('message', '')}")
                report.append(f"  Time: {alert.get('timestamp', 'N/A')}")
                
        report.append("\n" + "=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        report_text = "\n".join(report)
        
        # Save report
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = REPORTS_DIR / f"log_analysis_report_{timestamp}.txt"
        
        with open(report_file, 'w') as f:
            f.write(report_text)
            
        logger.info(f"Log analysis report saved to {report_file}")
        
        return report_text

# Initialize log analyzer
LOG_ANALYZER = LogAnalyzer()

# Vulnerability Database and CVE Lookup
class VulnerabilityDB:
    """CVE database and vulnerability lookup"""
    
    def __init__(self):
        self.cve_cache = CACHE_DIR / 'cve_cache.json'
        self.cve_data = {}
        self._load_cve_cache()
        
    def _load_cve_cache(self):
        """Load CVE data from cache"""
        if self.cve_cache.exists():
            try:
                with open(self.cve_cache, 'r') as f:
                    self.cve_data = json.load(f)
            except:
                self.cve_data = {}
                
    def _save_cve_cache(self):
        """Save CVE data to cache"""
        try:
            with open(self.cve_cache, 'w') as f:
                json.dump(self.cve_data, f, indent=2)
        except:
            pass
            
    def lookup_cve(self, cve_id: str) -> Optional[Dict]:
        """Look up CVE information"""
        # Check cache first
        if cve_id in self.cve_data:
            return self.cve_data[cve_id]
            
        # Try to fetch from online sources
        cve_info = self._fetch_cve_online(cve_id)
        if cve_info:
            self.cve_data[cve_id] = cve_info
            self._save_cve_cache()
            
        return cve_info
        
    def _fetch_cve_online(self, cve_id: str) -> Optional[Dict]:
        """Fetch CVE information from online sources"""
        if not REQUESTS_AVAILABLE:
            return None
            
        sources = [
            f'https://cve.circl.lu/api/cve/{cve_id}',
            f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}',
        ]
        
        for source in sources:
            try:
                response = requests.get(source, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    
                    # Parse based on source format
                    if 'circl.lu' in source:
                        return self._parse_circl_format(data)
                    elif 'nist.gov' in source:
                        return self._parse_nist_format(data)
                        
            except:
                continue
                
        return None
        
    def _parse_circl_format(self, data: Dict) -> Dict:
        """Parse CVE data from CIRCL format"""
        cve_info = {
            'id': data.get('id', ''),
            'summary': data.get('summary', ''),
            'cvss': data.get('cvss', 0.0),
            'references': data.get('references', []),
            'vulnerable_configuration': data.get('vulnerable_configuration', []),
            'published': data.get('Published', ''),
            'modified': data.get('Modified', '')
        }
        
        # Determine severity from CVSS
        cvss = cve_info['cvss']
        if cvss >= 9.0:
            cve_info['severity'] = 'critical'
        elif cvss >= 7.0:
            cve_info['severity'] = 'high'
        elif cvss >= 4.0:
            cve_info['severity'] = 'medium'
        else:
            cve_info['severity'] = 'low'
            
        return cve_info
        
    def _parse_nist_format(self, data: Dict) -> Dict:
        """Parse CVE data from NIST format"""
        try:
            vulnerabilities = data.get('vulnerabilities', [])
            if not vulnerabilities:
                return None
                
            cve_data = vulnerabilities[0].get('cve', {})
            
            cve_info = {
                'id': cve_data.get('id', ''),
                'summary': '',
                'cvss': 0.0,
                'references': [],
                'published': cve_data.get('published', ''),
                'modified': cve_data.get('lastModified', '')
            }
            
            # Get description
            descriptions = cve_data.get('descriptions', [])
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    cve_info['summary'] = desc.get('value', '')
                    break
                    
            # Get CVSS score
            metrics = cve_data.get('metrics', {})
            if 'cvssMetricV31' in metrics:
                cvss_metric = metrics['cvssMetricV31'][0]
                cve_info['cvss'] = cvss_metric['cvssData']['baseScore']
            elif 'cvssMetricV2' in metrics:
                cvss_metric = metrics['cvssMetricV2'][0]
                cve_info['cvss'] = cvss_metric['cvssData']['baseScore']
                
            # Get references
            references = cve_data.get('references', [])
            cve_info['references'] = [ref.get('url', '') for ref in references]
            
            # Determine severity
            cvss = cve_info['cvss']
            if cvss >= 9.0:
                cve_info['severity'] = 'critical'
            elif cvss >= 7.0:
                cve_info['severity'] = 'high'
            elif cvss >= 4.0:
                cve_info['severity'] = 'medium'
            else:
                cve_info['severity'] = 'low'
                
            return cve_info
            
        except:
            return None
            
    def check_service_vulnerabilities(self, service: str, version: str = None) -> List[Dict]:
        """Check for known vulnerabilities in a service"""
        vulnerabilities = []
        
        # Common service vulnerabilities database
        common_vulns = {
            'openssh': [
                {'cve': 'CVE-2021-41617', 'severity': 'high', 'affects': '<8.8', 'description': 'Privilege escalation'},
                {'cve': 'CVE-2020-15778', 'severity': 'medium', 'affects': 'all', 'description': 'Command injection'},
                {'cve': 'CVE-2019-6111', 'severity': 'medium', 'affects': '<8.0', 'description': 'File overwrite'},
            ],
            'apache': [
                {'cve': 'CVE-2021-44790', 'severity': 'critical', 'affects': '2.4.51', 'description': 'Buffer overflow'},
                {'cve': 'CVE-2021-40438', 'severity': 'high', 'affects': '<2.4.49', 'description': 'Mod_proxy SSRF'},
                {'cve': 'CVE-2020-11984', 'severity': 'high', 'affects': '<2.4.46', 'description': 'HTTP/2 DoS'},
            ],
            'nginx': [
                {'cve': 'CVE-2021-3618', 'severity': 'medium', 'affects': '<1.20.1', 'description': 'ALPACA attack'},
                {'cve': 'CVE-2019-20372', 'severity': 'medium', 'affects': '<1.17.7', 'description': 'Off-by-slash'},
            ],
            'mysql': [
                {'cve': 'CVE-2022-21549', 'severity': 'critical', 'affects': '8.0.29', 'description': 'Privilege escalation'},
                {'cve': 'CVE-2021-35604', 'severity': 'high', 'affects': '<8.0.26', 'description': 'DoS vulnerability'},
            ],
            'php': [
                {'cve': 'CVE-2022-31626', 'severity': 'critical', 'affects': '<8.1.10', 'description': 'Buffer overflow'},
                {'cve': 'CVE-2021-21708', 'severity': 'high', 'affects': '<8.0.14', 'description': 'Use-after-free'},
            ],
        }
        
        service_lower = service.lower()
        
        for service_name, vuln_list in common_vulns.items():
            if service_name in service_lower:
                for vuln in vuln_list:
                    # Check if version is affected
                    if version and vuln.get('affects'):
                        if self._is_version_affected(version, vuln['affects']):
                            vulnerabilities.append(vuln)
                    else:
                        vulnerabilities.append(vuln)
                        
        return vulnerabilities
        
    def _is_version_affected(self, version: str, affects: str) -> bool:
        """Check if version is affected by vulnerability"""
        try:
            if affects == 'all':
                return True
                
            if affects.startswith('<'):
                max_version = affects[1:]
                return self._compare_versions(version, max_version) < 0
            elif affects.startswith('<='):
                max_version = affects[2:]
                return self._compare_versions(version, max_version) <= 0
            elif affects.startswith('>'):
                min_version = affects[1:]
                return self._compare_versions(version, min_version) > 0
            elif affects.startswith('>='):
                min_version = affects[2:]
                return self._compare_versions(version, min_version) >= 0
            elif '=' in affects:
                target_version = affects.split('=')[1]
                return version == target_version
                
        except:
            return False
            
        return False
        
    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare version strings"""
        v1_parts = v1.split('.')
        v2_parts = v2.split('.')
        
        for i in range(max(len(v1_parts), len(v2_parts))):
            v1_part = int(v1_parts[i]) if i < len(v1_parts) else 0
            v2_part = int(v2_parts[i]) if i < len(v2_parts) else 0
            
            if v1_part < v2_part:
                return -1
            elif v1_part > v2_part:
                return 1
                
        return 0
        
    def generate_vulnerability_report(self, scan_results: Dict) -> str:
        """Generate vulnerability report from scan results"""
        report = []
        
        report.append("=" * 80)
        report.append("VULNERABILITY ASSESSMENT REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.datetime.now().isoformat()}")
        report.append(f"Target: {scan_results.get('target', 'N/A')}")
        report.append("=" * 80)
        
        # Process open ports and services
        open_ports = scan_results.get('open_ports', [])
        
        if open_ports:
            report.append("\nSERVICE VULNERABILITIES:")
            report.append("-" * 80)
            
            all_vulnerabilities = []
            
            for port_info in open_ports:
                port = port_info.get('port')
                service = port_info.get('service', 'unknown')
                banner = port_info.get('banner', '')
                
                # Extract version from banner
                version = None
                if banner:
                    version_match = re.search(r'(\d+\.\d+\.\d+|\d+\.\d+)', banner)
                    if version_match:
                        version = version_match.group(1)
                        
                # Check for vulnerabilities
                vulns = self.check_service_vulnerabilities(service, version)
                
                if vulns:
                    report.append(f"\nPort {port}/tcp - {service} {version or ''}:")
                    for vuln in vulns:
                        report.append(f"  [{vuln['severity'].upper()}] {vuln['cve']}: {vuln['description']}")
                        all_vulnerabilities.append(vuln)
                        
            # Summary
            if all_vulnerabilities:
                by_severity = Counter([v['severity'] for v in all_vulnerabilities])
                
                report.append("\n\nVULNERABILITY SUMMARY:")
                report.append("-" * 80)
                report.append(f"Total vulnerabilities: {len(all_vulnerabilities)}")
                report.append(f"Critical: {by_severity.get('critical', 0)}")
                report.append(f"High: {by_severity.get('high', 0)}")
                report.append(f"Medium: {by_severity.get('medium', 0)}")
                report.append(f"Low: {by_severity.get('low', 0)}")
                
                # Recommendations
                report.append("\nRECOMMENDATIONS:")
                report.append("-" * 80)
                report.append("1. Update all services to latest versions")
                report.append("2. Apply security patches immediately")
                report.append("3. Disable unnecessary services")
                report.append("4. Implement firewall rules to restrict access")
                report.append("5. Monitor for exploitation attempts")
            else:
                report.append("\nNo known vulnerabilities found in scanned services.")
        else:
            report.append("\nNo open ports found.")
            
        report.append("\n" + "=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        report_text = "\n".join(report)
        
        # Save report
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        target = scan_results.get('target', 'scan').replace('.', '_')
        report_file = REPORTS_DIR / f"vulnerability_report_{target}_{timestamp}.txt"
        
        with open(report_file, 'w') as f:
            f.write(report_text)
            
        logger.info(f"Vulnerability report saved to {report_file}")
        
        return report_text

# Initialize vulnerability database
VULN_DB = VulnerabilityDB()

# Main Command Line Interface
class HACK404CLI:
    """Command Line Interface for HACK404 PRODUCTION"""
    
    def __init__(self):
        self.session_token = None
        self.current_user = None
        self.scanner = NetworkScanner()
        self.monitor = SYSTEM_MONITOR
        self.running = True
        self.command_history = []
        
    def print_banner(self):
        """Display application banner"""
        banner = f"""
{Colors.RED}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════╗
║    HACK404 PRODUCTION - Enterprise Cybersecurity Platform     ║
║                    Version {CONFIG['version']}                           ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.ENDC}
{Colors.CYAN}Author: {CONFIG['author']}
Contact: {CONFIG['contact']} | {CONFIG['phone']}
GitHub: {CONFIG['github']}
LinkedIn: {CONFIG['linkedin']}
{Colors.ENDC}
{Colors.YELLOW}⚠️  WARNING: Authorized security testing only! ⚠️{Colors.ENDC}
"""
        print(banner)
        
    def login(self):
        """User authentication"""
        if not CONFIG['security'].require_authentication:
            self.session_token = "bypass"
            self.current_user = "anonymous"
            return True
            
        print(f"\n{Colors.BLUE}[*] Authentication Required{Colors.ENDC}")
        print(f"{Colors.CYAN}[*] Please login to continue{Colors.ENDC}")
        
        attempts = 0
        max_attempts = CONFIG['security'].max_login_attempts
        
        while attempts < max_attempts:
            print(f"\n{Colors.CYAN}─" * 50)
            username = input(f"{Colors.GREEN}[?] Username: {Colors.ENDC}").strip()
            password = input(f"{Colors.GREEN}[?] Password: {Colors.ENDC}")
            print(f"{Colors.CYAN}─" * 50)
            
            success, token_or_message = AUTH.authenticate(username, password)
            
            if success:
                self.session_token = token_or_message
                self.current_user = username
                print(f"\n{Colors.GREEN}[+] Authentication successful!{Colors.ENDC}")
                print(f"{Colors.GREEN}[+] Welcome, {username}!{Colors.ENDC}")
                return True
            else:
                attempts += 1
                remaining = max_attempts - attempts
                print(f"\n{Colors.RED}[-] Authentication failed: {token_or_message}{Colors.ENDC}")
                if remaining > 0:
                    print(f"{Colors.YELLOW}[!] {remaining} attempts remaining{Colors.ENDC}")
                    
        print(f"\n{Colors.RED}[-] Maximum login attempts exceeded{Colors.ENDC}")
        return False
        
    def validate_session(self):
        """Validate current session"""
        if not CONFIG['security'].require_authentication:
            return True
            
        if not self.session_token:
            return False
            
        valid, session_info = AUTH.validate_session(self.session_token)
        
        if valid:
            self.current_user = session_info.get('username')
            return True
            
        return False
        
    def logout(self):
        """Logout current user"""
        if self.session_token:
            AUTH.logout(self.session_token)
            self.session_token = None
            self.current_user = None
            print(f"\n{Colors.GREEN}[+] Logged out successfully{Colors.ENDC}")
            
    def print_menu(self):
        """Display main menu"""
        menu = f"""
{Colors.CYAN}{Colors.BOLD}═══════════════════ MAIN MENU ════════════════════{Colors.ENDC}

{Colors.GREEN}[1]{Colors.ENDC} Network Discovery & Scanning
{Colors.GREEN}[2]{Colors.ENDC} System Monitoring & Analysis
{Colors.GREEN}[3]{Colors.ENDC} Web Application Security
{Colors.GREEN}[4]{Colors.ENDC} Packet Capture & Analysis
{Colors.GREEN}[5]{Colors.ENDC} Log Analysis & Audit
{Colors.GREEN}[6]{Colors.ENDC} Vulnerability Assessment
{Colors.GREEN}[7]{Colors.ENDC} Alert Management
{Colors.GREEN}[8]{Colors.ENDC} Reports & Export
{Colors.GREEN}[9]{Colors.ENDC} System Information
{Colors.GREEN}[0]{Colors.ENDC} Exit

{Colors.CYAN}[*]{Colors.ENDC} Current User: {self.current_user or 'Not logged in'}
{Colors.CYAN}[*]{Colors.ENDC} Active Alerts: {len(ALERT_MANAGER.get_alerts(acknowledged=False))}
{Colors.CYAN}[*]{Colors.ENDC} Database: {'Connected' if DB else 'Disabled'}
{Colors.CYAN}═══════════════════════════════════════════════════{Colors.ENDC}
"""
        print(menu)
        
    def print_network_menu(self):
        """Display network scanning menu"""
        menu = f"""
{Colors.CYAN}{Colors.BOLD}══════════════ NETWORK SCANNING ══════════════{Colors.ENDC}

{Colors.GREEN}[1]{Colors.ENDC} Ping Sweep (Host Discovery)
{Colors.GREEN}[2]{Colors.ENDC} Port Scan
{Colors.GREEN}[3]{Colors.ENDC} SYN Stealth Scan
{Colors.GREEN}[4]{Colors.ENDC} FIN Stealth Scan
{Colors.GREEN}[5]{Colors.ENDC} XMAS Stealth Scan
{Colors.GREEN}[6]{Colors.ENDC} NULL Stealth Scan
{Colors.GREEN}[7]{Colors.ENDC} UDP Scan
{Colors.GREEN}[8]{Colors.ENDC} Comprehensive Scan
{Colors.GREEN}[9]{Colors.ENDC} Traceroute
{Colors.GREEN}[10]{Colors.ENDC} Network Interface Info
{Colors.GREEN}[11]{Colors.ENDC} ARP Table Scan
{Colors.GREEN}[12]{Colors.ENDC} Packet Sniffing
{Colors.GREEN}[13]{Colors.ENDC} Raw Socket Test
{Colors.GREEN}[0]{Colors.ENDC} Back to Main Menu

{Colors.CYAN}═══════════════════════════════════════════════════{Colors.ENDC}
"""
        print(menu)
        
    def handle_network_scanning(self):
        """Handle network scanning operations"""
        while True:
            self.print_network_menu()
            choice = input(f"\n{Colors.GREEN}[?] Select option: {Colors.ENDC}").strip()
            
            if choice == '0':
                break
                
            elif choice == '1':  # Ping Sweep
                network = input(f"{Colors.GREEN}[?] Enter network (CIDR): {Colors.ENDC}").strip()
                if network:
                    results = self.scanner.ping_sweep(network)
                    
            elif choice == '2':  # Port Scan
                target = input(f"{Colors.GREEN}[?] Enter target IP/hostname: {Colors.ENDC}").strip()
                if target:
                    port_input = input(f"{Colors.GREEN}[?] Enter ports (comma-separated or range, empty for common): {Colors.ENDC}").strip()
                    
                    ports = None
                    if port_input:
                        if '-' in port_input:
                            start, end = map(int, port_input.split('-'))
                            ports = list(range(start, end + 1))
                        elif ',' in port_input:
                            ports = [int(p.strip()) for p in port_input.split(',')]
                        else:
                            ports = [int(port_input)]
                    
                    results = self.scanner.port_scan(target, ports)
                    
            elif choice == '3':  # SYN Scan
                target = input(f"{Colors.GREEN}[?] Enter target IP/hostname: {Colors.ENDC}").strip()
                if target:
                    results = self.scanner.syn_scan(target)
                    
            elif choice == '4':  # FIN Scan
                target = input(f"{Colors.GREEN}[?] Enter target IP/hostname: {Colors.ENDC}").strip()
                if target:
                    results = self.scanner.fin_scan(target)
                    
            elif choice == '5':  # XMAS Scan
                target = input(f"{Colors.GREEN}[?] Enter target IP/hostname: {Colors.ENDC}").strip()
                if target:
                    results = self.scanner.xmas_scan(target)
                    
            elif choice == '6':  # NULL Scan
                target = input(f"{Colors.GREEN}[?] Enter target IP/hostname: {Colors.ENDC}").strip()
                if target:
                    results = self.scanner.null_scan(target)
                    
            elif choice == '7':  # UDP Scan
                target = input(f"{Colors.GREEN}[?] Enter target IP/hostname: {Colors.ENDC}").strip()
                if target:
                    results = self.scanner.udp_scan(target)
                    
            elif choice == '8':  # Comprehensive Scan
                target = input(f"{Colors.Green}[?] Enter target IP/hostname: {Colors.ENDC}").strip()
                if target:
                    results = self.scanner.comprehensive_scan(target)
                    
            elif choice == '9':  # Traceroute
                target = input(f"{Colors.GREEN}[?] Enter target hostname: {Colors.ENDC}").strip()
                if target:
                    NetworkUtils.traceroute(target)
                    
            elif choice == '10':  # Network Interface Info
                interfaces = NetworkUtils.get_network_interfaces()
                print(f"\n{Colors.CYAN}=== NETWORK INTERFACES ==={Colors.ENDC}")
                for iface, info in interfaces.items():
                    status = "UP" if info.get('is_up') else "DOWN"
                    color = Colors.GREEN if info.get('is_up') else Colors.RED
                    print(f"\n{color}{iface} [{status}]{Colors.ENDC}")
                    
                    for addr in info.get('addresses', []):
                        if addr['family'] == 'IPv4':
                            print(f"  IP: {addr['address']}")
                            print(f"  Netmask: {addr['netmask']}")
                        elif addr['family'] == 'MAC':
                            print(f"  MAC: {addr['address']}")
                            
            elif choice == '11':  # ARP Table
                arp_table = NetworkUtils.get_arp_table()
                print(f"\n{Colors.CYAN}=== ARP TABLE ==={Colors.ENDC}")
                for entry in arp_table:
                    print(f"IP: {entry['ip']} -> MAC: {entry['mac']} (Interface: {entry['interface']})")
                    
            elif choice == '12':  # Packet Sniffing
                interface = input(f"{Colors.GREEN}[?] Enter interface (empty for default): {Colors.ENDC}").strip()
                filter_str = input(f"{Colors.GREEN}[?] Enter BPF filter (empty for all): {Colors.ENDC}").strip()
                count = input(f"{Colors.GREEN}[?] Packet count (default 100): {Colors.ENDC}").strip()
                packet_count = int(count) if count.isdigit() else 100
                
                results = self.scanner.packet_sniff(interface or None, filter_str or None, packet_count)
                
            elif choice == '13':  # Raw Socket Test
                print(f"\n{Colors.CYAN}=== RAW SOCKET TEST ==={Colors.ENDC}")
                print(f"Raw sockets initialized: {RAW_SCANNER.initialized}")
                
                if RAW_SCANNER.initialized:
                    target = input(f"{Colors.GREEN}[?] Enter target IP for raw socket test: {Colors.ENDC}").strip()
                    if target:
                        # Test ICMP ping
                        print(f"\n{Colors.BLUE}[*] Testing raw ICMP ping...{Colors.ENDC}")
                        if RAW_SCANNER.send_icmp_echo(target):
                            responses = RAW_SCANNER.listen_for_responses(2)
                            for resp in responses:
                                if resp.get('protocol') == socket.IPPROTO_ICMP:
                                    print(f"{Colors.GREEN}[+] ICMP response received{Colors.ENDC}")
                                    break
                            else:
                                print(f"{Colors.YELLOW}[!] No ICMP response{Colors.ENDC}")
                                
                else:
                    print(f"{Colors.RED}[-] Raw sockets not available{Colors.ENDC}")
                    
            else:
                print(f"{Colors.RED}[-] Invalid option{Colors.ENDC}")
                
            input(f"\n{Colors.CYAN}[*] Press Enter to continue...{Colors.ENDC}")
            
    def handle_system_monitoring(self):
        """Handle system monitoring operations"""
        menu = f"""
{Colors.CYAN}{Colors.BOLD}══════════════ SYSTEM MONITORING ══════════════{Colors.ENDC}

{Colors.GREEN}[1]{Colors.ENDC} Start Real-time Monitoring
{Colors.GREEN}[2]{Colors.ENDC} Stop Monitoring
{Colors.GREEN}[3]{Colors.ENDC} Show Current Metrics
{Colors.GREEN}[4]{Colors.ENDC} Show Metrics History
{Colors.GREEN}[5]{Colors.ENDC} Check Disk Space
{Colors.GREEN}[6]{Colors.ENDC} Get System Information
{Colors.GREEN}[7]{Colors.ENDC} List Running Processes
{Colors.GREEN}[8]{Colors.ENDC} Check Running Services
{Colors.GREEN}[0]{Colors.ENDC} Back to Main Menu

{Colors.CYAN}═══════════════════════════════════════════════════{Colors.ENDC}
"""
        
        while True:
            print(menu)
            choice = input(f"\n{Colors.GREEN}[?] Select option: {Colors.ENDC}").strip()
            
            if choice == '0':
                break
                
            elif choice == '1':  # Start Monitoring
                if not self.monitor.monitoring:
                    self.monitor.start_monitoring()
                else:
                    print(f"{Colors.YELLOW}[!] Monitoring already running{Colors.ENDC}")
                    
            elif choice == '2':  # Stop Monitoring
                if self.monitor.monitoring:
                    self.monitor.stop_monitoring()
                else:
                    print(f"{Colors.YELLOW}[!] Monitoring not running{Colors.ENDC}")
                    
            elif choice == '3':  # Show Current Metrics
                if PSUTIL_AVAILABLE:
                    metrics = self.monitor._collect_metrics()
                    self.monitor._display_metrics(metrics)
                else:
                    print(f"{Colors.RED}[-] psutil not available{Colors.ENDC}")
                    
            elif choice == '4':  # Show Metrics History
                history = self.monitor.get_metrics_history(10)
                if history:
                    print(f"\n{Colors.CYAN}=== METRICS HISTORY (Last 10 samples) ==={Colors.ENDC}")
                    for metrics in history:
                        print(f"\nTime: {metrics.get('timestamp', 'N/A')}")
                        print(f"CPU: {metrics.get('cpu', {}).get('percent', 0):.1f}%")
                        print(f"Memory: {metrics.get('memory', {}).get('percent', 0):.1f}%")
                else:
                    print(f"{Colors.YELLOW}[!] No metrics history available{Colors.ENDC}")
                    
            elif choice == '5':  # Check Disk Space
                path = input(f"{Colors.GREEN}[?] Enter path (default /): {Colors.ENDC}").strip() or "/"
                ok, result = SystemUtils.check_disk_space(path)
                
                if ok:
                    print(f"{Colors.GREEN}[+] Disk space OK: {result.get('percent', 0):.1f}% used{Colors.ENDC}")
                else:
                    print(f"{Colors.RED}[-] Disk space critical: {result.get('percent', 0):.1f}% used{Colors.ENDC}")
                    
            elif choice == '6':  # Get System Information
                info = SystemUtils.get_system_info()
                print(f"\n{Colors.CYAN}=== SYSTEM INFORMATION ==={Colors.ENDC}")
                print(f"Hostname: {info['system'].get('hostname', 'N/A')}")
                print(f"Platform: {info['system'].get('platform', 'N/A')}")
                print(f"Architecture: {info['system'].get('architecture', 'N/A')}")
                print(f"Local IP: {info['system'].get('local_ip', 'N/A')}")
                print(f"Public IP: {info['system'].get('public_ip', 'N/A')}")
                
                if PSUTIL_AVAILABLE:
                    print(f"\nCPU: {info['system'].get('cpu_percent', 0):.1f}%")
                    print(f"Memory: {info['system'].get('memory_percent', 0):.1f}%")
                    print(f"Disk: {info['system'].get('disk_percent', 0):.1f}%")
                    
            elif choice == '7':  # List Running Processes
                if PSUTIL_AVAILABLE:
                    try:
                        print(f"\n{Colors.CYAN}=== TOP PROCESSES BY CPU ==={Colors.ENDC}")
                        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                            try:
                                info = proc.info
                                if info.get('cpu_percent', 0) > 1.0:  # Show processes using >1% CPU
                                    print(f"PID {info['pid']}: {info['name']} - {info['cpu_percent']:.1f}%")
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                continue
                    except Exception as e:
                        print(f"{Colors.RED}[-] Error: {e}{Colors.ENDC}")
                else:
                    print(f"{Colors.RED}[-] psutil not available{Colors.ENDC}")
                    
            elif choice == '8':  # Check Running Services
                services = SystemUtils.get_running_services()
                print(f"\n{Colors.CYAN}=== RUNNING SERVICES ==={Colors.ENDC}")
                for service in services[:20]:  # Limit to 20 services
                    name = service.get('name', 'Unknown')
                    status = service.get('status', 'Unknown')
                    print(f"{name}: {status}")
                    
            else:
                print(f"{Colors.RED}[-] Invalid option{Colors.ENDC}")
                
            input(f"\n{Colors.CYAN}[*] Press Enter to continue...{Colors.ENDC}")
            
    def handle_web_security(self):
        """Handle web application security operations"""
        menu = f"""
{Colors.CYAN}{Colors.BOLD}══════════════ WEB APPLICATION SECURITY ══════════════{Colors.ENDC}

{Colors.GREEN}[1]{Colors.ENDC} Scan Website for Vulnerabilities
{Colors.GREEN}[2]{Colors.ENDC} Check Security Headers
{Colors.GREEN}[3]{Colors.ENDC} Look for Sensitive Files
{Colors.GREEN}[4]{Colors.ENDC} Check for Admin Panels
{Colors.GREEN}[5]{Colors.ENDC} Test for XSS Vulnerabilities
{Colors.GREEN}[6]{Colors.ENDC} Test for SQL Injection
{Colors.GREEN}[7]{Colors.ENDC} Crawl Website
{Colors.GREEN}[0]{Colors.ENDC} Back to Main Menu

{Colors.CYAN}═════════════════════════════════════════════════════════════{Colors.ENDC}
"""
        
        while True:
            print(menu)
            choice = input(f"\n{Colors.GREEN}[?] Select option: {Colors.ENDC}").strip()
            
            if choice == '0':
                break
                
            elif choice == '1':  # Full Website Scan
                url = input(f"{Colors.GREEN}[?] Enter URL to scan: {Colors.ENDC}").strip()
                if url:
                    depth = input(f"{Colors.GREEN}[?] Enter crawl depth (default 1): {Colors.ENDC}").strip()
                    depth = int(depth) if depth.isdigit() else 1
                    
                    results = WEB_SCANNER.scan_url(url, depth)
                    
            elif choice == '2':  # Check Security Headers
                url = input(f"{Colors.GREEN}[?] Enter URL: {Colors.ENDC}").strip()
                if url and REQUESTS_AVAILABLE:
                    try:
                        response = requests.get(url, timeout=10)
                        headers = response.headers
                        
                        print(f"\n{Colors.CYAN}=== SECURITY HEADERS ==={Colors.ENDC}")
                        
                        security_headers = {
                            'X-Frame-Options': 'Prevents clickjacking',
                            'X-Content-Type-Options': 'Prevents MIME sniffing',
                            'X-XSS-Protection': 'XSS protection',
                            'Strict-Transport-Security': 'Enforces HTTPS',
                            'Content-Security-Policy': 'Prevents XSS',
                            'Referrer-Policy': 'Controls referrer info',
                        }
                        
                        for header, description in security_headers.items():
                            value = headers.get(header, 'NOT SET')
                            color = Colors.GREEN if value != 'NOT SET' else Colors.RED
                            print(f"{header}: {color}{value}{Colors.ENDC} - {description}")
                            
                    except Exception as e:
                        print(f"{Colors.RED}[-] Error: {e}{Colors.ENDC}")
                        
            elif choice == '3':  # Sensitive Files
                url = input(f"{Colors.GREEN}[?] Enter base URL: {Colors.ENDC}").strip()
                if url:
                    # Use the scanner's common files check
                    try:
                        response = requests.get(url, timeout=10)
                        vulnerabilities = WEB_SCANNER._check_common_files(url, response)
                        
                        if vulnerabilities:
                            for vuln in vulnerabilities:
                                print(f"{Colors.RED}[!] {vuln['title']}{Colors.ENDC}")
                        else:
                            print(f"{Colors.GREEN}[+] No common sensitive files found{Colors.ENDC}")
                    except:
                        print(f"{Colors.RED}[-] Error accessing URL{Colors.ENDC}")
                        
            elif choice in ['4', '5', '6']:
                print(f"{Colors.YELLOW}[!] This feature is included in full website scan{Colors.ENDC}")
                print(f"{Colors.CYAN}[*] Use option 1 for comprehensive testing{Colors.ENDC}")
                
            elif choice == '7':  # Crawl Website
                url = input(f"{Colors.GREEN}[?] Enter URL to crawl: {Colors.ENDC}").strip()
                if url:
                    if BEAUTIFULSOUP_AVAILABLE:
                        try:
                            from bs4 import BeautifulSoup
                            import requests
                            
                            response = requests.get(url, timeout=10)
                            soup = BeautifulSoup(response.text, 'html.parser')
                            
                            print(f"\n{Colors.CYAN}=== DISCOVERED LINKS ==={Colors.ENDC}")
                            
                            links_found = 0
                            for link in soup.find_all('a', href=True):
                                href = link['href']
                                absolute_url = urllib.parse.urljoin(url, href)
                                
                                # Filter to same domain
                                if urllib.parse.urlparse(absolute_url).netloc == urllib.parse.urlparse(url).netloc:
                                    print(f"- {absolute_url}")
                                    links_found += 1
                                    
                            print(f"\n{Colors.GREEN}[+] Found {links_found} internal links{Colors.ENDC}")
                            
                        except Exception as e:
                            print(f"{Colors.RED}[-] Error: {e}{Colors.ENDC}")
                    else:
                        print(f"{Colors.RED}[-] BeautifulSoup4 not installed{Colors.ENDC}")
                        
            else:
                print(f"{Colors.RED}[-] Invalid option{Colors.ENDC}")
                
            input(f"\n{Colors.CYAN}[*] Press Enter to continue...{Colors.ENDC}")
            
    def handle_packet_analysis(self):
        """Handle packet capture and analysis"""
        menu = f"""
{Colors.CYAN}{Colors.BOLD}══════════════ PACKET ANALYSIS ══════════════{Colors.ENDC}

{Colors.GREEN}[1]{Colors.ENDC} Start Real-time Packet Capture
{Colors.GREEN}[2]{Colors.ENDC} Stop Packet Capture
{Colors.GREEN}[3]{Colors.ENDC} View Capture Statistics
{Colors.GREEN}[4]{Colors.ENDC} Configure Intrusion Detection
{Colors.GREEN}[5]{Colors.ENDC} List Recent Threats
{Colors.GREEN}[0]{Colors.ENDC} Back to Main Menu

{Colors.CYAN}═══════════════════════════════════════════════════{Colors.ENDC}
"""
        
        while True:
            print(menu)
            choice = input(f"\n{Colors.GREEN}[?] Select option: {Colors.ENDC}").strip()
            
            if choice == '0':
                break
                
            elif choice == '1':  # Start Capture
                if not SCAPY_AVAILABLE:
                    print(f"{Colors.RED}[-] Scapy not installed{Colors.ENDC}")
                    continue
                    
                interface = input(f"{Colors.GREEN}[?] Enter interface (empty for default): {Colors.ENDC}").strip() or None
                filter_str = input(f"{Colors.GREEN}[?] Enter BPF filter (empty for all): {Colors.ENDC}").strip() or None
                
                PACKET_ANALYZER.start_realtime_analysis(interface, filter_str)
                
            elif choice == '2':  # Stop Capture
                PACKET_ANALYZER.stop_realtime_analysis()
                
            elif choice == '3':  # View Statistics
                stats = PACKET_ANALYZER.get_packet_statistics()
                
                if stats:
                    print(f"\n{Colors.CYAN}=== PACKET STATISTICS ==={Colors.ENDC}")
                    print(f"Total packets: {stats.get('total_packets', 0)}")
                    
                    print(f"\nBy protocol:")
                    for protocol, count in stats.get('by_protocol', {}).items():
                        print(f"  {protocol}: {count}")
                        
                    print(f"\nTop source IPs:")
                    for ip, count in stats.get('top_source_ips', {}).most_common(5):
                        print(f"  {ip}: {count}")
                        
                    print(f"\nTop destination IPs:")
                    for ip, count in stats.get('top_destination_ips', {}).most_common(5):
                        print(f"  {ip}: {count}")
                else:
                    print(f"{Colors.YELLOW}[!] No packet statistics available{Colors.ENDC}")
                    
            elif choice == '4':  # Configure IDS
                print(f"\n{Colors.CYAN}=== INTRUSION DETECTION SIGNATURES ==={Colors.ENDC}")
                for i, sig in enumerate(PACKET_ANALYZER.signatures, 1):
                    print(f"\n{i}. {sig['name']} ({sig['severity'].upper()})")
                    print(f"   Description: {sig['description']}")
                    
            elif choice == '5':  # List Recent Threats
                alerts = ALERT_MANAGER.get_alerts()
                packet_alerts = [a for a in alerts if a.get('source') == 'PacketAnalyzer']
                
                if packet_alerts:
                    print(f"\n{Colors.CYAN}=== RECENT PACKET THREATS ==={Colors.ENDC}")
                    for alert in packet_alerts[:10]:  # Last 10
                        severity = alert.get('severity', 'unknown').upper()
                        color = Colors.RED if severity in ['CRITICAL', 'HIGH'] else Colors.YELLOW
                        print(f"\n{color}[{severity}] {alert.get('message', '')}{Colors.ENDC}")
                        print(f"  Time: {alert.get('timestamp', 'N/A')}")
                else:
                    print(f"{Colors.GREEN}[+] No packet threats detected recently{Colors.ENDC}")
                    
            else:
                print(f"{Colors.RED}[-] Invalid option{Colors.ENDC}")
                
            input(f"\n{Colors.CYAN}[*] Press Enter to continue...{Colors.ENDC}")
            
    def handle_log_analysis(self):
        """Handle log analysis operations"""
        menu = f"""
{Colors.CYAN}{Colors.BOLD}══════════════ LOG ANALYSIS ══════════════{Colors.ENDC}

{Colors.GREEN}[1]{Colors.ENDC} Analyze Log File
{Colors.GREEN}[2]{Colors.ENDC} Real-time Log Monitoring
{Colors.GREEN}[3]{Colors.ENDC} Analyze System Logs
{Colors.GREEN}[4]{Colors.ENDC} View Log Patterns
{Colors.GREEN}[5]{Colors.ENDC} Generate Log Report
{Colors.GREEN}[0]{Colors.ENDC} Back to Main Menu

{Colors.CYAN}═══════════════════════════════════════════════════{Colors.ENDC}
"""
        
        while True:
            print(menu)
            choice = input(f"\n{Colors.GREEN}[?] Select option: {Colors.ENDC}").strip()
            
            if choice == '0':
                break
                
            elif choice == '1':  # Analyze Log File
                log_file = input(f"{Colors.GREEN}[?] Enter log file path: {Colors.ENDC}").strip()
                if os.path.exists(log_file):
                    results = LOG_ANALYZER.analyze_log_file(log_file)
                else:
                    print(f"{Colors.RED}[-] File not found: {log_file}{Colors.ENDC}")
                    
            elif choice == '2':  # Real-time Log Monitoring
                log_file = input(f"{Colors.GREEN}[?] Enter log file path: {Colors.ENDC}").strip()
                if os.path.exists(log_file):
                    print(f"{Colors.CYAN}[*] Starting real-time monitoring...{Colors.ENDC}")
                    print(f"{Colors.YELLOW}[!] Press Ctrl+C to stop{Colors.ENDC}")
                    LOG_ANALYZER.analyze_log_file(log_file, realtime=True)
                else:
                    print(f"{Colors.RED}[-] File not found: {log_file}{Colors.ENDC}")
                    
            elif choice == '3':  # Analyze System Logs
                print(f"{Colors.BLUE}[*] Analyzing system logs...{Colors.ENDC}")
                results = LOG_ANALYZER.analyze_system_logs()
                
                print(f"\n{Colors.CYAN}=== SYSTEM LOG ANALYSIS ==={Colors.ENDC}")
                print(f"Logs analyzed: {len(results.get('logs_analyzed', []))}")
                print(f"Total events: {results.get('total_events', 0)}")
                
                for log_info in results.get('logs_analyzed', []):
                    print(f"\n{log_info['file']}:")
                    print(f"  Events: {log_info['events']}")
                    print(f"  Critical: {log_info['critical_events']}")
                    
            elif choice == '4':  # View Log Patterns
                print(f"\n{Colors.CYAN}=== LOG ANALYSIS PATTERNS ==={Colors.ENDC}")
                for i, pattern in enumerate(LOG_ANALYZER.log_patterns, 1):
                    print(f"\n{i}. {pattern['name']} ({pattern['severity'].upper()})")
                    print(f"   Pattern: {pattern['pattern']}")
                    print(f"   Description: {pattern['description']}")
                    
            elif choice == '5':  # Generate Log Report
                results = LOG_ANALYZER.analyze_system_logs()
                report = LOG_ANALYZER.generate_log_report(results)
                print(f"{Colors.GREEN}[+] Log report generated{Colors.ENDC}")
                
            else:
                print(f"{Colors.RED}[-] Invalid option{Colors.ENDC}")
                
            input(f"\n{Colors.CYAN}[*] Press Enter to continue...{Colors.ENDC}")
            
    def handle_vulnerability_assessment(self):
        """Handle vulnerability assessment operations"""
        menu = f"""
{Colors.CYAN}{Colors.BOLD}══════════════ VULNERABILITY ASSESSMENT ══════════════{Colors.ENDC}

{Colors.GREEN}[1]{Colors.ENDC} Lookup CVE Information
{Colors.GREEN}[2]{Colors.ENDC} Check Service Vulnerabilities
{Colors.GREEN}[3]{Colors.ENDC} Generate Vulnerability Report
{Colors.GREEN}[4]{Colors.ENDC} Scan for Common Vulnerabilities
{Colors.GREEN}[0]{Colors.ENDC} Back to Main Menu

{Colors.CYAN}═════════════════════════════════════════════════════════════{Colors.ENDC}
"""
        
        while True:
            print(menu)
            choice = input(f"\n{Colors.GREEN}[?] Select option: {Colors.ENDC}").strip()
            
            if choice == '0':
                break
                
            elif choice == '1':  # Lookup CVE
                cve_id = input(f"{Colors.GREEN}[?] Enter CVE ID (e.g., CVE-2021-44228): {Colors.ENDC}").strip()
                if cve_id:
                    cve_info = VULN_DB.lookup_cve(cve_id)
                    
                    if cve_info:
                        print(f"\n{Colors.CYAN}=== CVE INFORMATION ==={Colors.ENDC}")
                        print(f"ID: {cve_info.get('id', 'N/A')}")
                        print(f"CVSS Score: {cve_info.get('cvss', 'N/A')}")
                        print(f"Severity: {cve_info.get('severity', 'N/A').upper()}")
                        print(f"\nDescription: {cve_info.get('summary', 'N/A')}")
                        
                        if cve_info.get('references'):
                            print(f"\nReferences:")
                            for ref in cve_info['references'][:5]:  # Limit to 5
                                print(f"  - {ref}")
                    else:
                        print(f"{Colors.YELLOW}[!] CVE not found{Colors.ENDC}")
                        
            elif choice == '2':  # Check Service Vulnerabilities
                service = input(f"{Colors.GREEN}[?] Enter service name (e.g., openssh): {Colors.ENDC}").strip()
                version = input(f"{Colors.GREEN}[?] Enter version (optional): {Colors.ENDC}").strip() or None
                
                if service:
                    vulns = VULN_DB.check_service_vulnerabilities(service, version)
                    
                    if vulns:
                        print(f"\n{Colors.CYAN}=== VULNERABILITIES FOR {service.upper()} ==={Colors.ENDC}")
                        for vuln in vulns:
                            severity_color = Colors.RED if vuln['severity'] in ['high', 'critical'] else Colors.YELLOW
                            print(f"\n{severity_color}[{vuln['severity'].upper()}] {vuln['cve']}{Colors.ENDC}")
                            print(f"  Description: {vuln['description']}")
                            if vuln.get('affects'):
                                print(f"  Affects: {vuln['affects']}")
                    else:
                        print(f"{Colors.GREEN}[+] No known vulnerabilities found{Colors.ENDC}")
                        
            elif choice == '3':  # Generate Vulnerability Report
                # First do a port scan
                target = input(f"{Colors.GREEN}[?] Enter target for vulnerability assessment: {Colors.ENDC}").strip()
                if target:
                    print(f"{Colors.BLUE}[*] Starting port scan for vulnerability assessment...{Colors.ENDC}")
                    scan_results = self.scanner.port_scan(target)
                    
                    if scan_results.get('open_ports'):
                        report = VULN_DB.generate_vulnerability_report(scan_results)
                        print(f"{Colors.GREEN}[+] Vulnerability report generated{Colors.ENDC}")
                    else:
                        print(f"{Colors.YELLOW}[!] No open ports found{Colors.ENDC}")
                        
            elif choice == '4':  # Scan for Common Vulnerabilities
                print(f"{Colors.YELLOW}[!] This is included in comprehensive network scan{Colors.ENDC}")
                print(f"{Colors.CYAN}[*] Use Network Scanning -> Comprehensive Scan{Colors.ENDC}")
                
            else:
                print(f"{Colors.RED}[-] Invalid option{Colors.ENDC}")
                
            input(f"\n{Colors.CYAN}[*] Press Enter to continue...{Colors.ENDC}")
            
    def handle_alert_management(self):
        """Handle alert management operations"""
        menu = f"""
{Colors.CYAN}{Colors.BOLD}══════════════ ALERT MANAGEMENT ══════════════{Colors.ENDC}

{Colors.GREEN}[1]{Colors.ENDC} View Active Alerts
{Colors.GREEN}[2]{Colors.ENDC} Acknowledge Alerts
{Colors.GREEN}[3]{Colors.ENDC} View Alert Statistics
{Colors.GREEN}[4]{Colors.ENDC} Clear Acknowledged Alerts
{Colors.GREEN}[5]{Colors.ENDC} View Alert History
{Colors.GREEN}[0]{Colors.ENDC} Back to Main Menu

{Colors.CYAN}═══════════════════════════════════════════════════{Colors.ENDC}
"""
        
        while True:
            print(menu)
            choice = input(f"\n{Colors.GREEN}[?] Select option: {Colors.ENDC}").strip()
            
            if choice == '0':
                break
                
            elif choice == '1':  # View Active Alerts
                alerts = ALERT_MANAGER.get_alerts(acknowledged=False)
                
                if alerts:
                    print(f"\n{Colors.CYAN}=== ACTIVE ALERTS ==={Colors.ENDC}")
                    for i, alert in enumerate(alerts, 1):
                        severity = alert.get('severity', 'unknown').upper()
                        
                        # Color code by severity
                        if severity == 'CRITICAL':
                            color = Colors.RED
                        elif severity == 'HIGH':
                            color = Colors.ORANGE
                        elif severity == 'MEDIUM':
                            color = Colors.YELLOW
                        else:
                            color = Colors.GREEN
                            
                        print(f"\n{color}[{severity}] {alert.get('message', '')}{Colors.ENDC}")
                        print(f"  Time: {alert.get('timestamp', 'N/A')}")
                        print(f"  Source: {alert.get('source', 'N/A')}")
                        print(f"  ID: {alert.get('id', 'N/A')}")
                else:
                    print(f"{Colors.GREEN}[+] No active alerts{Colors.ENDC}")
                    
            elif choice == '2':  # Acknowledge Alerts
                alert_id = input(f"{Colors.GREEN}[?] Enter alert ID to acknowledge: {Colors.ENDC}").strip()
                if alert_id:
                    if ALERT_MANAGER.acknowledge_alert(alert_id):
                        print(f"{Colors.GREEN}[+] Alert acknowledged{Colors.ENDC}")
                    else:
                        print(f"{Colors.RED}[-] Alert not found{Colors.ENDC}")
                        
            elif choice == '3':  # Alert Statistics
                stats = ALERT_MANAGER.get_stats()
                
                print(f"\n{Colors.CYAN}=== ALERT STATISTICS ==={Colors.ENDC}")
                print(f"Total alerts: {stats.get('total', 0)}")
                print(f"Active alerts: {stats.get('active', 0)}")
                print(f"Acknowledged alerts: {stats.get('acknowledged', 0)}")
                
                print(f"\nBy severity:")
                for severity, count in stats.get('by_severity', {}).items():
                    print(f"  {severity.upper()}: {count}")
                    
                print(f"\nBy type:")
                for alert_type, count in stats.get('by_type', {}).items():
                    print(f"  {alert_type}: {count}")
                    
            elif choice == '4':  # Clear Acknowledged
                ALERT_MANAGER.clear_acknowledged()
                print(f"{Colors.GREEN}[+] Acknowledged alerts cleared{Colors.ENDC}")
                
            elif choice == '5':  # Alert History
                alerts = ALERT_MANAGER.get_alerts()
                
                if alerts:
                    print(f"\n{Colors.CYAN}=== RECENT ALERTS (Last 20) ==={Colors.ENDC}")
                    for alert in alerts[:20]:
                        severity = alert.get('severity', 'unknown').upper()
                        acknowledged = "✓" if alert.get('acknowledged') else "✗"
                        
                        print(f"[{severity}] [{acknowledged}] {alert.get('message', '')[:50]}...")
                else:
                    print(f"{Colors.YELLOW}[!] No alert history{Colors.ENDC}")
                    
            else:
                print(f"{Colors.RED}[-] Invalid option{Colors.ENDC}")
                
            input(f"\n{Colors.CYAN}[*] Press Enter to continue...{Colors.ENDC}")
            
    def handle_reports(self):
        """Handle report generation and export"""
        menu = f"""
{Colors.CYAN}{Colors.BOLD}══════════════ REPORTS & EXPORT ══════════════{Colors.ENDC}

{Colors.GREEN}[1]{Colors.ENDC} List Recent Reports
{Colors.GREEN}[2]{Colors.ENDC} View Report
{Colors.GREEN}[3]{Colors.ENDC} Export Scan Results
{Colors.GREEN}[4]{Colors.ENDC} Generate Summary Report
{Colors.GREEN}[5]{Colors.ENDC} Backup Database
{Colors.GREEN}[0]{Colors.ENDC} Back to Main Menu

{Colors.CYAN}═══════════════════════════════════════════════════{Colors.ENDC}
"""
        
        while True:
            print(menu)
            choice = input(f"\n{Colors.GREEN}[?] Select option: {Colors.ENDC}").strip()
            
            if choice == '0':
                break
                
            elif choice == '1':  # List Reports
                report_files = list(REPORTS_DIR.glob("*.txt"))
                report_files.sort(key=os.path.getmtime, reverse=True)
                
                if report_files:
                    print(f"\n{Colors.CYAN}=== RECENT REPORTS ==={Colors.ENDC}")
                    for i, report_file in enumerate(report_files[:10], 1):
                        mtime = datetime.datetime.fromtimestamp(os.path.getmtime(report_file))
                        size = os.path.getsize(report_file)
                        print(f"{i}. {report_file.name}")
                        print(f"   Size: {size:,} bytes, Modified: {mtime.strftime('%Y-%m-%d %H:%M:%S')}")
                else:
                    print(f"{Colors.YELLOW}[!] No reports found{Colors.ENDC}")
                    
            elif choice == '2':  # View Report
                report_name = input(f"{Colors.GREEN}[?] Enter report name: {Colors.ENDC}").strip()
                report_file = REPORTS_DIR / report_name
                
                if report_file.exists():
                    try:
                        with open(report_file, 'r') as f:
                            content = f.read()
                            print(f"\n{Colors.CYAN}=== REPORT: {report_name} ==={Colors.ENDC}")
                            print(content[:1000])  # Show first 1000 chars
                            
                            if len(content) > 1000:
                                print(f"\n{Colors.YELLOW}[!] Report truncated. Full report at: {report_file}{Colors.ENDC}")
                    except:
                        print(f"{Colors.RED}[-] Error reading report{Colors.ENDC}")
                else:
                    print(f"{Colors.RED}[-] Report not found{Colors.ENDC}")
                    
            elif choice == '3':  # Export Scan Results
                if DB:
                    # Export recent scans to JSON
                    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    export_file = REPORTS_DIR / f"scan_export_{timestamp}.json"
                    
                    cursor = DB.conn.cursor()
                    cursor.execute('SELECT * FROM scans ORDER BY start_time DESC LIMIT 100')
                    scans = [dict(row) for row in cursor.fetchall()]
                    
                    export_data = {
                        'export_time': datetime.datetime.now().isoformat(),
                        'scans': scans
                    }
                    
                    with open(export_file, 'w') as f:
                        json.dump(export_data, f, indent=2, default=str)
                        
                    print(f"{Colors.GREEN}[+] Exported {len(scans)} scans to {export_file}{Colors.ENDC}")
                else:
                    print(f"{Colors.RED}[-] Database not available{Colors.ENDC}")
                    
            elif choice == '4':  # Generate Summary Report
                summary = self._generate_summary_report()
                print(f"\n{Colors.CYAN}=== SUMMARY REPORT ==={Colors.ENDC}")
                print(summary)
                
                # Save summary
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                summary_file = REPORTS_DIR / f"summary_report_{timestamp}.txt"
                
                with open(summary_file, 'w') as f:
                    f.write(summary)
                    
                print(f"\n{Colors.GREEN}[+] Summary saved to {summary_file}{Colors.ENDC}")
                
            elif choice == '5':  # Backup Database
                if DB:
                    backup_file = BACKUPS_DIR / f"scans_backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
                    shutil.copy2(DB.db_path, backup_file)
                    print(f"{Colors.GREEN}[+] Database backed up to {backup_file}{Colors.ENDC}")
                else:
                    print(f"{Colors.RED}[-] Database not available{Colors.ENDC}")
                    
            else:
                print(f"{Colors.RED}[-] Invalid option{Colors.ENDC}")
                
            input(f"\n{Colors.CYAN}[*] Press Enter to continue...{Colors.ENDC}")
            
    def _generate_summary_report(self) -> str:
        """Generate system summary report"""
        report = []
        
        report.append("=" * 80)
        report.append("HACK404 PRODUCTION - SYSTEM SUMMARY REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.datetime.now().isoformat()}")
        report.append(f"Version: {CONFIG['version']}")
        report.append(f"User: {self.current_user or 'Not logged in'}")
        report.append("=" * 80)
        
        # System Information
        sys_info = SystemUtils.get_system_info()
        report.append("\nSYSTEM INFORMATION:")
        report.append("-" * 80)
        report.append(f"Hostname: {sys_info['system'].get('hostname', 'N/A')}")
        report.append(f"Platform: {sys_info['system'].get('platform', 'N/A')}")
        report.append(f"Local IP: {sys_info['system'].get('local_ip', 'N/A')}")
        report.append(f"Public IP: {sys_info['system'].get('public_ip', 'N/A')}")
        
        # Database Statistics
        if DB:
            cursor = DB.conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM scans")
            scan_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM hosts WHERE is_active = 1")
            host_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
            vuln_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM alerts")
            alert_count = cursor.fetchone()[0]
            
            report.append("\nDATABASE STATISTICS:")
            report.append("-" * 80)
            report.append(f"Total scans: {scan_count}")
            report.append(f"Active hosts: {host_count}")
            report.append(f"Vulnerabilities: {vuln_count}")
            report.append(f"Alerts: {alert_count}")
            
        # Alert Statistics
        alert_stats = ALERT_MANAGER.get_stats()
        report.append("\nALERT STATISTICS:")
        report.append("-" * 80)
        report.append(f"Total alerts: {alert_stats.get('total', 0)}")
        report.append(f"Active alerts: {alert_stats.get('active', 0)}")
        
        if alert_stats.get('by_severity'):
            report.append("\nBy severity:")
            for severity, count in alert_stats['by_severity'].items():
                report.append(f"  {severity.upper()}: {count}")
                
        # Recent Scans
        if DB:
            cursor.execute("SELECT scan_type, target, start_time FROM scans ORDER BY start_time DESC LIMIT 5")
            recent_scans = cursor.fetchall()
            
            if recent_scans:
                report.append("\nRECENT SCANS:")
                report.append("-" * 80)
                for scan in recent_scans:
                    report.append(f"{scan[0]} - {scan[1]} ({scan[2]})")
                    
        # Disk Usage
        if PSUTIL_AVAILABLE:
            try:
                usage = psutil.disk_usage('/')
                report.append("\nDISK USAGE:")
                report.append("-" * 80)
                report.append(f"Total: {usage.total / (1024**3):.1f} GB")
                report.append(f"Used: {usage.used / (1024**3):.1f} GB ({usage.percent:.1f}%)")
                report.append(f"Free: {usage.free / (1024**3):.1f} GB")
            except:
                pass
                
        report.append("\n" + "=" * 80)
        report.append("END OF SUMMARY")
        report.append("=" * 80)
        
        return "\n".join(report)
        
    def handle_system_info(self):
        """Display system information and configuration"""
        menu = f"""
{Colors.CYAN}{Colors.BOLD}══════════════ SYSTEM INFORMATION ══════════════{Colors.ENDC}

{Colors.GREEN}[1]{Colors.ENDC} View Configuration
{Colors.GREEN}[2]{Colors.ENDC} Check Dependencies
{Colors.GREEN}[3]{Colors.ENDC} View Database Info
{Colors.GREEN}[4]{Colors.ENDC} View Log Files
{Colors.GREEN}[5]{Colors.ENDC} System Health Check
{Colors.GREEN}[6]{Colors.ENDC} View Network Info
{Colors.GREEN}[0]{Colors.ENDC} Back to Main Menu

{Colors.CYAN}═════════════════════════════════════════════════════════════{Colors.ENDC}
"""
        
        while True:
            print(menu)
            choice = input(f"\n{Colors.GREEN}[?] Select option: {Colors.ENDC}").strip()
            
            if choice == '0':
                break
                
            elif choice == '1':  # View Configuration
                print(f"\n{Colors.CYAN}=== CONFIGURATION ==={Colors.ENDC}")
                print(f"Tool Name: {CONFIG['name']}")
                print(f"Version: {CONFIG['version']}")
                print(f"Author: {CONFIG['author']}")
                
                print(f"\nSecurity Configuration:")
                print(f"  Authentication: {CONFIG['security'].require_authentication}")
                print(f"  Session Timeout: {CONFIG['security'].session_timeout}s")
                
                print(f"\nNetwork Configuration:")
                print(f"  Max Threads: {CONFIG['network'].max_scan_threads}")
                print(f"  Raw Sockets: {CONFIG['network'].use_raw_sockets}")
                print(f"  SYN Scan: {CONFIG['network'].syn_scan_enabled}")
                
            elif choice == '2':  # Check Dependencies
                print(f"\n{Colors.CYAN}=== DEPENDENCIES ==={Colors.ENDC}")
                
                print(f"\nRequired:")
                print(f"  psutil: {'✓' if PSUTIL_AVAILABLE else '✗'} {PSUTIL_VERSION or ''}")
                print(f"  requests: {'✓' if REQUESTS_AVAILABLE else '✗'} {REQUESTS_VERSION or ''}")
                
                print(f"\nOptional:")
                print(f"  python-nmap: {'✓' if NMAP_AVAILABLE else '✗'}")
                print(f"  scapy: {'✓' if SCAPY_AVAILABLE else '✗'}")
                print(f"  cryptography: {'✓' if CRYPTO_AVAILABLE else '✗'}")
                print(f"  beautifulsoup4: {'✓' if BEAUTIFULSOUP_AVAILABLE else '✗'}")
                print(f"  paramiko: {'✓' if PARAMIKO_AVAILABLE else '✗'}")
                
            elif choice == '3':  # Database Info
                if DB:
                    db_size = os.path.getsize(DB.db_path) if os.path.exists(DB.db_path) else 0
                    
                    print(f"\n{Colors.CYAN}=== DATABASE INFORMATION ==={Colors.ENDC}")
                    print(f"Path: {DB.db_path}")
                    print(f"Size: {db_size:,} bytes ({db_size/1024/1024:.2f} MB)")
                    
                    cursor = DB.conn.cursor()
                    
                    # Table counts
                    tables = ['scans', 'hosts', 'ports', 'vulnerabilities', 'alerts']
                    for table in tables:
                        cursor.execute(f"SELECT COUNT(*) FROM {table}")
                        count = cursor.fetchone()[0]
                        print(f"  {table}: {count:,} rows")
                else:
                    print(f"{Colors.RED}[-] Database not available{Colors.ENDC}")
                    
            elif choice == '4':  # View Log Files
                log_files = list(LOGS_DIR.glob("*.log"))
                
                if log_files:
                    print(f"\n{Colors.CYAN}=== LOG FILES ==={Colors.ENDC}")
                    for log_file in log_files[:5]:
                        size = os.path.getsize(log_file)
                        mtime = datetime.datetime.fromtimestamp(os.path.getmtime(log_file))
                        print(f"{log_file.name}: {size:,} bytes, Modified: {mtime.strftime('%Y-%m-%d %H:%M:%S')}")
                        
                        # Show last few lines
                        try:
                            with open(log_file, 'r') as f:
                                lines = f.readlines()[-5:]
                                if lines:
                                    print(f"  Last entries:")
                                    for line in lines:
                                        print(f"    {line.strip()}")
                        except:
                            pass
                else:
                    print(f"{Colors.YELLOW}[!] No log files found{Colors.ENDC}")
                    
            elif choice == '5':  # System Health Check
                print(f"\n{Colors.CYAN}=== SYSTEM HEALTH CHECK ==={Colors.ENDC}")
                
                # Check disk space
                ok, disk_info = SystemUtils.check_disk_space('/')
                if ok:
                    print(f"{Colors.GREEN}[✓] Disk space OK: {disk_info.get('percent', 0):.1f}% used{Colors.ENDC}")
                else:
                    print(f"{Colors.RED}[✗] Disk space critical: {disk_info.get('percent', 0):.1f}% used{Colors.ENDC}")
                    
                # Check memory
                if PSUTIL_AVAILABLE:
                    memory = psutil.virtual_memory()
                    if memory.percent < 90:
                        print(f"{Colors.Green}[✓] Memory OK: {memory.percent:.1f}% used{Colors.ENDC}")
                    else:
                        print(f"{Colors.RED}[✗] Memory critical: {memory.percent:.1f}% used{Colors.ENDC}")
                        
                # Check database
                if DB:
                    try:
                        cursor = DB.conn.cursor()
                        cursor.execute("SELECT 1")
                        print(f"{Colors.GREEN}[✓] Database connection OK{Colors.ENDC}")
                    except:
                        print(f"{Colors.RED}[✗] Database connection failed{Colors.ENDC}")
                else:
                    print(f"{Colors.YELLOW}[!] Database not available{Colors.ENDC}")
                    
                # Check raw sockets
                if CONFIG['network'].use_raw_sockets:
                    if RAW_SCANNER.initialized:
                        print(f"{Colors.GREEN}[✓] Raw sockets initialized{Colors.ENDC}")
                    else:
                        print(f"{Colors.YELLOW}[!] Raw sockets not available (permissions){Colors.ENDC}")
                        
            elif choice == '6':  # Network Info
                print(f"\n{Colors.CYAN}=== NETWORK INFORMATION ==={Colors.ENDC}")
                
                local_ip = NetworkUtils.get_local_ip()
                public_ip = NetworkUtils.get_public_ip()
                
                print(f"Local IP: {local_ip}")
                print(f"Public IP: {public_ip or 'Not available'}")
                
                interfaces = NetworkUtils.get_network_interfaces()
                print(f"\nNetwork Interfaces: {len(interfaces)}")
                
                for iface, info in interfaces.items():
                    status = "UP" if info.get('is_up') else "DOWN"
                    color = Colors.GREEN if info.get('is_up') else Colors.RED
                    print(f"  {color}{iface} [{status}]{Colors.ENDC}")
                    
            else:
                print(f"{Colors.RED}[-] Invalid option{Colors.ENDC}")
                
            input(f"\n{Colors.CYAN}[*] Press Enter to continue...{Colors.ENDC}")
            
    def run(self):
        """Main CLI loop"""
        self.print_banner()
        
        # Check dependencies
        if not PSUTIL_AVAILABLE:
            print(f"{Colors.YELLOW}[!] Warning: psutil not installed. System monitoring features disabled.{Colors.ENDC}")
            
        if not REQUESTS_AVAILABLE:
            print(f"{Colors.YELLOW}[!] Warning: requests not installed. Web scanning features disabled.{Colors.ENDC}")
            
        # Authenticate if required
        if CONFIG['security'].require_authentication:
            if not self.login():
                print(f"{Colors.RED}[-] Authentication failed. Exiting.{Colors.ENDC}")
                return
                
        print(f"\n{Colors.GREEN}[+] HACK404 PRODUCTION Ready!{Colors.ENDC}")
        print(f"{Colors.CYAN}[*] Type 'help' for commands, 'exit' to quit{Colors.ENDC}")
        
        # Main command loop
        while self.running:
            try:
                # Validate session
                if not self.validate_session():
                    print(f"{Colors.RED}[-] Session expired. Please login again.{Colors.ENDC}")
                    if not self.login():
                        break
                        
                self.print_menu()
                choice = input(f"\n{Colors.GREEN}[?] Select option: {Colors.ENDC}").strip()
                
                # Record command history
                self.command_history.append(choice)
                if len(self.command_history) > 100:
                    self.command_history.pop(0)
                    
                if choice == '1':
                    self.handle_network_scanning()
                elif choice == '2':
                    self.handle_system_monitoring()
                elif choice == '3':
                    self.handle_web_security()
                elif choice == '4':
                    self.handle_packet_analysis()
                elif choice == '5':
                    self.handle_log_analysis()
                elif choice == '6':
                    self.handle_vulnerability_assessment()
                elif choice == '7':
                    self.handle_alert_management()
                elif choice == '8':
                    self.handle_reports()
                elif choice == '9':
                    self.handle_system_info()
                elif choice == '0':
                    self.running = False
                elif choice.lower() == 'exit':
                    self.running = False
                elif choice.lower() == 'help':
                    print(f"\n{Colors.CYAN}=== HELP ==={Colors.ENDC}")
                    print(f"Main menu options 1-9 access different modules")
                    print(f"Type 'exit' to quit the application")
                    print(f"Use Ctrl+C to interrupt current operation")
                    input(f"\n{Colors.CYAN}[*] Press Enter to continue...{Colors.ENDC}")
                else:
                    print(f"{Colors.RED}[-] Invalid option. Please select 0-9.{Colors.ENDC}")
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[!] Interrupted. Returning to main menu...{Colors.ENDC}")
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                print(f"{Colors.RED}[-] Error: {e}{Colors.ENDC}")
                
        # Cleanup
        self.cleanup()
        print(f"\n{Colors.GREEN}[+] HACK404 PRODUCTION shutdown complete.{Colors.ENDC}")
        
    def cleanup(self):
        """Cleanup resources"""
        try:
            # Stop monitoring if running
            if self.monitor.monitoring:
                self.monitor.stop_monitoring()
                
            # Close scanner
            self.scanner.close()
            
            # Close raw sockets
            RAW_SCANNER.close()
            
            # Logout
            self.logout()
            
            # Close database
            if DB:
                DB.conn.close()
                
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

# Signal handler for graceful shutdown
def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print(f"\n{Colors.YELLOW}[!] Received shutdown signal. Exiting gracefully...{Colors.ENDC}")
    sys.exit(0)

# Main entry point
def main():
    """Main entry point for HACK404 PRODUCTION"""
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Check for administrative privileges (suggested but not required)
    if os.name != 'nt' and os.geteuid() != 0:
        print(f"{Colors.YELLOW}[!] Running without root privileges. Some features may be limited.{Colors.ENDC}")
        print(f"{Colors.CYAN}[*] For raw socket scanning and packet capture, run with sudo.{Colors.ENDC}")
        
    # Initialize and run CLI
    cli = HACK404CLI()
    
    try:
        cli.run()
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        print(f"{Colors.RED}[-] Fatal error: {e}{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()
