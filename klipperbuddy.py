"""
KlipperBuddy - Desktop application for Klipper printer management
All-in-one file for PyInstaller compatibility
"""

import sys
import os
import asyncio
import json
import logging
import base64
import socket
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional, Dict, List
from pathlib import Path
from ipaddress import IPv4Network

import aiohttp
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QIcon, QPixmap, QAction
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QLineEdit, QSpinBox, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    QDialog, QFormLayout, QDialogButtonBox, QGroupBox,
    QProgressBar, QFrame, QSplitter, QTextEdit, QComboBox,
    QSystemTrayIcon, QMenu, QScrollArea, QCheckBox, QProgressDialog
)

logger = logging.getLogger(__name__)

# ============================================================================
# Data Models
# ============================================================================

@dataclass
class PrinterStatus:
    """Current printer status from Moonraker"""
    connected: bool = False
    state: str = "unknown"
    state_message: str = ""
    filename: Optional[str] = None
    progress: float = 0.0
    print_duration: float = 0.0
    total_duration: float = 0.0
    filament_used: float = 0.0
    extruder_temp: float = 0.0
    extruder_target: float = 0.0
    bed_temp: float = 0.0
    bed_target: float = 0.0
    position: list = field(default_factory=lambda: [0.0, 0.0, 0.0, 0.0])
    speed: float = 0.0
    speed_factor: float = 1.0
    fan_speed: float = 0.0
    software_version: str = ""
    hostname: str = ""
    raw_data: dict = field(default_factory=dict)


@dataclass
class PrintJob:
    """Print job history entry"""
    job_id: str
    filename: str
    status: str
    start_time: datetime
    end_time: Optional[datetime]
    print_duration: float
    total_duration: float
    filament_used: float
    metadata: dict = field(default_factory=dict)


@dataclass
class GCodeFile:
    """G-code file info"""
    filename: str
    path: str
    modified: float
    size: int
    metadata: dict = field(default_factory=dict)


@dataclass
class PrinterConfig:
    """Configuration for a Klipper printer"""
    id: str
    name: str
    host: str
    port: int = 7125
    api_key: Optional[str] = None
    webcam_url: Optional[str] = None
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "api_key": self.api_key,
            "webcam_url": self.webcam_url,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat()
        }
        
    @classmethod
    def from_dict(cls, data: dict) -> "PrinterConfig":
        data = data.copy()
        if "created_at" in data and isinstance(data["created_at"], str):
            data["created_at"] = datetime.fromisoformat(data["created_at"])
        return cls(**data)


@dataclass
class DiscoveredPrinter:
    """A printer discovered on the network"""
    name: str
    host: str
    port: int
    service_type: str = "moonraker"
    requires_auth: bool = False
    
    def __hash__(self):
        return hash((self.host, self.port))
    
    def __eq__(self, other):
        if isinstance(other, DiscoveredPrinter):
            return self.host == other.host and self.port == other.port
        return False


@dataclass
class AuthCredentials:
    """Authentication credentials for a printer"""
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    auth_type: str = "none"
    
    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "api_key": self.api_key,
            "auth_type": self.auth_type
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "AuthCredentials":
        return cls(**data)


@dataclass
class AppSettings:
    """Application settings"""
    theme: str = "dark"
    refresh_interval: int = 2000
    auto_connect: bool = True
    minimize_to_tray: bool = True
    start_minimized: bool = False
    show_notifications: bool = True
    language: str = "en"
    
    def to_dict(self) -> dict:
        return {
            "theme": self.theme,
            "refresh_interval": self.refresh_interval,
            "auto_connect": self.auto_connect,
            "minimize_to_tray": self.minimize_to_tray,
            "start_minimized": self.start_minimized,
            "show_notifications": self.show_notifications,
            "language": self.language
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "AppSettings":
        return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})


# ============================================================================
# Printer Config Manager
# ============================================================================

class PrinterConfigManager:
    """Manages printer configurations with persistence"""
    
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.printers: dict[str, PrinterConfig] = {}
        self._load()
        
    def _load(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    data = json.load(f)
                    for printer_data in data.get("printers", []):
                        printer = PrinterConfig.from_dict(printer_data)
                        self.printers[printer.id] = printer
            except Exception as e:
                print(f"Error loading config: {e}")
                
    def _save(self):
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        data = {"printers": [p.to_dict() for p in self.printers.values()]}
        with open(self.config_path, "w") as f:
            json.dump(data, f, indent=2)
            
    def add_printer(self, printer: PrinterConfig):
        self.printers[printer.id] = printer
        self._save()
        
    def remove_printer(self, printer_id: str):
        if printer_id in self.printers:
            del self.printers[printer_id]
            self._save()
            
    def update_printer(self, printer: PrinterConfig):
        self.printers[printer.id] = printer
        self._save()
        
    def get_printer(self, printer_id: str) -> Optional[PrinterConfig]:
        return self.printers.get(printer_id)
        
    def get_all_printers(self) -> list[PrinterConfig]:
        return list(self.printers.values())


# ============================================================================
# Auth Manager
# ============================================================================

class AuthManager:
    """Manages authentication credentials for printers"""
    
    def __init__(self, config_dir: Optional[str] = None):
        if config_dir is None:
            if os.name == 'nt':
                config_dir = os.path.join(os.environ.get('APPDATA', ''), 'KlipperBuddy')
            else:
                config_dir = os.path.join(os.path.expanduser('~'), '.config', 'klipperbuddy')
        
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.credentials_file = self.config_dir / 'credentials.json'
        self._credentials: Dict[str, AuthCredentials] = {}
        self._load_credentials()
    
    def _get_key(self, host: str, port: int) -> str:
        return f"{host}:{port}"
    
    def _load_credentials(self):
        if self.credentials_file.exists():
            try:
                with open(self.credentials_file, 'r') as f:
                    data = json.load(f)
                    for key, cred_data in data.items():
                        self._credentials[key] = AuthCredentials.from_dict(cred_data)
            except Exception as e:
                print(f"Error loading credentials: {e}")
    
    def _save_credentials(self):
        try:
            data = {key: cred.to_dict() for key, cred in self._credentials.items()}
            with open(self.credentials_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving credentials: {e}")
    
    def set_credentials(self, host: str, port: int, 
                        username: Optional[str] = None,
                        password: Optional[str] = None,
                        api_key: Optional[str] = None):
        key = self._get_key(host, port)
        auth_type = "none"
        if api_key:
            auth_type = "api_key"
        elif username and password:
            auth_type = "basic"
        
        self._credentials[key] = AuthCredentials(
            host=host, port=port, username=username,
            password=password, api_key=api_key, auth_type=auth_type
        )
        self._save_credentials()
    
    def get_credentials(self, host: str, port: int) -> Optional[AuthCredentials]:
        key = self._get_key(host, port)
        return self._credentials.get(key)
    
    def remove_credentials(self, host: str, port: int):
        key = self._get_key(host, port)
        if key in self._credentials:
            del self._credentials[key]
            self._save_credentials()
    
    def get_auth_headers(self, host: str, port: int) -> Dict[str, str]:
        cred = self.get_credentials(host, port)
        headers = {}
        if cred:
            if cred.auth_type == 'api_key' and cred.api_key:
                headers['X-Api-Key'] = cred.api_key
            elif cred.auth_type == 'basic' and cred.username and cred.password:
                auth_str = f"{cred.username}:{cred.password}"
                auth_bytes = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
                headers['Authorization'] = f'Basic {auth_bytes}'
        return headers
    
    async def test_authentication(self, host: str, port: int,
                                   username: Optional[str] = None,
                                   password: Optional[str] = None,
                                   api_key: Optional[str] = None) -> tuple[bool, str]:
        headers = {}
        if api_key:
            headers['X-Api-Key'] = api_key
        elif username and password:
            auth_str = f"{username}:{password}"
            auth_bytes = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
            headers['Authorization'] = f'Basic {auth_bytes}'
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://{host}:{port}/printer/info"
                async with session.get(url, headers=headers, 
                                       timeout=aiohttp.ClientTimeout(total=5.0)) as response:
                    if response.status == 200:
                        return True, "Authentication successful"
                    elif response.status == 401:
                        return False, "Invalid credentials"
                    elif response.status == 403:
                        return False, "Access forbidden"
                    else:
                        return False, f"Unexpected response: {response.status}"
        except aiohttp.ClientError as e:
            return False, f"Connection error: {str(e)}"
        except Exception as e:
            return False, f"Error: {str(e)}"



# ============================================================================
# Moonraker Client
# ============================================================================

class MoonrakerClient:
    """Async client for Moonraker API with authentication support"""
    
    def __init__(self, host: str, port: int = 7125, 
                 api_key: Optional[str] = None,
                 username: Optional[str] = None,
                 password: Optional[str] = None):
        self.host = host
        self.port = port
        self.api_key = api_key
        self.username = username
        self.password = password
        self.base_url = f"http://{host}:{port}"
        self._session: Optional[aiohttp.ClientSession] = None
        self._connected = False
        self._auth_token: Optional[str] = None
        self._requires_auth = False
        
    @property
    def is_connected(self) -> bool:
        return self._connected
    
    @property
    def requires_auth(self) -> bool:
        return self._requires_auth
    
    def set_credentials(self, username: Optional[str] = None, 
                        password: Optional[str] = None,
                        api_key: Optional[str] = None):
        self.username = username
        self.password = password
        self.api_key = api_key
        self._auth_token = None
    
    def _get_auth_headers(self) -> Dict[str, str]:
        headers = {}
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"
        elif self.api_key:
            headers["X-Api-Key"] = self.api_key
        elif self.username and self.password:
            auth_str = f"{self.username}:{self.password}"
            auth_bytes = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
            headers["Authorization"] = f"Basic {auth_bytes}"
        return headers
        
    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            headers = self._get_auth_headers()
            self._session = aiohttp.ClientSession(headers=headers)
        return self._session
    
    async def _recreate_session(self):
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None
        return await self._get_session()
        
    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
        self._connected = False
            
    async def _request(self, method: str, endpoint: str, **kwargs) -> Optional[dict]:
        session = await self._get_session()
        url = f"{self.base_url}{endpoint}"
        headers = kwargs.pop('headers', {})
        headers.update(self._get_auth_headers())
        
        try:
            async with session.request(method, url, headers=headers, **kwargs) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("result", data)
                elif response.status == 401:
                    self._requires_auth = True
                    return None
                else:
                    return None
        except Exception as e:
            self._connected = False
            return None
    
    async def login(self) -> bool:
        if not self.username or not self.password:
            return True
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/access/login"
                payload = {"username": self.username, "password": self.password}
                async with session.post(url, json=payload,
                                        timeout=aiohttp.ClientTimeout(total=5.0)) as response:
                    if response.status == 200:
                        data = await response.json()
                        self._auth_token = data.get('result', {}).get('token')
                        if self._auth_token:
                            await self._recreate_session()
                            return True
        except Exception:
            pass
        return False
    
    async def check_auth_required(self) -> bool:
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/printer/info"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=3.0)) as response:
                    if response.status == 401:
                        self._requires_auth = True
                        return True
                    elif response.status == 200:
                        self._requires_auth = False
                        return False
        except Exception:
            pass
        return False
            
    async def connect(self) -> bool:
        try:
            await self.check_auth_required()
            if self._requires_auth and (self.username and self.password):
                if not await self.login():
                    return False
            
            result = await self._request("GET", "/printer/info")
            if result:
                self._connected = True
                return True
            return False
        except Exception:
            return False
            
    async def get_printer_info(self) -> Optional[dict]:
        return await self._request("GET", "/printer/info")
        
    async def get_printer_status(self) -> PrinterStatus:
        status = PrinterStatus()
        
        info = await self.get_printer_info()
        if info:
            status.connected = True
            status.state = info.get("state", "unknown")
            status.state_message = info.get("state_message", "")
            status.software_version = info.get("software_version", "")
            status.hostname = info.get("hostname", "")
        else:
            return status
            
        objects = {
            "print_stats": None, "extruder": None, "heater_bed": None,
            "toolhead": None, "gcode_move": None, "fan": None, "virtual_sdcard": None
        }
        
        result = await self._request("POST", "/printer/objects/query", json={"objects": objects})
        
        if result and "status" in result:
            data = result["status"]
            status.raw_data = data
            
            if "print_stats" in data:
                ps = data["print_stats"]
                status.filename = ps.get("filename")
                status.print_duration = ps.get("print_duration", 0.0)
                status.total_duration = ps.get("total_duration", 0.0)
                status.filament_used = ps.get("filament_used", 0.0)
            
            if "extruder" in data:
                ext = data["extruder"]
                status.extruder_temp = ext.get("temperature", 0.0)
                status.extruder_target = ext.get("target", 0.0)
            
            if "heater_bed" in data:
                bed = data["heater_bed"]
                status.bed_temp = bed.get("temperature", 0.0)
                status.bed_target = bed.get("target", 0.0)
            
            if "toolhead" in data:
                th = data["toolhead"]
                status.position = th.get("position", [0, 0, 0, 0])
            
            if "gcode_move" in data:
                gm = data["gcode_move"]
                status.speed = gm.get("speed", 0.0)
                status.speed_factor = gm.get("speed_factor", 1.0)
            
            if "fan" in data:
                status.fan_speed = data["fan"].get("speed", 0.0)
            
            if "virtual_sdcard" in data:
                status.progress = data["virtual_sdcard"].get("progress", 0.0)
        
        return status
    
    async def get_print_history(self, limit: int = 50) -> list[PrintJob]:
        result = await self._request("GET", f"/server/history/list?limit={limit}")
        jobs = []
        
        if result and "jobs" in result:
            for job_data in result["jobs"]:
                try:
                    job = PrintJob(
                        job_id=job_data.get("job_id", ""),
                        filename=job_data.get("filename", ""),
                        status=job_data.get("status", ""),
                        start_time=datetime.fromtimestamp(job_data.get("start_time", 0)),
                        end_time=datetime.fromtimestamp(job_data["end_time"]) if job_data.get("end_time") else None,
                        print_duration=job_data.get("print_duration", 0.0),
                        total_duration=job_data.get("total_duration", 0.0),
                        filament_used=job_data.get("filament_used", 0.0),
                        metadata=job_data.get("metadata", {})
                    )
                    jobs.append(job)
                except Exception:
                    continue
        
        return jobs
    
    async def get_gcode_files(self) -> list[GCodeFile]:
        result = await self._request("GET", "/server/files/list")
        files = []
        
        if result:
            for file_data in result:
                try:
                    gcode_file = GCodeFile(
                        filename=file_data.get("filename", ""),
                        path=file_data.get("path", ""),
                        modified=file_data.get("modified", 0.0),
                        size=file_data.get("size", 0),
                        metadata=file_data.get("metadata", {})
                    )
                    files.append(gcode_file)
                except Exception:
                    continue
        
        return files
    
    async def start_print(self, filename: str) -> bool:
        result = await self._request("POST", f"/printer/print/start?filename={filename}")
        return result is not None
    
    async def pause_print(self) -> bool:
        result = await self._request("POST", "/printer/print/pause")
        return result is not None
    
    async def resume_print(self) -> bool:
        result = await self._request("POST", "/printer/print/resume")
        return result is not None
    
    async def cancel_print(self) -> bool:
        result = await self._request("POST", "/printer/print/cancel")
        return result is not None
    
    async def emergency_stop(self) -> bool:
        result = await self._request("POST", "/printer/emergency_stop")
        return result is not None
    
    async def send_gcode(self, gcode: str) -> bool:
        result = await self._request("POST", "/printer/gcode/script", json={"script": gcode})
        return result is not None
    
    async def set_temperature(self, heater: str, target: float) -> bool:
        if heater == "extruder":
            gcode = f"SET_HEATER_TEMPERATURE HEATER=extruder TARGET={target}"
        elif heater == "bed":
            gcode = f"SET_HEATER_TEMPERATURE HEATER=heater_bed TARGET={target}"
        else:
            return False
        return await self.send_gcode(gcode)
    
    async def home(self, axes: str = "XYZ") -> bool:
        gcode = f"G28 {axes}"
        return await self.send_gcode(gcode)
    
    async def restart_firmware(self) -> bool:
        result = await self._request("POST", "/printer/firmware_restart")
        return result is not None



# ============================================================================
# Network Scanner
# ============================================================================

class NetworkScanner:
    """Scans the local network for Klipper printers running Moonraker"""
    
    MOONRAKER_PORTS = [7125, 80, 443]
    WEB_PORTS = [80, 443, 4408, 4409]
    
    def __init__(self):
        self._scanning = False
        self._cancel_scan = False
        self._discovered_printers: List[DiscoveredPrinter] = []
    
    def get_local_ip(self) -> Optional[str]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return None
    
    def get_network_range(self) -> Optional[IPv4Network]:
        local_ip = self.get_local_ip()
        if not local_ip:
            return None
        parts = local_ip.split('.')
        network_str = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return IPv4Network(network_str, strict=False)
    
    async def check_moonraker(self, host: str, port: int) -> Optional[DiscoveredPrinter]:
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://{host}:{port}/printer/info"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=2.0)) as response:
                    if response.status == 200:
                        data = await response.json()
                        hostname = data.get('result', {}).get('hostname', host)
                        return DiscoveredPrinter(
                            name=hostname, host=host, port=port,
                            service_type="moonraker", requires_auth=False
                        )
                    elif response.status == 401:
                        return DiscoveredPrinter(
                            name=host, host=host, port=port,
                            service_type="moonraker", requires_auth=True
                        )
        except Exception:
            pass
        return None
    
    async def scan_host(self, host: str) -> List[DiscoveredPrinter]:
        results = []
        for port in self.MOONRAKER_PORTS:
            printer = await self.check_moonraker(host, port)
            if printer:
                results.append(printer)
                break
        return results
    
    async def scan_network(self, 
                           progress_callback: Optional[Callable[[int, int, str], None]] = None,
                           max_concurrent: int = 50) -> List[DiscoveredPrinter]:
        self._scanning = True
        self._cancel_scan = False
        self._discovered_printers = []
        
        network = self.get_network_range()
        if not network:
            self._scanning = False
            return []
        
        hosts = list(network.hosts())
        total = len(hosts)
        
        if progress_callback:
            progress_callback(0, total, "Starting network scan...")
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scan_with_semaphore(host: str, index: int):
            if self._cancel_scan:
                return []
            async with semaphore:
                if progress_callback:
                    progress_callback(index, total, f"Scanning {host}...")
                return await self.scan_host(str(host))
        
        tasks = [scan_with_semaphore(str(host), i) for i, host in enumerate(hosts)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                self._discovered_printers.extend(result)
        
        self._discovered_printers = list(set(self._discovered_printers))
        
        if progress_callback:
            progress_callback(total, total, f"Found {len(self._discovered_printers)} printer(s)")
        
        self._scanning = False
        return self._discovered_printers
    
    def cancel_scan(self):
        self._cancel_scan = True
    
    @property
    def is_scanning(self) -> bool:
        return self._scanning


async def auto_discover_printers(
    progress_callback: Optional[Callable[[int, int, str], None]] = None
) -> List[DiscoveredPrinter]:
    scanner = NetworkScanner()
    return await scanner.scan_network(progress_callback)



# ============================================================================
# GUI Components
# ============================================================================

class AsyncWorker(QThread):
    """Worker thread for async operations"""
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    progress = pyqtSignal(int, int, str)
    
    def __init__(self, coro):
        super().__init__()
        self.coro = coro
        
    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self.coro)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class NetworkScanDialog(QDialog):
    """Dialog for network scanning and printer discovery"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Scan Network for Printers")
        self.setMinimumSize(600, 400)
        self.discovered_printers = []
        self.selected_printers = []
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        info_label = QLabel(
            "Scan your local network to automatically discover Klipper printers "
            "running Moonraker. This may take a few moments."
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        scan_layout = QHBoxLayout()
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        scan_layout.addWidget(self.scan_btn)
        
        self.cancel_scan_btn = QPushButton("Cancel Scan")
        self.cancel_scan_btn.setEnabled(False)
        self.cancel_scan_btn.clicked.connect(self.cancel_scan)
        scan_layout.addWidget(self.cancel_scan_btn)
        
        scan_layout.addStretch()
        layout.addLayout(scan_layout)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("")
        layout.addWidget(self.status_label)
        
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Select", "Name", "Host", "Port", "Auth Required"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
    def start_scan(self):
        self.scan_btn.setEnabled(False)
        self.cancel_scan_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 254)
        self.status_label.setText("Scanning network...")
        self.table.setRowCount(0)
        
        self.scanner = NetworkScanner()
        
        async def scan_with_progress():
            return await self.scanner.scan_network()
        
        self.worker = AsyncWorker(scan_with_progress())
        self.worker.finished.connect(self._on_scan_finished)
        self.worker.error.connect(self._on_scan_error)
        self.worker.start()
        
        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self._update_progress)
        self.progress_timer.start(100)
        
    def _update_progress(self):
        if hasattr(self, 'scanner') and self.scanner.is_scanning:
            current = self.progress_bar.value()
            if current < 250:
                self.progress_bar.setValue(current + 1)
        
    def cancel_scan(self):
        if hasattr(self, 'scanner'):
            self.scanner.cancel_scan()
        self.status_label.setText("Scan cancelled")
        self.scan_btn.setEnabled(True)
        self.cancel_scan_btn.setEnabled(False)
        if hasattr(self, 'progress_timer'):
            self.progress_timer.stop()
        
    def _on_scan_finished(self, printers):
        if hasattr(self, 'progress_timer'):
            self.progress_timer.stop()
        
        self.discovered_printers = printers
        self.progress_bar.setValue(254)
        self.scan_btn.setEnabled(True)
        self.cancel_scan_btn.setEnabled(False)
        
        if not printers:
            self.status_label.setText("No printers found on the network")
            return
            
        self.status_label.setText(f"Found {len(printers)} printer(s)")
        self.table.setRowCount(len(printers))
        
        for row, printer in enumerate(printers):
            checkbox = QCheckBox()
            checkbox.setChecked(True)
            self.table.setCellWidget(row, 0, checkbox)
            self.table.setItem(row, 1, QTableWidgetItem(printer.name))
            self.table.setItem(row, 2, QTableWidgetItem(printer.host))
            self.table.setItem(row, 3, QTableWidgetItem(str(printer.port)))
            self.table.setItem(row, 4, QTableWidgetItem("Yes" if printer.requires_auth else "No"))
            
    def _on_scan_error(self, error):
        if hasattr(self, 'progress_timer'):
            self.progress_timer.stop()
        self.status_label.setText(f"Scan error: {error}")
        self.scan_btn.setEnabled(True)
        self.cancel_scan_btn.setEnabled(False)
        
    def get_selected_printers(self):
        selected = []
        for row in range(self.table.rowCount()):
            checkbox = self.table.cellWidget(row, 0)
            if checkbox and checkbox.isChecked():
                selected.append(self.discovered_printers[row])
        return selected


class AddPrinterDialog(QDialog):
    """Dialog for adding a new printer with authentication support"""
    
    def __init__(self, parent=None, printer: Optional[PrinterConfig] = None):
        super().__init__(parent)
        self.printer = printer
        self.auth_manager = AuthManager()
        self.setWindowTitle("Add Printer" if not printer else "Edit Printer")
        self.setMinimumWidth(450)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QFormLayout(self)
        
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("My Voron 2.4")
        layout.addRow("Name:", self.name_edit)
        
        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("192.168.1.100 or voron.local")
        layout.addRow("Host:", self.host_edit)
        
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(7125)
        layout.addRow("Port:", self.port_spin)
        
        auth_group = QGroupBox("Authentication (for Fluidd/Mainsail)")
        auth_layout = QFormLayout(auth_group)
        
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Optional - for protected instances")
        auth_layout.addRow("Username:", self.username_edit)
        
        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("Optional")
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        auth_layout.addRow("Password:", self.password_edit)
        
        self.api_key_edit = QLineEdit()
        self.api_key_edit.setPlaceholderText("Alternative to username/password")
        self.api_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        auth_layout.addRow("API Key:", self.api_key_edit)
        
        layout.addRow(auth_group)
        
        self.webcam_edit = QLineEdit()
        self.webcam_edit.setPlaceholderText("http://192.168.1.100/webcam/?action=stream")
        layout.addRow("Webcam URL:", self.webcam_edit)
        
        test_layout = QHBoxLayout()
        self.test_btn = QPushButton("Test Connection")
        self.test_btn.clicked.connect(self.test_connection)
        test_layout.addWidget(self.test_btn)
        
        self.test_auth_btn = QPushButton("Test Auth")
        self.test_auth_btn.clicked.connect(self.test_authentication)
        test_layout.addWidget(self.test_auth_btn)
        layout.addRow("", test_layout)
        
        self.status_label = QLabel("")
        layout.addRow("", self.status_label)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)
        
        if self.printer:
            self.name_edit.setText(self.printer.name)
            self.host_edit.setText(self.printer.host)
            self.port_spin.setValue(self.printer.port)
            if self.printer.api_key:
                self.api_key_edit.setText(self.printer.api_key)
            if self.printer.webcam_url:
                self.webcam_edit.setText(self.printer.webcam_url)
            
            cred = self.auth_manager.get_credentials(self.printer.host, self.printer.port)
            if cred:
                if cred.username:
                    self.username_edit.setText(cred.username)
                if cred.api_key:
                    self.api_key_edit.setText(cred.api_key)
    
    def test_connection(self):
        host = self.host_edit.text().strip()
        port = self.port_spin.value()
        
        if not host:
            self.status_label.setText("Please enter a host")
            return
        
        self.status_label.setText("Testing connection...")
        self.test_btn.setEnabled(False)
        
        async def test():
            client = MoonrakerClient(host, port)
            return await client.connect()
        
        self.test_worker = AsyncWorker(test())
        self.test_worker.finished.connect(self._on_test_finished)
        self.test_worker.error.connect(self._on_test_error)
        self.test_worker.start()
    
    def _on_test_finished(self, success):
        self.test_btn.setEnabled(True)
        if success:
            self.status_label.setText("Connection successful!")
            self.status_label.setStyleSheet("color: green;")
        else:
            self.status_label.setText("Connection failed")
            self.status_label.setStyleSheet("color: red;")
    
    def _on_test_error(self, error):
        self.test_btn.setEnabled(True)
        self.status_label.setText(f"Error: {error}")
        self.status_label.setStyleSheet("color: red;")
    
    def test_authentication(self):
        host = self.host_edit.text().strip()
        port = self.port_spin.value()
        username = self.username_edit.text().strip() or None
        password = self.password_edit.text() or None
        api_key = self.api_key_edit.text().strip() or None
        
        if not host:
            self.status_label.setText("Please enter a host")
            return
        
        self.status_label.setText("Testing authentication...")
        self.test_auth_btn.setEnabled(False)
        
        async def test():
            return await self.auth_manager.test_authentication(
                host, port, username, password, api_key
            )
        
        self.auth_worker = AsyncWorker(test())
        self.auth_worker.finished.connect(self._on_auth_test_finished)
        self.auth_worker.error.connect(self._on_auth_test_error)
        self.auth_worker.start()
    
    def _on_auth_test_finished(self, result):
        self.test_auth_btn.setEnabled(True)
        success, message = result
        self.status_label.setText(message)
        self.status_label.setStyleSheet("color: green;" if success else "color: red;")
    
    def _on_auth_test_error(self, error):
        self.test_auth_btn.setEnabled(True)
        self.status_label.setText(f"Error: {error}")
        self.status_label.setStyleSheet("color: red;")
    
    def get_printer_config(self) -> Optional[PrinterConfig]:
        name = self.name_edit.text().strip()
        host = self.host_edit.text().strip()
        port = self.port_spin.value()
        api_key = self.api_key_edit.text().strip() or None
        webcam_url = self.webcam_edit.text().strip() or None
        
        if not name or not host:
            return None
        
        printer_id = self.printer.id if self.printer else str(uuid.uuid4())
        
        username = self.username_edit.text().strip() or None
        password = self.password_edit.text() or None
        
        if username or password or api_key:
            self.auth_manager.set_credentials(host, port, username, password, api_key)
        
        return PrinterConfig(
            id=printer_id, name=name, host=host, port=port,
            api_key=api_key, webcam_url=webcam_url
        )



# ============================================================================
# Main Window
# ============================================================================

class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("KlipperBuddy")
        self.setMinimumSize(1000, 700)
        
        # Initialize managers
        config_dir = self._get_config_dir()
        self.config_manager = PrinterConfigManager(os.path.join(config_dir, "printers.json"))
        self.auth_manager = AuthManager(config_dir)
        
        # Printer clients
        self.clients: Dict[str, MoonrakerClient] = {}
        self.current_printer_id: Optional[str] = None
        
        # Setup UI
        self.setup_ui()
        self.setup_tray()
        
        # Start refresh timer
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_status)
        self.refresh_timer.start(2000)
        
        # Load printers
        self.load_printers()
        
        # Auto-scan on first launch if no printers
        if not self.config_manager.get_all_printers():
            QTimer.singleShot(500, self.show_scan_dialog)
    
    def _get_config_dir(self) -> str:
        if os.name == 'nt':
            return os.path.join(os.environ.get('APPDATA', ''), 'KlipperBuddy')
        else:
            return os.path.join(os.path.expanduser('~'), '.config', 'klipperbuddy')
    
    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)
        
        # Left panel - Printer list
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_panel.setMaximumWidth(250)
        
        # Printer list header
        header_layout = QHBoxLayout()
        header_layout.addWidget(QLabel("Printers"))
        
        scan_btn = QPushButton("Scan")
        scan_btn.clicked.connect(self.show_scan_dialog)
        header_layout.addWidget(scan_btn)
        
        add_btn = QPushButton("+")
        add_btn.setMaximumWidth(30)
        add_btn.clicked.connect(self.add_printer)
        header_layout.addWidget(add_btn)
        
        left_layout.addLayout(header_layout)
        
        # Printer list
        self.printer_list = QTableWidget()
        self.printer_list.setColumnCount(2)
        self.printer_list.setHorizontalHeaderLabels(["Name", "Status"])
        self.printer_list.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.printer_list.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.printer_list.itemSelectionChanged.connect(self.on_printer_selected)
        left_layout.addWidget(self.printer_list)
        
        layout.addWidget(left_panel)
        
        # Right panel - Tabs
        self.tabs = QTabWidget()
        
        # Status tab
        self.status_tab = QWidget()
        self.setup_status_tab()
        self.tabs.addTab(self.status_tab, "Status")
        
        # Control tab
        self.control_tab = QWidget()
        self.setup_control_tab()
        self.tabs.addTab(self.control_tab, "Control")
        
        # Files tab
        self.files_tab = QWidget()
        self.setup_files_tab()
        self.tabs.addTab(self.files_tab, "Files")
        
        # History tab
        self.history_tab = QWidget()
        self.setup_history_tab()
        self.tabs.addTab(self.history_tab, "History")
        
        layout.addWidget(self.tabs)
    
    def setup_status_tab(self):
        layout = QVBoxLayout(self.status_tab)
        
        # Status info
        info_group = QGroupBox("Printer Status")
        info_layout = QGridLayout(info_group)
        
        self.state_label = QLabel("Not Connected")
        self.state_label.setFont(QFont("", 14, QFont.Weight.Bold))
        info_layout.addWidget(QLabel("State:"), 0, 0)
        info_layout.addWidget(self.state_label, 0, 1)
        
        self.file_label = QLabel("-")
        info_layout.addWidget(QLabel("File:"), 1, 0)
        info_layout.addWidget(self.file_label, 1, 1)
        
        self.progress_bar = QProgressBar()
        info_layout.addWidget(QLabel("Progress:"), 2, 0)
        info_layout.addWidget(self.progress_bar, 2, 1)
        
        layout.addWidget(info_group)
        
        # Temperatures
        temp_group = QGroupBox("Temperatures")
        temp_layout = QGridLayout(temp_group)
        
        self.extruder_label = QLabel("0°C / 0°C")
        temp_layout.addWidget(QLabel("Extruder:"), 0, 0)
        temp_layout.addWidget(self.extruder_label, 0, 1)
        
        self.bed_label = QLabel("0°C / 0°C")
        temp_layout.addWidget(QLabel("Bed:"), 1, 0)
        temp_layout.addWidget(self.bed_label, 1, 1)
        
        layout.addWidget(temp_group)
        
        # Position
        pos_group = QGroupBox("Position")
        pos_layout = QGridLayout(pos_group)
        
        self.position_label = QLabel("X: 0  Y: 0  Z: 0")
        pos_layout.addWidget(self.position_label, 0, 0)
        
        self.speed_label = QLabel("Speed: 0 mm/s")
        pos_layout.addWidget(self.speed_label, 0, 1)
        
        layout.addWidget(pos_group)
        
        layout.addStretch()
    
    def setup_control_tab(self):
        layout = QVBoxLayout(self.control_tab)
        
        # Print controls
        print_group = QGroupBox("Print Control")
        print_layout = QHBoxLayout(print_group)
        
        self.pause_btn = QPushButton("Pause")
        self.pause_btn.clicked.connect(self.pause_print)
        print_layout.addWidget(self.pause_btn)
        
        self.resume_btn = QPushButton("Resume")
        self.resume_btn.clicked.connect(self.resume_print)
        print_layout.addWidget(self.resume_btn)
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.cancel_print)
        print_layout.addWidget(self.cancel_btn)
        
        layout.addWidget(print_group)
        
        # Temperature controls
        temp_group = QGroupBox("Temperature Control")
        temp_layout = QGridLayout(temp_group)
        
        temp_layout.addWidget(QLabel("Extruder:"), 0, 0)
        self.extruder_temp_spin = QSpinBox()
        self.extruder_temp_spin.setRange(0, 350)
        temp_layout.addWidget(self.extruder_temp_spin, 0, 1)
        
        set_ext_btn = QPushButton("Set")
        set_ext_btn.clicked.connect(lambda: self.set_temperature("extruder", self.extruder_temp_spin.value()))
        temp_layout.addWidget(set_ext_btn, 0, 2)
        
        temp_layout.addWidget(QLabel("Bed:"), 1, 0)
        self.bed_temp_spin = QSpinBox()
        self.bed_temp_spin.setRange(0, 150)
        temp_layout.addWidget(self.bed_temp_spin, 1, 1)
        
        set_bed_btn = QPushButton("Set")
        set_bed_btn.clicked.connect(lambda: self.set_temperature("bed", self.bed_temp_spin.value()))
        temp_layout.addWidget(set_bed_btn, 1, 2)
        
        layout.addWidget(temp_group)
        
        # Movement controls
        move_group = QGroupBox("Movement")
        move_layout = QGridLayout(move_group)
        
        home_btn = QPushButton("Home All")
        home_btn.clicked.connect(lambda: self.send_gcode("G28"))
        move_layout.addWidget(home_btn, 0, 0, 1, 3)
        
        layout.addWidget(move_group)
        
        # Emergency stop
        estop_btn = QPushButton("EMERGENCY STOP")
        estop_btn.setStyleSheet("background-color: red; color: white; font-weight: bold; padding: 10px;")
        estop_btn.clicked.connect(self.emergency_stop)
        layout.addWidget(estop_btn)
        
        layout.addStretch()
    
    def setup_files_tab(self):
        layout = QVBoxLayout(self.files_tab)
        
        refresh_btn = QPushButton("Refresh Files")
        refresh_btn.clicked.connect(self.load_files)
        layout.addWidget(refresh_btn)
        
        self.files_table = QTableWidget()
        self.files_table.setColumnCount(3)
        self.files_table.setHorizontalHeaderLabels(["Filename", "Size", "Modified"])
        self.files_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.files_table.doubleClicked.connect(self.start_selected_print)
        layout.addWidget(self.files_table)
    
    def setup_history_tab(self):
        layout = QVBoxLayout(self.history_tab)
        
        refresh_btn = QPushButton("Refresh History")
        refresh_btn.clicked.connect(self.load_history)
        layout.addWidget(refresh_btn)
        
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels(["Filename", "Status", "Duration", "Filament", "Date"])
        self.history_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.history_table)
    
    def setup_tray(self):
        self.tray_icon = QSystemTrayIcon(self)
        
        tray_menu = QMenu()
        show_action = tray_menu.addAction("Show")
        show_action.triggered.connect(self.show)
        quit_action = tray_menu.addAction("Quit")
        quit_action.triggered.connect(QApplication.quit)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.on_tray_activated)
        self.tray_icon.show()
    
    def on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show()
            self.activateWindow()
    
    def closeEvent(self, event):
        event.ignore()
        self.hide()
    
    def load_printers(self):
        self.printer_list.setRowCount(0)
        printers = self.config_manager.get_all_printers()
        
        for printer in printers:
            row = self.printer_list.rowCount()
            self.printer_list.insertRow(row)
            self.printer_list.setItem(row, 0, QTableWidgetItem(printer.name))
            self.printer_list.setItem(row, 1, QTableWidgetItem("Connecting..."))
            
            # Create client
            cred = self.auth_manager.get_credentials(printer.host, printer.port)
            client = MoonrakerClient(
                printer.host, printer.port,
                api_key=cred.api_key if cred else printer.api_key,
                username=cred.username if cred else None,
                password=cred.password if cred else None
            )
            self.clients[printer.id] = client
            
            # Connect async
            self.connect_printer(printer.id)
        
        if printers:
            self.printer_list.selectRow(0)
    
    def connect_printer(self, printer_id: str):
        if printer_id not in self.clients:
            return
        
        client = self.clients[printer_id]
        
        async def connect():
            return await client.connect()
        
        worker = AsyncWorker(connect())
        worker.finished.connect(lambda success: self.on_printer_connected(printer_id, success))
        worker.start()
        
        # Keep reference to prevent garbage collection
        if not hasattr(self, '_workers'):
            self._workers = []
        self._workers.append(worker)
    
    def on_printer_connected(self, printer_id: str, success: bool):
        printers = self.config_manager.get_all_printers()
        for row, printer in enumerate(printers):
            if printer.id == printer_id:
                status = "Connected" if success else "Offline"
                self.printer_list.setItem(row, 1, QTableWidgetItem(status))
                break
    
    def on_printer_selected(self):
        selected = self.printer_list.selectedItems()
        if not selected:
            return
        
        row = selected[0].row()
        printers = self.config_manager.get_all_printers()
        if row < len(printers):
            self.current_printer_id = printers[row].id
            self.refresh_status()
            self.load_files()
            self.load_history()
    
    def refresh_status(self):
        if not self.current_printer_id or self.current_printer_id not in self.clients:
            return
        
        client = self.clients[self.current_printer_id]
        
        async def get_status():
            return await client.get_printer_status()
        
        worker = AsyncWorker(get_status())
        worker.finished.connect(self.update_status_display)
        worker.start()
        
        if not hasattr(self, '_workers'):
            self._workers = []
        self._workers.append(worker)
    
    def update_status_display(self, status: PrinterStatus):
        if not status.connected:
            self.state_label.setText("Not Connected")
            return
        
        self.state_label.setText(status.state.capitalize())
        self.file_label.setText(status.filename or "-")
        self.progress_bar.setValue(int(status.progress * 100))
        
        self.extruder_label.setText(f"{status.extruder_temp:.1f}°C / {status.extruder_target:.1f}°C")
        self.bed_label.setText(f"{status.bed_temp:.1f}°C / {status.bed_target:.1f}°C")
        
        pos = status.position
        self.position_label.setText(f"X: {pos[0]:.1f}  Y: {pos[1]:.1f}  Z: {pos[2]:.1f}")
        self.speed_label.setText(f"Speed: {status.speed:.0f} mm/s")
    
    def show_scan_dialog(self):
        dialog = NetworkScanDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            selected = dialog.get_selected_printers()
            for discovered in selected:
                printer = PrinterConfig(
                    id=str(uuid.uuid4()),
                    name=discovered.name,
                    host=discovered.host,
                    port=discovered.port
                )
                self.config_manager.add_printer(printer)
            self.load_printers()
    
    def add_printer(self):
        dialog = AddPrinterDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            printer = dialog.get_printer_config()
            if printer:
                self.config_manager.add_printer(printer)
                self.load_printers()
    
    def load_files(self):
        if not self.current_printer_id or self.current_printer_id not in self.clients:
            return
        
        client = self.clients[self.current_printer_id]
        
        async def get_files():
            return await client.get_gcode_files()
        
        worker = AsyncWorker(get_files())
        worker.finished.connect(self.update_files_display)
        worker.start()
        
        if not hasattr(self, '_workers'):
            self._workers = []
        self._workers.append(worker)
    
    def update_files_display(self, files: list):
        self.files_table.setRowCount(0)
        for gcode_file in files:
            row = self.files_table.rowCount()
            self.files_table.insertRow(row)
            self.files_table.setItem(row, 0, QTableWidgetItem(gcode_file.filename))
            self.files_table.setItem(row, 1, QTableWidgetItem(f"{gcode_file.size / 1024:.1f} KB"))
            modified = datetime.fromtimestamp(gcode_file.modified).strftime("%Y-%m-%d %H:%M")
            self.files_table.setItem(row, 2, QTableWidgetItem(modified))
    
    def load_history(self):
        if not self.current_printer_id or self.current_printer_id not in self.clients:
            return
        
        client = self.clients[self.current_printer_id]
        
        async def get_history():
            return await client.get_print_history()
        
        worker = AsyncWorker(get_history())
        worker.finished.connect(self.update_history_display)
        worker.start()
        
        if not hasattr(self, '_workers'):
            self._workers = []
        self._workers.append(worker)
    
    def update_history_display(self, jobs: list):
        self.history_table.setRowCount(0)
        for job in jobs:
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)
            self.history_table.setItem(row, 0, QTableWidgetItem(job.filename))
            self.history_table.setItem(row, 1, QTableWidgetItem(job.status))
            duration = f"{job.print_duration / 60:.1f} min"
            self.history_table.setItem(row, 2, QTableWidgetItem(duration))
            filament = f"{job.filament_used / 1000:.2f} m"
            self.history_table.setItem(row, 3, QTableWidgetItem(filament))
            date = job.start_time.strftime("%Y-%m-%d %H:%M")
            self.history_table.setItem(row, 4, QTableWidgetItem(date))
    
    def start_selected_print(self):
        selected = self.files_table.selectedItems()
        if not selected:
            return
        
        row = selected[0].row()
        filename = self.files_table.item(row, 0).text()
        
        reply = QMessageBox.question(
            self, "Start Print",
            f"Start printing {filename}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.start_print(filename)
    
    def start_print(self, filename: str):
        if not self.current_printer_id or self.current_printer_id not in self.clients:
            return
        
        client = self.clients[self.current_printer_id]
        
        async def start():
            return await client.start_print(filename)
        
        worker = AsyncWorker(start())
        worker.start()
        
        if not hasattr(self, '_workers'):
            self._workers = []
        self._workers.append(worker)
    
    def pause_print(self):
        if not self.current_printer_id or self.current_printer_id not in self.clients:
            return
        client = self.clients[self.current_printer_id]
        worker = AsyncWorker(client.pause_print())
        worker.start()
        if not hasattr(self, '_workers'):
            self._workers = []
        self._workers.append(worker)
    
    def resume_print(self):
        if not self.current_printer_id or self.current_printer_id not in self.clients:
            return
        client = self.clients[self.current_printer_id]
        worker = AsyncWorker(client.resume_print())
        worker.start()
        if not hasattr(self, '_workers'):
            self._workers = []
        self._workers.append(worker)
    
    def cancel_print(self):
        if not self.current_printer_id or self.current_printer_id not in self.clients:
            return
        
        reply = QMessageBox.question(
            self, "Cancel Print",
            "Are you sure you want to cancel the current print?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            client = self.clients[self.current_printer_id]
            worker = AsyncWorker(client.cancel_print())
            worker.start()
            if not hasattr(self, '_workers'):
                self._workers = []
            self._workers.append(worker)
    
    def set_temperature(self, heater: str, target: float):
        if not self.current_printer_id or self.current_printer_id not in self.clients:
            return
        client = self.clients[self.current_printer_id]
        worker = AsyncWorker(client.set_temperature(heater, target))
        worker.start()
        if not hasattr(self, '_workers'):
            self._workers = []
        self._workers.append(worker)
    
    def send_gcode(self, gcode: str):
        if not self.current_printer_id or self.current_printer_id not in self.clients:
            return
        client = self.clients[self.current_printer_id]
        worker = AsyncWorker(client.send_gcode(gcode))
        worker.start()
        if not hasattr(self, '_workers'):
            self._workers = []
        self._workers.append(worker)
    
    def emergency_stop(self):
        if not self.current_printer_id or self.current_printer_id not in self.clients:
            return
        client = self.clients[self.current_printer_id]
        worker = AsyncWorker(client.emergency_stop())
        worker.start()
        if not hasattr(self, '_workers'):
            self._workers = []
        self._workers.append(worker)


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main entry point"""
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    
    app = QApplication(sys.argv)
    app.setApplicationName("KlipperBuddy")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("KlipperBuddy")
    app.setStyle("Fusion")
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
