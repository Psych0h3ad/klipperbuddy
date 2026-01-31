"""
KlipperBuddy v3 - Cyberpunk-style Desktop Dashboard for Klipper Printers
Inspired by Bambuddy (https://github.com/maziggy/bambuddy)

Design: Black theme with Tiffany Blue (#0ABAB5) accents
Font: Play (OFL License) for UI, ToaHI for title logo (image)
"""

import sys
import os
import json
import asyncio
import socket
import time
import webbrowser
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Deque
from pathlib import Path
from collections import deque
from concurrent.futures import ThreadPoolExecutor

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QPushButton, QLineEdit, QDialog, QDialogButtonBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox, QProgressBar,
    QMessageBox, QFrame, QScrollArea, QSpinBox, QFormLayout, QGraphicsDropShadowEffect,
    QSplitter, QGroupBox, QSizePolicy, QFileDialog
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QRect, QPoint, QMargins
from PyQt6.QtGui import (
    QFont, QColor, QPalette, QLinearGradient, QPainter, QBrush, QPen,
    QFontDatabase, QPixmap, QPainterPath, QPaintEvent, QIcon
)

import aiohttp
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# =============================================================================
# Resource Path Helper (for PyInstaller)
# =============================================================================

def resource_path(relative_path: str) -> str:
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)


# =============================================================================
# Color Scheme - Cyberpunk with Tiffany Blue
# =============================================================================
COLORS = {
    'bg_dark': '#0a0a0a',
    'bg_card': '#141414',
    'bg_card_hover': '#1a1a1a',
    'accent': '#0ABAB5',  # Tiffany Blue
    'accent_dark': '#088F8B',
    'accent_glow': '#0ABAB5',
    'text_primary': '#ffffff',
    'text_secondary': '#888888',
    'text_muted': '#555555',
    'success': '#00ff88',
    'warning': '#ffaa00',
    'error': '#ff4444',
    'border': '#2a2a2a',
    'progress_bg': '#1a1a1a',
    'temp_hotend': '#ff6b6b',
    'temp_bed': '#ffa94d',
    'temp_chamber': '#74c0fc',
}

STYLESHEET = f"""
QMainWindow, QDialog {{
    background-color: {COLORS['bg_dark']};
}}

QWidget {{
    color: {COLORS['text_primary']};
}}

QLabel {{
    color: {COLORS['text_primary']};
}}

QPushButton {{
    background-color: {COLORS['bg_card']};
    color: {COLORS['accent']};
    border: 1px solid {COLORS['accent']};
    border-radius: 4px;
    padding: 8px 16px;
    font-weight: bold;
}}

QPushButton:hover {{
    background-color: {COLORS['accent']};
    color: {COLORS['bg_dark']};
}}

QPushButton:pressed {{
    background-color: {COLORS['accent_dark']};
}}

QPushButton:disabled {{
    background-color: {COLORS['bg_card']};
    color: {COLORS['text_muted']};
    border-color: {COLORS['text_muted']};
}}

QLineEdit, QSpinBox {{
    background-color: {COLORS['bg_card']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
    border-radius: 4px;
    padding: 8px;
}}

QLineEdit:focus, QSpinBox:focus {{
    border-color: {COLORS['accent']};
}}

QProgressBar {{
    background-color: {COLORS['progress_bg']};
    border: none;
    border-radius: 4px;
    height: 8px;
    text-align: center;
}}

QProgressBar::chunk {{
    background-color: {COLORS['accent']};
    border-radius: 4px;
}}

QScrollArea {{
    background-color: transparent;
    border: none;
}}

QScrollBar:vertical {{
    background-color: {COLORS['bg_dark']};
    width: 8px;
    border-radius: 4px;
}}

QScrollBar::handle:vertical {{
    background-color: {COLORS['accent']};
    border-radius: 4px;
    min-height: 20px;
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QTableWidget {{
    background-color: {COLORS['bg_card']};
    gridline-color: {COLORS['border']};
    border: 1px solid {COLORS['border']};
    border-radius: 4px;
}}

QTableWidget::item {{
    padding: 8px;
}}

QTableWidget::item:selected {{
    background-color: {COLORS['accent']};
    color: {COLORS['bg_dark']};
}}

QHeaderView::section {{
    background-color: {COLORS['bg_dark']};
    color: {COLORS['accent']};
    padding: 8px;
    border: none;
    border-bottom: 1px solid {COLORS['accent']};
    font-weight: bold;
}}

QCheckBox {{
    color: {COLORS['text_primary']};
}}

QCheckBox::indicator {{
    width: 18px;
    height: 18px;
    border: 1px solid {COLORS['accent']};
    border-radius: 3px;
    background-color: {COLORS['bg_card']};
}}

QCheckBox::indicator:checked {{
    background-color: {COLORS['accent']};
}}

QMessageBox {{
    background-color: {COLORS['bg_dark']};
}}

QGroupBox {{
    background-color: {COLORS['bg_card']};
    border: 1px solid {COLORS['border']};
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 8px;
}}

QGroupBox::title {{
    color: {COLORS['accent']};
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
}}

QSplitter::handle {{
    background-color: {COLORS['border']};
}}
"""


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class PrinterStatus:
    state: str = "offline"
    state_message: str = ""
    extruder_temp: float = 0.0
    extruder_target: float = 0.0
    bed_temp: float = 0.0
    bed_target: float = 0.0
    chamber_temp: float = 0.0
    progress: float = 0.0
    filename: str = ""
    print_duration: float = 0.0
    eta_seconds: float = 0.0
    software_version: str = ""
    last_update: float = 0.0


@dataclass
class PrinterStats:
    total_print_time: float = 0.0  # seconds
    total_filament: float = 0.0  # mm
    total_jobs: int = 0
    completed_jobs: int = 0


@dataclass
class SystemInfo:
    klipper_version: str = ""
    moonraker_version: str = ""
    os_info: str = ""
    disk_total: int = 0  # bytes
    disk_used: int = 0  # bytes
    disk_free: int = 0  # bytes
    cpu_temp: float = 0.0
    webcam_url: str = ""


@dataclass
class PrinterConfig:
    name: str = ""
    host: str = ""
    port: int = 7125
    api_key: str = ""
    username: str = ""
    password: str = ""
    enabled: bool = True


# =============================================================================
# Configuration Manager
# =============================================================================

class ConfigManager:
    def __init__(self):
        self.config_dir = Path.home() / ".klipperbuddy"
        self.config_file = self.config_dir / "config.json"
        self.key_file = self.config_dir / ".key"
        self.printers: List[PrinterConfig] = []
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self._fernet = self._get_fernet()
        self.load()
    
    def _get_fernet(self) -> Fernet:
        """Get or create encryption key"""
        if self.key_file.exists():
            with open(self.key_file, 'rb') as f:
                key = f.read()
        else:
            # Generate a key based on machine-specific data
            salt = b'klipperbuddy_salt_v1'
            machine_id = (socket.gethostname() + str(Path.home())).encode()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(machine_id))
            with open(self.key_file, 'wb') as f:
                f.write(key)
            # Make key file readable only by owner
            try:
                os.chmod(self.key_file, 0o600)
            except:
                pass
        return Fernet(key)
    
    def _encrypt(self, text: str) -> str:
        """Encrypt sensitive data"""
        if not text:
            return ""
        return self._fernet.encrypt(text.encode()).decode()
    
    def _decrypt(self, encrypted: str) -> str:
        """Decrypt sensitive data"""
        if not encrypted:
            return ""
        try:
            return self._fernet.decrypt(encrypted.encode()).decode()
        except:
            return encrypted  # Return as-is if decryption fails (legacy plain text)
    
    def load(self):
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    self.printers = []
                    for p in data.get('printers', []):
                        # Decrypt sensitive fields
                        if 'password' in p and p['password']:
                            p['password'] = self._decrypt(p['password'])
                        if 'api_key' in p and p['api_key']:
                            p['api_key'] = self._decrypt(p['api_key'])
                        self.printers.append(PrinterConfig(**p))
            except:
                self.printers = []
    
    def save(self):
        printers_data = []
        for p in self.printers:
            p_dict = vars(p).copy()
            # Encrypt sensitive fields
            if p_dict.get('password'):
                p_dict['password'] = self._encrypt(p_dict['password'])
            if p_dict.get('api_key'):
                p_dict['api_key'] = self._encrypt(p_dict['api_key'])
            printers_data.append(p_dict)
        data = {'printers': printers_data}
        with open(self.config_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def add_printer(self, printer: PrinterConfig) -> bool:
        for p in self.printers:
            if p.host == printer.host and p.port == printer.port:
                return False
        self.printers.append(printer)
        self.save()
        return True
    
    def remove_printer(self, host: str, port: int):
        self.printers = [p for p in self.printers if not (p.host == host and p.port == port)]
        self.save()
    
    def get_setting(self, key: str, default=None):
        """Get a setting value"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    return data.get('settings', {}).get(key, default)
            except:
                pass
        return default
    
    def set_setting(self, key: str, value):
        """Set a setting value"""
        data = {}
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
            except:
                pass
        
        if 'settings' not in data:
            data['settings'] = {}
        data['settings'][key] = value
        
        # Preserve printers data
        printers_data = []
        for p in self.printers:
            p_dict = vars(p).copy()
            if p_dict.get('password'):
                p_dict['password'] = self._encrypt(p_dict['password'])
            if p_dict.get('api_key'):
                p_dict['api_key'] = self._encrypt(p_dict['api_key'])
            printers_data.append(p_dict)
        data['printers'] = printers_data
        
        with open(self.config_file, 'w') as f:
            json.dump(data, f, indent=2)


# =============================================================================
# Moonraker API Client
# =============================================================================

class MoonrakerClient:
    def __init__(self, host: str, port: int = 7125, api_key: str = "", 
                 username: str = "", password: str = ""):
        self.host = host
        self.port = port
        self.api_key = api_key
        self.username = username
        self.password = password
        self.base_url = f"http://{host}:{port}"
        self._session: Optional[aiohttp.ClientSession] = None
        self._token: Optional[str] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            headers = {}
            if self.api_key:
                headers['X-Api-Key'] = self.api_key
            if self._token:
                headers['Authorization'] = f'Bearer {self._token}'
            self._session = aiohttp.ClientSession(headers=headers)
        return self._session
    
    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
    
    async def _request(self, method: str, endpoint: str, **kwargs) -> Optional[Dict]:
        try:
            session = await self._get_session()
            url = f"{self.base_url}{endpoint}"
            async with session.request(method, url, timeout=aiohttp.ClientTimeout(total=5), **kwargs) as resp:
                if resp.status == 200:
                    return await resp.json()
                elif resp.status == 401 and self.username and self.password:
                    if await self._authenticate():
                        return await self._request(method, endpoint, **kwargs)
        except:
            pass
        return None
    
    async def _authenticate(self) -> bool:
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/access/login"
                data = {"username": self.username, "password": self.password}
                async with session.post(url, json=data, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        result = await resp.json()
                        self._token = result.get('result', {}).get('token')
                        if self._token:
                            if self._session:
                                await self._session.close()
                            self._session = None
                            return True
        except:
            pass
        return False
    
    async def get_printer_info(self) -> Optional[Dict]:
        return await self._request('GET', '/printer/info')
    
    async def get_printer_name(self) -> str:
        """Get the best available printer name"""
        # Try Fluidd config first
        try:
            resp = await self._request('GET', '/server/database/item?namespace=fluidd&key=uiSettings')
            if resp and 'result' in resp:
                value = resp['result'].get('value', {})
                if isinstance(value, dict):
                    name = value.get('general', {}).get('instanceName')
                    if name:
                        return name
        except:
            pass
        
        # Try Mainsail config
        try:
            resp = await self._request('GET', '/server/database/item?namespace=mainsail&key=general')
            if resp and 'result' in resp:
                value = resp['result'].get('value', {})
                if isinstance(value, dict):
                    name = value.get('instanceName')
                    if name:
                        return name
        except:
            pass
        
        # Fall back to hostname from printer info
        info = await self.get_printer_info()
        if info and 'result' in info:
            hostname = info['result'].get('hostname', '')
            if hostname:
                return hostname
        
        return self.host
    
    async def get_status(self) -> PrinterStatus:
        status = PrinterStatus()
        status.last_update = time.time()
        
        info = await self.get_printer_info()
        if not info or 'result' not in info:
            status.state = 'offline'
            return status
        
        result = info['result']
        status.state = result.get('state', 'unknown')
        status.state_message = result.get('state_message', '')
        status.software_version = result.get('software_version', '')
        
        # Get printer objects
        objects_resp = await self._request('GET', 
            '/printer/objects/query?extruder&heater_bed&print_stats&display_status&'
            'heater_generic%20chamber_heater&temperature_sensor%20chamber')
        
        if objects_resp and 'result' in objects_resp:
            data = objects_resp['result'].get('status', {})
            
            ext = data.get('extruder', {})
            status.extruder_temp = ext.get('temperature', 0.0)
            status.extruder_target = ext.get('target', 0.0)
            
            bed = data.get('heater_bed', {})
            status.bed_temp = bed.get('temperature', 0.0)
            status.bed_target = bed.get('target', 0.0)
            
            chamber = data.get('heater_generic chamber_heater', data.get('temperature_sensor chamber', {}))
            status.chamber_temp = chamber.get('temperature', 0.0)
            
            ps = data.get('print_stats', {})
            ps_state = ps.get('state', '')
            if ps_state == 'printing':
                status.state = 'printing'
            elif ps_state == 'paused':
                status.state = 'paused'
            
            status.filename = ps.get('filename', '')
            status.print_duration = ps.get('print_duration', 0.0)
            
            display = data.get('display_status', {})
            status.progress = display.get('progress', 0.0) * 100
            
            if status.progress > 0 and status.print_duration > 0:
                total_est = status.print_duration / (status.progress / 100)
                status.eta_seconds = total_est - status.print_duration
        
        return status
    
    async def get_print_stats(self) -> PrinterStats:
        """Get print history statistics"""
        stats = PrinterStats()
        
        try:
            resp = await self._request('GET', '/server/history/totals')
            if resp and 'result' in resp:
                totals = resp['result'].get('job_totals', {})
                stats.total_print_time = totals.get('total_time', 0.0)
                stats.total_filament = totals.get('total_filament_used', 0.0)
                stats.total_jobs = totals.get('total_jobs', 0)
                stats.completed_jobs = totals.get('total_jobs', 0) - totals.get('total_failed', 0)
        except:
            pass
        
        return stats
    
    async def get_system_info(self) -> SystemInfo:
        """Get system information"""
        info = SystemInfo()
        
        # Get Moonraker version
        try:
            resp = await self._request('GET', '/server/info')
            if resp and 'result' in resp:
                info.moonraker_version = resp['result'].get('moonraker_version', '')
        except:
            pass
        
        # Get Klipper version from printer info
        try:
            resp = await self._request('GET', '/printer/info')
            if resp and 'result' in resp:
                info.klipper_version = resp['result'].get('software_version', '')
        except:
            pass
        
        # Get system info (OS, CPU temp)
        try:
            resp = await self._request('GET', '/machine/system_info')
            if resp and 'result' in resp:
                sys_info = resp['result'].get('system_info', {})
                
                # OS info
                distro = sys_info.get('distribution', {})
                info.os_info = f"{distro.get('name', '')} {distro.get('version', '')}".strip()
                
                # CPU temp
                cpu_temp = sys_info.get('cpu_info', {}).get('cpu_temp')
                if cpu_temp:
                    info.cpu_temp = cpu_temp
        except:
            pass
        
        # Get disk usage
        try:
            resp = await self._request('GET', '/server/files/roots')
            if resp and 'result' in resp:
                for root in resp['result']:
                    if root.get('name') == 'gcodes':
                        info.disk_total = root.get('disk_total', 0)
                        info.disk_used = root.get('disk_used', 0)
                        info.disk_free = root.get('disk_free', 0)
                        break
        except:
            pass
        
        # Get webcam URL
        try:
            resp = await self._request('GET', '/server/webcams/list')
            if resp and 'result' in resp:
                webcams = resp['result'].get('webcams', [])
                if webcams:
                    cam = webcams[0]
                    stream_url = cam.get('stream_url', '')
                    if stream_url:
                        if stream_url.startswith('/'):
                            info.webcam_url = f"http://{self.host}{stream_url}"
                        else:
                            info.webcam_url = stream_url
        except:
            pass
        
        return info
    
    async def check_auth_required(self) -> bool:
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/printer/info"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                    return resp.status == 401
        except:
            return False
    
    async def send_gcode(self, gcode: str) -> bool:
        """Send G-code command to printer"""
        try:
            resp = await self._request('POST', '/printer/gcode/script', json={'script': gcode})
            return resp is not None
        except:
            return False
    
    async def get_input_shaper_data(self) -> Optional[Dict]:
        """Get Input Shaper configuration and recommendations"""
        try:
            resp = await self._request('GET', '/printer/objects/query?input_shaper&configfile')
            if resp and 'result' in resp:
                data = resp['result'].get('status', {})
                shaper = data.get('input_shaper', {})
                config = data.get('configfile', {}).get('settings', {})
                
                return {
                    'shaper_type_x': shaper.get('shaper_type_x', ''),
                    'shaper_freq_x': shaper.get('shaper_freq_x', 0),
                    'shaper_type_y': shaper.get('shaper_type_y', ''),
                    'shaper_freq_y': shaper.get('shaper_freq_y', 0),
                    'damping_ratio_x': shaper.get('damping_ratio_x', 0.1),
                    'damping_ratio_y': shaper.get('damping_ratio_y', 0.1),
                    'config': config.get('input_shaper', {})
                }
        except:
            pass
        return None


# =============================================================================
# Network Scanner
# =============================================================================

class NetworkScanner:
    @staticmethod
    def get_local_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "192.168.1.1"
    
    @staticmethod
    def get_network_range() -> List[str]:
        local_ip = NetworkScanner.get_local_ip()
        base = '.'.join(local_ip.split('.')[:-1])
        return [f"{base}.{i}" for i in range(1, 255)]
    
    @staticmethod
    async def check_moonraker(host: str, port: int = 7125) -> Optional[Dict]:
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://{host}:{port}/printer/info"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=1)) as resp:
                    if resp.status in [200, 401]:
                        auth_required = resp.status == 401
                        if resp.status == 200:
                            data = await resp.json()
                            hostname = data.get('result', {}).get('hostname', host)
                        else:
                            hostname = host
                        return {
                            'host': host,
                            'port': port,
                            'hostname': hostname,
                            'auth_required': auth_required
                        }
        except:
            pass
        return None
    
    @staticmethod
    async def scan_network_parallel(progress_callback=None) -> List[Dict]:
        """Scan network in parallel for much faster discovery"""
        hosts = NetworkScanner.get_network_range()
        results = []
        total = len(hosts)
        completed = 0
        
        # Create semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(50)
        
        async def check_with_semaphore(host: str) -> Optional[Dict]:
            nonlocal completed
            async with semaphore:
                result = await NetworkScanner.check_moonraker(host)
                completed += 1
                if progress_callback:
                    progress_callback(int(completed / total * 100))
                return result
        
        # Run all checks in parallel
        tasks = [check_with_semaphore(host) for host in hosts]
        check_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter successful results
        for result in check_results:
            if result and isinstance(result, dict):
                results.append(result)
        
        return results


# =============================================================================
# Async Worker Thread
# =============================================================================

class AsyncWorker(QThread):
    finished = pyqtSignal(object)
    
    def __init__(self, coro):
        super().__init__()
        self.coro = coro
    
    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(self.coro)
            self.finished.emit(result)
        finally:
            loop.close()


# =============================================================================
# Temperature Chart Widget (Custom QPainter implementation - no QtCharts needed)
# =============================================================================

class TemperatureChart(QWidget):
    """Real-time temperature chart with cyberpunk styling using QPainter"""
    
    MAX_POINTS = 60  # 60 data points (3 seconds * 60 = 3 minutes of data)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(180)
        
        self.hotend_data: deque = deque(maxlen=self.MAX_POINTS)
        self.bed_data: deque = deque(maxlen=self.MAX_POINTS)
        self.chamber_data: deque = deque(maxlen=self.MAX_POINTS)
        
        self.max_temp = 300
    
    def add_data(self, hotend: float, bed: float, chamber: float):
        self.hotend_data.append(hotend)
        self.bed_data.append(bed)
        self.chamber_data.append(chamber)
        
        # Auto-scale
        all_temps = list(self.hotend_data) + list(self.bed_data) + list(self.chamber_data)
        if all_temps:
            self.max_temp = max(300, max(all_temps) + 20)
        
        self.update()
    
    def clear_data(self):
        self.hotend_data.clear()
        self.bed_data.clear()
        self.chamber_data.clear()
        self.update()
    
    def paintEvent(self, event: QPaintEvent):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Background
        painter.fillRect(self.rect(), QColor(COLORS['bg_card']))
        
        # Chart area
        margin = 40
        chart_rect = QRect(margin, 10, self.width() - margin - 10, self.height() - 30)
        
        # Draw grid
        painter.setPen(QPen(QColor(COLORS['border']), 1))
        for i in range(5):
            y = chart_rect.top() + (chart_rect.height() * i // 4)
            painter.drawLine(chart_rect.left(), y, chart_rect.right(), y)
        
        # Draw Y axis labels
        painter.setPen(QPen(QColor(COLORS['text_secondary']), 1))
        painter.setFont(QFont("Play", 8))
        for i in range(5):
            y = chart_rect.top() + (chart_rect.height() * i // 4)
            temp = int(self.max_temp * (4 - i) / 4)
            painter.drawText(5, y + 4, f"{temp}°C")
        
        # Draw data lines
        def draw_line(data: deque, color: str):
            if len(data) < 2:
                return
            
            pen = QPen(QColor(color), 2)
            painter.setPen(pen)
            
            path = QPainterPath()
            for i, temp in enumerate(data):
                x = chart_rect.left() + (chart_rect.width() * i // (self.MAX_POINTS - 1))
                y = chart_rect.bottom() - (chart_rect.height() * temp / self.max_temp)
                
                if i == 0:
                    path.moveTo(x, y)
                else:
                    path.lineTo(x, y)
            
            painter.drawPath(path)
        
        draw_line(self.hotend_data, COLORS['temp_hotend'])
        draw_line(self.bed_data, COLORS['temp_bed'])
        draw_line(self.chamber_data, COLORS['temp_chamber'])
        
        # Legend - positioned below the chart with proper spacing
        legend_y = self.height() - 12
        painter.setFont(QFont("Play", 8))
        
        # Calculate positions to spread evenly
        legend_start = margin
        spacing = 80
        
        painter.setPen(QPen(QColor(COLORS['temp_hotend']), 2))
        painter.drawLine(legend_start, legend_y, legend_start + 15, legend_y)
        painter.setPen(QColor(COLORS['text_secondary']))
        painter.drawText(legend_start + 18, legend_y + 4, "Hotend")
        
        painter.setPen(QPen(QColor(COLORS['temp_bed']), 2))
        painter.drawLine(legend_start + spacing, legend_y, legend_start + spacing + 15, legend_y)
        painter.setPen(QColor(COLORS['text_secondary']))
        painter.drawText(legend_start + spacing + 18, legend_y + 4, "Bed")
        
        painter.setPen(QPen(QColor(COLORS['temp_chamber']), 2))
        painter.drawLine(legend_start + spacing * 2, legend_y, legend_start + spacing * 2 + 15, legend_y)
        painter.setPen(QColor(COLORS['text_secondary']))
        painter.drawText(legend_start + spacing * 2 + 18, legend_y + 4, "Chamber")


# =============================================================================
# Printer Card Widget
# =============================================================================

class PrinterCard(QFrame):
    """Cyberpunk-style printer status card"""
    
    camera_clicked = pyqtSignal(str)  # webcam_url
    card_clicked = pyqtSignal(object)  # self - emitted when card is clicked
    
    def __init__(self, config: PrinterConfig, parent=None):
        super().__init__(parent)
        self.config = config
        self.status = PrinterStatus()
        self.stats = PrinterStats()
        self.system_info = SystemInfo()
        self.client: Optional[MoonrakerClient] = None
        self._selected = False
        self._setup_ui()
        self._apply_style()
    
    def _setup_ui(self):
        self.setFixedSize(340, 320)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)
        
        # Header with name and status indicator
        header = QHBoxLayout()
        
        self.status_indicator = QLabel("●")
        self.status_indicator.setFont(QFont("Arial", 12))
        header.addWidget(self.status_indicator)
        
        self.name_label = QLabel(self.config.name or self.config.host)
        self.name_label.setFont(QFont("Play", 14, QFont.Weight.Bold))
        self.name_label.setStyleSheet(f"color: {COLORS['accent']};")
        header.addWidget(self.name_label)
        header.addStretch()
        
        self.state_label = QLabel("OFFLINE")
        self.state_label.setFont(QFont("Play", 10, QFont.Weight.Bold))
        header.addWidget(self.state_label)
        
        layout.addLayout(header)
        
        # Separator line
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet(f"background-color: {COLORS['accent']}; max-height: 1px;")
        layout.addWidget(line)
        
        # Temperature section
        temp_layout = QGridLayout()
        temp_layout.setSpacing(4)
        
        # Extruder
        ext_icon = QLabel()
        ext_icon_path = resource_path("icons/icon_hotend.png")
        if os.path.exists(ext_icon_path):
            ext_pixmap = QPixmap(ext_icon_path).scaled(20, 20, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            ext_icon.setPixmap(ext_pixmap)
        else:
            ext_icon.setText("🔥")
            ext_icon.setFont(QFont("Segoe UI Emoji", 14))
        ext_icon.setFixedSize(24, 24)
        temp_layout.addWidget(ext_icon, 0, 0)
        
        ext_label = QLabel("Extruder")
        ext_label.setFont(QFont("Play", 10))
        ext_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        temp_layout.addWidget(ext_label, 0, 1)
        
        self.ext_temp_label = QLabel("--°C / --°C")
        self.ext_temp_label.setFont(QFont("Play", 11))
        self.ext_temp_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        temp_layout.addWidget(self.ext_temp_label, 0, 2)
        
        # Bed
        bed_icon = QLabel()
        bed_icon_path = resource_path("icons/icon_bed.png")
        if os.path.exists(bed_icon_path):
            bed_pixmap = QPixmap(bed_icon_path).scaled(20, 20, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            bed_icon.setPixmap(bed_pixmap)
        else:
            bed_icon.setText("🛏️")
            bed_icon.setFont(QFont("Segoe UI Emoji", 14))
        bed_icon.setFixedSize(24, 24)
        temp_layout.addWidget(bed_icon, 1, 0)
        
        bed_label = QLabel("Bed")
        bed_label.setFont(QFont("Play", 10))
        bed_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        temp_layout.addWidget(bed_label, 1, 1)
        
        self.bed_temp_label = QLabel("--°C / --°C")
        self.bed_temp_label.setFont(QFont("Play", 11))
        self.bed_temp_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        temp_layout.addWidget(self.bed_temp_label, 1, 2)
        
        # Chamber
        chamber_icon = QLabel()
        chamber_icon_path = resource_path("icons/icon_chamber.png")
        if os.path.exists(chamber_icon_path):
            chamber_pixmap = QPixmap(chamber_icon_path).scaled(20, 20, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            chamber_icon.setPixmap(chamber_pixmap)
        else:
            chamber_icon.setText("📦")
            chamber_icon.setFont(QFont("Segoe UI Emoji", 14))
        chamber_icon.setFixedSize(24, 24)
        temp_layout.addWidget(chamber_icon, 2, 0)
        
        chamber_label = QLabel("Chamber")
        chamber_label.setFont(QFont("Play", 10))
        chamber_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        temp_layout.addWidget(chamber_label, 2, 1)
        
        self.chamber_temp_label = QLabel("--°C")
        self.chamber_temp_label.setFont(QFont("Play", 11))
        self.chamber_temp_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        temp_layout.addWidget(self.chamber_temp_label, 2, 2)
        
        layout.addLayout(temp_layout)
        
        # Print progress section
        layout.addSpacing(8)
        
        self.filename_label = QLabel("No active print")
        self.filename_label.setFont(QFont("Play", 10))
        self.filename_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        self.filename_label.setWordWrap(True)
        layout.addWidget(self.filename_label)
        
        # Progress bar
        progress_container = QHBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(8)
        progress_container.addWidget(self.progress_bar)
        
        self.progress_label = QLabel("0%")
        self.progress_label.setFont(QFont("Play", 11, QFont.Weight.Bold))
        self.progress_label.setStyleSheet(f"color: {COLORS['accent']};")
        self.progress_label.setFixedWidth(45)
        self.progress_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        progress_container.addWidget(self.progress_label)
        
        layout.addLayout(progress_container)
        
        # ETA
        self.eta_label = QLabel("ETA: --:--:--")
        self.eta_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        self.eta_label.setFont(QFont("Play", 10))
        layout.addWidget(self.eta_label)
        
        layout.addStretch()
        
        # Action buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)
        
        self.camera_btn = QPushButton()
        camera_icon_path = resource_path("icons/icon_camera.png")
        if os.path.exists(camera_icon_path):
            self.camera_btn.setIcon(QIcon(camera_icon_path))
        else:
            self.camera_btn.setText("📷")
        self.camera_btn.setFixedSize(40, 32)
        self.camera_btn.setToolTip("View Camera")
        self.camera_btn.clicked.connect(self._on_camera_click)
        btn_layout.addWidget(self.camera_btn)
        
        self.graph_btn = QPushButton()
        graph_icon_path = resource_path("icons/icon_graph.png")
        if os.path.exists(graph_icon_path):
            self.graph_btn.setIcon(QIcon(graph_icon_path))
        else:
            self.graph_btn.setText("📈")
        self.graph_btn.setFixedSize(40, 32)
        self.graph_btn.setToolTip("Temperature Graph")
        self.graph_btn.clicked.connect(self._on_graph_click)
        btn_layout.addWidget(self.graph_btn)
        
        self.web_btn = QPushButton("🌐")
        self.web_btn.setFixedSize(40, 32)
        self.web_btn.setToolTip("Open Web Interface")
        self.web_btn.clicked.connect(self._on_web_click)
        btn_layout.addWidget(self.web_btn)
        
        btn_layout.addStretch()
        
        layout.addLayout(btn_layout)
        
        # Host info
        self.host_label = QLabel(f"{self.config.host}:{self.config.port}")
        self.host_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 9px;")
        layout.addWidget(self.host_label)
    
    def _apply_style(self, selected: bool = False):
        if selected:
            self.setStyleSheet(f"""
                PrinterCard {{
                    background-color: {COLORS['bg_card']};
                    border: 2px solid {COLORS['accent']};
                    border-radius: 8px;
                }}
            """)
            shadow = QGraphicsDropShadowEffect()
            shadow.setBlurRadius(25)
            shadow.setColor(QColor(COLORS['accent']))
            shadow.setOffset(0, 0)
            self.setGraphicsEffect(shadow)
        else:
            self.setStyleSheet(f"""
                PrinterCard {{
                    background-color: {COLORS['bg_card']};
                    border: 1px solid {COLORS['border']};
                    border-radius: 8px;
                }}
                PrinterCard:hover {{
                    border-color: {COLORS['accent']};
                }}
            """)
            shadow = QGraphicsDropShadowEffect()
            shadow.setBlurRadius(15)
            shadow.setColor(QColor(COLORS['accent']))
            shadow.setOffset(0, 0)
            self.setGraphicsEffect(shadow)
    
    def set_selected(self, selected: bool):
        self._selected = selected
        self._apply_style(selected)
    
    def mousePressEvent(self, event):
        """Handle card click to select this printer"""
        self.card_clicked.emit(self)
        super().mousePressEvent(event)
    
    def _on_camera_click(self):
        if self.system_info.webcam_url:
            self.camera_clicked.emit(self.system_info.webcam_url)
        else:
            # Try to open default webcam URL
            url = f"http://{self.config.host}/webcam/?action=stream"
            self.camera_clicked.emit(url)
    
    def _on_graph_click(self):
        self.card_clicked.emit(self)
    
    def _on_web_click(self):
        url = f"http://{self.config.host}"
        webbrowser.open(url)
    
    def update_status(self, status: PrinterStatus):
        self.status = status
        
        # Update state indicator
        state_colors = {
            'ready': COLORS['success'],
            'printing': COLORS['accent'],
            'paused': COLORS['warning'],
            'error': COLORS['error'],
            'offline': COLORS['text_muted'],
        }
        color = state_colors.get(status.state, COLORS['text_muted'])
        self.status_indicator.setStyleSheet(f"color: {color};")
        self.state_label.setText(status.state.upper())
        self.state_label.setStyleSheet(f"color: {color};")
        
        # Update temperatures
        self.ext_temp_label.setText(f"{status.extruder_temp:.1f}°C / {status.extruder_target:.0f}°C")
        self.bed_temp_label.setText(f"{status.bed_temp:.1f}°C / {status.bed_target:.0f}°C")
        self.chamber_temp_label.setText(f"{status.chamber_temp:.1f}°C" if status.chamber_temp > 0 else "--°C")
        
        # Update print info
        if status.filename:
            # Truncate filename if too long
            fn = status.filename
            if len(fn) > 35:
                fn = fn[:32] + "..."
            self.filename_label.setText(fn)
            self.filename_label.setStyleSheet(f"color: {COLORS['text_primary']};")
        else:
            self.filename_label.setText("No active print")
            self.filename_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        
        # Update progress
        self.progress_bar.setValue(int(status.progress))
        self.progress_label.setText(f"{status.progress:.1f}%")
        
        # Update ETA
        if status.eta_seconds > 0:
            hours = int(status.eta_seconds // 3600)
            minutes = int((status.eta_seconds % 3600) // 60)
            seconds = int(status.eta_seconds % 60)
            self.eta_label.setText(f"ETA: {hours:02d}:{minutes:02d}:{seconds:02d}")
        else:
            self.eta_label.setText("ETA: --:--:--")
    
    def update_stats(self, stats: PrinterStats):
        self.stats = stats
    
    def update_system_info(self, info: SystemInfo):
        self.system_info = info
    
    def set_name(self, name: str):
        self.config.name = name
        self.name_label.setText(name)


# =============================================================================
# Statistics Panel Widget
# =============================================================================

class StatsPanel(QFrame):
    """Statistics and system info panel"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        self._apply_style()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)
        
        # Selected printer name
        self.printer_name_label = QLabel("Select a printer")
        self.printer_name_label.setFont(QFont("Play", 14, QFont.Weight.Bold))
        self.printer_name_label.setStyleSheet(f"color: {COLORS['accent']};")
        self.printer_name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.printer_name_label)
        
        # Temperature Graph
        graph_label = QLabel("📈 TEMPERATURE GRAPH")
        graph_label.setFont(QFont("Play", 11, QFont.Weight.Bold))
        graph_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        layout.addWidget(graph_label)
        
        self.temp_chart = TemperatureChart()
        self.temp_chart.setMinimumHeight(150)
        self.temp_chart.setMaximumHeight(150)
        layout.addWidget(self.temp_chart)
        
        # Current temps display
        temp_display = QHBoxLayout()
        
        self.hotend_label = QLabel("Hotend: --°C")
        self.hotend_label.setFont(QFont("Play", 10))
        self.hotend_label.setStyleSheet(f"color: {COLORS['temp_hotend']};")
        temp_display.addWidget(self.hotend_label)
        
        self.bed_label = QLabel("Bed: --°C")
        self.bed_label.setFont(QFont("Play", 10))
        self.bed_label.setStyleSheet(f"color: {COLORS['temp_bed']};")
        temp_display.addWidget(self.bed_label)
        
        self.chamber_label = QLabel("Chamber: --°C")
        self.chamber_label.setFont(QFont("Play", 10))
        self.chamber_label.setStyleSheet(f"color: {COLORS['temp_chamber']};")
        temp_display.addWidget(self.chamber_label)
        
        layout.addLayout(temp_display)
        
        # Separator
        line1 = QFrame()
        line1.setFrameShape(QFrame.Shape.HLine)
        line1.setStyleSheet(f"background-color: {COLORS['border']}; max-height: 1px;")
        layout.addWidget(line1)
        
        # Camera Preview section
        cam_label = QLabel("📷 CAMERA PREVIEW")
        cam_label.setFont(QFont("Play", 11, QFont.Weight.Bold))
        cam_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        layout.addWidget(cam_label)
        
        self.camera_frame = QFrame()
        self.camera_frame.setFixedHeight(140)
        self.camera_frame.setStyleSheet(f"""
            background-color: {COLORS['bg_dark']};
            border: 1px solid {COLORS['border']};
            border-radius: 4px;
        """)
        
        cam_layout = QVBoxLayout(self.camera_frame)
        cam_layout.setContentsMargins(4, 4, 4, 4)
        cam_layout.setSpacing(4)
        
        self.camera_image = QLabel()
        self.camera_image.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.camera_image.setStyleSheet(f"color: {COLORS['text_muted']};")
        self.camera_image.setFont(QFont("Play", 9))
        self.camera_image.setText("Click a printer to view camera")
        self.camera_image.setMinimumHeight(90)
        cam_layout.addWidget(self.camera_image)
        
        self.open_camera_btn = QPushButton("Open in Browser")
        self.open_camera_btn.setFixedHeight(28)
        self.open_camera_btn.setEnabled(False)
        self.open_camera_btn.clicked.connect(self._open_camera)
        cam_layout.addWidget(self.open_camera_btn)
        
        layout.addWidget(self.camera_frame)
        
        self.current_webcam_url = ""
        
        # Camera refresh timer
        self.camera_timer = QTimer()
        self.camera_timer.timeout.connect(self._refresh_camera)
        self._camera_session = None
        
        # Separator
        line2 = QFrame()
        line2.setFrameShape(QFrame.Shape.HLine)
        line2.setStyleSheet(f"background-color: {COLORS['border']}; max-height: 1px;")
        layout.addWidget(line2)
        
        # Statistics section
        stats_label = QLabel("📊 STATISTICS")
        stats_label.setFont(QFont("Play", 12, QFont.Weight.Bold))
        stats_label.setStyleSheet(f"color: {COLORS['accent']};")
        layout.addWidget(stats_label)
        
        stats_grid = QGridLayout()
        stats_grid.setSpacing(8)
        
        # Total Print Time
        stats_grid.addWidget(QLabel("Total Print Time:"), 0, 0)
        self.total_time_label = QLabel("--")
        self.total_time_label.setFont(QFont("Play", 10, QFont.Weight.Bold))
        self.total_time_label.setStyleSheet(f"color: {COLORS['accent']};")
        stats_grid.addWidget(self.total_time_label, 0, 1)
        
        # Total Filament
        stats_grid.addWidget(QLabel("Filament Used:"), 1, 0)
        self.total_filament_label = QLabel("--")
        self.total_filament_label.setFont(QFont("Play", 10, QFont.Weight.Bold))
        self.total_filament_label.setStyleSheet(f"color: {COLORS['accent']};")
        stats_grid.addWidget(self.total_filament_label, 1, 1)
        
        # Print Count
        stats_grid.addWidget(QLabel("Print Count:"), 2, 0)
        self.print_count_label = QLabel("--")
        self.print_count_label.setFont(QFont("Play", 10, QFont.Weight.Bold))
        self.print_count_label.setStyleSheet(f"color: {COLORS['accent']};")
        stats_grid.addWidget(self.print_count_label, 2, 1)
        
        # Success Rate
        stats_grid.addWidget(QLabel("Success Rate:"), 3, 0)
        self.success_rate_label = QLabel("--")
        self.success_rate_label.setFont(QFont("Play", 10, QFont.Weight.Bold))
        self.success_rate_label.setStyleSheet(f"color: {COLORS['success']};")
        stats_grid.addWidget(self.success_rate_label, 3, 1)
        
        layout.addLayout(stats_grid)
        
        # Separator
        line3 = QFrame()
        line3.setFrameShape(QFrame.Shape.HLine)
        line3.setStyleSheet(f"background-color: {COLORS['border']}; max-height: 1px;")
        layout.addWidget(line3)
        
        # System Info section
        sys_label = QLabel("💻 SYSTEM INFO")
        sys_label.setFont(QFont("Play", 12, QFont.Weight.Bold))
        sys_label.setStyleSheet(f"color: {COLORS['accent']};")
        layout.addWidget(sys_label)
        
        sys_grid = QGridLayout()
        sys_grid.setSpacing(4)
        
        sys_grid.addWidget(QLabel("Klipper:"), 0, 0)
        self.klipper_ver_label = QLabel("--")
        self.klipper_ver_label.setFont(QFont("Play", 9))
        sys_grid.addWidget(self.klipper_ver_label, 0, 1)
        
        sys_grid.addWidget(QLabel("Moonraker:"), 1, 0)
        self.moonraker_ver_label = QLabel("--")
        self.moonraker_ver_label.setFont(QFont("Play", 9))
        sys_grid.addWidget(self.moonraker_ver_label, 1, 1)
        
        sys_grid.addWidget(QLabel("OS:"), 2, 0)
        self.os_label = QLabel("--")
        self.os_label.setFont(QFont("Play", 9))
        sys_grid.addWidget(self.os_label, 2, 1)
        
        layout.addLayout(sys_grid)
        
        # Disk usage
        disk_layout = QHBoxLayout()
        disk_layout.addWidget(QLabel("Disk:"))
        self.disk_label = QLabel("-- / --")
        self.disk_label.setFont(QFont("Play", 9))
        disk_layout.addWidget(self.disk_label)
        layout.addLayout(disk_layout)
        
        self.disk_bar = QProgressBar()
        self.disk_bar.setRange(0, 100)
        self.disk_bar.setValue(0)
        self.disk_bar.setFixedHeight(8)
        self.disk_bar.setTextVisible(False)
        layout.addWidget(self.disk_bar)
        
        # Separator
        line4 = QFrame()
        line4.setFrameShape(QFrame.Shape.HLine)
        line4.setStyleSheet(f"background-color: {COLORS['border']}; max-height: 1px;")
        layout.addWidget(line4)
        
        # Tuning Advisor section
        tuning_label = QLabel("🔧 TUNING ADVISOR")
        tuning_label.setFont(QFont("Play", 12, QFont.Weight.Bold))
        tuning_label.setStyleSheet(f"color: {COLORS['accent']};")
        layout.addWidget(tuning_label)
        
        # PID Warning
        self.pid_warning_frame = QFrame()
        self.pid_warning_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_dark']};
                border: 1px solid {COLORS['warning']};
                border-radius: 4px;
                padding: 4px;
            }}
        """)
        self.pid_warning_frame.setVisible(False)
        pid_warning_layout = QVBoxLayout(self.pid_warning_frame)
        pid_warning_layout.setContentsMargins(8, 8, 8, 8)
        pid_warning_layout.setSpacing(4)
        
        self.pid_warning_label = QLabel("⚠️ Temperature fluctuation detected")
        self.pid_warning_label.setFont(QFont("Play", 9))
        self.pid_warning_label.setStyleSheet(f"color: {COLORS['warning']};")
        self.pid_warning_label.setWordWrap(True)
        pid_warning_layout.addWidget(self.pid_warning_label)
        
        pid_btn_layout = QHBoxLayout()
        self.pid_hotend_btn = QPushButton("PID Tune Hotend")
        self.pid_hotend_btn.setFixedHeight(28)
        self.pid_hotend_btn.clicked.connect(lambda: self._run_pid_calibrate('extruder'))
        pid_btn_layout.addWidget(self.pid_hotend_btn)
        
        self.pid_bed_btn = QPushButton("PID Tune Bed")
        self.pid_bed_btn.setFixedHeight(28)
        self.pid_bed_btn.clicked.connect(lambda: self._run_pid_calibrate('heater_bed'))
        pid_btn_layout.addWidget(self.pid_bed_btn)
        pid_warning_layout.addLayout(pid_btn_layout)
        
        layout.addWidget(self.pid_warning_frame)
        
        # Input Shaper section
        self.shaper_frame = QFrame()
        self.shaper_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_dark']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
            }}
        """)
        shaper_layout = QVBoxLayout(self.shaper_frame)
        shaper_layout.setContentsMargins(8, 8, 8, 8)
        shaper_layout.setSpacing(4)
        
        shaper_title = QLabel("Input Shaper")
        shaper_title.setFont(QFont("Play", 10, QFont.Weight.Bold))
        shaper_title.setStyleSheet(f"color: {COLORS['text_secondary']};")
        shaper_layout.addWidget(shaper_title)
        
        shaper_grid = QGridLayout()
        shaper_grid.setSpacing(4)
        
        shaper_grid.addWidget(QLabel("X Axis:"), 0, 0)
        self.shaper_x_label = QLabel("--")
        self.shaper_x_label.setFont(QFont("Play", 9))
        self.shaper_x_label.setStyleSheet(f"color: {COLORS['accent']};")
        shaper_grid.addWidget(self.shaper_x_label, 0, 1)
        
        shaper_grid.addWidget(QLabel("Y Axis:"), 1, 0)
        self.shaper_y_label = QLabel("--")
        self.shaper_y_label.setFont(QFont("Play", 9))
        self.shaper_y_label.setStyleSheet(f"color: {COLORS['accent']};")
        shaper_grid.addWidget(self.shaper_y_label, 1, 1)
        
        shaper_layout.addLayout(shaper_grid)
        
        self.shaper_calibrate_btn = QPushButton("Run SHAPER_CALIBRATE")
        self.shaper_calibrate_btn.setFixedHeight(28)
        self.shaper_calibrate_btn.clicked.connect(self._run_shaper_calibrate)
        self.shaper_calibrate_btn.setEnabled(False)
        shaper_layout.addWidget(self.shaper_calibrate_btn)
        
        layout.addWidget(self.shaper_frame)
        
        # Separator
        line5 = QFrame()
        line5.setFrameShape(QFrame.Shape.HLine)
        line5.setStyleSheet(f"background-color: {COLORS['border']}; max-height: 1px;")
        layout.addWidget(line5)
        
        # Printer Control section
        control_label = QLabel("🎮 PRINTER CONTROL")
        control_label.setFont(QFont("Play", 12, QFont.Weight.Bold))
        control_label.setStyleSheet(f"color: {COLORS['accent']};")
        layout.addWidget(control_label)
        
        control_frame = QFrame()
        control_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_dark']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
            }}
        """)
        control_layout = QVBoxLayout(control_frame)
        control_layout.setContentsMargins(8, 8, 8, 8)
        control_layout.setSpacing(8)
        
        # Firmware Restart button
        self.firmware_restart_btn = QPushButton("🔄 FIRMWARE_RESTART")
        self.firmware_restart_btn.setFixedHeight(32)
        self.firmware_restart_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['warning']};
                border: 1px solid {COLORS['warning']};
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLORS['warning']};
                color: {COLORS['bg_dark']};
            }}
        """)
        self.firmware_restart_btn.clicked.connect(self._firmware_restart)
        self.firmware_restart_btn.setEnabled(False)
        control_layout.addWidget(self.firmware_restart_btn)
        
        # Restart button
        self.restart_btn = QPushButton("🔁 RESTART")
        self.restart_btn.setFixedHeight(32)
        self.restart_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['accent']};
                border: 1px solid {COLORS['accent']};
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent']};
                color: {COLORS['bg_dark']};
            }}
        """)
        self.restart_btn.clicked.connect(self._restart_klipper)
        self.restart_btn.setEnabled(False)
        control_layout.addWidget(self.restart_btn)
        
        # Emergency Stop button
        self.emergency_stop_btn = QPushButton("🛑 EMERGENCY STOP")
        self.emergency_stop_btn.setFixedHeight(36)
        self.emergency_stop_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['error']};
                color: {COLORS['text_primary']};
                border: 2px solid {COLORS['error']};
                border-radius: 4px;
                font-weight: bold;
                font-size: 12px;
            }}
            QPushButton:hover {{
                background-color: #ff0000;
                border-color: #ff0000;
            }}
        """)
        self.emergency_stop_btn.clicked.connect(self._emergency_stop)
        self.emergency_stop_btn.setEnabled(False)
        control_layout.addWidget(self.emergency_stop_btn)
        
        layout.addWidget(control_frame)
        
        # Separator
        line6 = QFrame()
        line6.setFrameShape(QFrame.Shape.HLine)
        line6.setStyleSheet(f"background-color: {COLORS['border']}; max-height: 1px;")
        layout.addWidget(line6)
        
        # Log Analyzer section
        log_label = QLabel("📊 LOG ANALYZER")
        log_label.setFont(QFont("Play", 12, QFont.Weight.Bold))
        log_label.setStyleSheet(f"color: {COLORS['accent']};")
        layout.addWidget(log_label)
        
        log_frame = QFrame()
        log_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_dark']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
            }}
        """)
        log_layout = QVBoxLayout(log_frame)
        log_layout.setContentsMargins(8, 8, 8, 8)
        log_layout.setSpacing(8)
        
        # Log status
        self.log_status_label = QLabel("No log analyzed yet")
        self.log_status_label.setFont(QFont("Play", 9))
        self.log_status_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        self.log_status_label.setWordWrap(True)
        log_layout.addWidget(self.log_status_label)
        
        # Error/Warning counts
        log_stats_layout = QHBoxLayout()
        self.log_errors_label = QLabel("⚠️ Errors: --")
        self.log_errors_label.setFont(QFont("Play", 9))
        self.log_errors_label.setStyleSheet(f"color: {COLORS['error']};")
        log_stats_layout.addWidget(self.log_errors_label)
        
        self.log_warnings_label = QLabel("⚠️ Warnings: --")
        self.log_warnings_label.setFont(QFont("Play", 9))
        self.log_warnings_label.setStyleSheet(f"color: {COLORS['warning']};")
        log_stats_layout.addWidget(self.log_warnings_label)
        log_layout.addLayout(log_stats_layout)
        
        # Analyze Log button
        self.analyze_log_btn = QPushButton("🔍 Analyze Log")
        self.analyze_log_btn.setFixedHeight(32)
        self.analyze_log_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['accent']};
                border: 1px solid {COLORS['accent']};
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent']};
                color: {COLORS['bg_dark']};
            }}
        """)
        self.analyze_log_btn.clicked.connect(self._analyze_log)
        self.analyze_log_btn.setEnabled(False)
        log_layout.addWidget(self.analyze_log_btn)
        
        # Download Log button
        self.download_log_btn = QPushButton("💾 Download Log")
        self.download_log_btn.setFixedHeight(28)
        self.download_log_btn.clicked.connect(self._download_log)
        self.download_log_btn.setEnabled(False)
        log_layout.addWidget(self.download_log_btn)
        
        layout.addWidget(log_frame)
        
        # Store temperature history for PID warning
        self._temp_history_hotend: deque = deque(maxlen=30)
        self._temp_history_bed: deque = deque(maxlen=30)
        self._current_printer_config = None
        
        # Signal for G-code commands
        self.gcode_requested = None  # Will be set by MainWindow
        
        layout.addStretch()
    
    def _apply_style(self):
        self.setStyleSheet(f"""
            StatsPanel {{
                background-color: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
            }}
        """)
    
    def _open_camera(self):
        if self.current_webcam_url:
            webbrowser.open(self.current_webcam_url)
    
    def _refresh_camera(self):
        """Refresh camera image from stream"""
        if not self.current_webcam_url:
            return
        
        try:
            import urllib.request
            # For snapshot URL, try common patterns
            snapshot_url = self.current_webcam_url.replace('?action=stream', '?action=snapshot')
            if 'snapshot' not in snapshot_url:
                snapshot_url = self.current_webcam_url.rstrip('/') + '?action=snapshot'
            
            req = urllib.request.Request(snapshot_url, headers={'User-Agent': 'KlipperBuddy'})
            with urllib.request.urlopen(req, timeout=2) as response:
                data = response.read()
                pixmap = QPixmap()
                pixmap.loadFromData(data)
                if not pixmap.isNull():
                    scaled = pixmap.scaled(
                        self.camera_image.width() - 10,
                        self.camera_image.height() - 10,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation
                    )
                    self.camera_image.setPixmap(scaled)
        except Exception as e:
            self.camera_image.setText(f"Camera unavailable")
    
    def set_webcam_url(self, url: str):
        self.current_webcam_url = url
        self.open_camera_btn.setEnabled(True)
        # Start camera refresh
        self.camera_timer.start(2000)  # Refresh every 2 seconds
        self._refresh_camera()  # Immediate first refresh
    
    def set_printer_name(self, name: str):
        self.printer_name_label.setText(f"📊 {name}")
    
    def update_temps(self, hotend: float, bed: float, chamber: float):
        self.temp_chart.add_data(hotend, bed, chamber)
        self.hotend_label.setText(f"Hotend: {hotend:.1f}°C")
        self.bed_label.setText(f"Bed: {bed:.1f}°C")
        self.chamber_label.setText(f"Chamber: {chamber:.1f}°C" if chamber > 0 else "Chamber: --°C")
    
    def update_stats(self, stats: PrinterStats):
        # Format print time
        hours = int(stats.total_print_time // 3600)
        self.total_time_label.setText(f"{hours:,}h")
        
        # Format filament (mm to meters/kg)
        meters = stats.total_filament / 1000
        if meters > 1000:
            kg = meters * 0.003  # Approximate: 1m of 1.75mm filament ≈ 3g
            self.total_filament_label.setText(f"{kg:.1f} kg")
        else:
            self.total_filament_label.setText(f"{meters:.1f} m")
        
        # Print count
        self.print_count_label.setText(f"{stats.total_jobs:,}")
        
        # Success rate
        if stats.total_jobs > 0:
            rate = (stats.completed_jobs / stats.total_jobs) * 100
            self.success_rate_label.setText(f"{rate:.1f}%")
        else:
            self.success_rate_label.setText("--")
    
    def update_system_info(self, info: SystemInfo):
        # Versions
        if info.klipper_version:
            ver = info.klipper_version.split('-')[0] if '-' in info.klipper_version else info.klipper_version
            self.klipper_ver_label.setText(ver[:20])
        
        if info.moonraker_version:
            ver = info.moonraker_version.split('-')[0] if '-' in info.moonraker_version else info.moonraker_version
            self.moonraker_ver_label.setText(ver[:20])
        
        if info.os_info:
            self.os_label.setText(info.os_info[:25])
        
        # Disk usage
        if info.disk_total > 0:
            used_gb = info.disk_used / (1024**3)
            total_gb = info.disk_total / (1024**3)
            self.disk_label.setText(f"{used_gb:.1f} GB / {total_gb:.1f} GB")
            
            percent = (info.disk_used / info.disk_total) * 100
            self.disk_bar.setValue(int(percent))
    
    def _run_pid_calibrate(self, heater: str):
        """Run PID calibration for specified heater"""
        if not self._current_printer_config:
            return
        
        # Determine target temperature
        if heater == 'extruder':
            target = 200  # Default hotend temp
            gcode = f"PID_CALIBRATE HEATER=extruder TARGET={target}"
        else:
            target = 60  # Default bed temp
            gcode = f"PID_CALIBRATE HEATER=heater_bed TARGET={target}"
        
        # Confirm with user
        reply = QMessageBox.question(
            self, "PID Calibration",
            f"Run PID calibration for {heater} at {target}°C?\n\n"
            "This will take several minutes. The printer should be at room temperature.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            if self.gcode_requested:
                self.gcode_requested(self._current_printer_config, gcode)
    
    def _run_shaper_calibrate(self):
        """Run Input Shaper calibration"""
        if not self._current_printer_config:
            return
        
        reply = QMessageBox.question(
            self, "Input Shaper Calibration",
            "Run SHAPER_CALIBRATE?\n\n"
            "This will measure resonance frequencies on both axes.\n"
            "Make sure an accelerometer is connected and configured.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            if self.gcode_requested:
                self.gcode_requested(self._current_printer_config, "SHAPER_CALIBRATE")
    
    def _check_pid_warning(self, hotend: float, bed: float, hotend_target: float, bed_target: float):
        """Check for temperature fluctuations that suggest PID tuning is needed"""
        self._temp_history_hotend.append(hotend)
        self._temp_history_bed.append(bed)
        
        show_warning = False
        warning_text = ""
        
        # Check hotend fluctuation when heating
        if hotend_target > 50 and len(self._temp_history_hotend) >= 10:
            temps = list(self._temp_history_hotend)[-10:]
            fluctuation = max(temps) - min(temps)
            if fluctuation > 5:  # More than 5°C fluctuation
                show_warning = True
                warning_text = f"⚠️ Hotend temp fluctuation: ±{fluctuation/2:.1f}°C\nPID tuning recommended."
        
        # Check bed fluctuation when heating
        if bed_target > 30 and len(self._temp_history_bed) >= 10:
            temps = list(self._temp_history_bed)[-10:]
            fluctuation = max(temps) - min(temps)
            if fluctuation > 3:  # More than 3°C fluctuation
                show_warning = True
                if warning_text:
                    warning_text += f"\n⚠️ Bed temp fluctuation: ±{fluctuation/2:.1f}°C"
                else:
                    warning_text = f"⚠️ Bed temp fluctuation: ±{fluctuation/2:.1f}°C\nPID tuning recommended."
        
        self.pid_warning_frame.setVisible(show_warning)
        if show_warning:
            self.pid_warning_label.setText(warning_text)
    
    def update_input_shaper(self, shaper_data: Optional[Dict]):
        """Update Input Shaper display"""
        if shaper_data:
            x_type = shaper_data.get('shaper_type_x', '--')
            x_freq = shaper_data.get('shaper_freq_x', 0)
            y_type = shaper_data.get('shaper_type_y', '--')
            y_freq = shaper_data.get('shaper_freq_y', 0)
            
            if x_type and x_freq > 0:
                self.shaper_x_label.setText(f"{x_type.upper()} @ {x_freq:.1f} Hz")
            else:
                self.shaper_x_label.setText("Not configured")
            
            if y_type and y_freq > 0:
                self.shaper_y_label.setText(f"{y_type.upper()} @ {y_freq:.1f} Hz")
            else:
                self.shaper_y_label.setText("Not configured")
            
            self.shaper_calibrate_btn.setEnabled(True)
        else:
            self.shaper_x_label.setText("--")
            self.shaper_y_label.setText("--")
            self.shaper_calibrate_btn.setEnabled(False)
    
    def set_printer_config(self, config):
        """Set current printer config for G-code commands"""
        self._current_printer_config = config
        self.shaper_calibrate_btn.setEnabled(config is not None)
    
    def clear(self):
        self.temp_chart.clear_data()
        self.hotend_label.setText("Hotend: --°C")
        self.bed_label.setText("Bed: --°C")
        self.chamber_label.setText("Chamber: --°C")
        self.total_time_label.setText("--")
        self.total_filament_label.setText("--")
        self.print_count_label.setText("--")
        self.success_rate_label.setText("--")
        self.klipper_ver_label.setText("--")
        self.moonraker_ver_label.setText("--")
        self.os_label.setText("--")
        self.disk_label.setText("-- / --")
        self.disk_bar.setValue(0)
        self.camera_image.setText("Click a printer to view camera")
        self.camera_image.setPixmap(QPixmap())  # Clear any existing image
        self.open_camera_btn.setEnabled(False)
        self.current_webcam_url = ""
        self.camera_timer.stop()
        self.printer_name_label.setText("Select a printer")
        self.pid_warning_frame.setVisible(False)
        self.shaper_x_label.setText("--")
        self.shaper_y_label.setText("--")
        self.shaper_calibrate_btn.setEnabled(False)
        self._temp_history_hotend.clear()
        self._temp_history_bed.clear()
        self._current_printer_config = None
        # Clear log analyzer
        self.log_status_label.setText("No log analyzed yet")
        self.log_errors_label.setText("⚠️ Errors: --")
        self.log_warnings_label.setText("⚠️ Warnings: --")
        self.analyze_log_btn.setEnabled(False)
        self.download_log_btn.setEnabled(False)
        # Clear control buttons
        self.firmware_restart_btn.setEnabled(False)
        self.restart_btn.setEnabled(False)
        self.emergency_stop_btn.setEnabled(False)
    
    def enable_controls(self, enabled: bool = True):
        """Enable or disable printer control buttons"""
        self.firmware_restart_btn.setEnabled(enabled)
        self.restart_btn.setEnabled(enabled)
        self.emergency_stop_btn.setEnabled(enabled)
        self.analyze_log_btn.setEnabled(enabled)
        self.download_log_btn.setEnabled(enabled)
    
    def _firmware_restart(self):
        """Send FIRMWARE_RESTART command"""
        if not self._current_printer_config:
            return
        
        reply = QMessageBox.question(
            self, "Firmware Restart",
            "Send FIRMWARE_RESTART command?\n\n"
            "This will restart the Klipper firmware.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            if self.gcode_requested:
                self.gcode_requested(self._current_printer_config, "FIRMWARE_RESTART")
    
    def _restart_klipper(self):
        """Send RESTART command"""
        if not self._current_printer_config:
            return
        
        reply = QMessageBox.question(
            self, "Restart Klipper",
            "Send RESTART command?\n\n"
            "This will restart the Klipper host software.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            if self.gcode_requested:
                self.gcode_requested(self._current_printer_config, "RESTART")
    
    def _emergency_stop(self):
        """Send EMERGENCY_STOP command"""
        if not self._current_printer_config:
            return
        
        reply = QMessageBox.warning(
            self, "⚠️ EMERGENCY STOP",
            "Send M112 EMERGENCY STOP?\n\n"
            "This will immediately halt the printer!\n"
            "You will need to restart Klipper after this.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            if self.gcode_requested:
                self.gcode_requested(self._current_printer_config, "M112")
    
    def _analyze_log(self):
        """Download and analyze klippy.log"""
        if not self._current_printer_config:
            return
        
        self.log_status_label.setText("Downloading log...")
        QApplication.processEvents()
        
        # Download log via Moonraker API
        try:
            import urllib.request
            url = f"http://{self._current_printer_config.host}:{self._current_printer_config.port}/server/files/klippy.log"
            req = urllib.request.Request(url, headers={'User-Agent': 'KlipperBuddy'})
            
            with urllib.request.urlopen(req, timeout=30) as response:
                log_content = response.read().decode('utf-8', errors='ignore')
            
            # Analyze log
            errors = log_content.count('!! ')
            warnings = log_content.count('// ')
            
            # Check for common errors
            temp_errors = []
            if 'ADC out of range' in log_content:
                temp_errors.append('ADC out of range')
            if 'Heater not heating' in log_content:
                temp_errors.append('Heater not heating')
            if 'Timer too close' in log_content:
                temp_errors.append('Timer too close')
            if 'MCU' in log_content and 'shutdown' in log_content:
                temp_errors.append('MCU shutdown')
            
            self.log_errors_label.setText(f"❌ Errors: {errors}")
            self.log_warnings_label.setText(f"⚠️ Warnings: {warnings}")
            
            if temp_errors:
                self.log_status_label.setText(f"Issues found: {', '.join(temp_errors)}")
                self.log_status_label.setStyleSheet(f"color: {COLORS['error']};")
            else:
                self.log_status_label.setText("Log analyzed - No critical issues")
                self.log_status_label.setStyleSheet(f"color: {COLORS['success']};")
            
            # Store log for potential download
            self._last_log_content = log_content
            
        except Exception as e:
            self.log_status_label.setText(f"Error: {str(e)[:50]}")
            self.log_status_label.setStyleSheet(f"color: {COLORS['error']};")
    
    def _download_log(self):
        """Download klippy.log to specified folder"""
        if not self._current_printer_config:
            return
        
        # Get save path from config or use default
        from pathlib import Path
        default_path = Path.home() / "Documents" / "KlipperBuddy" / "logs"
        default_path.mkdir(parents=True, exist_ok=True)
        
        # Generate filename with timestamp
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        printer_name = self._current_printer_config.name.replace(' ', '_')
        filename = f"klippy_{printer_name}_{timestamp}.log"
        
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save klippy.log",
            str(default_path / filename),
            "Log files (*.log);;All files (*.*)"
        )
        
        if not save_path:
            return
        
        self.log_status_label.setText("Downloading...")
        QApplication.processEvents()
        
        try:
            import urllib.request
            url = f"http://{self._current_printer_config.host}:{self._current_printer_config.port}/server/files/klippy.log"
            req = urllib.request.Request(url, headers={'User-Agent': 'KlipperBuddy'})
            
            with urllib.request.urlopen(req, timeout=30) as response:
                log_content = response.read()
            
            with open(save_path, 'wb') as f:
                f.write(log_content)
            
            self.log_status_label.setText(f"Saved to: {Path(save_path).name}")
            self.log_status_label.setStyleSheet(f"color: {COLORS['success']};")
            
            QMessageBox.information(
                self, "Download Complete",
                f"Log saved to:\n{save_path}"
            )
            
        except Exception as e:
            self.log_status_label.setText(f"Error: {str(e)[:50]}")
            self.log_status_label.setStyleSheet(f"color: {COLORS['error']};")


# =============================================================================
# Network Scanner Dialog
# =============================================================================

class ScanDialog(QDialog):
    """Network scanner dialog with cyberpunk styling"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("⚡ Scan Network for Printers")
        self.setFixedSize(700, 500)
        self.discovered = []
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        
        # Header
        header = QLabel("🔍 Network Scanner")
        header.setFont(QFont("Play", 16, QFont.Weight.Bold))
        header.setStyleSheet(f"color: {COLORS['accent']};")
        layout.addWidget(header)
        
        desc = QLabel("Scan your local network to discover Klipper printers running Moonraker.")
        desc.setFont(QFont("Play", 10))
        desc.setStyleSheet(f"color: {COLORS['text_secondary']};")
        layout.addWidget(desc)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        self.scan_btn = QPushButton("⚡ Start Scan")
        self.scan_btn.clicked.connect(self._start_scan)
        btn_layout.addWidget(self.scan_btn)
        
        self.cancel_scan_btn = QPushButton("Stop")
        self.cancel_scan_btn.setEnabled(False)
        self.cancel_scan_btn.clicked.connect(self._cancel_scan)
        btn_layout.addWidget(self.cancel_scan_btn)
        
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        layout.addWidget(self.progress)
        
        self.status_label = QLabel("Ready to scan")
        self.status_label.setFont(QFont("Play", 10))
        self.status_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        layout.addWidget(self.status_label)
        
        # Results table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Select", "Name", "Host", "Port", "Auth"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, 60)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.table)
        
        # Dialog buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self._scanning = False
        self._scan_worker = None
    
    def _start_scan(self):
        self._scanning = True
        self.scan_btn.setEnabled(False)
        self.cancel_scan_btn.setEnabled(True)
        self.table.setRowCount(0)
        self.discovered = []
        self.progress.setValue(0)
        self.status_label.setText("Scanning network (parallel)...")
        
        def update_progress(value):
            self.progress.setValue(value)
        
        async def scan():
            # Fast parallel scan
            results = await NetworkScanner.scan_network_parallel(update_progress)
            
            # Get printer names for found printers
            for result in results:
                if not self._scanning:
                    break
                try:
                    client = MoonrakerClient(result['host'], result['port'])
                    name = await client.get_printer_name()
                    await client.close()
                    result['name'] = name
                except:
                    result['name'] = result['host']
            
            return results
        
        self._scan_worker = AsyncWorker(scan())
        self._scan_worker.finished.connect(self._on_scan_complete)
        self._scan_worker.start()
    
    def _cancel_scan(self):
        self._scanning = False
        self.status_label.setText("Scan cancelled")
    
    def _on_scan_complete(self, results):
        self._scanning = False
        self.scan_btn.setEnabled(True)
        self.cancel_scan_btn.setEnabled(False)
        
        self.discovered = results
        
        self.table.setRowCount(len(results))
        for i, r in enumerate(results):
            cb = QCheckBox()
            cb.setChecked(True)
            self.table.setCellWidget(i, 0, cb)
            self.table.setItem(i, 1, QTableWidgetItem(r['name']))
            self.table.setItem(i, 2, QTableWidgetItem(r['host']))
            self.table.setItem(i, 3, QTableWidgetItem(str(r['port'])))
            self.table.setItem(i, 4, QTableWidgetItem("Yes" if r['auth_required'] else "No"))
        
        self.status_label.setText(f"Found {len(results)} printer(s)")
        self.progress.setValue(100)
    
    def get_selected_printers(self) -> List[Dict]:
        selected = []
        for i in range(self.table.rowCount()):
            cb = self.table.cellWidget(i, 0)
            if cb and cb.isChecked():
                selected.append(self.discovered[i])
        return selected


# =============================================================================
# Add Printer Dialog
# =============================================================================

class AddPrinterDialog(QDialog):
    def __init__(self, parent=None, prefill: Dict = None):
        super().__init__(parent)
        self.setWindowTitle("➕ Add Printer")
        self.setFixedSize(400, 350)
        self._setup_ui(prefill)
    
    def _setup_ui(self, prefill: Dict = None):
        layout = QFormLayout(self)
        layout.setSpacing(12)
        
        header = QLabel("Add Klipper Printer")
        header.setFont(QFont("Play", 14, QFont.Weight.Bold))
        header.setStyleSheet(f"color: {COLORS['accent']};")
        layout.addRow(header)
        
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("My Printer")
        layout.addRow("Name:", self.name_edit)
        
        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("192.168.1.100")
        layout.addRow("Host:", self.host_edit)
        
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(7125)
        layout.addRow("Port:", self.port_spin)
        
        self.api_key_edit = QLineEdit()
        self.api_key_edit.setPlaceholderText("Optional")
        layout.addRow("API Key:", self.api_key_edit)
        
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Optional")
        layout.addRow("Username:", self.username_edit)
        
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setPlaceholderText("Optional")
        layout.addRow("Password:", self.password_edit)
        
        if prefill:
            self.name_edit.setText(prefill.get('name', ''))
            self.host_edit.setText(prefill.get('host', ''))
            self.port_spin.setValue(prefill.get('port', 7125))
        
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)
    
    def get_config(self) -> PrinterConfig:
        return PrinterConfig(
            name=self.name_edit.text() or self.host_edit.text(),
            host=self.host_edit.text(),
            port=self.port_spin.value(),
            api_key=self.api_key_edit.text(),
            username=self.username_edit.text(),
            password=self.password_edit.text(),
            enabled=True
        )


# =============================================================================
# Settings Dialog
# =============================================================================

class SettingsDialog(QDialog):
    """Settings dialog for KlipperBuddy"""
    
    def __init__(self, config_manager, parent=None):
        super().__init__(parent)
        self.config_manager = config_manager
        self.setWindowTitle("⚙️ Settings")
        self.setFixedSize(500, 400)
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        
        # Header
        header = QLabel("⚙️ KlipperBuddy Settings")
        header.setFont(QFont("Play", 14, QFont.Weight.Bold))
        header.setStyleSheet(f"color: {COLORS['accent']};")
        layout.addWidget(header)
        
        # Log folder setting
        log_group = QGroupBox("Log Files")
        log_layout = QVBoxLayout(log_group)
        
        log_path_layout = QHBoxLayout()
        log_path_layout.addWidget(QLabel("Log Save Folder:"))
        self.log_path_edit = QLineEdit()
        self.log_path_edit.setText(str(self.config_manager.get_setting('log_folder', str(Path.home() / 'Documents' / 'KlipperBuddy' / 'logs'))))
        self.log_path_edit.setReadOnly(True)
        log_path_layout.addWidget(self.log_path_edit)
        
        self.browse_log_btn = QPushButton("📁 Browse")
        self.browse_log_btn.clicked.connect(self._browse_log_folder)
        log_path_layout.addWidget(self.browse_log_btn)
        log_layout.addLayout(log_path_layout)
        
        layout.addWidget(log_group)
        
        # Shortcuts group
        shortcut_group = QGroupBox("Shortcuts")
        shortcut_layout = QVBoxLayout(shortcut_group)
        
        shortcut_desc = QLabel("Create shortcuts to launch KlipperBuddy easily")
        shortcut_desc.setStyleSheet(f"color: {COLORS['text_secondary']};")
        shortcut_layout.addWidget(shortcut_desc)
        
        btn_layout = QHBoxLayout()
        
        self.desktop_shortcut_btn = QPushButton("🖥️ Create Desktop Shortcut")
        self.desktop_shortcut_btn.clicked.connect(self._create_desktop_shortcut)
        btn_layout.addWidget(self.desktop_shortcut_btn)
        
        self.startmenu_shortcut_btn = QPushButton("📁 Create Start Menu Shortcut")
        self.startmenu_shortcut_btn.clicked.connect(self._create_startmenu_shortcut)
        btn_layout.addWidget(self.startmenu_shortcut_btn)
        
        shortcut_layout.addLayout(btn_layout)
        layout.addWidget(shortcut_group)
        
        # Auto-scan setting
        scan_group = QGroupBox("Startup")
        scan_layout = QVBoxLayout(scan_group)
        
        self.auto_scan_check = QCheckBox("Auto-scan network on startup")
        self.auto_scan_check.setChecked(self.config_manager.get_setting('auto_scan', True))
        scan_layout.addWidget(self.auto_scan_check)
        
        layout.addWidget(scan_group)
        
        layout.addStretch()
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._save_and_close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    
    def _browse_log_folder(self):
        folder = QFileDialog.getExistingDirectory(
            self, "Select Log Folder",
            self.log_path_edit.text()
        )
        if folder:
            self.log_path_edit.setText(folder)
    
    def _create_desktop_shortcut(self):
        """Create desktop shortcut"""
        try:
            import sys
            exe_path = sys.executable if getattr(sys, 'frozen', False) else __file__
            
            if sys.platform == 'win32':
                # Windows shortcut
                desktop = Path.home() / 'Desktop'
                shortcut_path = desktop / 'KlipperBuddy.lnk'
                
                try:
                    import winshell
                    from win32com.client import Dispatch
                    
                    shell = Dispatch('WScript.Shell')
                    shortcut = shell.CreateShortCut(str(shortcut_path))
                    shortcut.Targetpath = exe_path
                    shortcut.WorkingDirectory = str(Path(exe_path).parent)
                    shortcut.IconLocation = exe_path
                    shortcut.save()
                    
                    QMessageBox.information(self, "Success", f"Desktop shortcut created!\n{shortcut_path}")
                except ImportError:
                    # Fallback: create batch file
                    batch_path = desktop / 'KlipperBuddy.bat'
                    with open(batch_path, 'w') as f:
                        f.write(f'@echo off\nstart "" "{exe_path}"\n')
                    QMessageBox.information(self, "Success", f"Desktop shortcut created!\n{batch_path}")
            else:
                # Linux/Mac
                desktop = Path.home() / 'Desktop'
                shortcut_path = desktop / 'KlipperBuddy.desktop'
                
                with open(shortcut_path, 'w') as f:
                    f.write(f"""[Desktop Entry]
Name=KlipperBuddy
Exec={exe_path}
Type=Application
Terminal=false
Icon=printer
""")
                shortcut_path.chmod(0o755)
                QMessageBox.information(self, "Success", f"Desktop shortcut created!\n{shortcut_path}")
                
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to create shortcut:\n{str(e)}")
    
    def _create_startmenu_shortcut(self):
        """Create start menu shortcut"""
        try:
            import sys
            exe_path = sys.executable if getattr(sys, 'frozen', False) else __file__
            
            if sys.platform == 'win32':
                # Windows Start Menu
                start_menu = Path.home() / 'AppData' / 'Roaming' / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs'
                shortcut_path = start_menu / 'KlipperBuddy.lnk'
                
                try:
                    import winshell
                    from win32com.client import Dispatch
                    
                    shell = Dispatch('WScript.Shell')
                    shortcut = shell.CreateShortCut(str(shortcut_path))
                    shortcut.Targetpath = exe_path
                    shortcut.WorkingDirectory = str(Path(exe_path).parent)
                    shortcut.IconLocation = exe_path
                    shortcut.save()
                    
                    QMessageBox.information(self, "Success", f"Start Menu shortcut created!\n{shortcut_path}")
                except ImportError:
                    QMessageBox.warning(self, "Note", "Install 'pywin32' for proper Windows shortcuts.\nRun: pip install pywin32")
            else:
                # Linux applications menu
                apps_dir = Path.home() / '.local' / 'share' / 'applications'
                apps_dir.mkdir(parents=True, exist_ok=True)
                shortcut_path = apps_dir / 'klipperbuddy.desktop'
                
                with open(shortcut_path, 'w') as f:
                    f.write(f"""[Desktop Entry]
Name=KlipperBuddy
Exec={exe_path}
Type=Application
Terminal=false
Icon=printer
Categories=Utility;
""")
                QMessageBox.information(self, "Success", f"Applications menu shortcut created!\n{shortcut_path}")
                
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to create shortcut:\n{str(e)}")
    
    def _save_and_close(self):
        """Save settings and close dialog"""
        self.config_manager.set_setting('log_folder', self.log_path_edit.text())
        self.config_manager.set_setting('auto_scan', self.auto_scan_check.isChecked())
        self.accept()


# =============================================================================
# Main Window
# =============================================================================

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("⚡ KlipperBuddy")
        self.setMinimumSize(1400, 800)
        
        self.config_manager = ConfigManager()
        self.printer_cards: Dict[str, PrinterCard] = {}
        self.update_workers: List[AsyncWorker] = []
        self.selected_printer: Optional[PrinterCard] = None
        self._startup_scan_done = False
        
        self._setup_ui()
        self._load_printers()
        
        # Connect G-code request handler
        self.stats_panel.gcode_requested = self._send_gcode
        
        # Auto-refresh timer
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self._refresh_all_status)
        self.refresh_timer.start(3000)  # Refresh every 3 seconds
    
    def showEvent(self, event):
        """Run auto-scan on first show"""
        super().showEvent(event)
        if not self._startup_scan_done:
            self._startup_scan_done = True
            # Delay scan slightly to allow window to fully render
            QTimer.singleShot(500, self._auto_scan_network)
    
    def _auto_scan_network(self):
        """Automatically scan network on startup"""
        self.status_label.setText("Scanning network for printers...")
        
        # Run scan in background
        async def scan():
            scanner = NetworkScanner()
            return await scanner.scan_network()
        
        def on_result(printers):
            if printers:
                added_count = 0
                for p in printers:
                    # Check if printer already exists
                    exists = any(
                        pc.host == p['host'] and pc.port == p['port']
                        for pc in self.config_manager.printers
                    )
                    if not exists:
                        config = PrinterConfig(
                            name=p['name'],
                            host=p['host'],
                            port=p['port'],
                            enabled=True
                        )
                        if self.config_manager.add_printer(config):
                            self._add_printer_card(config)
                            added_count += 1
                
                if added_count > 0:
                    self.status_label.setText(f"Found {added_count} new printer(s)")
                else:
                    self.status_label.setText(f"Scan complete - {len(printers)} printer(s) online")
                self._refresh_all_status()
            else:
                self.status_label.setText("No printers found on network")
        
        worker = AsyncWorker(scan)
        worker.result_ready.connect(on_result)
        worker.error_occurred.connect(lambda e: self.status_label.setText(f"Scan error: {e}"))
        self.update_workers.append(worker)
        worker.start()
    
    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(16)
        
        # Header
        header_layout = QHBoxLayout()
        
        # P3D Logo
        p3d_logo_path = resource_path("p3d_logo.png")
        if os.path.exists(p3d_logo_path):
            p3d_pixmap = QPixmap(p3d_logo_path)
            p3d_label = QLabel()
            p3d_label.setPixmap(p3d_pixmap.scaledToHeight(36, Qt.TransformationMode.SmoothTransformation))
            header_layout.addWidget(p3d_label)
        
        # KlipperBuddy title logo
        logo_path = resource_path("title_logo.png")
        if os.path.exists(logo_path):
            logo_pixmap = QPixmap(logo_path)
            logo_label = QLabel()
            logo_label.setPixmap(logo_pixmap.scaledToHeight(40, Qt.TransformationMode.SmoothTransformation))
            header_layout.addWidget(logo_label)
        else:
            # Fallback text title
            title = QLabel("⚡ KLIPPERBUDDY")
            title.setFont(QFont("Play", 24, QFont.Weight.Bold))
            title.setStyleSheet(f"color: {COLORS['accent']};")
            header_layout.addWidget(title)
        
        subtitle = QLabel("Klipper Printer Dashboard")
        subtitle.setFont(QFont("Play", 12))
        subtitle.setStyleSheet(f"color: {COLORS['text_secondary']}; margin-left: 10px;")
        header_layout.addWidget(subtitle)
        
        header_layout.addStretch()
        
        # Buttons
        self.scan_btn = QPushButton("🔍 Scan Network")
        self.scan_btn.clicked.connect(self._show_scan_dialog)
        header_layout.addWidget(self.scan_btn)
        
        self.add_btn = QPushButton("➕ Add Printer")
        self.add_btn.clicked.connect(self._show_add_dialog)
        header_layout.addWidget(self.add_btn)
        
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.clicked.connect(self._refresh_all_status)
        header_layout.addWidget(self.refresh_btn)
        
        self.settings_btn = QPushButton("⚙️ Settings")
        self.settings_btn.clicked.connect(self._show_settings_dialog)
        header_layout.addWidget(self.settings_btn)
        
        main_layout.addLayout(header_layout)
        
        # Separator
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet(f"background-color: {COLORS['border']}; max-height: 1px;")
        main_layout.addWidget(line)
        
        # Main content area with splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left side - Printer cards area
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        cards_label = QLabel("PRINTERS")
        cards_label.setFont(QFont("Play", 12, QFont.Weight.Bold))
        cards_label.setStyleSheet(f"color: {COLORS['accent']};")
        left_layout.addWidget(cards_label)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        self.cards_container = QWidget()
        self.cards_layout = QGridLayout(self.cards_container)
        self.cards_layout.setSpacing(16)
        self.cards_layout.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        
        scroll.setWidget(self.cards_container)
        left_layout.addWidget(scroll)
        
        splitter.addWidget(left_widget)
        
        # Right side - Stats panel
        self.stats_panel = StatsPanel()
        self.stats_panel.setMinimumWidth(350)
        self.stats_panel.setMaximumWidth(400)
        splitter.addWidget(self.stats_panel)
        
        splitter.setSizes([900, 350])
        
        main_layout.addWidget(splitter)
        
        # Status bar
        self.status_label = QLabel("Ready")
        self.status_label.setFont(QFont("Play", 9))
        self.status_label.setStyleSheet(f"color: {COLORS['text_muted']};")
        main_layout.addWidget(self.status_label)
    
    def _load_printers(self):
        for printer in self.config_manager.printers:
            self._add_printer_card(printer)
        self._refresh_all_status()
    
    def _add_printer_card(self, config: PrinterConfig):
        key = f"{config.host}:{config.port}"
        if key in self.printer_cards:
            return
        
        card = PrinterCard(config)
        card.camera_clicked.connect(self._on_camera_clicked)
        card.card_clicked.connect(self._on_card_clicked)
        self.printer_cards[key] = card
        
        # Add to grid
        count = len(self.printer_cards) - 1
        cols = 3
        row = count // cols
        col = count % cols
        self.cards_layout.addWidget(card, row, col)
    
    def _remove_printer_card(self, host: str, port: int):
        key = f"{host}:{port}"
        if key in self.printer_cards:
            card = self.printer_cards.pop(key)
            self.cards_layout.removeWidget(card)
            card.deleteLater()
            self._reorganize_cards()
    
    def _reorganize_cards(self):
        # Remove all cards from layout
        for card in self.printer_cards.values():
            self.cards_layout.removeWidget(card)
        
        # Re-add in order
        cols = 3
        for i, card in enumerate(self.printer_cards.values()):
            row = i // cols
            col = i % cols
            self.cards_layout.addWidget(card, row, col)
    
    def _show_scan_dialog(self):
        dialog = ScanDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            selected = dialog.get_selected_printers()
            for p in selected:
                config = PrinterConfig(
                    name=p['name'],
                    host=p['host'],
                    port=p['port'],
                    enabled=True
                )
                if self.config_manager.add_printer(config):
                    self._add_printer_card(config)
            self._refresh_all_status()
    
    def _show_add_dialog(self):
        dialog = AddPrinterDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            config = dialog.get_config()
            if self.config_manager.add_printer(config):
                self._add_printer_card(config)
                self._refresh_all_status()
            else:
                QMessageBox.warning(self, "Error", "Printer already exists!")
    
    def _show_settings_dialog(self):
        """Show settings dialog"""
        dialog = SettingsDialog(self.config_manager, self)
        dialog.exec()
    
    def _on_camera_clicked(self, webcam_url: str):
        self.stats_panel.set_webcam_url(webcam_url)
    
    def _on_card_clicked(self, card: PrinterCard):
        """Handle card selection"""
        # Deselect previous card
        if self.selected_printer and self.selected_printer != card:
            self.selected_printer.set_selected(False)
        
        # Select new card
        self.selected_printer = card
        card.set_selected(True)
        
        # Update stats panel
        self.stats_panel.clear()
        self.stats_panel.set_printer_name(card.config.name or card.config.host)
        self.stats_panel.update_stats(card.stats)
        self.stats_panel.update_system_info(card.system_info)
        
        # Set webcam URL
        if card.system_info.webcam_url:
            self.stats_panel.set_webcam_url(card.system_info.webcam_url)
        else:
            # Try default webcam URL
            default_url = f"http://{card.config.host}/webcam/?action=stream"
            self.stats_panel.set_webcam_url(default_url)
    
    def _refresh_all_status(self):
        for key, card in self.printer_cards.items():
            self._refresh_printer_status(card)
    
    def _refresh_printer_status(self, card: PrinterCard):
        config = card.config
        
        async def fetch():
            client = MoonrakerClient(
                config.host, config.port,
                config.api_key, config.username, config.password
            )
            try:
                status = await client.get_status()
                stats = await client.get_print_stats()
                system_info = await client.get_system_info()
                shaper_data = await client.get_input_shaper_data()
                
                # Also try to get better name if not set
                if not config.name or config.name == config.host:
                    name = await client.get_printer_name()
                    if name and name != config.host:
                        config.name = name
                
                return status, stats, system_info, shaper_data, config.name
            finally:
                await client.close()
        
        worker = AsyncWorker(fetch())
        worker.finished.connect(lambda result: self._on_status_received(card, result))
        worker.start()
        self.update_workers.append(worker)
    
    def _on_status_received(self, card: PrinterCard, result):
        if result:
            status, stats, system_info, shaper_data, name = result
            card.update_status(status)
            card.update_stats(stats)
            card.update_system_info(system_info)
            if name:
                card.set_name(name)
            
            # Update stats panel if this is the selected printer
            if self.selected_printer == card:
                self.stats_panel.update_temps(
                    status.extruder_temp,
                    status.bed_temp,
                    status.chamber_temp
                )
                self.stats_panel.update_stats(stats)
                self.stats_panel.update_system_info(system_info)
                self.stats_panel.update_input_shaper(shaper_data)
                self.stats_panel.set_printer_config(card.config)
                
                # Check for PID warning
                self.stats_panel._check_pid_warning(
                    status.extruder_temp,
                    status.bed_temp,
                    status.extruder_target,
                    status.bed_target
                )
            
            # If no printer selected, select the first one
            if self.selected_printer is None and self.printer_cards:
                first_card = list(self.printer_cards.values())[0]
                self._on_card_clicked(first_card)
        
        # Clean up finished workers
        self.update_workers = [w for w in self.update_workers if w.isRunning()]
    
    def _send_gcode(self, config: PrinterConfig, gcode: str):
        """Send G-code command to a printer"""
        async def send():
            client = MoonrakerClient(
                config.host, config.port,
                config.api_key, config.username, config.password
            )
            try:
                success = await client.send_gcode(gcode)
                return success
            finally:
                await client.close()
        
        def on_result(success):
            if success:
                self.status_label.setText(f"Command sent: {gcode[:30]}...")
                QMessageBox.information(self, "Success", f"Command sent successfully:\n{gcode}")
            else:
                self.status_label.setText("Failed to send command")
                QMessageBox.warning(self, "Error", f"Failed to send command:\n{gcode}")
        
        worker = AsyncWorker(send())
        worker.finished.connect(on_result)
        worker.start()
        self.update_workers.append(worker)
    
    def closeEvent(self, event):
        self.refresh_timer.stop()
        # Clean up workers
        for worker in self.update_workers:
            worker.quit()
            worker.wait()
        event.accept()


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Load Play font
    font_path = resource_path("Play-Regular.ttf")
    if os.path.exists(font_path):
        QFontDatabase.addApplicationFont(font_path)
    
    font_bold_path = resource_path("Play-Bold.ttf")
    if os.path.exists(font_bold_path):
        QFontDatabase.addApplicationFont(font_bold_path)
    
    # Set default font
    app.setFont(QFont("Play", 10))
    
    app.setStyleSheet(STYLESHEET)
    
    # Set dark palette
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(COLORS['bg_dark']))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(COLORS['text_primary']))
    palette.setColor(QPalette.ColorRole.Base, QColor(COLORS['bg_card']))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(COLORS['bg_dark']))
    palette.setColor(QPalette.ColorRole.Text, QColor(COLORS['text_primary']))
    palette.setColor(QPalette.ColorRole.Button, QColor(COLORS['bg_card']))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(COLORS['accent']))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(COLORS['accent']))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(COLORS['bg_dark']))
    app.setPalette(palette)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
