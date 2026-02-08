"""
KlipperBuddy v3 - Cyberpunk-style Desktop Dashboard for Klipper Printers
Inspired by Bambuddy (https://github.com/maziggy/bambuddy)

Design: Black theme with Tiffany Blue (#0ABAB5) accents
Font: Play (OFL License) for UI, ToaHI for title logo (image)

P3D Logo: Copyright (c) Yuto Horiuchi (YuTR0N/Psych0h3ad)
          All rights reserved. Unauthorized use prohibited.
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
    QSplitter, QGroupBox, QSizePolicy, QFileDialog, QSystemTrayIcon, QMenu,
    QSlider, QComboBox
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QRect, QPoint, QMargins
from PyQt6.QtGui import (
    QFont, QColor, QPalette, QLinearGradient, QPainter, QBrush, QPen,
    QFontDatabase, QPixmap, QPainterPath, QPaintEvent, QIcon, QAction
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


def get_icon(name: str, size: int = 16) -> QIcon:
    """Load an SVG icon from the icons directory"""
    icon_path = resource_path(f"icons/{name}.svg")
    if os.path.exists(icon_path):
        return QIcon(icon_path)
    return QIcon()


# =============================================================================
# Color Scheme - Cyberpunk with Tiffany Blue
# =============================================================================
COLORS = {
    'bg_dark': '#0a0a0a',
    'bg_card': '#141414',
    'bg_card_hover': '#1a1a1a',
    'bg_hover': '#1f1f1f',  # General hover background
    'surface': '#1a1a1a',  # For dialog backgrounds
    'accent': '#0ABAB5',  # Tiffany Blue
    'accent_dark': '#088F8B',
    'accent_hover': '#0CD5D0',  # Lighter tiffany for hover
    'accent_light': '#0CD5D0',  # Alias for accent_hover
    'accent_glow': '#0ABAB5',
    'text': '#ffffff',  # Alias for text_primary
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
    # Multi-extruder support (Snapmaker U1, etc.)
    extruder_count: int = 1
    extruder_temps: list = None  # [(current, target), ...] for each extruder


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
    # MCU info
    mcu_name: str = ""  # MCU type (e.g., "STM32F446", "RP2040")
    mcu_version: str = ""  # MCU firmware version
    mcu_freq: str = ""  # MCU frequency
    mcu_list: list = None  # List of all MCUs: [(name, mcu_type, version), ...]
    # Host info
    host_cpu: str = ""  # Host CPU model (e.g., "Raspberry Pi 4")
    host_memory_total: int = 0  # bytes
    host_memory_used: int = 0  # bytes
    host_cpu_usage: float = 0.0  # percentage
    # Network
    mac_address: str = ""  # MAC address for unique identification
    # Uptime
    system_uptime: float = 0.0  # seconds
    # Multi-color unit info (MMU/ERCF/AFC/QIDI BOX)
    mmu_type: str = ""  # "MMU", "ERCF", "AFC", "Tradrack", "QIDI BOX", etc.
    mmu_enabled: bool = False
    mmu_gate_count: int = 0
    mmu_current_gate: int = -1
    mmu_filament_loaded: bool = False
    # QIDI BOX heater temperatures (list of temps for each channel)
    mmu_heater_temps: list = None  # [(current, target), ...]


@dataclass
class PrinterConfig:
    name: str = ""
    host: str = ""
    port: int = 7125
    api_key: str = ""
    username: str = ""
    password: str = ""
    enabled: bool = True
    camera_enabled: bool = True  # Enable camera preview on card
    mac_address: str = ""  # Unique identifier for the printer (from Moonraker)


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
        # Check by MAC address first (most reliable identifier)
        if printer.mac_address:
            for p in self.printers:
                if p.mac_address and p.mac_address == printer.mac_address:
                    # Same printer, update host/port if changed
                    if p.host != printer.host or p.port != printer.port:
                        p.host = printer.host
                        p.port = printer.port
                        self.save()
                    return False  # Not a new printer
        # Fallback: check by host:port
        for p in self.printers:
            if p.host == printer.host and p.port == printer.port:
                return False
        self.printers.append(printer)
        self.save()
        return True
    
    def update_printer_host(self, name: str, new_host: str, new_port: int) -> bool:
        """Update a printer's host/port by name (for when IP changes)"""
        for p in self.printers:
            if p.name and p.name == name:
                if p.host != new_host or p.port != new_port:
                    p.host = new_host
                    p.port = new_port
                    self.save()
                    return True
        return False
    
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
                elif resp.status == 401:
                    if self.username and self.password:
                        if await self._authenticate():
                            return await self._request(method, endpoint, **kwargs)
                    # Return special marker for auth required
                    return {'error': 'unauthorized', 'status': 401}
                elif resp.status == 403:
                    return {'error': 'forbidden', 'status': 403}
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
        # Try Fluidd config first (instanceName) - user-configured names have highest priority
        try:
            resp = await self._request('GET', '/server/database/item?namespace=fluidd&key=uiSettings')
            if resp and 'result' in resp:
                value = resp['result'].get('value', {})
                if isinstance(value, dict):
                    # Try both paths for instanceName in Fluidd
                    name = value.get('general', {}).get('instanceName')
                    if not name:
                        name = value.get('instanceName')  # Alternative path
                    if name and name.strip():
                        # User explicitly set this name in Fluidd, always use it
                        print(f"[DEBUG] Found Fluidd instanceName: {name.strip()}")
                        return name.strip()
        except Exception as e:
            print(f"[DEBUG] Fluidd instanceName error: {e}")
            pass
        
        # Try Mainsail config (instanceName) - user-configured names have highest priority
        try:
            resp = await self._request('GET', '/server/database/item?namespace=mainsail&key=general')
            if resp and 'result' in resp:
                value = resp['result'].get('value', {})
                if isinstance(value, dict):
                    name = value.get('instanceName')
                    if name and name.strip():
                        # User explicitly set this name in Mainsail, always use it
                        print(f"[DEBUG] Found Mainsail instanceName: {name.strip()}")
                        return name.strip()
        except Exception as e:
            print(f"[DEBUG] Mainsail instanceName error: {e}")
            pass
        
        # Also try Mainsail uiSettings path (some versions store it differently)
        try:
            resp = await self._request('GET', '/server/database/item?namespace=mainsail&key=uiSettings')
            if resp and 'result' in resp:
                value = resp['result'].get('value', {})
                if isinstance(value, dict):
                    name = value.get('general', {}).get('instanceName')
                    if not name:
                        name = value.get('instanceName')
                    if name and name.strip():
                        print(f"[DEBUG] Found Mainsail uiSettings instanceName: {name.strip()}")
                        return name.strip()
        except:
            pass
        
        # Try Moonraker config (machine name from [machine] section)
        try:
            resp = await self._request('GET', '/server/config')
            if resp and 'result' in resp:
                config = resp['result'].get('config', {})
                # Check for machine name in moonraker config
                machine = config.get('machine', {})
                if machine:
                    name = machine.get('name')
                    if name and name.strip() and not self._is_generic_name(name.strip()):
                        return name.strip()
        except:
            pass
        
        # Try to get printer model from Klipper config (printer section)
        try:
            resp = await self._request('GET', '/printer/objects/query?configfile')
            if resp and 'result' in resp:
                status = resp['result'].get('status', {})
                configfile = status.get('configfile', {})
                config = configfile.get('config', {})
                # Check for printer section with model info
                printer_section = config.get('printer', {})
                # Some printers store model in kinematics or other fields
                # Check for mcu section which might have board info
                mcu = config.get('mcu', {})
                serial = mcu.get('serial', '')
                # Snapmaker U1 might have identifiable serial pattern
                if 'snapmaker' in serial.lower():
                    return 'Snapmaker U1'
        except:
            pass
        
        # Try to get machine info from Moonraker
        try:
            resp = await self._request('GET', '/machine/system_info')
            if resp and 'result' in resp:
                system_info = resp['result'].get('system_info', {})
                # Try to get model from distribution info
                dist_info = system_info.get('distribution', {})
                dist_id = dist_info.get('id', '')
                # Check for Snapmaker
                if 'snapmaker' in dist_id.lower():
                    return 'Snapmaker U1'
                # QIDI printers often have specific identifiers
                if 'qidi' in dist_id.lower():
                    pass
                # Check CPU info for Snapmaker
                cpu_info = system_info.get('cpu_info', {})
                model = cpu_info.get('model', '')
                if 'snapmaker' in model.lower():
                    return 'Snapmaker U1'
        except:
            pass
        
        # Fall back to hostname from printer info
        info = await self.get_printer_info()
        if info and 'result' in info:
            hostname = info['result'].get('hostname', '')
            if hostname and hostname.strip() and not self._is_generic_name(hostname.strip()):
                return hostname.strip()
        
        return self.host
    
    def _is_generic_name(self, name: str) -> bool:
        """Check if name is a generic/default name that should be skipped"""
        generic_names = [
            'klipper', 'printer', 'mainsail', 'fluidd', 'localhost',
            'raspberry', 'raspberrypi', 'pi', 'mks', 'btt',
            'sonic', 'pad', 'host'
        ]
        name_lower = name.lower()
        # Skip if it's just an IP address
        if name_lower.replace('.', '').isdigit():
            return True
        # Skip generic names
        for generic in generic_names:
            if name_lower == generic or name_lower.startswith(generic + '-'):
                return True
        return False
    
    async def get_status(self) -> PrinterStatus:
        status = PrinterStatus()
        status.last_update = time.time()
        
        info = await self.get_printer_info()
        if not info:
            status.state = 'offline'
            return status
        
        # Check for authentication errors
        if 'error' in info:
            if info.get('status') == 401:
                status.state = 'unauthorized'
                status.state_message = 'Login required'
            elif info.get('status') == 403:
                status.state = 'forbidden'
                status.state_message = 'Access denied'
            else:
                status.state = 'error'
            return status
        
        if 'result' not in info:
            status.state = 'offline'
            return status
        
        result = info['result']
        status.state = result.get('state', 'unknown')
        status.state_message = result.get('state_message', '')
        status.software_version = result.get('software_version', '')
        
        # First, check for available extruders (for multi-toolhead printers like Snapmaker U1)
        extruder_count = 1
        try:
            objects_list = await self._request('GET', '/printer/objects/list')
            if objects_list and 'result' in objects_list:
                objects = objects_list['result'].get('objects', [])
                # Count extruders (extruder, extruder1, extruder2, extruder3, etc.)
                extruder_names = [obj for obj in objects if obj.startswith('extruder') and not 'stepper' in obj]
                extruder_count = len(extruder_names)
        except:
            pass
        
        # Build query for all extruders
        extruder_query = '&'.join([f'extruder{i}' if i > 0 else 'extruder' for i in range(extruder_count)])
        
        # Get printer objects
        objects_resp = await self._request('GET', 
            f'/printer/objects/query?{extruder_query}&heater_bed&print_stats&display_status&'
            'heater_generic%20chamber_heater&temperature_sensor%20chamber')
        
        if objects_resp and 'result' in objects_resp:
            data = objects_resp['result'].get('status', {})
            
            # Get primary extruder (extruder)
            ext = data.get('extruder', {})
            status.extruder_temp = ext.get('temperature', 0.0)
            status.extruder_target = ext.get('target', 0.0)
            
            # Get all extruder temperatures for multi-toolhead printers
            status.extruder_count = extruder_count
            if extruder_count > 1:
                status.extruder_temps = []
                for i in range(extruder_count):
                    ext_name = f'extruder{i}' if i > 0 else 'extruder'
                    ext_data = data.get(ext_name, {})
                    current = ext_data.get('temperature', 0.0)
                    target = ext_data.get('target', 0.0)
                    status.extruder_temps.append((current, target))
            
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
        
        # Get system info (OS, CPU temp, host info)
        try:
            resp = await self._request('GET', '/machine/system_info')
            if resp and 'result' in resp:
                sys_info = resp['result'].get('system_info', {})
                
                # OS info
                distro = sys_info.get('distribution', {})
                info.os_info = f"{distro.get('name', '')} {distro.get('version', '')}".strip()
                
                # CPU temp and model
                cpu_info = sys_info.get('cpu_info', {})
                cpu_temp = cpu_info.get('cpu_temp')
                if cpu_temp:
                    info.cpu_temp = cpu_temp
                
                # Host CPU model
                cpu_model = cpu_info.get('model', '')
                if cpu_model:
                    info.host_cpu = cpu_model
                
                # Memory info
                memory_info = sys_info.get('memory', {})
                if memory_info:
                    info.host_memory_total = memory_info.get('total', 0)
                    info.host_memory_used = memory_info.get('used', 0)
                
                # CPU usage
                cpu_usage = cpu_info.get('usage', 0)
                if cpu_usage:
                    info.host_cpu_usage = cpu_usage
                
                # Network info - get MAC address
                network = sys_info.get('network', {})
                for iface_name, iface_data in network.items():
                    mac = iface_data.get('mac_address', '')
                    if mac and mac != '00:00:00:00:00:00':
                        info.mac_address = mac
                        break  # Use first valid MAC
        except:
            pass
        
        # Get MCU info
        try:
            resp = await self._request('GET', '/printer/objects/query?mcu')
            if resp and 'result' in resp:
                mcu_data = resp['result'].get('status', {}).get('mcu', {})
                if mcu_data:
                    # MCU name from mcu_constants
                    mcu_constants = mcu_data.get('mcu_constants', {})
                    mcu_name = mcu_constants.get('MCU', '')
                    if mcu_name:
                        info.mcu_name = mcu_name
                    
                    # MCU version
                    mcu_version = mcu_data.get('mcu_version', '')
                    if mcu_version:
                        info.mcu_version = mcu_version
                    
                    # MCU frequency
                    freq = mcu_constants.get('CLOCK_FREQ', 0)
                    if freq:
                        freq_mhz = int(freq) / 1000000
                        info.mcu_freq = f"{freq_mhz:.0f}MHz"
        except:
            pass
        
        # Get system uptime from proc stats
        try:
            resp = await self._request('GET', '/machine/proc_stats')
            if resp and 'result' in resp:
                # System uptime in seconds
                uptime = resp['result'].get('system_uptime', 0)
                if uptime:
                    info.system_uptime = uptime
                
                # Also get CPU usage from here if not already set
                if info.host_cpu_usage == 0:
                    cpu_usage = resp['result'].get('system_cpu_usage', {}).get('cpu', 0)
                    if cpu_usage:
                        info.host_cpu_usage = cpu_usage
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
        
        # Check for Multi-Color Units (MMU/ERCF/AFC/Tradrack/QIDI BOX)
        try:
            # Query for various MMU systems
            resp = await self._request('GET', 
                '/printer/objects/query?mmu&ercf&AFC&tradrack')
            if resp and 'result' in resp:
                data = resp['result'].get('status', {})
                
                # Check for Happy Hare MMU (most common)
                mmu = data.get('mmu', {})
                if mmu:
                    info.mmu_enabled = True
                    info.mmu_type = "MMU"
                    info.mmu_gate_count = mmu.get('num_gates', mmu.get('gate_count', 0))
                    info.mmu_current_gate = mmu.get('gate', mmu.get('tool', -1))
                    info.mmu_filament_loaded = mmu.get('filament_loaded', False)
                
                # Check for ERCF
                ercf = data.get('ercf', {})
                if ercf and not info.mmu_enabled:
                    info.mmu_enabled = True
                    info.mmu_type = "ERCF"
                    info.mmu_gate_count = ercf.get('num_gates', 0)
                    info.mmu_current_gate = ercf.get('gate', -1)
                    info.mmu_filament_loaded = ercf.get('is_loaded', False)
                
                # Check for AFC (Armored Turtle)
                afc = data.get('AFC', {})
                if afc and not info.mmu_enabled:
                    info.mmu_enabled = True
                    info.mmu_type = "AFC"
                    info.mmu_gate_count = afc.get('lane_count', 0)
                    info.mmu_current_gate = afc.get('current_lane', -1)
                    info.mmu_filament_loaded = afc.get('loaded', False)
                
                # Check for Tradrack
                tradrack = data.get('tradrack', {})
                if tradrack and not info.mmu_enabled:
                    info.mmu_enabled = True
                    info.mmu_type = "Tradrack"
                    info.mmu_gate_count = tradrack.get('num_lanes', 0)
                    info.mmu_current_gate = tradrack.get('current_lane', -1)
        except:
            pass
        
        # Check for QIDI BOX (multi-color dryer unit with heaters)
        if not info.mmu_enabled:
            try:
                # QIDI BOX uses heater_generic for each channel
                resp = await self._request('GET', '/printer/objects/list')
                if resp and 'result' in resp:
                    objects = resp['result'].get('objects', [])
                    # Look for QIDI BOX heaters (heater_generic box_heater_* or similar)
                    box_heaters = [obj for obj in objects if 'box' in obj.lower() and 'heater' in obj.lower()]
                    if box_heaters:
                        info.mmu_enabled = True
                        info.mmu_type = "QIDI BOX"
                        info.mmu_gate_count = len(box_heaters)
                        
                        # Get heater temperatures
                        heater_query = '&'.join([h.replace(' ', '%20') for h in box_heaters])
                        temp_resp = await self._request('GET', f'/printer/objects/query?{heater_query}')
                        if temp_resp and 'result' in temp_resp:
                            temps = []
                            status = temp_resp['result'].get('status', {})
                            for heater in box_heaters:
                                heater_data = status.get(heater, {})
                                current = heater_data.get('temperature', 0)
                                target = heater_data.get('target', 0)
                                temps.append((current, target))
                            info.mmu_heater_temps = temps
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
                
                result = {
                    'shaper_type_x': shaper.get('shaper_type_x', ''),
                    'shaper_freq_x': shaper.get('shaper_freq_x', 0),
                    'shaper_type_y': shaper.get('shaper_type_y', ''),
                    'shaper_freq_y': shaper.get('shaper_freq_y', 0),
                    'damping_ratio_x': shaper.get('damping_ratio_x', 0.1),
                    'damping_ratio_y': shaper.get('damping_ratio_y', 0.1),
                    'config': config.get('input_shaper', {}),
                    'advice': [],
                    'max_accel_x': 0,
                    'max_accel_y': 0
                }
                
                # Generate advice based on shaper data
                freq_x = result['shaper_freq_x']
                freq_y = result['shaper_freq_y']
                shaper_type_x = result['shaper_type_x']
                shaper_type_y = result['shaper_type_y']
                
                # Calculate recommended max acceleration based on shaper type and frequency
                # Formula: max_accel = shaper_freq^2 * factor (factor depends on shaper type)
                accel_factors = {
                    'zv': 0.5, 'mzv': 0.4, 'zvd': 0.3, 'ei': 0.4,
                    '2hump_ei': 0.3, '3hump_ei': 0.25, 'smooth_zv': 0.35,
                    'smooth_mzv': 0.3, 'smooth_ei': 0.3
                }
                
                if freq_x > 0 and shaper_type_x:
                    factor = accel_factors.get(shaper_type_x.lower(), 0.4)
                    result['max_accel_x'] = int(freq_x * freq_x * factor * 100)
                
                if freq_y > 0 and shaper_type_y:
                    factor = accel_factors.get(shaper_type_y.lower(), 0.4)
                    result['max_accel_y'] = int(freq_y * freq_y * factor * 100)
                
                # Generate advice
                if freq_x > 0 and freq_x < 30:
                    result['advice'].append("⚠️ X axis frequency is low (<30Hz). Check frame rigidity and belt tension.")
                if freq_y > 0 and freq_y < 30:
                    result['advice'].append("⚠️ Y axis frequency is low (<30Hz). Check frame rigidity and belt tension.")
                
                if freq_x > 0 and freq_y > 0:
                    diff = abs(freq_x - freq_y)
                    if diff > 20:
                        result['advice'].append(f"ℹ️ Large frequency difference between axes ({diff:.1f}Hz). This is normal for CoreXY/bed-slinger.")
                
                if shaper_type_x and shaper_type_x.lower() in ['3hump_ei', 'smooth_ei']:
                    result['advice'].append("ℹ️ X axis uses aggressive smoothing. Consider checking for mechanical issues.")
                if shaper_type_y and shaper_type_y.lower() in ['3hump_ei', 'smooth_ei']:
                    result['advice'].append("ℹ️ Y axis uses aggressive smoothing. Consider checking for mechanical issues.")
                
                return result
        except:
            pass
        return None
    
    async def get_shaper_graph_files(self) -> List[str]:
        """Get list of Input Shaper calibration graph files"""
        try:
            # Check for resonance test results in /tmp
            resp = await self._request('GET', '/server/files/list?root=config')
            if resp and 'result' in resp:
                files = resp['result']
                # Look for shaper calibration PNG files
                shaper_files = [f['path'] for f in files 
                               if f['path'].endswith('.png') and 
                               ('shaper' in f['path'].lower() or 'resonance' in f['path'].lower())]
                return shaper_files
        except:
            pass
        return []
    
    async def download_shaper_graph(self, filename: str) -> Optional[bytes]:
        """Download a shaper calibration graph file"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/server/files/config/{filename}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        return await resp.read()
        except:
            pass
        return None
    
    async def list_config_files(self) -> List[Dict]:
        """List all configuration files"""
        try:
            resp = await self._request('GET', '/server/files/list?root=config')
            if resp and 'result' in resp:
                return resp['result']
        except:
            pass
        return []
    
    async def download_config_file(self, filename: str) -> Optional[bytes]:
        """Download a configuration file"""
        try:
            session = await self._get_session()
            url = f"{self.base_url}/server/files/config/{filename}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    return await resp.read()
        except:
            pass
        return None
    
    async def backup_all_configs(self, backup_dir: str, progress_callback=None) -> Dict:
        """Backup all configuration files to a local directory"""
        import zipfile
        from datetime import datetime
        
        result = {
            'success': False,
            'files_backed_up': 0,
            'total_files': 0,
            'backup_path': '',
            'errors': []
        }
        
        try:
            files = await self.list_config_files()
            result['total_files'] = len(files)
            
            if not files:
                result['errors'].append('No configuration files found')
                return result
            
            backup_path = Path(backup_dir)
            backup_path.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            printer_name = self.host.replace('.', '_').replace(':', '_')
            zip_filename = f"klipper_backup_{printer_name}_{timestamp}.zip"
            zip_path = backup_path / zip_filename
            
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for i, file_info in enumerate(files):
                    filename = file_info.get('path', '')
                    if not filename:
                        continue
                    
                    try:
                        content = await self.download_config_file(filename)
                        if content:
                            zipf.writestr(filename, content)
                            result['files_backed_up'] += 1
                    except Exception as e:
                        result['errors'].append(f"Failed to backup {filename}: {str(e)}")
                    
                    if progress_callback:
                        progress_callback(int((i + 1) / len(files) * 100))
            
            result['success'] = result['files_backed_up'] > 0
            result['backup_path'] = str(zip_path)
            
        except Exception as e:
            result['errors'].append(f"Backup failed: {str(e)}")
        
        return result

    async def get_thumbnail(self, filename: str) -> Optional[bytes]:
        """Get thumbnail image for a gcode file"""
        try:
            # URL encode the filename for the request
            import urllib.parse
            encoded_filename = urllib.parse.quote(filename, safe='')
            
            # First get the file metadata to find thumbnail path
            response = await self._request("GET", f"/server/files/metadata?filename={encoded_filename}")
            if not response or 'result' not in response:
                return None
            
            result = response.get('result', {})
            thumbnails = result.get('thumbnails', [])
            if not thumbnails:
                return None
            
            # Get the largest thumbnail
            largest = max(thumbnails, key=lambda t: t.get('width', 0) * t.get('height', 0))
            thumb_path = largest.get('relative_path', '')
            
            if not thumb_path:
                return None
            
            # Build the full path - thumbnail path is relative to the gcode file's directory
            # If filename has a directory, prepend it to the thumbnail path
            file_dir = '/'.join(filename.split('/')[:-1])
            if file_dir:
                full_thumb_path = f"{file_dir}/{thumb_path}"
            else:
                full_thumb_path = thumb_path
            
            # URL encode the thumbnail path
            encoded_thumb_path = urllib.parse.quote(full_thumb_path, safe='/')
            
            # Download the thumbnail
            thumb_url = f"{self.base_url}/server/files/gcodes/{encoded_thumb_path}"
            async with aiohttp.ClientSession() as session:
                headers = {}
                if self.api_key:
                    headers['X-Api-Key'] = self.api_key
                async with session.get(thumb_url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        return await resp.read()
        except Exception as e:
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
                        
                        # Try to get MAC address for unique identification
                        mac_address = ''
                        try:
                            sys_url = f"http://{host}:{port}/machine/system_info"
                            async with session.get(sys_url, timeout=aiohttp.ClientTimeout(total=2)) as sys_resp:
                                if sys_resp.status == 200:
                                    sys_data = await sys_resp.json()
                                    network = sys_data.get('result', {}).get('system_info', {}).get('network', {})
                                    for iface_name, iface_data in network.items():
                                        mac = iface_data.get('mac_address', '')
                                        if mac and mac != '00:00:00:00:00:00':
                                            mac_address = mac
                                            break
                        except:
                            pass
                        
                        return {
                            'host': host,
                            'port': port,
                            'hostname': hostname,
                            'auth_required': auth_required,
                            'mac_address': mac_address
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
    result_ready = pyqtSignal(object)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, coro):
        super().__init__()
        self.coro = coro
    
    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(self.coro)
            self.finished.emit(result)
            self.result_ready.emit(result)
        except Exception as e:
            self.error_occurred.emit(str(e))
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
        chart_rect = QRect(margin, 15, self.width() - margin - 10, self.height() - 35)
        
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
# Mini Temperature Chart Widget (for printer cards)
# =============================================================================

class MiniTemperatureChart(QWidget):
    """Compact temperature chart for printer cards"""
    
    MAX_POINTS = 30  # 30 data points for compact display
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(60)
        self.setMinimumWidth(100)
        
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
            max_val = max(all_temps)
            if max_val > 0:
                self.max_temp = max(100, max_val + 20)
        
        self.update()
    
    def clear_data(self):
        self.hotend_data.clear()
        self.bed_data.clear()
        self.chamber_data.clear()
        self.update()
    
    def paintEvent(self, event: QPaintEvent):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Background - slightly lighter for contrast
        bg_color = QColor(COLORS['bg_dark'])
        bg_color = bg_color.lighter(120)
        painter.fillRect(self.rect(), bg_color)
        
        # Chart area (minimal margins)
        margin_left = 5
        margin_right = 5
        margin_top = 5
        margin_bottom = 5
        chart_rect = QRect(margin_left, margin_top, 
                          self.width() - margin_left - margin_right, 
                          self.height() - margin_top - margin_bottom)
        
        # Draw subtle grid lines
        grid_color = QColor(COLORS['border'])
        grid_color.setAlpha(100)
        painter.setPen(QPen(grid_color, 1, Qt.PenStyle.DotLine))
        for i in range(3):
            y = chart_rect.top() + (chart_rect.height() * i // 2)
            painter.drawLine(chart_rect.left(), y, chart_rect.right(), y)
        
        # Draw data lines with glow effect
        def draw_line(data: deque, color: str, width: int = 2):
            if len(data) < 2:
                return
            
            path = QPainterPath()
            for i, temp in enumerate(data):
                x = chart_rect.left() + (chart_rect.width() * i // (self.MAX_POINTS - 1))
                y = chart_rect.bottom() - (chart_rect.height() * temp / self.max_temp) if self.max_temp > 0 else chart_rect.bottom()
                
                if i == 0:
                    path.moveTo(x, y)
                else:
                    path.lineTo(x, y)
            
            # Draw glow (thicker, semi-transparent)
            glow_color = QColor(color)
            glow_color.setAlpha(80)
            painter.setPen(QPen(glow_color, width + 3))
            painter.drawPath(path)
            
            # Draw main line
            painter.setPen(QPen(QColor(color), width))
            painter.drawPath(path)
        
        # Draw lines with increased width
        draw_line(self.hotend_data, COLORS['temp_hotend'], 3)
        draw_line(self.bed_data, COLORS['temp_bed'], 3)
        draw_line(self.chamber_data, COLORS['temp_chamber'], 2)
        
        # Draw border with accent color
        painter.setPen(QPen(QColor(COLORS['border']), 1))
        painter.drawRect(self.rect().adjusted(0, 0, -1, -1))


# =============================================================================
# Circular Progress Widget
# =============================================================================

class CircularProgress(QWidget):
    """Circular progress indicator widget"""
    
    def __init__(self, size=60, parent=None):
        super().__init__(parent)
        self._size = size
        self._value = 0
        self._max_value = 100
        self.setFixedSize(size, size)
    
    def setValue(self, value):
        self._value = max(0, min(value, self._max_value))
        self.update()
    
    def value(self):
        return self._value
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Calculate dimensions
        width = self.width()
        height = self.height()
        margin = 4
        pen_width = 6
        
        # Draw background circle
        painter.setPen(QPen(QColor(COLORS['border']), pen_width))
        painter.drawEllipse(margin, margin, width - 2*margin, height - 2*margin)
        
        # Draw progress arc
        if self._value > 0:
            painter.setPen(QPen(QColor(COLORS['accent']), pen_width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            span_angle = int(-self._value / self._max_value * 360 * 16)  # Negative for clockwise
            painter.drawArc(margin, margin, width - 2*margin, height - 2*margin, 90 * 16, span_angle)
        
        # Draw percentage text
        painter.setPen(QColor(COLORS['text']))
        font_size = max(8, self._size // 5)
        painter.setFont(QFont("Play", font_size, QFont.Weight.Bold))
        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, f"{int(self._value)}%")


# =============================================================================
# Printer Card Widget
# =============================================================================

class PrinterCard(QFrame):
    """Cyberpunk-style printer status card with state-based border colors"""
    
    camera_clicked = pyqtSignal(str)  # webcam_url
    card_clicked = pyqtSignal(object)  # self - emitted when card is clicked
    login_requested = pyqtSignal(object)  # self - emitted when login is requested
    
    # State-based border colors
    STATE_COLORS = {
        'ready': '#00ff88',      # Green
        'printing': '#0ABAB5',   # Tiffany Blue
        'paused': '#ffaa00',     # Orange
        'error': '#ff4444',      # Red
        'unauthorized': '#ff8800',  # Orange-red (login required)
        'forbidden': '#ff4444',  # Red (access denied)
        'offline': '#555555',    # Gray
    }
    
    def __init__(self, config: PrinterConfig, compact_mode: bool = False, parent=None):
        super().__init__(parent)
        self.config = config
        self.compact_mode = compact_mode
        self.status = PrinterStatus()
        self.stats = PrinterStats()
        self.system_info = SystemInfo()
        self.client: Optional[MoonrakerClient] = None
        self._selected = False
        self._current_state = 'offline'
        self._camera_url = None
        self._camera_timer = None
        self._thumbnail_timer = None
        self._current_filename = None  # Track current print file for thumbnail
        self._setup_ui()
        self._apply_style()
        if not compact_mode:
            self._setup_camera_timer()
    
    def _setup_camera_timer(self):
        """Setup timer for camera preview updates"""
        self._camera_timer = QTimer(self)
        self._camera_timer.timeout.connect(self._update_camera_preview)
        self._camera_timer.start(15000)  # Update every 15 seconds (reduced for performance)
        
        # Setup thumbnail timer
        self._thumbnail_timer = QTimer(self)
        self._thumbnail_timer.timeout.connect(self._update_thumbnail)
        self._thumbnail_timer.start(30000)  # Update every 30 seconds
    
    def _update_camera_preview(self):
        """Fetch and update camera preview image"""
        # Check if camera is disabled for this printer
        if not self.config.camera_enabled:
            return
        if not self._camera_url or not self.camera_preview:
            return
        
        try:
            # Use snapshot URL instead of stream for preview
            snapshot_url = self._camera_url.replace('?action=stream', '?action=snapshot')
            if '?action=' not in snapshot_url:
                snapshot_url = snapshot_url.rstrip('/') + '?action=snapshot'
            
            # Fetch image in background thread
            import urllib.request
            req = urllib.request.Request(snapshot_url, headers={'User-Agent': 'KlipperBuddy'})
            with urllib.request.urlopen(req, timeout=2) as response:
                data = response.read()
                pixmap = QPixmap()
                pixmap.loadFromData(data)
                if not pixmap.isNull():
                    # setScaledContents(True) handles scaling automatically
                    self.camera_preview.setPixmap(pixmap)
                    self.camera_preview.setStyleSheet("")
        except Exception as e:
            # Keep showing "No Camera" on error
            pass
    
    def _update_thumbnail(self):
        """Fetch and update thumbnail for current print using synchronous HTTP request"""
        if not self._current_filename:
            return
        
        if not self.config:
            return
        
        try:
            import urllib.request
            import urllib.parse
            
            # Build the metadata URL
            encoded_filename = urllib.parse.quote(self._current_filename, safe='')
            base_url = f"http://{self.config.host}:{self.config.port}"
            metadata_url = f"{base_url}/server/files/metadata?filename={encoded_filename}"
            
            print(f"[DEBUG] Fetching thumbnail metadata from: {metadata_url}")
            
            # Fetch metadata
            req = urllib.request.Request(metadata_url, headers={'User-Agent': 'KlipperBuddy'})
            with urllib.request.urlopen(req, timeout=5) as response:
                import json
                data = json.loads(response.read().decode('utf-8'))
            
            if 'result' not in data:
                print(f"[DEBUG] No result in metadata response")
                return
            
            result = data.get('result', {})
            thumbnails = result.get('thumbnails', [])
            
            if not thumbnails:
                print(f"[DEBUG] No thumbnails found in metadata")
                return
            
            print(f"[DEBUG] Found {len(thumbnails)} thumbnails")
            
            # Get the largest thumbnail
            largest = max(thumbnails, key=lambda t: t.get('width', 0) * t.get('height', 0))
            thumb_path = largest.get('relative_path', '')
            
            if not thumb_path:
                print(f"[DEBUG] No relative_path in thumbnail")
                return
            
            print(f"[DEBUG] Thumbnail relative_path: {thumb_path}")
            
            # Build the full path - thumbnail path is relative to the gcode file's directory
            file_dir = '/'.join(self._current_filename.split('/')[:-1])
            if file_dir:
                full_thumb_path = f"{file_dir}/{thumb_path}"
            else:
                full_thumb_path = thumb_path
            
            # URL encode the thumbnail path
            encoded_thumb_path = urllib.parse.quote(full_thumb_path, safe='/')
            thumb_url = f"{base_url}/server/files/gcodes/{encoded_thumb_path}"
            
            print(f"[DEBUG] Downloading thumbnail from: {thumb_url}")
            
            # Download the thumbnail
            req = urllib.request.Request(thumb_url, headers={'User-Agent': 'KlipperBuddy'})
            with urllib.request.urlopen(req, timeout=5) as response:
                thumb_data = response.read()
            
            if thumb_data:
                pixmap = QPixmap()
                pixmap.loadFromData(thumb_data)
                if not pixmap.isNull():
                    # setScaledContents(True) handles scaling automatically
                    self.thumbnail_label.setPixmap(pixmap)
                    self.thumbnail_label.setStyleSheet("")
                    print(f"[DEBUG] Thumbnail loaded successfully")
                else:
                    print(f"[DEBUG] Failed to load pixmap from thumbnail data")
        except Exception as e:
            print(f"[DEBUG] Thumbnail fetch error: {e}")
            pass
    
    def update_thumbnail_from_filename(self, filename: str):
        """Update thumbnail when filename changes"""
        if filename != self._current_filename:
            self._current_filename = filename
            if filename:
                print(f"[DEBUG] Updating thumbnail for: {filename}")
                # Trigger immediate thumbnail update
                self._update_thumbnail()
            else:
                # Clear thumbnail
                self.thumbnail_label.setText("No Print")
                self.thumbnail_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 9px;")
    
    def _setup_ui(self):
        if self.compact_mode:
            self.setFixedSize(230, 320)  # Compact card (6 columns at 1920)
        else:
            self.setFixedSize(320, 380)  # Standard card with camera + thumbnail
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(4)
        
        # Header with name and status indicator
        header = QHBoxLayout()
        
        self.status_indicator = QLabel("●")
        self.status_indicator.setFont(QFont("Arial", 14))
        header.addWidget(self.status_indicator)
        
        self.name_label = QLabel(self.config.name or self.config.host)
        self.name_label.setFont(QFont("Play", 11 if self.compact_mode else 12, QFont.Weight.Bold))
        self.name_label.setStyleSheet(f"color: {COLORS['accent']};")
        self.name_label.setMaximumWidth(140 if self.compact_mode else 200)
        self.name_label.setToolTip(self.config.name or self.config.host)
        header.addWidget(self.name_label)
        header.addStretch()
        
        self.state_label = QLabel("OFFLINE")
        self.state_label.setFont(QFont("Play", 10, QFont.Weight.Bold))
        header.addWidget(self.state_label)
        
        layout.addLayout(header)
        
        # Camera + Thumbnail + Progress section (horizontal layout)
        media_section = QHBoxLayout()
        media_section.setSpacing(6)
        
        # Camera preview - MUCH LARGER with fixed size label
        if not self.compact_mode:
            self.camera_frame = QFrame()
            self.camera_frame.setFixedSize(130, 100)  # Much larger camera
            self.camera_frame.setStyleSheet(f"""
                QFrame {{
                    background-color: #0a0a0a;
                    border: 1px solid {COLORS['border']};
                    border-radius: 4px;
                }}
            """)
            camera_layout = QHBoxLayout(self.camera_frame)
            camera_layout.setContentsMargins(2, 2, 2, 2)
            camera_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            self.camera_preview = QLabel("No Camera")
            self.camera_preview.setFixedSize(126, 96)  # Fixed size = frame - margins
            self.camera_preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.camera_preview.setScaledContents(True)  # Scale image to fill label
            self.camera_preview.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 9px;")
            camera_layout.addWidget(self.camera_preview)
            media_section.addWidget(self.camera_frame)
        else:
            self.camera_frame = None
            self.camera_preview = None
        
        # Thumbnail preview - MUCH LARGER with fixed size label
        self.thumbnail_frame = QFrame()
        thumb_size = 80 if self.compact_mode else 100  # Much larger thumbnail
        self.thumbnail_frame.setFixedSize(thumb_size, thumb_size)
        self.thumbnail_frame.setStyleSheet(f"""
            QFrame {{
                background-color: #0a0a0a;
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
            }}
        """)
        thumb_layout = QHBoxLayout(self.thumbnail_frame)
        thumb_layout.setContentsMargins(2, 2, 2, 2)
        thumb_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        thumb_label_size = 76 if self.compact_mode else 96  # Fixed size = frame - margins
        self.thumbnail_label = QLabel("No Print")
        self.thumbnail_label.setFixedSize(thumb_label_size, thumb_label_size)
        self.thumbnail_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.thumbnail_label.setScaledContents(True)  # Scale image to fill label
        self.thumbnail_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 9px;")
        thumb_layout.addWidget(self.thumbnail_label)
        media_section.addWidget(self.thumbnail_frame)
        
        # Circular progress - LARGER
        progress_size = 70 if self.compact_mode else 80  # Much larger progress
        self.circular_progress = CircularProgress(progress_size)
        media_section.addWidget(self.circular_progress)
        
        layout.addLayout(media_section)
        
        # Compact temperature display (single row)
        temp_row = QHBoxLayout()
        temp_row.setSpacing(4)
        
        # T0 temperature
        self.ext_label = QLabel("T0")
        self.ext_label.setFont(QFont("Play", 9))
        self.ext_label.setStyleSheet(f"color: {COLORS['temp_hotend']};")
        temp_row.addWidget(self.ext_label)
        
        self.ext_temp_label = QLabel("--/--°C")
        self.ext_temp_label.setFont(QFont("Play", 9))
        self.ext_temp_label.setStyleSheet(f"color: {COLORS['text']};")
        temp_row.addWidget(self.ext_temp_label)
        
        temp_row.addWidget(QLabel("|"))
        
        # Bed temperature
        bed_label = QLabel("Bed")
        bed_label.setFont(QFont("Play", 9))
        bed_label.setStyleSheet(f"color: {COLORS['temp_bed']};")
        temp_row.addWidget(bed_label)
        
        self.bed_temp_label = QLabel("--/--°C")
        self.bed_temp_label.setFont(QFont("Play", 9))
        self.bed_temp_label.setStyleSheet(f"color: {COLORS['text']};")
        temp_row.addWidget(self.bed_temp_label)
        
        temp_row.addWidget(QLabel("|"))
        
        # Chamber temperature
        ch_label = QLabel("Ch")
        ch_label.setFont(QFont("Play", 9))
        ch_label.setStyleSheet(f"color: {COLORS['temp_chamber']};")
        temp_row.addWidget(ch_label)
        
        self.chamber_temp_label = QLabel("--°C")
        self.chamber_temp_label.setFont(QFont("Play", 9))
        self.chamber_temp_label.setStyleSheet(f"color: {COLORS['text']};")
        temp_row.addWidget(self.chamber_temp_label)
        
        temp_row.addStretch()
        layout.addLayout(temp_row)
        
        # Multi-extruder row (T1, T2, T3... - hidden by default)
        self.multi_ext_row_widget = QWidget()
        multi_ext_layout = QHBoxLayout(self.multi_ext_row_widget)
        multi_ext_layout.setContentsMargins(0, 0, 0, 0)
        multi_ext_layout.setSpacing(4)
        
        self.multi_ext_labels = []
        for i in range(1, 6):
            label = QLabel(f"T{i}")
            label.setFont(QFont("Play", 8))
            label.setStyleSheet(f"color: {COLORS['text_secondary']};")
            multi_ext_layout.addWidget(label)
            
            temp_label = QLabel("--°C")
            temp_label.setFont(QFont("Play", 8))
            temp_label.setStyleSheet(f"color: {COLORS['text_primary']};")
            multi_ext_layout.addWidget(temp_label)
            
            if i < 5:
                sep = QLabel("|")
                sep.setFont(QFont("Play", 8))
                sep.setStyleSheet(f"color: {COLORS['text_muted']};")
                multi_ext_layout.addWidget(sep)
            
            self.multi_ext_labels.append((label, temp_label))
        
        multi_ext_layout.addStretch()
        self.multi_ext_row_widget.setVisible(False)
        layout.addWidget(self.multi_ext_row_widget)
        
        # Filename + ETA row
        info_row = QHBoxLayout()
        info_row.setSpacing(8)
        
        self.filename_label = QLabel("No active print")
        self.filename_label.setFont(QFont("Play", 9))
        self.filename_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        self.filename_label.setWordWrap(False)
        max_fn_width = 130 if self.compact_mode else 180
        self.filename_label.setMaximumWidth(max_fn_width)
        info_row.addWidget(self.filename_label)
        
        info_row.addStretch()
        
        self.eta_label = QLabel("ETA: --:--")
        self.eta_label.setFont(QFont("Play", 9))
        self.eta_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        info_row.addWidget(self.eta_label)
        
        layout.addLayout(info_row)
        
        # System info row (MCU, Host, Uptime)
        sys_info_row = QHBoxLayout()
        sys_info_row.setSpacing(4)
        
        self.mcu_label = QLabel("MCU: --")
        self.mcu_label.setFont(QFont("Play", 8))
        self.mcu_label.setStyleSheet(f"color: {COLORS['text_muted']};")
        sys_info_row.addWidget(self.mcu_label)
        
        sep1 = QLabel("|")
        sep1.setFont(QFont("Play", 8))
        sep1.setStyleSheet(f"color: {COLORS['text_muted']};")
        sys_info_row.addWidget(sep1)
        
        self.host_info_label = QLabel("Host: --")
        self.host_info_label.setFont(QFont("Play", 8))
        self.host_info_label.setStyleSheet(f"color: {COLORS['text_muted']};")
        sys_info_row.addWidget(self.host_info_label)
        
        sep2 = QLabel("|")
        sep2.setFont(QFont("Play", 8))
        sep2.setStyleSheet(f"color: {COLORS['text_muted']};")
        sys_info_row.addWidget(sep2)
        
        self.uptime_label = QLabel("Up: --")
        self.uptime_label.setFont(QFont("Play", 8))
        self.uptime_label.setStyleSheet(f"color: {COLORS['text_muted']};")
        sys_info_row.addWidget(self.uptime_label)
        
        sys_info_row.addStretch()
        layout.addLayout(sys_info_row)
        
        # Keep progress_bar and progress_label for compatibility (hidden)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_label = QLabel()
        self.progress_label.setVisible(False)
        
        # Temp container for compatibility
        self.temp_container = QWidget()
        self.temp_layout = QVBoxLayout(self.temp_container)
        self.temp_container.setVisible(False)
        
        # Mini temperature chart
        self.mini_chart = MiniTemperatureChart()
        layout.addWidget(self.mini_chart)
        
        # Action buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)
        
        btn_style = f"""
            QPushButton {{
                background-color: {COLORS['bg_dark']};
                border: 1px solid {COLORS['accent']};
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent']};
            }}
        """
        
        # Camera button
        self.camera_btn = QPushButton()
        self.camera_btn.setIcon(get_icon("camera"))
        self.camera_btn.setIconSize(QPixmap(20, 20).size())
        self.camera_btn.setFixedSize(40, 32)
        self.camera_btn.setToolTip("View Camera")
        self.camera_btn.setStyleSheet(btn_style)
        self.camera_btn.clicked.connect(self._on_camera_click)
        self.camera_btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.camera_btn.customContextMenuRequested.connect(self._show_camera_menu)
        btn_layout.addWidget(self.camera_btn)
        
        # Graph button
        self.graph_btn = QPushButton()
        self.graph_btn.setIcon(get_icon("graph"))
        self.graph_btn.setIconSize(QPixmap(20, 20).size())
        self.graph_btn.setFixedSize(40, 32)
        self.graph_btn.setToolTip("Temperature Graph")
        self.graph_btn.setStyleSheet(btn_style)
        self.graph_btn.clicked.connect(self._on_graph_click)
        btn_layout.addWidget(self.graph_btn)
        
        # Web button
        self.web_btn = QPushButton()
        self.web_btn.setIcon(get_icon("web"))
        self.web_btn.setIconSize(QPixmap(20, 20).size())
        self.web_btn.setFixedSize(40, 32)
        self.web_btn.setToolTip("Open Web Interface")
        self.web_btn.setStyleSheet(btn_style)
        self.web_btn.clicked.connect(self._on_web_click)
        btn_layout.addWidget(self.web_btn)
        
        # Login button (hidden by default)
        self.login_btn = QPushButton("🔐")
        self.login_btn.setFixedSize(40, 32)
        self.login_btn.setToolTip("Login Required")
        self.login_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['bg_dark']};
                border: 1px solid #ff8800;
                border-radius: 4px;
                color: #ff8800;
                font-size: 14px;
            }}
            QPushButton:hover {{
                background-color: #ff8800;
                color: {COLORS['bg_dark']};
            }}
        """)
        self.login_btn.clicked.connect(self._on_login_click)
        self.login_btn.setVisible(False)
        btn_layout.addWidget(self.login_btn)
        
        btn_layout.addStretch()
        
        layout.addLayout(btn_layout)
        
        # Host info
        self.host_label = QLabel(f"{self.config.host}:{self.config.port}")
        self.host_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 8px;")
        layout.addWidget(self.host_label)
    
    def _apply_style(self, selected: bool = False):
        # Get border color based on printer state
        state_color = self.STATE_COLORS.get(self._current_state, COLORS['border'])
        
        if selected:
            # Selected: thick border with state color + strong glow
            self.setStyleSheet(f"""
                PrinterCard {{
                    background-color: #1a1a1a;
                    border: 3px solid {state_color};
                    border-radius: 10px;
                }}
            """)
            shadow = QGraphicsDropShadowEffect()
            shadow.setBlurRadius(40)
            shadow.setColor(QColor(state_color))
            shadow.setOffset(0, 0)
            self.setGraphicsEffect(shadow)
        else:
            # Not selected: thin border with state color + subtle glow
            self.setStyleSheet(f"""
                PrinterCard {{
                    background-color: {COLORS['bg_card']};
                    border: 2px solid {state_color};
                    border-radius: 8px;
                }}
                PrinterCard:hover {{
                    background-color: #1a1a1a;
                }}
            """)
            shadow = QGraphicsDropShadowEffect()
            shadow.setBlurRadius(15)
            shadow.setColor(QColor(state_color))
            shadow.setOffset(0, 0)
            self.setGraphicsEffect(shadow)
    
    def set_selected(self, selected: bool):
        self._selected = selected
        self._apply_style(selected)
        # Also update name label style for selected state
        if selected:
            self.name_label.setStyleSheet(f"color: {COLORS['accent']}; font-size: 15px;")
        else:
            self.name_label.setStyleSheet(f"color: {COLORS['accent']};")
            self.name_label.setFont(QFont("Play", 14, QFont.Weight.Bold))
    
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
    
    def toggle_camera(self):
        """Toggle camera preview on/off for this printer"""
        self.config.camera_enabled = not self.config.camera_enabled
        if self.camera_preview:
            if self.config.camera_enabled:
                self.camera_preview.setText("Loading...")
                self._update_camera_preview()
            else:
                self.camera_preview.setText("Camera Off")
                self.camera_preview.setPixmap(QPixmap())
    
    def _show_camera_menu(self, pos):
        """Show context menu for camera button"""
        from PyQt6.QtWidgets import QMenu
        menu = QMenu(self)
        menu.setStyleSheet(f"""
            QMenu {{
                background-color: {COLORS['bg_secondary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['accent']};
            }}
            QMenu::item:selected {{
                background-color: {COLORS['accent']};
            }}
        """)
        
        if self.config.camera_enabled:
            action = menu.addAction("🚫 Disable Camera Preview")
        else:
            action = menu.addAction("📷 Enable Camera Preview")
        
        action.triggered.connect(self.toggle_camera)
        menu.exec(self.camera_btn.mapToGlobal(pos))
    
    def _on_graph_click(self):
        self.card_clicked.emit(self)
    
    def _on_web_click(self):
        url = f"http://{self.config.host}"
        webbrowser.open(url)
    
    def _on_login_click(self):
        """Show login dialog for authentication"""
        print(f"Login button clicked for {self.config.host}:{self.config.port}")
        try:
            dialog = LoginDialog(self.config.host, self.config.port, self)
            result = dialog.exec()
            print(f"Dialog result: {result}")
            if result == QDialog.DialogCode.Accepted:
                username, password = dialog.get_credentials()
                # Update config with credentials
                self.config.username = username
                self.config.password = password
                # Emit signal to save config and refresh
                self.login_btn.setVisible(False)
                # Trigger refresh with new credentials
                if self.client:
                    self.client.username = username
                    self.client.password = password
                    self.client._token = None  # Clear old token
                    if self.client._session:
                        import asyncio
                        try:
                            loop = asyncio.get_event_loop()
                            if loop.is_running():
                                asyncio.ensure_future(self.client._session.close())
                            else:
                                loop.run_until_complete(self.client._session.close())
                        except:
                            pass
                        self.client._session = None
                # Emit signal to trigger status refresh
                self.login_requested.emit(self)
        except Exception as e:
            print(f"Login dialog error: {e}")
            import traceback
            traceback.print_exc()
    
    def update_status(self, status: PrinterStatus):
        self.status = status
        
        # Update state and re-apply style if state changed
        old_state = self._current_state
        self._current_state = status.state
        if old_state != status.state:
            self._apply_style(self._selected)
        
        # Update state indicator
        state_colors = {
            'ready': COLORS['success'],
            'printing': COLORS['accent'],
            'paused': COLORS['warning'],
            'error': COLORS['error'],
            'unauthorized': '#ff8800',  # Orange-red
            'forbidden': COLORS['error'],
            'offline': COLORS['text_muted'],
        }
        # Map state to display text
        state_display = {
            'ready': 'READY',
            'printing': 'PRINTING',
            'paused': 'PAUSED',
            'error': 'ERROR',
            'unauthorized': 'LOGIN REQ',
            'forbidden': 'DENIED',
            'offline': 'OFFLINE',
        }
        color = state_colors.get(status.state, COLORS['text_muted'])
        self.status_indicator.setStyleSheet(f"color: {color};")
        self.state_label.setText(state_display.get(status.state, status.state.upper()))
        self.state_label.setStyleSheet(f"color: {color};")
        
        # Show state message as tooltip if available
        if status.state_message:
            self.state_label.setToolTip(status.state_message)
        
        # Show/hide login button based on auth state
        if status.state in ('unauthorized', 'forbidden'):
            self.login_btn.setVisible(True)
        else:
            self.login_btn.setVisible(False)
        
        # Update temperatures (compact format)
        # Handle multi-extruder printers (like Snapmaker U1 with 4 toolheads)
        if status.extruder_count > 1 and status.extruder_temps:
            # Show T0 for first extruder (compact format)
            self.ext_label.setText("T0")
            if status.extruder_target > 0:
                self.ext_temp_label.setText(f"{status.extruder_temp:.0f}/{status.extruder_target:.0f}°C")
            else:
                self.ext_temp_label.setText(f"{status.extruder_temp:.0f}°C")
            
            # Show additional extruders horizontally (T1, T2, T3, etc.)
            self.multi_ext_row_widget.setVisible(True)
            for i, (label, temp_label) in enumerate(self.multi_ext_labels):
                ext_idx = i + 1  # T1 = index 1, T2 = index 2, etc.
                if ext_idx < status.extruder_count:
                    label.setVisible(True)
                    temp_label.setVisible(True)
                    current, target = status.extruder_temps[ext_idx]
                    if target > 0:
                        temp_label.setText(f"{current:.0f}/{target:.0f}°C")
                    else:
                        temp_label.setText(f"{current:.0f}°C")
                else:
                    label.setVisible(False)
                    temp_label.setVisible(False)
        else:
            # Single extruder - hide multi-extruder row (compact format)
            self.ext_label.setText("T0")
            if status.extruder_target > 0:
                self.ext_temp_label.setText(f"{status.extruder_temp:.0f}/{status.extruder_target:.0f}°C")
            else:
                self.ext_temp_label.setText(f"{status.extruder_temp:.0f}°C")
            self.multi_ext_row_widget.setVisible(False)
        
        # Bed temperature (compact format)
        if status.bed_target > 0:
            self.bed_temp_label.setText(f"{status.bed_temp:.0f}/{status.bed_target:.0f}°C")
        else:
            self.bed_temp_label.setText(f"{status.bed_temp:.0f}°C")
        
        # Chamber temperature
        self.chamber_temp_label.setText(f"{status.chamber_temp:.0f}°C" if status.chamber_temp > 0 else "--°C")
        
        # Update mini temperature chart
        self.mini_chart.add_data(status.extruder_temp, status.bed_temp, status.chamber_temp)
        
        # Update print info and thumbnail
        if status.filename:
            # Truncate filename if too long (shorter for compact mode)
            fn = status.filename
            max_len = 20 if self.compact_mode else 35
            if len(fn) > max_len:
                fn = fn[:max_len-3] + "..."
            self.filename_label.setText(fn)
            self.filename_label.setToolTip(status.filename)  # Full name in tooltip
            self.filename_label.setStyleSheet(f"color: {COLORS['text_primary']};")
            # Update thumbnail if filename changed
            self.update_thumbnail_from_filename(status.filename)
        else:
            self.filename_label.setText("No active print")
            self.filename_label.setToolTip("")
            self.filename_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
            # Clear thumbnail
            self.update_thumbnail_from_filename(None)
        
        
        # Update progress (circular progress)
        self.circular_progress.setValue(status.progress)
        
        # Also update hidden progress_bar for compatibility
        self.progress_bar.setValue(int(status.progress))
        self.progress_label.setText(f"{status.progress:.1f}%")
        
        # Update ETA (compact format - hours:minutes only)
        if status.eta_seconds > 0:
            hours = int(status.eta_seconds // 3600)
            minutes = int((status.eta_seconds % 3600) // 60)
            if hours > 0:
                self.eta_label.setText(f"ETA: {hours}h{minutes:02d}m")
            else:
                self.eta_label.setText(f"ETA: {minutes}m")
        else:
            self.eta_label.setText("ETA: --")
    
    def update_stats(self, stats: PrinterStats):
        self.stats = stats
    
    def update_system_info(self, info: SystemInfo):
        self.system_info = info
        
        # Save MAC address to config for unique identification
        if info.mac_address and not self.config.mac_address:
            self.config.mac_address = info.mac_address
            # Save to config file
            try:
                if hasattr(self, 'parent') and hasattr(self.parent(), 'config_manager'):
                    self.parent().config_manager.save()
            except:
                pass
        
        # Update camera URL if available
        if info.webcam_url:
            self._camera_url = info.webcam_url
        else:
            # Try default webcam URL
            self._camera_url = f"http://{self.config.host}/webcam/?action=stream"
        
        # Update MCU info
        if info.mcu_name:
            self.mcu_label.setText(f"MCU: {info.mcu_name}")
        elif info.mcu_version:
            # Show version if name not available
            ver = info.mcu_version[:15] if len(info.mcu_version) > 15 else info.mcu_version
            self.mcu_label.setText(f"MCU: {ver}")
        else:
            self.mcu_label.setText("MCU: --")
        
        # Add tooltip with all MCU details
        if info.mcu_list and len(info.mcu_list) > 0:
            tooltip_lines = ["MCU Information:"]
            for mcu_name, mcu_type, mcu_ver in info.mcu_list:
                if mcu_type:
                    tooltip_lines.append(f"  {mcu_name}: {mcu_type}")
                elif mcu_ver:
                    tooltip_lines.append(f"  {mcu_name}: {mcu_ver[:30]}")
                else:
                    tooltip_lines.append(f"  {mcu_name}")
            self.mcu_label.setToolTip("\n".join(tooltip_lines))
        else:
            self.mcu_label.setToolTip("")
        
        # Update Host info (CPU model + memory usage)
        if info.host_cpu:
            # Shorten CPU model name
            cpu = info.host_cpu
            if len(cpu) > 20:
                cpu = cpu[:17] + "..."
            if info.host_memory_total > 0:
                mem_pct = (info.host_memory_used / info.host_memory_total) * 100
                self.host_info_label.setText(f"{cpu} ({mem_pct:.0f}%)")
            else:
                self.host_info_label.setText(f"{cpu}")
        else:
            self.host_info_label.setText("Host: --")
        
        # Update Uptime
        if info.system_uptime > 0:
            uptime_secs = info.system_uptime
            days = int(uptime_secs // 86400)
            hours = int((uptime_secs % 86400) // 3600)
            mins = int((uptime_secs % 3600) // 60)
            if days > 0:
                self.uptime_label.setText(f"Up: {days}d {hours}h")
            elif hours > 0:
                self.uptime_label.setText(f"Up: {hours}h {mins}m")
            else:
                self.uptime_label.setText(f"Up: {mins}m")
        else:
            self.uptime_label.setText("Up: --")
    
    def set_name(self, name: str):
        self.config.name = name
        self.name_label.setText(name)
    
    def update_privacy_mode(self, privacy_enabled: bool):
        """Update display based on privacy mode setting"""
        if privacy_enabled:
            self.host_label.setText("***")
        else:
            self.host_label.setText(f"{self.config.host}:{self.config.port}")


# =============================================================================
# Statistics Panel Widget
# =============================================================================

class StatsPanel(QFrame):
    """Statistics and system info panel with internal scrolling"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)
        self._setup_ui()
        self._apply_style()
    
    def _setup_ui(self):
        # Main layout for the frame
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Create scroll area inside the panel
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setStyleSheet(f"""
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
                background-color: {COLORS['border']};
                border-radius: 4px;
                min-height: 20px;
            }}
            QScrollBar::handle:vertical:hover {{
                background-color: {COLORS['accent']};
            }}
        """)
        
        # Content widget inside scroll area
        content_widget = QWidget()
        layout = QVBoxLayout(content_widget)
        layout.setContentsMargins(6, 6, 12, 6)  # Compact margins
        layout.setSpacing(3)
        
        # Selected printer name
        self.printer_name_label = QLabel("Select a printer")
        self.printer_name_label.setFont(QFont("Play", 12, QFont.Weight.Bold))
        self.printer_name_label.setStyleSheet(f"color: {COLORS['accent']};")
        self.printer_name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.printer_name_label.setWordWrap(True)  # Allow wrapping for long names
        layout.addWidget(self.printer_name_label)
        
        # Temperature Graph
        graph_header = QHBoxLayout()
        graph_header.setSpacing(4)
        graph_icon = QLabel()
        graph_icon.setPixmap(get_icon("temperature").pixmap(14, 14))
        graph_header.addWidget(graph_icon)
        graph_label = QLabel("TEMPERATURE GRAPH")
        graph_label.setFont(QFont("Play", 9, QFont.Weight.Bold))
        graph_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        graph_header.addWidget(graph_label)
        graph_header.addStretch()
        layout.addLayout(graph_header)
        
        self.temp_chart = TemperatureChart()
        self.temp_chart.setMinimumHeight(80)
        self.temp_chart.setMaximumHeight(80)
        layout.addWidget(self.temp_chart)
        
        # Current temps display
        temp_display = QHBoxLayout()
        temp_display.setSpacing(2)
        
        self.hotend_label = QLabel("Hotend: --°C")
        self.hotend_label.setFont(QFont("Play", 8))
        self.hotend_label.setStyleSheet(f"color: {COLORS['temp_hotend']};")
        temp_display.addWidget(self.hotend_label)
        
        self.bed_label = QLabel("Bed: --°C")
        self.bed_label.setFont(QFont("Play", 8))
        self.bed_label.setStyleSheet(f"color: {COLORS['temp_bed']};")
        temp_display.addWidget(self.bed_label)
        
        self.chamber_label = QLabel("Chamber: --°C")
        self.chamber_label.setFont(QFont("Play", 8))
        self.chamber_label.setStyleSheet(f"color: {COLORS['temp_chamber']};")
        temp_display.addWidget(self.chamber_label)
        
        layout.addLayout(temp_display)
        
        # Separator
        line1 = QFrame()
        line1.setFrameShape(QFrame.Shape.HLine)
        line1.setStyleSheet(f"background-color: {COLORS['border']}; max-height: 1px;")
        layout.addWidget(line1)
        
        # Camera Preview section
        cam_header = QHBoxLayout()
        cam_header.setSpacing(4)
        cam_icon = QLabel()
        cam_icon.setPixmap(get_icon("camera").pixmap(14, 14))
        cam_header.addWidget(cam_icon)
        cam_label = QLabel("CAMERA PREVIEW")
        cam_label.setFont(QFont("Play", 9, QFont.Weight.Bold))
        cam_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        cam_header.addWidget(cam_label)
        cam_header.addStretch()
        layout.addLayout(cam_header)
        
        self.camera_frame = QFrame()
        # Camera preview size: 180px height for better visibility
        self.camera_frame.setFixedHeight(180)
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
        self.camera_image.setMinimumHeight(140)  # Increased from 80
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
        stats_header = QHBoxLayout()
        stats_header.setSpacing(4)
        stats_icon = QLabel()
        stats_icon.setPixmap(get_icon("stats").pixmap(14, 14))
        stats_header.addWidget(stats_icon)
        stats_label = QLabel("STATISTICS")
        stats_label.setFont(QFont("Play", 9, QFont.Weight.Bold))
        stats_label.setStyleSheet(f"color: {COLORS['accent']};")
        stats_header.addWidget(stats_label)
        stats_header.addStretch()
        layout.addLayout(stats_header)
        
        stats_grid = QGridLayout()
        stats_grid.setSpacing(1)
        
        # Total Print Time
        lbl = QLabel("Total Print Time:")
        lbl.setFont(QFont("Play", 8))
        stats_grid.addWidget(lbl, 0, 0)
        self.total_time_label = QLabel("--")
        self.total_time_label.setFont(QFont("Play", 8, QFont.Weight.Bold))
        self.total_time_label.setStyleSheet(f"color: {COLORS['accent']};")
        stats_grid.addWidget(self.total_time_label, 0, 1)
        
        # Total Filament
        lbl = QLabel("Filament Used:")
        lbl.setFont(QFont("Play", 8))
        stats_grid.addWidget(lbl, 1, 0)
        self.total_filament_label = QLabel("--")
        self.total_filament_label.setFont(QFont("Play", 8, QFont.Weight.Bold))
        self.total_filament_label.setStyleSheet(f"color: {COLORS['accent']};")
        stats_grid.addWidget(self.total_filament_label, 1, 1)
        
        # Print Count
        lbl = QLabel("Print Count:")
        lbl.setFont(QFont("Play", 8))
        stats_grid.addWidget(lbl, 2, 0)
        self.print_count_label = QLabel("--")
        self.print_count_label.setFont(QFont("Play", 8, QFont.Weight.Bold))
        self.print_count_label.setStyleSheet(f"color: {COLORS['accent']};")
        stats_grid.addWidget(self.print_count_label, 2, 1)
        
        # Success Rate
        lbl = QLabel("Success Rate:")
        lbl.setFont(QFont("Play", 8))
        stats_grid.addWidget(lbl, 3, 0)
        self.success_rate_label = QLabel("--")
        self.success_rate_label.setFont(QFont("Play", 8, QFont.Weight.Bold))
        self.success_rate_label.setStyleSheet(f"color: {COLORS['success']};")
        stats_grid.addWidget(self.success_rate_label, 3, 1)
        
        layout.addLayout(stats_grid)
        
        # Separator
        line3 = QFrame()
        line3.setFrameShape(QFrame.Shape.HLine)
        line3.setStyleSheet(f"background-color: {COLORS['border']}; max-height: 1px;")
        layout.addWidget(line3)
        
        # System Info section
        sys_header = QHBoxLayout()
        sys_header.setSpacing(4)
        sys_icon = QLabel()
        sys_icon.setPixmap(get_icon("system").pixmap(14, 14))
        sys_header.addWidget(sys_icon)
        sys_label = QLabel("SYSTEM INFO")
        sys_label.setFont(QFont("Play", 9, QFont.Weight.Bold))
        sys_label.setStyleSheet(f"color: {COLORS['accent']};")
        sys_header.addWidget(sys_label)
        sys_header.addStretch()
        layout.addLayout(sys_header)
        
        sys_grid = QGridLayout()
        sys_grid.setSpacing(1)
        
        lbl = QLabel("Klipper:")
        lbl.setFont(QFont("Play", 8))
        sys_grid.addWidget(lbl, 0, 0)
        self.klipper_ver_label = QLabel("--")
        self.klipper_ver_label.setFont(QFont("Play", 8))
        sys_grid.addWidget(self.klipper_ver_label, 0, 1)
        
        lbl = QLabel("Moonraker:")
        lbl.setFont(QFont("Play", 8))
        sys_grid.addWidget(lbl, 1, 0)
        self.moonraker_ver_label = QLabel("--")
        self.moonraker_ver_label.setFont(QFont("Play", 8))
        sys_grid.addWidget(self.moonraker_ver_label, 1, 1)
        
        lbl = QLabel("OS:")
        lbl.setFont(QFont("Play", 8))
        sys_grid.addWidget(lbl, 2, 0)
        self.os_label = QLabel("--")
        self.os_label.setFont(QFont("Play", 8))
        sys_grid.addWidget(self.os_label, 2, 1)
        
        layout.addLayout(sys_grid)
        
        # Disk usage
        disk_layout = QHBoxLayout()
        lbl = QLabel("Disk:")
        lbl.setFont(QFont("Play", 8))
        disk_layout.addWidget(lbl)
        self.disk_label = QLabel("-- / --")
        self.disk_label.setFont(QFont("Play", 8))
        disk_layout.addWidget(self.disk_label)
        layout.addLayout(disk_layout)
        
        self.disk_bar = QProgressBar()
        self.disk_bar.setRange(0, 100)
        self.disk_bar.setValue(0)
        self.disk_bar.setFixedHeight(8)
        self.disk_bar.setTextVisible(False)
        layout.addWidget(self.disk_bar)
        
        # Separator
        line_mmu = QFrame()
        line_mmu.setFrameShape(QFrame.Shape.HLine)
        line_mmu.setStyleSheet(f"background-color: {COLORS['border']}; max-height: 1px;")
        layout.addWidget(line_mmu)
        
        # Multi-Color Unit section (MMU/ERCF/AFC)
        self.mmu_section = QWidget()
        mmu_layout = QVBoxLayout(self.mmu_section)
        mmu_layout.setContentsMargins(0, 0, 0, 0)
        mmu_layout.setSpacing(2)
        
        self.mmu_label = QLabel("🎨 MULTI-COLOR UNIT")
        self.mmu_label.setFont(QFont("Play", 9, QFont.Weight.Bold))
        self.mmu_label.setStyleSheet(f"color: {COLORS['accent']};")
        mmu_layout.addWidget(self.mmu_label)
        
        self.mmu_frame = QFrame()
        self.mmu_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_dark']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
            }}
        """)
        mmu_frame_layout = QVBoxLayout(self.mmu_frame)
        mmu_frame_layout.setContentsMargins(4, 4, 4, 4)
        mmu_frame_layout.setSpacing(2)
        
        # MMU Type
        mmu_type_layout = QHBoxLayout()
        lbl = QLabel("Type:")
        lbl.setFont(QFont("Play", 8))
        mmu_type_layout.addWidget(lbl)
        self.mmu_type_label = QLabel("--")
        self.mmu_type_label.setFont(QFont("Play", 8, QFont.Weight.Bold))
        self.mmu_type_label.setStyleSheet(f"color: {COLORS['accent']};")
        mmu_type_layout.addWidget(self.mmu_type_label)
        mmu_type_layout.addStretch()
        mmu_frame_layout.addLayout(mmu_type_layout)
        
        # Gate info
        mmu_gate_layout = QHBoxLayout()
        lbl = QLabel("Gates:")
        lbl.setFont(QFont("Play", 8))
        mmu_gate_layout.addWidget(lbl)
        self.mmu_gate_label = QLabel("--")
        self.mmu_gate_label.setFont(QFont("Play", 8))
        mmu_gate_layout.addWidget(self.mmu_gate_label)
        mmu_gate_layout.addStretch()
        mmu_frame_layout.addLayout(mmu_gate_layout)
        
        # Current gate
        mmu_current_layout = QHBoxLayout()
        lbl = QLabel("Current:")
        lbl.setFont(QFont("Play", 8))
        mmu_current_layout.addWidget(lbl)
        self.mmu_current_label = QLabel("--")
        self.mmu_current_label.setFont(QFont("Play", 8, QFont.Weight.Bold))
        self.mmu_current_label.setStyleSheet(f"color: {COLORS['success']};")
        mmu_current_layout.addWidget(self.mmu_current_label)
        mmu_current_layout.addStretch()
        mmu_frame_layout.addLayout(mmu_current_layout)
        
        # Filament loaded status
        self.mmu_loaded_label = QLabel("● Filament: --")
        self.mmu_loaded_label.setFont(QFont("Play", 8))
        mmu_frame_layout.addWidget(self.mmu_loaded_label)
        
        mmu_layout.addWidget(self.mmu_frame)
        
        layout.addWidget(self.mmu_section)
        self.mmu_section.setVisible(False)  # Hidden by default
        
        # Separator
        line4 = QFrame()
        line4.setFrameShape(QFrame.Shape.HLine)
        line4.setStyleSheet(f"background-color: {COLORS['border']}; max-height: 1px;")
        layout.addWidget(line4)
        
        # Tuning Advisor section
        tuning_header = QHBoxLayout()
        tuning_header.setSpacing(4)
        tuning_icon = QLabel()
        tuning_icon.setPixmap(get_icon("tuning").pixmap(14, 14))
        tuning_header.addWidget(tuning_icon)
        tuning_label = QLabel("TUNING ADVISOR")
        tuning_label.setFont(QFont("Play", 9, QFont.Weight.Bold))
        tuning_label.setStyleSheet(f"color: {COLORS['accent']};")
        tuning_header.addWidget(tuning_label)
        tuning_header.addStretch()
        layout.addLayout(tuning_header)
        
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
        pid_warning_layout.setContentsMargins(6, 6, 6, 6)
        pid_warning_layout.setSpacing(2)
        
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
        shaper_layout.setContentsMargins(4, 4, 4, 4)
        shaper_layout.setSpacing(1)
        
        shaper_title = QLabel("Input Shaper")
        shaper_title.setFont(QFont("Play", 9, QFont.Weight.Bold))
        shaper_title.setStyleSheet(f"color: {COLORS['text_secondary']};")
        shaper_layout.addWidget(shaper_title)
        
        shaper_grid = QGridLayout()
        shaper_grid.setSpacing(2)
        
        lbl = QLabel("X Axis:")
        lbl.setFont(QFont("Play", 8))
        shaper_grid.addWidget(lbl, 0, 0)
        self.shaper_x_label = QLabel("--")
        self.shaper_x_label.setFont(QFont("Play", 8))
        self.shaper_x_label.setStyleSheet(f"color: {COLORS['accent']};")
        shaper_grid.addWidget(self.shaper_x_label, 0, 1)
        
        lbl = QLabel("Y Axis:")
        lbl.setFont(QFont("Play", 8))
        shaper_grid.addWidget(lbl, 1, 0)
        self.shaper_y_label = QLabel("--")
        self.shaper_y_label.setFont(QFont("Play", 8))
        self.shaper_y_label.setStyleSheet(f"color: {COLORS['accent']};")
        shaper_grid.addWidget(self.shaper_y_label, 1, 1)
        
        # Max acceleration recommendations
        lbl = QLabel("Max Accel X:")
        lbl.setFont(QFont("Play", 8))
        shaper_grid.addWidget(lbl, 2, 0)
        self.shaper_accel_x_label = QLabel("--")
        self.shaper_accel_x_label.setFont(QFont("Play", 8))
        self.shaper_accel_x_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        shaper_grid.addWidget(self.shaper_accel_x_label, 2, 1)
        
        lbl = QLabel("Max Accel Y:")
        lbl.setFont(QFont("Play", 8))
        shaper_grid.addWidget(lbl, 3, 0)
        self.shaper_accel_y_label = QLabel("--")
        self.shaper_accel_y_label.setFont(QFont("Play", 8))
        self.shaper_accel_y_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        shaper_grid.addWidget(self.shaper_accel_y_label, 3, 1)
        
        shaper_layout.addLayout(shaper_grid)
        
        # Shaper advice label
        self.shaper_advice_label = QLabel("")
        self.shaper_advice_label.setFont(QFont("Play", 8))
        self.shaper_advice_label.setWordWrap(True)
        self.shaper_advice_label.setStyleSheet(f"color: {COLORS['warning']}; padding: 2px;")
        self.shaper_advice_label.setVisible(False)
        shaper_layout.addWidget(self.shaper_advice_label)
        
        # Buttons row
        shaper_btn_layout = QHBoxLayout()
        shaper_btn_layout.setSpacing(4)
        
        self.shaper_calibrate_btn = QPushButton("Calibrate")
        self.shaper_calibrate_btn.setFixedHeight(28)
        self.shaper_calibrate_btn.setToolTip("Run SHAPER_CALIBRATE macro")
        self.shaper_calibrate_btn.clicked.connect(self._run_shaper_calibrate)
        self.shaper_calibrate_btn.setEnabled(False)
        shaper_btn_layout.addWidget(self.shaper_calibrate_btn)
        
        self.save_shaper_graph_btn = QPushButton("Graph")
        self.save_shaper_graph_btn.setFixedHeight(28)
        self.save_shaper_graph_btn.clicked.connect(self._save_shaper_graph)
        self.save_shaper_graph_btn.setEnabled(False)
        self.save_shaper_graph_btn.setToolTip("Save Input Shaper calibration graph (requires Shake&Tune)")
        shaper_btn_layout.addWidget(self.save_shaper_graph_btn)
        
        shaper_layout.addLayout(shaper_btn_layout)
        
        layout.addWidget(self.shaper_frame)
        
        # Separator before Log Analyzer
        line5 = QFrame()
        line5.setFrameShape(QFrame.Shape.HLine)
        line5.setStyleSheet(f"background-color: {COLORS['border']}; max-height: 1px;")
        layout.addWidget(line5)
        
        # Log Analyzer section
        log_header = QHBoxLayout()
        log_header.setSpacing(4)
        log_icon = QLabel()
        log_icon.setPixmap(get_icon("log").pixmap(14, 14))
        log_header.addWidget(log_icon)
        log_label = QLabel("LOG ANALYZER")
        log_label.setFont(QFont("Play", 9, QFont.Weight.Bold))
        log_label.setStyleSheet(f"color: {COLORS['accent']};")
        log_header.addWidget(log_label)
        log_header.addStretch()
        layout.addLayout(log_header)
        
        log_frame = QFrame()
        log_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_dark']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
            }}
        """)
        log_layout = QVBoxLayout(log_frame)
        log_layout.setContentsMargins(4, 4, 4, 4)
        log_layout.setSpacing(2)
        
        # Log status
        self.log_status_label = QLabel("No log analyzed yet")
        self.log_status_label.setFont(QFont("Play", 8))
        self.log_status_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        self.log_status_label.setWordWrap(True)
        log_layout.addWidget(self.log_status_label)
        
        # Error/Warning counts
        log_stats_layout = QHBoxLayout()
        self.log_errors_label = QLabel("⚠️ Errors: --")
        self.log_errors_label.setFont(QFont("Play", 8))
        self.log_errors_label.setStyleSheet(f"color: {COLORS['error']};")
        log_stats_layout.addWidget(self.log_errors_label)
        
        self.log_warnings_label = QLabel("⚠️ Warnings: --")
        self.log_warnings_label.setFont(QFont("Play", 8))
        self.log_warnings_label.setStyleSheet(f"color: {COLORS['warning']};")
        log_stats_layout.addWidget(self.log_warnings_label)
        log_layout.addLayout(log_stats_layout)
        
        # Analyze Log button
        self.analyze_log_btn = QPushButton("🔍 Analyze Log")
        self.analyze_log_btn.setFixedHeight(28)
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
            QPushButton:disabled {{
                color: {COLORS['text_muted']};
                border-color: {COLORS['text_muted']};
            }}
        """)
        self.analyze_log_btn.clicked.connect(self._analyze_log)
        # Keep enabled - will check for printer selection on click
        log_layout.addWidget(self.analyze_log_btn)
        
        # Download Log button
        self.download_log_btn = QPushButton("💾 Download Log")
        self.download_log_btn.setFixedHeight(28)
        self.download_log_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['text_secondary']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['bg_hover']};
                color: {COLORS['text_primary']};
            }}
            QPushButton:disabled {{
                color: {COLORS['text_muted']};
                border-color: {COLORS['text_muted']};
            }}
        """)
        self.download_log_btn.clicked.connect(self._download_log)
        # Keep enabled - will check for printer selection on click
        log_layout.addWidget(self.download_log_btn)
        
        # Credit for Klipper Log Visualizer
        log_credit = QLabel("Powered by <a href='https://sineos.github.io/' style='color: #0ABAB5;'>Klipper Log Visualizer</a> by sineos")
        log_credit.setFont(QFont("Play", 8))
        log_credit.setStyleSheet(f"color: {COLORS['text_muted']};")
        log_credit.setOpenExternalLinks(True)
        log_layout.addWidget(log_credit)
        
        layout.addWidget(log_frame)
        
        # Separator before Config Backup
        line6 = QFrame()
        line6.setFrameShape(QFrame.Shape.HLine)
        line6.setStyleSheet(f"background-color: {COLORS['border']}; max-height: 1px;")
        layout.addWidget(line6)
        
        # Config Backup section
        backup_header = QHBoxLayout()
        backup_header.setSpacing(4)
        backup_icon = QLabel()
        backup_icon.setPixmap(get_icon("backup").pixmap(14, 14))
        backup_header.addWidget(backup_icon)
        backup_label = QLabel("CONFIG BACKUP")
        backup_label.setFont(QFont("Play", 9, QFont.Weight.Bold))
        backup_label.setStyleSheet(f"color: {COLORS['accent']};")
        backup_header.addWidget(backup_label)
        backup_header.addStretch()
        layout.addLayout(backup_header)
        
        backup_frame = QFrame()
        backup_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_dark']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
            }}
        """)
        backup_layout = QVBoxLayout(backup_frame)
        backup_layout.setContentsMargins(4, 4, 4, 4)
        backup_layout.setSpacing(2)
        
        # Backup status
        self.backup_status_label = QLabel("Backup printer.cfg and configs")
        self.backup_status_label.setFont(QFont("Play", 8))
        self.backup_status_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        self.backup_status_label.setWordWrap(True)
        backup_layout.addWidget(self.backup_status_label)
        
        # Backup button
        self.backup_config_btn = QPushButton("📦 Backup Configs")
        self.backup_config_btn.setFixedHeight(28)
        self.backup_config_btn.setStyleSheet(f"""
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
            QPushButton:disabled {{
                color: {COLORS['text_muted']};
                border-color: {COLORS['text_muted']};
            }}
        """)
        self.backup_config_btn.clicked.connect(self._backup_configs)
        # Keep enabled - will check for printer selection on click
        backup_layout.addWidget(self.backup_config_btn)
        
        layout.addWidget(backup_frame)
        
        # Set content widget to scroll area and add to main layout
        scroll_area.setWidget(content_widget)
        main_layout.addWidget(scroll_area)
        
        # Store temperature history for PID warning
        self._temp_history_hotend: deque = deque(maxlen=30)
        self._temp_history_bed: deque = deque(maxlen=30)
        self._current_printer_config = None
        
        # Signal for G-code commands
        self.gcode_requested = None  # Will be set by MainWindow
    
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
        self.camera_timer.start(5000)  # Refresh every 5 seconds (reduced for performance)
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
        
        # Update MMU info
        self.update_mmu_info(info)
    
    def update_mmu_info(self, info: SystemInfo):
        """Update Multi-Color Unit display"""
        if info.mmu_enabled:
            self.mmu_section.setVisible(True)
            self.mmu_type_label.setText(info.mmu_type)
            
            # For QIDI BOX, show channels instead of gates
            if info.mmu_type == "QIDI BOX":
                self.mmu_gate_label.setText(f"{info.mmu_gate_count} channels")
            else:
                self.mmu_gate_label.setText(f"{info.mmu_gate_count} gates")
            
            if info.mmu_current_gate >= 0:
                self.mmu_current_label.setText(f"Gate {info.mmu_current_gate}")
                self.mmu_current_label.setStyleSheet(f"color: {COLORS['success']};")
            else:
                self.mmu_current_label.setText("None")
                self.mmu_current_label.setStyleSheet(f"color: {COLORS['text_muted']};")
            
            # For QIDI BOX, show heater temperatures instead of filament loaded status
            if info.mmu_type == "QIDI BOX" and info.mmu_heater_temps:
                temp_strs = []
                for i, (current, target) in enumerate(info.mmu_heater_temps):
                    if target > 0:
                        temp_strs.append(f"CH{i+1}: {current:.0f}°C/{target:.0f}°C")
                    else:
                        temp_strs.append(f"CH{i+1}: {current:.0f}°C")
                self.mmu_loaded_label.setText(" | ".join(temp_strs))
                self.mmu_loaded_label.setStyleSheet(f"color: {COLORS['accent']};")
            elif info.mmu_filament_loaded:
                self.mmu_loaded_label.setText("● Filament: Loaded")
                self.mmu_loaded_label.setStyleSheet(f"color: {COLORS['success']};")
            else:
                self.mmu_loaded_label.setText("○ Filament: Not loaded")
                self.mmu_loaded_label.setStyleSheet(f"color: {COLORS['text_muted']};")
        else:
            self.mmu_section.setVisible(False)
    
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
            "This will:\n"
            "1. Home all axes (G28)\n"
            "2. Measure resonance frequencies on both axes\n\n"
            "Make sure an accelerometer is connected and configured.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            if self.gcode_requested:
                # First home, then run shaper calibrate
                self.gcode_requested(self._current_printer_config, "G28")
                # Use a small delay before running calibration
                QTimer.singleShot(2000, lambda: self._run_shaper_after_home())
    
    def _run_shaper_after_home(self):
        """Run SHAPER_CALIBRATE after homing is complete"""
        if self._current_printer_config and self.gcode_requested:
            self.gcode_requested(self._current_printer_config, "SHAPER_CALIBRATE")
    
    def _save_shaper_graph(self):
        """Save Input Shaper calibration graph from Shake&Tune"""
        if not self._current_printer_config:
            return
        
        async def download_graphs():
            try:
                client = MoonrakerClient(self._current_printer_config['host'])
                
                # Try to find Shake&Tune results
                files = await client.get_shaper_graph_files()
                
                if not files:
                    # Check ShakeTune_results folder
                    try:
                        resp = await client._request('GET', '/server/files/list?root=config&path=ShakeTune_results')
                        if resp and 'result' in resp:
                            files = [f'ShakeTune_results/{f["path"]}' for f in resp['result'] 
                                    if f['path'].endswith('.png')]
                    except:
                        pass
                
                if not files:
                    QMessageBox.information(
                        self, "No Graphs Found",
                        "No Input Shaper calibration graphs found.\n\n"
                        "To generate graphs, install Shake&Tune:\n"
                        "https://github.com/Frix-x/klippain-shaketune"
                    )
                    return
                
                # Get the most recent file
                latest_file = files[0]
                
                # Download the file
                data = await client.download_shaper_graph(latest_file)
                
                if data:
                    # Ask user where to save
                    from PyQt6.QtWidgets import QFileDialog
                    save_path, _ = QFileDialog.getSaveFileName(
                        self, "Save Shaper Graph",
                        f"shaper_calibration_{self._current_printer_config.get('name', 'printer')}.png",
                        "PNG Images (*.png)"
                    )
                    
                    if save_path:
                        with open(save_path, 'wb') as f:
                            f.write(data)
                        QMessageBox.information(self, "Saved", f"Graph saved to:\n{save_path}")
                else:
                    QMessageBox.warning(self, "Error", "Failed to download graph file.")
                    
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to get shaper graphs: {e}")
        
        asyncio.ensure_future(download_graphs())
    
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
            max_accel_x = shaper_data.get('max_accel_x', 0)
            max_accel_y = shaper_data.get('max_accel_y', 0)
            advice = shaper_data.get('advice', [])
            
            if x_type and x_freq > 0:
                self.shaper_x_label.setText(f"{x_type.upper()} @ {x_freq:.1f} Hz")
            else:
                self.shaper_x_label.setText("Not configured")
            
            if y_type and y_freq > 0:
                self.shaper_y_label.setText(f"{y_type.upper()} @ {y_freq:.1f} Hz")
            else:
                self.shaper_y_label.setText("Not configured")
            
            # Display recommended max acceleration
            if max_accel_x > 0:
                self.shaper_accel_x_label.setText(f"{max_accel_x:,} mm/s²")
            else:
                self.shaper_accel_x_label.setText("--")
            
            if max_accel_y > 0:
                self.shaper_accel_y_label.setText(f"{max_accel_y:,} mm/s²")
            else:
                self.shaper_accel_y_label.setText("--")
            
            # Display advice
            if advice:
                self.shaper_advice_label.setText("\n".join(advice))
                self.shaper_advice_label.setVisible(True)
            else:
                self.shaper_advice_label.setVisible(False)
            
            self.shaper_calibrate_btn.setEnabled(True)
            # Enable save graph button if shaper is configured
            self.save_shaper_graph_btn.setEnabled(x_freq > 0 or y_freq > 0)
        else:
            self.shaper_x_label.setText("--")
            self.shaper_y_label.setText("--")
            self.shaper_accel_x_label.setText("--")
            self.shaper_accel_y_label.setText("--")
            self.shaper_advice_label.setVisible(False)
            self.shaper_calibrate_btn.setEnabled(False)
            self.save_shaper_graph_btn.setEnabled(False)
    
    def set_printer_config(self, config):
        """Set current printer config for G-code commands"""
        self._current_printer_config = config
        self.shaper_calibrate_btn.setEnabled(config is not None)
        self.enable_controls(config is not None)
    
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
        self.shaper_accel_x_label.setText("--")
        self.shaper_accel_y_label.setText("--")
        self.shaper_advice_label.setVisible(False)
        self.shaper_calibrate_btn.setEnabled(False)
        self.save_shaper_graph_btn.setEnabled(False)
        self._temp_history_hotend.clear()
        self._temp_history_bed.clear()
        self._current_printer_config = None
        # Clear log analyzer
        self.log_status_label.setText("No log analyzed yet")
        self.log_errors_label.setText("⚠️ Errors: --")
        self.log_warnings_label.setText("⚠️ Warnings: --")
        # Keep log buttons enabled - they check for printer selection on click
        # Clear control buttons (keep backup enabled - checks on click)
        self.firmware_restart_btn.setEnabled(False)
        self.restart_btn.setEnabled(False)
        self.emergency_stop_btn.setEnabled(False)
        # backup_config_btn stays enabled - checks for printer on click
        # Clear MMU section
        self.mmu_section.setVisible(False)
        self.mmu_type_label.setText("--")
        self.mmu_gate_label.setText("--")
        self.mmu_current_label.setText("--")
        self.mmu_loaded_label.setText("● Filament: --")
    
    def enable_controls(self, enabled: bool = True):
        """Enable or disable printer control buttons"""
        # Use QTimer to ensure this runs after all other UI updates
        def _do_enable():
            self.firmware_restart_btn.setEnabled(enabled)
            self.restart_btn.setEnabled(enabled)
            self.emergency_stop_btn.setEnabled(enabled)
            self.analyze_log_btn.setEnabled(enabled)
            self.download_log_btn.setEnabled(enabled)
            self.backup_config_btn.setEnabled(enabled)
            # Force UI update
            self.backup_config_btn.repaint()
            self.analyze_log_btn.repaint()
            self.firmware_restart_btn.repaint()
            self.restart_btn.repaint()
            self.emergency_stop_btn.repaint()
            self.download_log_btn.repaint()
            QApplication.processEvents()
        
        # Execute immediately and also schedule for later to ensure it takes effect
        _do_enable()
        QTimer.singleShot(100, _do_enable)
    
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
            QMessageBox.warning(self, "No Printer Selected", "Please select a printer first by clicking on a printer card.")
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
            QMessageBox.warning(self, "No Printer Selected", "Please select a printer first by clicking on a printer card.")
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
    
    def _backup_configs(self):
        """Backup all Klipper configuration files using synchronous HTTP requests"""
        if not self._current_printer_config:
            QMessageBox.warning(self, "Error", "No printer selected. Please select a printer first.")
            return
        
        from pathlib import Path
        import zipfile
        from datetime import datetime
        import urllib.request
        import json
        
        # Get save directory
        default_path = Path.home() / "Documents" / "KlipperBuddy" / "backups"
        default_path.mkdir(parents=True, exist_ok=True)
        
        save_dir = QFileDialog.getExistingDirectory(
            self, "Select Backup Directory",
            str(default_path)
        )
        
        if not save_dir:
            return
        
        self.backup_status_label.setText("Backing up...")
        self.backup_config_btn.setEnabled(False)
        QApplication.processEvents()
        
        try:
            base_url = f"http://{self._current_printer_config.host}:{self._current_printer_config.port}"
            
            # Get list of config files
            list_url = f"{base_url}/server/files/list?root=config"
            req = urllib.request.Request(list_url, headers={'User-Agent': 'KlipperBuddy'})
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
            
            if 'result' not in data:
                raise Exception("Failed to get config file list")
            
            files = data['result']
            if not files:
                raise Exception("No configuration files found")
            
            # Create zip file
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            printer_name = self._current_printer_config.host.replace('.', '_').replace(':', '_')
            zip_filename = f"klipper_backup_{printer_name}_{timestamp}.zip"
            zip_path = Path(save_dir) / zip_filename
            
            files_backed_up = 0
            errors = []
            
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for i, file_info in enumerate(files):
                    filename = file_info.get('path', '')
                    if not filename:
                        continue
                    
                    # Update progress
                    self.backup_status_label.setText(f"Backing up {i+1}/{len(files)}...")
                    QApplication.processEvents()
                    
                    try:
                        # Download file
                        import urllib.parse
                        encoded_filename = urllib.parse.quote(filename, safe='')
                        file_url = f"{base_url}/server/files/config/{encoded_filename}"
                        req = urllib.request.Request(file_url, headers={'User-Agent': 'KlipperBuddy'})
                        with urllib.request.urlopen(req, timeout=30) as response:
                            content = response.read()
                        
                        zipf.writestr(filename, content)
                        files_backed_up += 1
                    except Exception as e:
                        errors.append(f"Failed to backup {filename}: {str(e)}")
            
            if files_backed_up > 0:
                self.backup_status_label.setText(f"Backed up {files_backed_up} files")
                self.backup_status_label.setStyleSheet(f"color: {COLORS['success']};")
                
                QMessageBox.information(
                    self, "Backup Complete",
                    f"Successfully backed up {files_backed_up} configuration files.\n\n"
                    f"Saved to:\n{zip_path}"
                )
            else:
                self.backup_status_label.setText("Backup failed")
                self.backup_status_label.setStyleSheet(f"color: {COLORS['error']};")
                error_msg = '\n'.join(errors[:3]) if errors else "Unknown error"
                QMessageBox.warning(self, "Backup Failed", f"Errors:\n{error_msg}")
                
        except Exception as e:
            self.backup_status_label.setText(f"Error: {str(e)[:50]}")
            self.backup_status_label.setStyleSheet(f"color: {COLORS['error']};")
            QMessageBox.warning(self, "Backup Error", f"Failed to backup configs:\n{str(e)}")
        finally:
            self.backup_config_btn.setEnabled(True)


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
# Login Dialog
# =============================================================================

class LoginDialog(QDialog):
    """Dialog for entering login credentials for a printer"""
    
    def __init__(self, host: str, port: int = 7125, parent=None):
        super().__init__(parent)
        self.setWindowTitle("🔐 Login Required")
        self.setFixedSize(350, 200)
        self._setup_ui(f"{host}:{port}")
    
    def _setup_ui(self, printer_name: str):
        layout = QFormLayout(self)
        layout.setSpacing(12)
        
        header = QLabel(f"Login to {printer_name}")
        header.setFont(QFont("Play", 14, QFont.Weight.Bold))
        header.setStyleSheet(f"color: {COLORS['accent']};")
        layout.addRow(header)
        
        desc = QLabel("This printer requires authentication.")
        desc.setStyleSheet(f"color: {COLORS['text_secondary']};")
        layout.addRow(desc)
        
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Username")
        layout.addRow("Username:", self.username_edit)
        
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setPlaceholderText("Password")
        layout.addRow("Password:", self.password_edit)
        
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)
        
        # Apply dark theme
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLORS['bg_dark']};
            }}
            QLabel {{
                color: {COLORS['text_primary']};
            }}
            QLineEdit {{
                background-color: {COLORS['surface']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 6px;
            }}
            QLineEdit:focus {{
                border-color: {COLORS['accent']};
            }}
            QPushButton {{
                background-color: {COLORS['accent']};
                color: {COLORS['bg_dark']};
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent_hover']};
            }}
        """)
    
    def get_credentials(self) -> tuple:
        """Return (username, password) tuple"""
        return (self.username_edit.text(), self.password_edit.text())


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
        
        # Display settings
        display_group = QGroupBox("Display")
        display_layout = QVBoxLayout(display_group)
        
        self.compact_mode_check = QCheckBox("Compact Mode (smaller cards without camera preview)")
        self.compact_mode_check.setChecked(self.config_manager.get_setting('compact_mode', False))
        display_layout.addWidget(self.compact_mode_check)
        
        compact_desc = QLabel("Compact mode shows more printers on screen but without camera preview")
        compact_desc.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 10px;")
        compact_desc.setWordWrap(True)
        display_layout.addWidget(compact_desc)
        
        layout.addWidget(display_group)
        
        # Privacy mode setting
        privacy_group = QGroupBox("Privacy")
        privacy_layout = QVBoxLayout(privacy_group)
        
        self.privacy_mode_check = QCheckBox("Privacy Mode (hide IP addresses and hostnames)")
        self.privacy_mode_check.setChecked(self.config_manager.get_setting('privacy_mode', False))
        privacy_layout.addWidget(self.privacy_mode_check)
        
        privacy_desc = QLabel("When enabled, IP addresses and hostnames will be shown as '***' for screenshots")
        privacy_desc.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 10px;")
        privacy_desc.setWordWrap(True)
        privacy_layout.addWidget(privacy_desc)
        
        layout.addWidget(privacy_group)
        
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
        old_compact_mode = self.config_manager.get_setting('compact_mode', False)
        new_compact_mode = self.compact_mode_check.isChecked()
        
        self.config_manager.set_setting('log_folder', self.log_path_edit.text())
        self.config_manager.set_setting('auto_scan', self.auto_scan_check.isChecked())
        self.config_manager.set_setting('compact_mode', new_compact_mode)
        self.config_manager.set_setting('privacy_mode', self.privacy_mode_check.isChecked())
        
        # Store whether compact mode changed
        self.compact_mode_changed = (old_compact_mode != new_compact_mode)
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
        self._last_print_states: Dict[str, str] = {}  # Track print states for notifications
        
        self._setup_ui()
        self._load_printers()
        
        # Connect G-code request handler
        self.stats_panel.gcode_requested = self._send_gcode
        
        # Auto-refresh timer (lightweight updates only)
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(lambda: self._refresh_all_status(full_refresh=False))
        self.refresh_timer.start(5000)  # Refresh every 5 seconds (reduced for performance)
    
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
                updated_count = 0
                for p in printers:
                    # Check if printer already exists by host:port
                    exists_by_host = any(
                        pc.host == p['host'] and pc.port == p['port']
                        for pc in self.config_manager.printers
                    )
                    if exists_by_host:
                        continue
                    
                    # Check if printer exists by MAC address (most reliable)
                    existing_by_mac = None
                    scan_mac = p.get('mac_address', '')
                    if scan_mac:
                        for pc in self.config_manager.printers:
                            if pc.mac_address and pc.mac_address == scan_mac:
                                existing_by_mac = pc
                                break
                    
                    # Fallback: check by name
                    existing_by_name = None
                    if not existing_by_mac and p.get('name'):
                        for pc in self.config_manager.printers:
                            if pc.name and pc.name == p['name']:
                                existing_by_name = pc
                                break
                    
                    existing = existing_by_mac or existing_by_name
                    if existing:
                        # IP changed - update existing printer
                        old_key = f"{existing.host}:{existing.port}"
                        existing.host = p['host']
                        existing.port = p['port']
                        if scan_mac and not existing.mac_address:
                            existing.mac_address = scan_mac
                        self.config_manager.save()
                        # Update card key
                        new_key = f"{p['host']}:{p['port']}"
                        if old_key in self.printer_cards:
                            card = self.printer_cards.pop(old_key)
                            card.config = existing
                            self.printer_cards[new_key] = card
                        updated_count += 1
                    else:
                        # Truly new printer
                        config = PrinterConfig(
                            name=p['name'],
                            host=p['host'],
                            port=p['port'],
                            enabled=True
                        )
                        if self.config_manager.add_printer(config):
                            self._add_printer_card(config)
                            added_count += 1
                
                if added_count > 0 or updated_count > 0:
                    parts = []
                    if added_count > 0:
                        parts.append(f"{added_count} new")
                    if updated_count > 0:
                        parts.append(f"{updated_count} updated")
                    self.status_label.setText(f"Found {', '.join(parts)} printer(s)")
                else:
                    self.status_label.setText(f"Scan complete - {len(printers)} printer(s) online")
                self._refresh_all_status()
            else:
                self.status_label.setText("No printers found on network")
            
            # Clear status after 5 seconds
            QTimer.singleShot(5000, lambda: self.status_label.setText(""))
        
        def on_error(e):
            self.status_label.setText(f"Scan error: {e}")
            # Clear status after 5 seconds
            QTimer.singleShot(5000, lambda: self.status_label.setText(""))
        
        worker = AsyncWorker(scan)
        worker.result_ready.connect(on_result)
        worker.error_occurred.connect(on_error)
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
        
        # P3D Logo - Copyright Yuto Horiuchi (YuTR0N/Psych0h3ad)
        # All rights reserved. Unauthorized use prohibited.
        p3d_logo_path = resource_path("p3d_logo.png")
        if os.path.exists(p3d_logo_path):
            p3d_pixmap = QPixmap(p3d_logo_path)
            p3d_label = QLabel()
            p3d_label.setPixmap(p3d_pixmap.scaledToHeight(36, Qt.TransformationMode.SmoothTransformation))
            p3d_label.setToolTip("P3D Logo © Yuto Horiuchi (YuTR0N). All rights reserved.")
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
        
        # Right side - Stats panel container with toggle button
        right_container = QWidget()
        right_layout = QHBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        
        # Toggle button for sidebar - more visible
        self.sidebar_toggle_btn = QPushButton("◀")
        self.sidebar_toggle_btn.setFixedSize(24, 80)
        self.sidebar_toggle_btn.setToolTip("Toggle Sidebar")
        self.sidebar_toggle_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['accent']};
                color: {COLORS['bg_dark']};
                border: none;
                border-radius: 4px;
                font-size: 14px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent_light']};
            }}
        """)
        self.sidebar_toggle_btn.clicked.connect(self._toggle_sidebar)
        right_layout.addWidget(self.sidebar_toggle_btn, 0, Qt.AlignmentFlag.AlignVCenter)
        
        # Stats panel
        self.stats_panel = StatsPanel()
        self.stats_panel.setFixedWidth(300)  # Fixed width to prevent overflow
        right_layout.addWidget(self.stats_panel)
        
        self.sidebar_visible = True
        
        splitter.addWidget(left_widget)
        splitter.addWidget(right_container)
        
        splitter.setSizes([1100, 320])
        splitter.setStretchFactor(0, 1)  # Left side stretches
        splitter.setStretchFactor(1, 0)  # Right side fixed width
        
        main_layout.addWidget(splitter, 1)  # Give splitter stretch priority
        
        # Status bar
        self.status_label = QLabel("")
        self.status_label.setFont(QFont("Play", 9))
        self.status_label.setStyleSheet(f"color: {COLORS['text_muted']};")
        self.status_label.setFixedHeight(20)  # Prevent layout shift
        main_layout.addWidget(self.status_label)
    
    def _load_printers(self):
        for printer in self.config_manager.printers:
            self._add_printer_card(printer)
        self._refresh_all_status()
    
    def _add_printer_card(self, config: PrinterConfig):
        key = f"{config.host}:{config.port}"
        if key in self.printer_cards:
            return
        
        compact_mode = self.config_manager.get_setting('compact_mode', False)
        card = PrinterCard(config, compact_mode=compact_mode)
        card.camera_clicked.connect(self._on_camera_clicked)
        card.card_clicked.connect(self._on_card_clicked)
        card.login_requested.connect(self._on_login_requested)
        self.printer_cards[key] = card
        
        # Add to grid - more columns in compact mode
        count = len(self.printer_cards) - 1
        cols = 6 if compact_mode else 3  # 6 columns for compact (1920px), 3 for standard
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
        compact_mode = self.config_manager.get_setting('compact_mode', False)
        cols = 6 if compact_mode else 3  # 6 columns for compact (1920px), 3 for standard
        for i, card in enumerate(self.printer_cards.values()):
            row = i // cols
            col = i % cols
            self.cards_layout.addWidget(card, row, col)
    
    def _recreate_all_cards(self):
        """Recreate all printer cards (used when compact mode changes)"""
        # Store current configs and states
        configs = [card.config for card in self.printer_cards.values()]
        selected_key = None
        if self.selected_printer:
            selected_key = f"{self.selected_printer.config.host}:{self.selected_printer.config.port}"
        
        # Remove all existing cards
        for key in list(self.printer_cards.keys()):
            card = self.printer_cards.pop(key)
            self.cards_layout.removeWidget(card)
            card.deleteLater()
        
        # Clear selection
        self.selected_printer = None
        
        # Recreate cards with new compact_mode setting
        for config in configs:
            self._add_printer_card(config)
        
        # Restore selection if possible
        if selected_key and selected_key in self.printer_cards:
            self._on_card_clicked(self.printer_cards[selected_key])
        
        # Refresh all status
        self._refresh_all_status()
    
    def _show_scan_dialog(self):
        dialog = ScanDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            selected = dialog.get_selected_printers()
            for p in selected:
                # Check by MAC address first
                existing_by_mac = None
                scan_mac = p.get('mac_address', '')
                if scan_mac:
                    for pc in self.config_manager.printers:
                        if pc.mac_address and pc.mac_address == scan_mac:
                            existing_by_mac = pc
                            break
                
                # Fallback: check by name
                existing_by_name = None
                if not existing_by_mac and p.get('name'):
                    for pc in self.config_manager.printers:
                        if pc.name and pc.name == p['name']:
                            existing_by_name = pc
                            break
                
                existing = existing_by_mac or existing_by_name
                if existing and (existing.host != p['host'] or existing.port != p['port']):
                    # IP changed - update existing printer
                    old_key = f"{existing.host}:{existing.port}"
                    existing.host = p['host']
                    existing.port = p['port']
                    if scan_mac and not existing.mac_address:
                        existing.mac_address = scan_mac
                    self.config_manager.save()
                    new_key = f"{p['host']}:{p['port']}"
                    if old_key in self.printer_cards:
                        card = self.printer_cards.pop(old_key)
                        card.config = existing
                        self.printer_cards[new_key] = card
                elif not existing:
                    config = PrinterConfig(
                        name=p['name'],
                        host=p['host'],
                        port=p['port'],
                        mac_address=scan_mac,
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
        dialog.compact_mode_changed = False  # Initialize flag
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Update privacy mode on all cards
            privacy_mode = self.config_manager.get_setting('privacy_mode', False)
            for card in self.printer_cards.values():
                card.update_privacy_mode(privacy_mode)
            
            # Recreate all cards if compact mode changed
            if dialog.compact_mode_changed:
                self._recreate_all_cards()
    
    def _on_camera_clicked(self, webcam_url: str):
        self.stats_panel.set_webcam_url(webcam_url)
    
    def _toggle_sidebar(self):
        """Toggle sidebar visibility"""
        self.sidebar_visible = not self.sidebar_visible
        if self.sidebar_visible:
            self.stats_panel.show()
            self.sidebar_toggle_btn.setText("◀")
        else:
            self.stats_panel.hide()
            self.sidebar_toggle_btn.setText("▶")
    
    def _on_login_requested(self, card: PrinterCard):
        """Handle login request - save config and refresh status"""
        # Save updated credentials to config
        self.config_manager.save()
        # Trigger status refresh for this printer
        self._refresh_printer_status(card, full_refresh=True)
    
    def _on_card_clicked(self, card: PrinterCard):
        """Handle card selection"""
        # Deselect previous card
        if self.selected_printer and self.selected_printer != card:
            self.selected_printer.set_selected(False)
        
        # Select new card
        self.selected_printer = card
        card.set_selected(True)
        
        # Update stats panel with this printer's info
        # Note: clear() disables buttons, so we must call enable_controls AFTER clear()
        self.stats_panel.clear()
        self.stats_panel.set_printer_config(card.config)  # Set config for G-code commands
        # Enable control buttons AFTER clear() since clear() disables them
        self.stats_panel.enable_controls(True)
        self.stats_panel.set_printer_name(card.config.name or card.config.host)
        self.stats_panel.update_stats(card.stats)
        self.stats_panel.update_system_info(card.system_info)  # Also updates MMU info
        
        # Set webcam URL
        if card.system_info.webcam_url:
            self.stats_panel.set_webcam_url(card.system_info.webcam_url)
        else:
            # Try default webcam URL
            default_url = f"http://{card.config.host}/webcam/?action=stream"
            self.stats_panel.set_webcam_url(default_url)
    
    def _refresh_all_status(self, full_refresh: bool = True):
        """Refresh all printers. full_refresh=True on startup/manual refresh."""
        # Stagger updates to avoid overwhelming the network
        for i, (key, card) in enumerate(self.printer_cards.items()):
            # Delay each printer's update by 500ms to spread the load
            QTimer.singleShot(i * 500, lambda c=card, fr=full_refresh: self._refresh_printer_status(c, full_refresh=fr))
    
    def _refresh_printer_status(self, card: PrinterCard, full_refresh: bool = False):
        """Refresh printer status. full_refresh=True fetches all info including name/system info."""
        config = card.config
        
        async def fetch():
            client = MoonrakerClient(
                config.host, config.port,
                config.api_key, config.username, config.password
            )
            try:
                # Always fetch status and stats (lightweight)
                status = await client.get_status()
                stats = await client.get_print_stats()
                
                # Only fetch heavy info on full refresh (startup or manual refresh)
                system_info = None
                shaper_data = None
                name = config.name
                
                if full_refresh:
                    system_info = await client.get_system_info()
                    shaper_data = await client.get_input_shaper_data()
                    
                    # Try to get better name if not set
                    if not config.name or config.name == config.host:
                        name = await client.get_printer_name()
                        if name and name != config.host:
                            config.name = name
                
                return status, stats, system_info, shaper_data, name, full_refresh
            finally:
                await client.close()
        
        worker = AsyncWorker(fetch())
        worker.finished.connect(lambda result: self._on_status_received(card, result))
        worker.start()
        self.update_workers.append(worker)
    
    def _on_status_received(self, card: PrinterCard, result):
        if result:
            status, stats, system_info, shaper_data, name, full_refresh = result
            card.update_status(status)
            card.update_stats(stats)
            
            # Only update heavy info on full refresh
            if full_refresh and system_info:
                card.update_system_info(system_info)
                # Save MAC address to config for unique identification
                if system_info.mac_address and not card.config.mac_address:
                    card.config.mac_address = system_info.mac_address
                    self.config_manager.save()
            if full_refresh and name:
                card.set_name(name)
            
            # Update stats panel if this is the selected printer
            if self.selected_printer == card:
                self.stats_panel.update_temps(
                    status.extruder_temp,
                    status.bed_temp,
                    status.chamber_temp
                )
                self.stats_panel.update_stats(stats)
                if full_refresh and system_info:
                    self.stats_panel.update_system_info(system_info)
                if full_refresh and shaper_data:
                    self.stats_panel.update_input_shaper(shaper_data)
                self.stats_panel.set_printer_config(card.config)
                # Ensure controls are enabled when printer is selected
                self.stats_panel.enable_controls(True)
                
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
        # Long-running commands that don't need success confirmation popup
        long_running_commands = ['SHAPER_CALIBRATE', 'G28', 'BED_MESH_CALIBRATE', 'PROBE_CALIBRATE', 
                                  'PID_CALIBRATE', 'QUAD_GANTRY_LEVEL', 'Z_TILT_ADJUST']
        is_long_running = any(cmd in gcode.upper() for cmd in long_running_commands)
        
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
                # Don't show popup for long-running commands - they run in background
                if not is_long_running:
                    QMessageBox.information(self, "Success", f"Command sent successfully:\n{gcode}")
            else:
                # For long-running commands, the API might return before completion
                # Check if the command was actually accepted
                if is_long_running:
                    self.status_label.setText(f"Command started: {gcode[:30]}...")
                    # Don't show error for long-running commands as they may still be running
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
    # Setup error logging
    import traceback
    from datetime import datetime
    
    log_dir = Path.home() / ".klipperbuddy"
    log_dir.mkdir(parents=True, exist_ok=True)
    error_log_path = log_dir / "error.log"
    
    def log_error(exc_type, exc_value, exc_tb):
        """Log uncaught exceptions to file"""
        with open(error_log_path, 'a') as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write(f"{'='*60}\n")
            traceback.print_exception(exc_type, exc_value, exc_tb, file=f)
        # Also call default handler
        sys.__excepthook__(exc_type, exc_value, exc_tb)
    
    sys.excepthook = log_error
    
    try:
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
    except Exception as e:
        # Log startup error
        with open(error_log_path, 'a') as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"Startup Error: {datetime.now().isoformat()}\n")
            f.write(f"{'='*60}\n")
            traceback.print_exc(file=f)
        raise


if __name__ == "__main__":
    main()
