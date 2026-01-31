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
    QSplitter, QGroupBox, QSizePolicy
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QRect, QPoint, QMargins
from PyQt6.QtGui import (
    QFont, QColor, QPalette, QLinearGradient, QPainter, QBrush, QPen,
    QFontDatabase, QPixmap, QPainterPath, QPaintEvent
)

import aiohttp

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
        self.printers: List[PrinterConfig] = []
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.load()
    
    def load(self):
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    self.printers = [PrinterConfig(**p) for p in data.get('printers', [])]
            except:
                self.printers = []
    
    def save(self):
        data = {'printers': [vars(p) for p in self.printers]}
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
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=2)) as resp:
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
        
        # Legend
        legend_y = self.height() - 15
        painter.setFont(QFont("Play", 9))
        
        painter.setPen(QPen(QColor(COLORS['temp_hotend']), 2))
        painter.drawLine(margin, legend_y, margin + 20, legend_y)
        painter.setPen(QColor(COLORS['text_secondary']))
        painter.drawText(margin + 25, legend_y + 4, "Hotend")
        
        painter.setPen(QPen(QColor(COLORS['temp_bed']), 2))
        painter.drawLine(margin + 90, legend_y, margin + 110, legend_y)
        painter.setPen(QColor(COLORS['text_secondary']))
        painter.drawText(margin + 115, legend_y + 4, "Bed")
        
        painter.setPen(QPen(QColor(COLORS['temp_chamber']), 2))
        painter.drawLine(margin + 160, legend_y, margin + 180, legend_y)
        painter.setPen(QColor(COLORS['text_secondary']))
        painter.drawText(margin + 185, legend_y + 4, "Chamber")


# =============================================================================
# Printer Card Widget
# =============================================================================

class PrinterCard(QFrame):
    """Cyberpunk-style printer status card"""
    
    camera_clicked = pyqtSignal(str)  # webcam_url
    graph_clicked = pyqtSignal(object)  # self
    
    def __init__(self, config: PrinterConfig, parent=None):
        super().__init__(parent)
        self.config = config
        self.status = PrinterStatus()
        self.stats = PrinterStats()
        self.system_info = SystemInfo()
        self.client: Optional[MoonrakerClient] = None
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
        ext_icon = QLabel("🔥")
        ext_icon.setFont(QFont("Segoe UI Emoji", 14))
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
        bed_icon = QLabel("🛏️")
        bed_icon.setFont(QFont("Segoe UI Emoji", 14))
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
        chamber_icon = QLabel("📦")
        chamber_icon.setFont(QFont("Segoe UI Emoji", 14))
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
        
        self.camera_btn = QPushButton("📷")
        self.camera_btn.setFixedSize(40, 32)
        self.camera_btn.setToolTip("View Camera")
        self.camera_btn.clicked.connect(self._on_camera_click)
        btn_layout.addWidget(self.camera_btn)
        
        self.graph_btn = QPushButton("📈")
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
    
    def _apply_style(self):
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
        
        # Add glow effect
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(15)
        shadow.setColor(QColor(COLORS['accent']))
        shadow.setOffset(0, 0)
        self.setGraphicsEffect(shadow)
    
    def _on_camera_click(self):
        if self.system_info.webcam_url:
            self.camera_clicked.emit(self.system_info.webcam_url)
        else:
            # Try to open default webcam URL
            url = f"http://{self.config.host}/webcam/?action=stream"
            self.camera_clicked.emit(url)
    
    def _on_graph_click(self):
        self.graph_clicked.emit(self)
    
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
        
        # Temperature Graph
        graph_label = QLabel("📈 TEMPERATURE GRAPH")
        graph_label.setFont(QFont("Play", 12, QFont.Weight.Bold))
        graph_label.setStyleSheet(f"color: {COLORS['accent']};")
        layout.addWidget(graph_label)
        
        self.temp_chart = TemperatureChart()
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
        cam_label.setFont(QFont("Play", 12, QFont.Weight.Bold))
        cam_label.setStyleSheet(f"color: {COLORS['accent']};")
        layout.addWidget(cam_label)
        
        self.camera_frame = QFrame()
        self.camera_frame.setFixedHeight(120)
        self.camera_frame.setStyleSheet(f"""
            background-color: {COLORS['bg_dark']};
            border: 1px solid {COLORS['border']};
            border-radius: 4px;
        """)
        
        cam_layout = QVBoxLayout(self.camera_frame)
        self.camera_placeholder = QLabel("📷 Click camera button on a printer card")
        self.camera_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.camera_placeholder.setStyleSheet(f"color: {COLORS['text_muted']};")
        self.camera_placeholder.setFont(QFont("Play", 10))
        cam_layout.addWidget(self.camera_placeholder)
        
        self.open_camera_btn = QPushButton("Open in Browser")
        self.open_camera_btn.setEnabled(False)
        self.open_camera_btn.clicked.connect(self._open_camera)
        cam_layout.addWidget(self.open_camera_btn)
        
        layout.addWidget(self.camera_frame)
        
        self.current_webcam_url = ""
        
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
    
    def set_webcam_url(self, url: str):
        self.current_webcam_url = url
        self.camera_placeholder.setText(f"📷 {url[:40]}..." if len(url) > 40 else f"📷 {url}")
        self.open_camera_btn.setEnabled(True)
    
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
        self.camera_placeholder.setText("📷 Click camera button on a printer card")
        self.open_camera_btn.setEnabled(False)
        self.current_webcam_url = ""


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
        self.status_label.setText("Scanning network...")
        
        async def scan():
            hosts = NetworkScanner.get_network_range()
            results = []
            total = len(hosts)
            
            for i, host in enumerate(hosts):
                if not self._scanning:
                    break
                
                result = await NetworkScanner.check_moonraker(host)
                if result:
                    # Get printer name
                    client = MoonrakerClient(host, result['port'])
                    name = await client.get_printer_name()
                    await client.close()
                    result['name'] = name
                    results.append(result)
                
                progress = int((i + 1) / total * 100)
                self.progress.setValue(progress)
            
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
        
        self._setup_ui()
        self._load_printers()
        
        # Auto-refresh timer
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self._refresh_all_status)
        self.refresh_timer.start(3000)  # Refresh every 3 seconds
    
    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(16)
        
        # Header
        header_layout = QHBoxLayout()
        
        # Logo image
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
        card.graph_clicked.connect(self._on_graph_clicked)
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
    
    def _on_camera_clicked(self, webcam_url: str):
        self.stats_panel.set_webcam_url(webcam_url)
    
    def _on_graph_clicked(self, card: PrinterCard):
        self.selected_printer = card
        self.stats_panel.clear()
        # Update stats panel with this printer's data
        self.stats_panel.update_stats(card.stats)
        self.stats_panel.update_system_info(card.system_info)
        if card.system_info.webcam_url:
            self.stats_panel.set_webcam_url(card.system_info.webcam_url)
    
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
                
                # Also try to get better name if not set
                if not config.name or config.name == config.host:
                    name = await client.get_printer_name()
                    if name and name != config.host:
                        config.name = name
                
                return status, stats, system_info, config.name
            finally:
                await client.close()
        
        worker = AsyncWorker(fetch())
        worker.finished.connect(lambda result: self._on_status_received(card, result))
        worker.start()
        self.update_workers.append(worker)
    
    def _on_status_received(self, card: PrinterCard, result):
        if result:
            status, stats, system_info, name = result
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
            
            # If no printer selected, select the first one
            if self.selected_printer is None and self.printer_cards:
                first_card = list(self.printer_cards.values())[0]
                self._on_graph_clicked(first_card)
        
        # Clean up finished workers
        self.update_workers = [w for w in self.update_workers if w.isRunning()]
    
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
