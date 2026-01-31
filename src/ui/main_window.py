"""
Main Window for KlipperBuddy
With network auto-discovery and Fluidd/Mainsail authentication support
"""

import asyncio
import uuid
from datetime import datetime
from typing import Optional

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QIcon, QPixmap, QAction
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QLineEdit, QSpinBox, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    QDialog, QFormLayout, QDialogButtonBox, QGroupBox,
    QProgressBar, QFrame, QSplitter, QTextEdit, QComboBox,
    QSystemTrayIcon, QMenu, QApplication, QScrollArea,
    QCheckBox, QProgressDialog
)

from api.moonraker_client import MoonrakerClient, PrinterStatus
from models.printer import PrinterConfig, PrinterConfigManager
from utils.network_scanner import NetworkScanner, DiscoveredPrinter, auto_discover_printers
from utils.auth_manager import AuthManager


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
        
        # Info
        info_label = QLabel(
            "Scan your local network to automatically discover Klipper printers "
            "running Moonraker. This may take a few moments."
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # Scan button
        scan_layout = QHBoxLayout()
        self.scan_btn = QPushButton("🔍 Start Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        scan_layout.addWidget(self.scan_btn)
        
        self.cancel_scan_btn = QPushButton("Cancel Scan")
        self.cancel_scan_btn.setEnabled(False)
        self.cancel_scan_btn.clicked.connect(self.cancel_scan)
        scan_layout.addWidget(self.cancel_scan_btn)
        
        scan_layout.addStretch()
        layout.addLayout(scan_layout)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("")
        layout.addWidget(self.status_label)
        
        # Results table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "Select", "Name", "Host", "Port", "Auth Required"
        ])
        self.table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        layout.addWidget(self.table)
        
        # Dialog buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
    def start_scan(self):
        """Start network scan"""
        self.scan_btn.setEnabled(False)
        self.cancel_scan_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 254)
        self.status_label.setText("Scanning network...")
        self.table.setRowCount(0)
        
        self.scanner = NetworkScanner()
        
        async def scan_with_progress():
            def progress_callback(current, total, message):
                # This will be called from the async context
                pass
            return await self.scanner.scan_network(progress_callback)
        
        self.worker = AsyncWorker(scan_with_progress())
        self.worker.finished.connect(self._on_scan_finished)
        self.worker.error.connect(self._on_scan_error)
        self.worker.start()
        
        # Timer to update progress
        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self._update_progress)
        self.progress_timer.start(100)
        
    def _update_progress(self):
        """Update progress bar"""
        if hasattr(self, 'scanner') and self.scanner.is_scanning:
            # Estimate progress
            current = self.progress_bar.value()
            if current < 250:
                self.progress_bar.setValue(current + 1)
        
    def cancel_scan(self):
        """Cancel the network scan"""
        if hasattr(self, 'scanner'):
            self.scanner.cancel_scan()
        self.status_label.setText("Scan cancelled")
        self.scan_btn.setEnabled(True)
        self.cancel_scan_btn.setEnabled(False)
        if hasattr(self, 'progress_timer'):
            self.progress_timer.stop()
        
    def _on_scan_finished(self, printers):
        """Handle scan completion"""
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
            # Checkbox
            checkbox = QCheckBox()
            checkbox.setChecked(True)
            self.table.setCellWidget(row, 0, checkbox)
            
            self.table.setItem(row, 1, QTableWidgetItem(printer.name))
            self.table.setItem(row, 2, QTableWidgetItem(printer.host))
            self.table.setItem(row, 3, QTableWidgetItem(str(printer.port)))
            self.table.setItem(row, 4, QTableWidgetItem(
                "Yes" if printer.requires_auth else "No"
            ))
            
    def _on_scan_error(self, error):
        """Handle scan error"""
        if hasattr(self, 'progress_timer'):
            self.progress_timer.stop()
        self.status_label.setText(f"Scan error: {error}")
        self.scan_btn.setEnabled(True)
        self.cancel_scan_btn.setEnabled(False)
        
    def get_selected_printers(self):
        """Get list of selected printers"""
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
        
        # Basic info
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
        
        # Authentication section
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
        
        # Webcam
        self.webcam_edit = QLineEdit()
        self.webcam_edit.setPlaceholderText("http://192.168.1.100/webcam/?action=stream")
        layout.addRow("Webcam URL:", self.webcam_edit)
        
        # Test connection button
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
        
        # Dialog buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)
        
        # Load existing data if editing
        if self.printer:
            self.name_edit.setText(self.printer.name)
            self.host_edit.setText(self.printer.host)
            self.port_spin.setValue(self.printer.port)
            if self.printer.api_key:
                self.api_key_edit.setText(self.printer.api_key)
            if self.printer.webcam_url:
                self.webcam_edit.setText(self.printer.webcam_url)
            # Load saved credentials
            cred = self.auth_manager.get_credentials(self.printer.host, self.printer.port)
            if cred:
                if cred.username:
                    self.username_edit.setText(cred.username)
                if cred.password:
                    self.password_edit.setText(cred.password)
                    
    def test_connection(self):
        """Test connection to printer"""
        host = self.host_edit.text().strip()
        port = self.port_spin.value()
        api_key = self.api_key_edit.text().strip() or None
        username = self.username_edit.text().strip() or None
        password = self.password_edit.text().strip() or None
        
        if not host:
            self.status_label.setText("❌ Please enter a host")
            return
            
        self.status_label.setText("⏳ Testing connection...")
        self.test_btn.setEnabled(False)
        
        async def test():
            client = MoonrakerClient(host, port, api_key, username, password)
            try:
                result = await client.connect()
                if result:
                    info = await client.get_printer_info()
                    return {"success": True, "info": info, "requires_auth": client.requires_auth}
                return {"success": False, "requires_auth": client.requires_auth}
            finally:
                await client.close()
                
        self.worker = AsyncWorker(test())
        self.worker.finished.connect(self._on_test_finished)
        self.worker.error.connect(self._on_test_error)
        self.worker.start()
        
    def _on_test_finished(self, result):
        self.test_btn.setEnabled(True)
        if result.get("success"):
            info = result.get("info", {})
            version = info.get("software_version", "unknown")
            self.status_label.setText(f"✅ Connected! Klipper {version}")
            self.status_label.setStyleSheet("color: green;")
        elif result.get("requires_auth"):
            self.status_label.setText("🔐 Authentication required - please enter credentials")
            self.status_label.setStyleSheet("color: orange;")
        else:
            self.status_label.setText("❌ Connection failed")
            self.status_label.setStyleSheet("color: red;")
            
    def _on_test_error(self, error):
        self.test_btn.setEnabled(True)
        self.status_label.setText(f"❌ Error: {error}")
        self.status_label.setStyleSheet("color: red;")
        
    def test_authentication(self):
        """Test authentication credentials"""
        host = self.host_edit.text().strip()
        port = self.port_spin.value()
        username = self.username_edit.text().strip()
        password = self.password_edit.text().strip()
        api_key = self.api_key_edit.text().strip()
        
        if not host:
            self.status_label.setText("❌ Please enter a host")
            return
            
        if not (username and password) and not api_key:
            self.status_label.setText("❌ Please enter credentials")
            return
            
        self.status_label.setText("⏳ Testing authentication...")
        self.test_auth_btn.setEnabled(False)
        
        async def test():
            return await self.auth_manager.test_authentication(
                host, port, username, password, api_key
            )
            
        self.worker = AsyncWorker(test())
        self.worker.finished.connect(self._on_auth_test_finished)
        self.worker.error.connect(self._on_auth_test_error)
        self.worker.start()
        
    def _on_auth_test_finished(self, result):
        self.test_auth_btn.setEnabled(True)
        success, message = result
        if success:
            self.status_label.setText(f"✅ {message}")
            self.status_label.setStyleSheet("color: green;")
            # Save credentials
            host = self.host_edit.text().strip()
            port = self.port_spin.value()
            username = self.username_edit.text().strip() or None
            password = self.password_edit.text().strip() or None
            api_key = self.api_key_edit.text().strip() or None
            self.auth_manager.set_credentials(host, port, username, password, api_key)
        else:
            self.status_label.setText(f"❌ {message}")
            self.status_label.setStyleSheet("color: red;")
            
    def _on_auth_test_error(self, error):
        self.test_auth_btn.setEnabled(True)
        self.status_label.setText(f"❌ Error: {error}")
        self.status_label.setStyleSheet("color: red;")
        
    def get_printer_config(self) -> Optional[PrinterConfig]:
        """Get printer configuration from dialog"""
        name = self.name_edit.text().strip()
        host = self.host_edit.text().strip()
        
        if not name or not host:
            return None
        
        # Save credentials if provided
        username = self.username_edit.text().strip() or None
        password = self.password_edit.text().strip() or None
        api_key = self.api_key_edit.text().strip() or None
        
        if username or password or api_key:
            self.auth_manager.set_credentials(
                host, self.port_spin.value(),
                username, password, api_key
            )
            
        return PrinterConfig(
            id=self.printer.id if self.printer else str(uuid.uuid4()),
            name=name,
            host=host,
            port=self.port_spin.value(),
            api_key=api_key,
            webcam_url=self.webcam_edit.text().strip() or None,
            created_at=self.printer.created_at if self.printer else datetime.now()
        )


class PrinterCard(QFrame):
    """Widget displaying printer status"""
    
    def __init__(self, printer: PrinterConfig, parent=None):
        super().__init__(parent)
        self.printer = printer
        self.client: Optional[MoonrakerClient] = None
        self.status: Optional[PrinterStatus] = None
        self.setup_ui()
        
    def setup_ui(self):
        self.setFrameStyle(QFrame.Shape.Box | QFrame.Shadow.Raised)
        self.setLineWidth(2)
        self.setMinimumWidth(300)
        self.setMaximumWidth(400)
        
        layout = QVBoxLayout(self)
        
        # Header
        header = QHBoxLayout()
        self.name_label = QLabel(self.printer.name)
        self.name_label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        header.addWidget(self.name_label)
        
        self.status_indicator = QLabel("⚪")
        self.status_indicator.setFont(QFont("Arial", 16))
        header.addWidget(self.status_indicator)
        layout.addLayout(header)
        
        # Host info
        self.host_label = QLabel(f"{self.printer.host}:{self.printer.port}")
        self.host_label.setStyleSheet("color: gray;")
        layout.addWidget(self.host_label)
        
        # State
        self.state_label = QLabel("Disconnected")
        self.state_label.setFont(QFont("Arial", 12))
        layout.addWidget(self.state_label)
        
        # Progress
        self.progress_group = QGroupBox("Current Print")
        progress_layout = QVBoxLayout(self.progress_group)
        
        self.filename_label = QLabel("No active print")
        progress_layout.addWidget(self.filename_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        progress_layout.addWidget(self.progress_bar)
        
        progress_info = QHBoxLayout()
        self.progress_label = QLabel("0%")
        self.time_label = QLabel("--:--:--")
        progress_info.addWidget(self.progress_label)
        progress_info.addStretch()
        progress_info.addWidget(self.time_label)
        progress_layout.addLayout(progress_info)
        
        layout.addWidget(self.progress_group)
        
        # Temperatures
        temp_group = QGroupBox("Temperatures")
        temp_layout = QGridLayout(temp_group)
        
        temp_layout.addWidget(QLabel("Extruder:"), 0, 0)
        self.extruder_label = QLabel("-- / --°C")
        temp_layout.addWidget(self.extruder_label, 0, 1)
        
        temp_layout.addWidget(QLabel("Bed:"), 1, 0)
        self.bed_label = QLabel("-- / --°C")
        temp_layout.addWidget(self.bed_label, 1, 1)
        
        layout.addWidget(temp_group)
        
        # Control buttons
        btn_layout = QHBoxLayout()
        
        self.pause_btn = QPushButton("⏸ Pause")
        self.pause_btn.clicked.connect(self.pause_print)
        btn_layout.addWidget(self.pause_btn)
        
        self.resume_btn = QPushButton("▶ Resume")
        self.resume_btn.clicked.connect(self.resume_print)
        btn_layout.addWidget(self.resume_btn)
        
        self.cancel_btn = QPushButton("⏹ Cancel")
        self.cancel_btn.clicked.connect(self.cancel_print)
        self.cancel_btn.setStyleSheet("background-color: #ff6b6b;")
        btn_layout.addWidget(self.cancel_btn)
        
        layout.addLayout(btn_layout)
        
        # Emergency stop
        self.estop_btn = QPushButton("🛑 EMERGENCY STOP")
        self.estop_btn.setStyleSheet("background-color: red; color: white; font-weight: bold;")
        self.estop_btn.clicked.connect(self.emergency_stop)
        layout.addWidget(self.estop_btn)
        
    def update_status(self, status: PrinterStatus):
        """Update display with new status"""
        self.status = status
        
        # Connection indicator
        if status.connected:
            if status.state == "ready":
                self.status_indicator.setText("🟢")
            elif status.state == "printing":
                self.status_indicator.setText("🔵")
            elif status.state == "error":
                self.status_indicator.setText("🔴")
            else:
                self.status_indicator.setText("🟡")
        else:
            self.status_indicator.setText("⚪")
            
        # State
        self.state_label.setText(status.state_message or status.state.title())
        
        # Progress
        if status.filename:
            self.filename_label.setText(status.filename)
            self.progress_bar.setValue(int(status.progress))
            self.progress_label.setText(f"{status.progress:.1f}%")
            
            # Format time
            duration = int(status.print_duration)
            hours, remainder = divmod(duration, 3600)
            minutes, seconds = divmod(remainder, 60)
            self.time_label.setText(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        else:
            self.filename_label.setText("No active print")
            self.progress_bar.setValue(0)
            self.progress_label.setText("0%")
            self.time_label.setText("--:--:--")
            
        # Temperatures
        self.extruder_label.setText(
            f"{status.extruder_temp:.1f} / {status.extruder_target:.0f}°C"
        )
        self.bed_label.setText(
            f"{status.bed_temp:.1f} / {status.bed_target:.0f}°C"
        )
        
    def _run_async(self, coro, callback=None):
        """Run async operation"""
        worker = AsyncWorker(coro)
        if callback:
            worker.finished.connect(callback)
        worker.start()
        # Keep reference to prevent garbage collection
        self._worker = worker
        
    def pause_print(self):
        if self.client:
            self._run_async(self.client.pause_print())
            
    def resume_print(self):
        if self.client:
            self._run_async(self.client.resume_print())
            
    def cancel_print(self):
        reply = QMessageBox.question(
            self, "Cancel Print",
            "Are you sure you want to cancel the current print?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes and self.client:
            self._run_async(self.client.cancel_print())
            
    def emergency_stop(self):
        reply = QMessageBox.warning(
            self, "Emergency Stop",
            "This will immediately stop the printer!\nAre you sure?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes and self.client:
            self._run_async(self.client.emergency_stop())


class HistoryTab(QWidget):
    """Tab showing print history"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.clients: dict[str, MoonrakerClient] = {}
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.printer_combo = QComboBox()
        self.printer_combo.addItem("All Printers", "all")
        self.printer_combo.currentIndexChanged.connect(self.refresh_history)
        toolbar.addWidget(QLabel("Printer:"))
        toolbar.addWidget(self.printer_combo)
        
        toolbar.addStretch()
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.refresh_history)
        toolbar.addWidget(refresh_btn)
        
        layout.addLayout(toolbar)
        
        # History table
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "Printer", "Filename", "Status", "Start Time", 
            "Duration", "Filament", "Actions"
        ])
        self.table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        layout.addWidget(self.table)
        
        # Statistics
        stats_group = QGroupBox("Statistics")
        stats_layout = QHBoxLayout(stats_group)
        
        self.total_prints_label = QLabel("Total Prints: 0")
        stats_layout.addWidget(self.total_prints_label)
        
        self.total_time_label = QLabel("Total Time: 0h")
        stats_layout.addWidget(self.total_time_label)
        
        self.total_filament_label = QLabel("Total Filament: 0m")
        stats_layout.addWidget(self.total_filament_label)
        
        self.success_rate_label = QLabel("Success Rate: --%")
        stats_layout.addWidget(self.success_rate_label)
        
        layout.addWidget(stats_group)
        
    def add_printer(self, printer_id: str, name: str, client: MoonrakerClient):
        """Add printer to combo box"""
        self.printer_combo.addItem(name, printer_id)
        self.clients[printer_id] = client
        
    def refresh_history(self):
        """Refresh print history"""
        self.table.setRowCount(0)
        
        selected = self.printer_combo.currentData()
        
        if selected == "all":
            clients = list(self.clients.items())
        else:
            if selected in self.clients:
                clients = [(selected, self.clients[selected])]
            else:
                return
                
        async def fetch_all():
            all_jobs = []
            for printer_id, client in clients:
                try:
                    jobs = await client.get_job_history(limit=100)
                    for job in jobs:
                        all_jobs.append((printer_id, job))
                except Exception as e:
                    print(f"Error fetching history: {e}")
            return all_jobs
            
        worker = AsyncWorker(fetch_all())
        worker.finished.connect(self._on_history_loaded)
        worker.start()
        self._worker = worker
        
    def _on_history_loaded(self, jobs):
        """Handle loaded history"""
        self.table.setRowCount(len(jobs))
        
        total_prints = len(jobs)
        total_time = 0
        total_filament = 0
        completed = 0
        
        for row, (printer_id, job) in enumerate(jobs):
            # Find printer name
            idx = self.printer_combo.findData(printer_id)
            printer_name = self.printer_combo.itemText(idx) if idx >= 0 else printer_id
            
            self.table.setItem(row, 0, QTableWidgetItem(printer_name))
            self.table.setItem(row, 1, QTableWidgetItem(job.filename))
            
            status_item = QTableWidgetItem(job.status)
            if job.status == "completed":
                status_item.setBackground(Qt.GlobalColor.green)
                completed += 1
            elif job.status == "cancelled":
                status_item.setBackground(Qt.GlobalColor.yellow)
            elif job.status == "error":
                status_item.setBackground(Qt.GlobalColor.red)
            self.table.setItem(row, 2, status_item)
            
            self.table.setItem(row, 3, QTableWidgetItem(
                job.start_time.strftime("%Y-%m-%d %H:%M")
            ))
            
            duration_hours = job.print_duration / 3600
            self.table.setItem(row, 4, QTableWidgetItem(f"{duration_hours:.1f}h"))
            total_time += job.print_duration
            
            filament_m = job.filament_used / 1000
            self.table.setItem(row, 5, QTableWidgetItem(f"{filament_m:.1f}m"))
            total_filament += job.filament_used
            
        # Update statistics
        self.total_prints_label.setText(f"Total Prints: {total_prints}")
        self.total_time_label.setText(f"Total Time: {total_time/3600:.1f}h")
        self.total_filament_label.setText(f"Total Filament: {total_filament/1000:.1f}m")
        
        if total_prints > 0:
            success_rate = (completed / total_prints) * 100
            self.success_rate_label.setText(f"Success Rate: {success_rate:.1f}%")


class FilesTab(QWidget):
    """Tab for file management"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.clients: dict[str, MoonrakerClient] = {}
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.printer_combo = QComboBox()
        self.printer_combo.currentIndexChanged.connect(self.refresh_files)
        toolbar.addWidget(QLabel("Printer:"))
        toolbar.addWidget(self.printer_combo)
        
        toolbar.addStretch()
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.refresh_files)
        toolbar.addWidget(refresh_btn)
        
        layout.addLayout(toolbar)
        
        # Files table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "Filename", "Size", "Modified", "Print Time", "Actions"
        ])
        self.table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.table.doubleClicked.connect(self.on_file_double_click)
        layout.addWidget(self.table)
        
    def add_printer(self, printer_id: str, name: str, client: MoonrakerClient):
        """Add printer to combo box"""
        self.printer_combo.addItem(name, printer_id)
        self.clients[printer_id] = client
        
    def refresh_files(self):
        """Refresh file list"""
        printer_id = self.printer_combo.currentData()
        if not printer_id or printer_id not in self.clients:
            return
            
        client = self.clients[printer_id]
        
        async def fetch():
            return await client.get_files()
            
        worker = AsyncWorker(fetch())
        worker.finished.connect(self._on_files_loaded)
        worker.start()
        self._worker = worker
        
    def _on_files_loaded(self, files):
        """Handle loaded files"""
        self.table.setRowCount(len(files))
        
        for row, file_info in enumerate(files):
            filename = file_info.get("path", file_info.get("filename", ""))
            self.table.setItem(row, 0, QTableWidgetItem(filename))
            
            size_mb = file_info.get("size", 0) / (1024 * 1024)
            self.table.setItem(row, 1, QTableWidgetItem(f"{size_mb:.2f} MB"))
            
            modified = file_info.get("modified", 0)
            if modified:
                mod_time = datetime.fromtimestamp(modified)
                self.table.setItem(row, 2, QTableWidgetItem(
                    mod_time.strftime("%Y-%m-%d %H:%M")
                ))
            else:
                self.table.setItem(row, 2, QTableWidgetItem("-"))
                
            print_time = file_info.get("estimated_time", 0)
            if print_time:
                hours = print_time / 3600
                self.table.setItem(row, 3, QTableWidgetItem(f"{hours:.1f}h"))
            else:
                self.table.setItem(row, 3, QTableWidgetItem("-"))
                
            # Print button
            print_btn = QPushButton("▶ Print")
            print_btn.clicked.connect(lambda checked, f=filename: self.start_print(f))
            self.table.setCellWidget(row, 4, print_btn)
            
    def on_file_double_click(self, index):
        """Handle double click on file"""
        row = index.row()
        filename = self.table.item(row, 0).text()
        self.start_print(filename)
        
    def start_print(self, filename: str):
        """Start printing a file"""
        reply = QMessageBox.question(
            self, "Start Print",
            f"Start printing {filename}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            printer_id = self.printer_combo.currentData()
            if printer_id and printer_id in self.clients:
                client = self.clients[printer_id]
                
                async def start():
                    return await client.start_print(filename)
                    
                worker = AsyncWorker(start())
                worker.finished.connect(
                    lambda r: QMessageBox.information(
                        self, "Print Started", 
                        f"Print started: {filename}" if r else "Failed to start print"
                    )
                )
                worker.start()
                self._worker = worker


class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("KlipperBuddy")
        self.setMinimumSize(1200, 800)
        
        # Config manager
        import os
        config_dir = os.path.join(os.path.expanduser("~"), ".klipperbuddy")
        os.makedirs(config_dir, exist_ok=True)
        self.config_manager = PrinterConfigManager(
            os.path.join(config_dir, "config.json")
        )
        
        # Auth manager
        self.auth_manager = AuthManager()
        
        # Printer clients
        self.clients: dict[str, MoonrakerClient] = {}
        self.printer_cards: dict[str, PrinterCard] = {}
        
        self.setup_ui()
        self.setup_tray()
        self.setup_timer()
        
        # Load printers
        self.load_printers()
        
        # Auto-scan on startup
        QTimer.singleShot(1000, self.auto_scan_startup)
        
    def setup_ui(self):
        """Setup main UI"""
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        
        # Tabs
        self.tabs = QTabWidget()
        
        # Dashboard tab
        dashboard = QWidget()
        dashboard_layout = QVBoxLayout(dashboard)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        add_btn = QPushButton("➕ Add Printer")
        add_btn.clicked.connect(self.add_printer)
        toolbar.addWidget(add_btn)
        
        scan_btn = QPushButton("🔍 Scan Network")
        scan_btn.clicked.connect(self.scan_network)
        toolbar.addWidget(scan_btn)
        
        toolbar.addStretch()
        
        refresh_btn = QPushButton("🔄 Refresh All")
        refresh_btn.clicked.connect(self.refresh_all)
        toolbar.addWidget(refresh_btn)
        
        dashboard_layout.addLayout(toolbar)
        
        # Printer cards area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        self.cards_widget = QWidget()
        self.cards_layout = QHBoxLayout(self.cards_widget)
        self.cards_layout.setAlignment(Qt.AlignmentFlag.AlignLeft)
        scroll.setWidget(self.cards_widget)
        
        dashboard_layout.addWidget(scroll)
        
        self.tabs.addTab(dashboard, "📊 Dashboard")
        
        # History tab
        self.history_tab = HistoryTab()
        self.tabs.addTab(self.history_tab, "📜 History")
        
        # Files tab
        self.files_tab = FilesTab()
        self.tabs.addTab(self.files_tab, "📁 Files")
        
        # Settings tab
        settings = QWidget()
        settings_layout = QVBoxLayout(settings)
        
        # Auto-scan settings
        scan_group = QGroupBox("Network Scanning")
        scan_layout = QVBoxLayout(scan_group)
        
        self.auto_scan_checkbox = QCheckBox("Auto-scan network on startup")
        self.auto_scan_checkbox.setChecked(True)
        scan_layout.addWidget(self.auto_scan_checkbox)
        
        rescan_layout = QHBoxLayout()
        rescan_layout.addWidget(QLabel("Re-scan interval (minutes):"))
        self.rescan_interval_spin = QSpinBox()
        self.rescan_interval_spin.setRange(0, 60)
        self.rescan_interval_spin.setValue(5)
        self.rescan_interval_spin.setSpecialValueText("Disabled")
        rescan_layout.addWidget(self.rescan_interval_spin)
        rescan_layout.addStretch()
        scan_layout.addLayout(rescan_layout)
        
        settings_layout.addWidget(scan_group)
        
        # Printers list
        printers_group = QGroupBox("Configured Printers")
        printers_layout = QVBoxLayout(printers_group)
        
        self.printers_table = QTableWidget()
        self.printers_table.setColumnCount(5)
        self.printers_table.setHorizontalHeaderLabels([
            "Name", "Host", "Port", "Status", "Actions"
        ])
        self.printers_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        printers_layout.addWidget(self.printers_table)
        
        settings_layout.addWidget(printers_group)
        settings_layout.addStretch()
        
        self.tabs.addTab(settings, "⚙️ Settings")
        
        layout.addWidget(self.tabs)
        
        # Status bar
        self.statusBar().showMessage("Ready")
        
        # Menu bar
        menubar = self.menuBar()
        
        file_menu = menubar.addMenu("File")
        
        add_action = QAction("Add Printer", self)
        add_action.triggered.connect(self.add_printer)
        file_menu.addAction(add_action)
        
        scan_action = QAction("Scan Network", self)
        scan_action.triggered.connect(self.scan_network)
        file_menu.addAction(scan_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def setup_tray(self):
        """Setup system tray icon"""
        self.tray = QSystemTrayIcon(self)
        self.tray.setToolTip("KlipperBuddy")
        
        tray_menu = QMenu()
        
        show_action = tray_menu.addAction("Show")
        show_action.triggered.connect(self.show)
        
        scan_action = tray_menu.addAction("Scan Network")
        scan_action.triggered.connect(self.scan_network)
        
        tray_menu.addSeparator()
        
        quit_action = tray_menu.addAction("Quit")
        quit_action.triggered.connect(QApplication.quit)
        
        self.tray.setContextMenu(tray_menu)
        self.tray.activated.connect(self.on_tray_activated)
        self.tray.show()
        
    def setup_timer(self):
        """Setup status update timer"""
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.refresh_all)
        self.update_timer.start(5000)  # Update every 5 seconds
        
    def on_tray_activated(self, reason):
        """Handle tray icon activation"""
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show()
            self.activateWindow()
            
    def auto_scan_startup(self):
        """Auto-scan network on startup if enabled"""
        if self.auto_scan_checkbox.isChecked() and len(self.clients) == 0:
            self.statusBar().showMessage("Scanning network for printers...")
            self.scan_network_silent()
            
    def scan_network(self):
        """Show network scan dialog"""
        dialog = NetworkScanDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            selected = dialog.get_selected_printers()
            for discovered in selected:
                # Check if already exists
                existing = False
                for printer in self.config_manager.get_all_printers():
                    if printer.host == discovered.host and printer.port == discovered.port:
                        existing = True
                        break
                
                if not existing:
                    printer = PrinterConfig(
                        id=str(uuid.uuid4()),
                        name=discovered.name or f"Printer at {discovered.host}",
                        host=discovered.host,
                        port=discovered.port,
                        created_at=datetime.now()
                    )
                    self.config_manager.add_printer(printer)
                    self.connect_printer(printer)
                    
            self.update_printers_table()
            
    def scan_network_silent(self):
        """Scan network silently and add discovered printers"""
        async def scan():
            return await auto_discover_printers()
            
        worker = AsyncWorker(scan())
        worker.finished.connect(self._on_silent_scan_finished)
        worker.start()
        self._scan_worker = worker
        
    def _on_silent_scan_finished(self, printers):
        """Handle silent scan completion"""
        added = 0
        for discovered in printers:
            # Check if already exists
            existing = False
            for printer in self.config_manager.get_all_printers():
                if printer.host == discovered.host and printer.port == discovered.port:
                    existing = True
                    break
            
            if not existing:
                printer = PrinterConfig(
                    id=str(uuid.uuid4()),
                    name=discovered.name or f"Printer at {discovered.host}",
                    host=discovered.host,
                    port=discovered.port,
                    created_at=datetime.now()
                )
                self.config_manager.add_printer(printer)
                self.connect_printer(printer)
                added += 1
                
        if added > 0:
            self.update_printers_table()
            self.statusBar().showMessage(f"Found and added {added} new printer(s)")
            self.tray.showMessage(
                "KlipperBuddy",
                f"Discovered {added} new printer(s) on the network",
                QSystemTrayIcon.MessageIcon.Information,
                3000
            )
        else:
            self.statusBar().showMessage("Network scan complete - no new printers found")
            
    def load_printers(self):
        """Load configured printers"""
        for printer in self.config_manager.get_all_printers():
            self.connect_printer(printer)
            
        self.update_printers_table()
        
    def connect_printer(self, printer: PrinterConfig):
        """Connect to a printer with authentication support"""
        # Get saved credentials
        cred = self.auth_manager.get_credentials(printer.host, printer.port)
        
        username = None
        password = None
        api_key = printer.api_key
        
        if cred:
            username = cred.username
            password = cred.password
            if cred.api_key:
                api_key = cred.api_key
        
        client = MoonrakerClient(printer.host, printer.port, api_key, username, password)
        self.clients[printer.id] = client
        
        # Create card
        card = PrinterCard(printer)
        card.client = client
        self.printer_cards[printer.id] = card
        self.cards_layout.addWidget(card)
        
        # Add to tabs
        self.history_tab.add_printer(printer.id, printer.name, client)
        self.files_tab.add_printer(printer.id, printer.name, client)
        
        # Initial status fetch
        self.refresh_printer(printer.id)
        
    def add_printer(self):
        """Show add printer dialog"""
        dialog = AddPrinterDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            printer = dialog.get_printer_config()
            if printer:
                self.config_manager.add_printer(printer)
                self.connect_printer(printer)
                self.update_printers_table()
                
    def edit_printer(self, printer_id: str):
        """Edit printer configuration"""
        printer = self.config_manager.get_printer(printer_id)
        if not printer:
            return
            
        dialog = AddPrinterDialog(self, printer)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            updated = dialog.get_printer_config()
            if updated:
                self.config_manager.update_printer(updated)
                # Reconnect
                if printer_id in self.clients:
                    async def close():
                        await self.clients[printer_id].close()
                    worker = AsyncWorker(close())
                    worker.start()
                
                # Get credentials
                cred = self.auth_manager.get_credentials(updated.host, updated.port)
                username = cred.username if cred else None
                password = cred.password if cred else None
                api_key = updated.api_key or (cred.api_key if cred else None)
                    
                self.clients[printer_id] = MoonrakerClient(
                    updated.host, updated.port, api_key, username, password
                )
                if printer_id in self.printer_cards:
                    self.printer_cards[printer_id].printer = updated
                    self.printer_cards[printer_id].client = self.clients[printer_id]
                    self.printer_cards[printer_id].name_label.setText(updated.name)
                    self.printer_cards[printer_id].host_label.setText(
                        f"{updated.host}:{updated.port}"
                    )
                self.update_printers_table()
                
    def remove_printer(self, printer_id: str):
        """Remove a printer"""
        reply = QMessageBox.question(
            self, "Remove Printer",
            "Are you sure you want to remove this printer?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            printer = self.config_manager.get_printer(printer_id)
            if printer:
                # Remove saved credentials
                self.auth_manager.remove_credentials(printer.host, printer.port)
            
            self.config_manager.remove_printer(printer_id)
            
            if printer_id in self.clients:
                async def close():
                    await self.clients[printer_id].close()
                worker = AsyncWorker(close())
                worker.start()
                del self.clients[printer_id]
                
            if printer_id in self.printer_cards:
                card = self.printer_cards[printer_id]
                self.cards_layout.removeWidget(card)
                card.deleteLater()
                del self.printer_cards[printer_id]
                
            self.update_printers_table()
            
    def update_printers_table(self):
        """Update printers settings table"""
        printers = self.config_manager.get_all_printers()
        self.printers_table.setRowCount(len(printers))
        
        for row, printer in enumerate(printers):
            self.printers_table.setItem(row, 0, QTableWidgetItem(printer.name))
            self.printers_table.setItem(row, 1, QTableWidgetItem(printer.host))
            self.printers_table.setItem(row, 2, QTableWidgetItem(str(printer.port)))
            
            # Status
            if printer.id in self.clients:
                client = self.clients[printer.id]
                if client.is_connected:
                    status = "Connected"
                elif client.requires_auth:
                    status = "Auth Required"
                else:
                    status = "Disconnected"
            else:
                status = "Not connected"
            self.printers_table.setItem(row, 3, QTableWidgetItem(status))
            
            # Actions
            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(0, 0, 0, 0)
            
            edit_btn = QPushButton("Edit")
            edit_btn.clicked.connect(lambda checked, pid=printer.id: self.edit_printer(pid))
            actions_layout.addWidget(edit_btn)
            
            remove_btn = QPushButton("Remove")
            remove_btn.clicked.connect(lambda checked, pid=printer.id: self.remove_printer(pid))
            actions_layout.addWidget(remove_btn)
            
            self.printers_table.setCellWidget(row, 4, actions_widget)
            
    def refresh_printer(self, printer_id: str):
        """Refresh single printer status"""
        if printer_id not in self.clients:
            return
            
        client = self.clients[printer_id]
        
        async def fetch():
            if not client.is_connected:
                await client.connect()
            return await client.get_printer_status()
            
        worker = AsyncWorker(fetch())
        worker.finished.connect(
            lambda status: self._on_status_updated(printer_id, status)
        )
        worker.start()
        # Store worker reference
        if not hasattr(self, '_workers'):
            self._workers = {}
        self._workers[printer_id] = worker
        
    def _on_status_updated(self, printer_id: str, status: PrinterStatus):
        """Handle status update"""
        if printer_id in self.printer_cards:
            self.printer_cards[printer_id].update_status(status)
            
    def refresh_all(self):
        """Refresh all printers"""
        for printer_id in self.clients:
            self.refresh_printer(printer_id)
            
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(
            self,
            "About KlipperBuddy",
            "KlipperBuddy v1.0.0\n\n"
            "A desktop application for monitoring and managing\n"
            "Klipper 3D printers via Moonraker API.\n\n"
            "Features:\n"
            "• Auto-discover printers on network\n"
            "• Fluidd/Mainsail authentication support\n"
            "• Print history and statistics\n"
            "• File management\n\n"
            "Inspired by Bambuddy for Bambu Lab printers.\n\n"
            "License: MIT"
        )
        
    def closeEvent(self, event):
        """Handle window close"""
        # Minimize to tray instead of closing
        event.ignore()
        self.hide()
        self.tray.showMessage(
            "KlipperBuddy",
            "Application minimized to tray",
            QSystemTrayIcon.MessageIcon.Information,
            2000
        )
