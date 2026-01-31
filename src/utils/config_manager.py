"""
Configuration Manager for KlipperBuddy
Handles application settings and printer configurations
"""

import json
import os
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict, field
from pathlib import Path


@dataclass
class PrinterConfig:
    """Configuration for a single printer"""
    name: str
    host: str
    port: int = 7125
    webcam_url: Optional[str] = None
    enabled: bool = True
    auto_connect: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PrinterConfig':
        return cls(**data)


@dataclass
class AppSettings:
    """Application-wide settings"""
    auto_scan_on_startup: bool = True
    scan_interval_minutes: int = 5
    minimize_to_tray: bool = True
    start_minimized: bool = False
    theme: str = 'dark'
    language: str = 'en'
    refresh_interval_seconds: int = 2
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AppSettings':
        # Filter out unknown keys
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered_data)


class ConfigManager:
    """
    Manages application configuration and printer settings
    """
    
    def __init__(self, config_dir: Optional[str] = None):
        if config_dir is None:
            if os.name == 'nt':  # Windows
                config_dir = os.path.join(os.environ.get('APPDATA', ''), 'KlipperBuddy')
            else:  # Linux/Mac
                config_dir = os.path.join(os.path.expanduser('~'), '.config', 'klipperbuddy')
        
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.config_file = self.config_dir / 'config.json'
        self.printers_file = self.config_dir / 'printers.json'
        
        self._settings = AppSettings()
        self._printers: Dict[str, PrinterConfig] = {}
        
        self._load_config()
        self._load_printers()
    
    def _load_config(self):
        """Load application settings from file"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    self._settings = AppSettings.from_dict(data)
            except Exception as e:
                print(f"Error loading config: {e}")
    
    def _save_config(self):
        """Save application settings to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self._settings.to_dict(), f, indent=2)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def _load_printers(self):
        """Load printer configurations from file"""
        if self.printers_file.exists():
            try:
                with open(self.printers_file, 'r') as f:
                    data = json.load(f)
                    for key, printer_data in data.items():
                        self._printers[key] = PrinterConfig.from_dict(printer_data)
            except Exception as e:
                print(f"Error loading printers: {e}")
    
    def _save_printers(self):
        """Save printer configurations to file"""
        try:
            data = {key: printer.to_dict() for key, printer in self._printers.items()}
            with open(self.printers_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving printers: {e}")
    
    def _get_printer_key(self, host: str, port: int) -> str:
        """Generate a unique key for a printer"""
        return f"{host}:{port}"
    
    # Settings methods
    @property
    def settings(self) -> AppSettings:
        """Get application settings"""
        return self._settings
    
    def update_settings(self, **kwargs):
        """Update application settings"""
        for key, value in kwargs.items():
            if hasattr(self._settings, key):
                setattr(self._settings, key, value)
        self._save_config()
    
    # Printer methods
    def add_printer(self, name: str, host: str, port: int = 7125,
                    webcam_url: Optional[str] = None,
                    auto_connect: bool = True) -> PrinterConfig:
        """Add a new printer configuration"""
        key = self._get_printer_key(host, port)
        printer = PrinterConfig(
            name=name,
            host=host,
            port=port,
            webcam_url=webcam_url,
            auto_connect=auto_connect
        )
        self._printers[key] = printer
        self._save_printers()
        return printer
    
    def update_printer(self, host: str, port: int, **kwargs) -> Optional[PrinterConfig]:
        """Update an existing printer configuration"""
        key = self._get_printer_key(host, port)
        if key in self._printers:
            printer = self._printers[key]
            for k, v in kwargs.items():
                if hasattr(printer, k):
                    setattr(printer, k, v)
            self._save_printers()
            return printer
        return None
    
    def remove_printer(self, host: str, port: int) -> bool:
        """Remove a printer configuration"""
        key = self._get_printer_key(host, port)
        if key in self._printers:
            del self._printers[key]
            self._save_printers()
            return True
        return False
    
    def get_printer(self, host: str, port: int) -> Optional[PrinterConfig]:
        """Get a printer configuration"""
        key = self._get_printer_key(host, port)
        return self._printers.get(key)
    
    def get_all_printers(self) -> List[PrinterConfig]:
        """Get all printer configurations"""
        return list(self._printers.values())
    
    def get_enabled_printers(self) -> List[PrinterConfig]:
        """Get all enabled printer configurations"""
        return [p for p in self._printers.values() if p.enabled]
    
    def printer_exists(self, host: str, port: int) -> bool:
        """Check if a printer configuration exists"""
        key = self._get_printer_key(host, port)
        return key in self._printers
