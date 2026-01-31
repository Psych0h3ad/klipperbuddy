"""
Printer data models for KlipperBuddy
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import json
import os


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


class PrinterConfigManager:
    """Manages printer configurations with persistence"""
    
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.printers: dict[str, PrinterConfig] = {}
        self._load()
        
    def _load(self):
        """Load configurations from file"""
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
        """Save configurations to file"""
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        data = {
            "printers": [p.to_dict() for p in self.printers.values()]
        }
        with open(self.config_path, "w") as f:
            json.dump(data, f, indent=2)
            
    def add_printer(self, printer: PrinterConfig):
        """Add a new printer"""
        self.printers[printer.id] = printer
        self._save()
        
    def remove_printer(self, printer_id: str):
        """Remove a printer"""
        if printer_id in self.printers:
            del self.printers[printer_id]
            self._save()
            
    def update_printer(self, printer: PrinterConfig):
        """Update printer configuration"""
        self.printers[printer.id] = printer
        self._save()
        
    def get_printer(self, printer_id: str) -> Optional[PrinterConfig]:
        """Get printer by ID"""
        return self.printers.get(printer_id)
        
    def get_all_printers(self) -> list[PrinterConfig]:
        """Get all printers"""
        return list(self.printers.values())
