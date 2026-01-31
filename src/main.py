"""
KlipperBuddy - Desktop application for Klipper printer management
Main entry point
"""

import sys
import os

# Add parent directory to path for PyInstaller compatibility
if getattr(sys, 'frozen', False):
    # Running as compiled executable
    application_path = os.path.dirname(sys.executable)
else:
    # Running as script
    application_path = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, application_path)

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon

# Use relative imports for PyInstaller compatibility
from ui.main_window import MainWindow


def main():
    """Main entry point"""
    # Enable high DPI scaling
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    
    app = QApplication(sys.argv)
    app.setApplicationName("KlipperBuddy")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("KlipperBuddy")
    
    # Set style
    app.setStyle("Fusion")
    
    # Create and show main window
    window = MainWindow()
    window.show()
    
    # Run event loop
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
