# KlipperBuddy

A desktop application for monitoring and managing Klipper 3D printers via Moonraker API.

Inspired by [Bambuddy](https://github.com/maziggy/bambuddy) for Bambu Lab printers.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

## Features

### Auto-Discovery
- **Automatic network scanning** to find Klipper printers on your local network
- Detects printers even when IP addresses change
- mDNS/Bonjour support for `.local` hostnames
- Scan on startup option

### Authentication Support
- **Fluidd/Mainsail authentication** support
- Username/password login
- API key authentication
- Secure credential storage

### Dashboard
- Real-time printer status monitoring
- Temperature display (extruder, bed)
- Print progress tracking
- Multi-printer support

### Print Control
- Start/Pause/Resume/Cancel prints
- Emergency stop
- GCode command execution

### Print History
- View print history from all connected printers
- Statistics (total prints, time, filament usage, success rate)
- Filter by printer

### File Management
- Browse GCode files on printers
- Start prints directly from file browser
- View file metadata (estimated time, size)

### System Tray
- Minimize to system tray
- Quick access to printer status
- Network scan from tray menu

## Requirements

- Python 3.10 or higher
- Klipper printer with Moonraker installed
- Network access to printer

## Installation

### From Release (Windows)

1. Download the latest `KlipperBuddy.exe` from [Releases](https://github.com/Psych0h3ad/klipperbuddy/releases)
2. Run the executable
3. The app will automatically scan for printers on your network
4. Or manually add printers via the "Add Printer" button

### From Source

```bash
# Clone the repository
git clone https://github.com/Psych0h3ad/klipperbuddy.git
cd klipperbuddy

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Run the application
python -m src.main
```

### Building Executable

```bash
# Install PyInstaller
pip install pyinstaller

# Build executable
pyinstaller --onefile --windowed --name KlipperBuddy src/main.py

# The executable will be in dist/KlipperBuddy.exe
```

## Configuration

### Auto-Discovery

KlipperBuddy can automatically discover printers on your network:

1. Click "Scan Network" button on the Dashboard
2. Wait for the scan to complete (may take 30-60 seconds)
3. Select the printers you want to add
4. Click "OK" to add them

The app can also scan automatically on startup (configurable in Settings).

### Adding a Printer Manually

1. Click "Add Printer" button
2. Enter printer details:
   - **Name**: A friendly name for your printer
   - **Host**: IP address or hostname (e.g., `192.168.1.100` or `voron.local`)
   - **Port**: Moonraker port (default: 7125)
3. If authentication is required (Fluidd/Mainsail):
   - **Username**: Your Fluidd/Mainsail username
   - **Password**: Your password
   - **API Key**: Alternative to username/password
4. Optional:
   - **Webcam URL**: For camera streaming
5. Click "Test Connection" to verify
6. Click "OK" to save

### Fluidd/Mainsail Authentication

If your Fluidd or Mainsail instance requires login:

1. Enter your username and password in the "Authentication" section
2. Click "Test Auth" to verify credentials
3. Credentials are securely stored locally

### Moonraker Setup

Ensure Moonraker is properly configured on your printer:

```ini
# moonraker.conf

[server]
host: 0.0.0.0
port: 7125

[authorization]
trusted_clients:
    192.168.1.0/24  # Your local network
cors_domains:
    *

[history]
# Enable print history tracking

[octoprint_compat]
# Optional: Enable OctoPrint compatibility
```

For authentication, add:

```ini
[authorization]
login_timeout: 90
force_logins: true
```

## Supported Printers

Any 3D printer running Klipper with Moonraker, including:

- VORON (Trident, 2.4, 0.1, etc.)
- RatRig V-Core
- Creality (with Klipper mod)
- Prusa (with Klipper mod)
- Ender 3/5 (with Klipper)
- And many more...

## API Reference

KlipperBuddy uses the [Moonraker API](https://moonraker.readthedocs.io/) for communication:

| Endpoint | Description |
|----------|-------------|
| `GET /printer/info` | Get printer state |
| `POST /printer/objects/query` | Query printer objects |
| `GET /server/history/list` | Get print history |
| `POST /printer/print/start` | Start a print |
| `POST /printer/print/pause` | Pause current print |
| `POST /printer/print/resume` | Resume paused print |
| `POST /printer/print/cancel` | Cancel current print |
| `POST /printer/emergency_stop` | Emergency stop |
| `POST /access/login` | Login (authentication) |

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Bambuddy](https://github.com/maziggy/bambuddy) - Inspiration for this project
- [Moonraker](https://github.com/Arksine/moonraker) - API server for Klipper
- [Klipper](https://www.klipper3d.org/) - 3D printer firmware
- [PyQt6](https://www.riverbankcomputing.com/software/pyqt/) - GUI framework

## Changelog

### v1.0.0
- Initial release
- Dashboard with printer cards
- Print history tracking
- File management
- System tray support
- **Network auto-discovery**
- **Fluidd/Mainsail authentication support**
