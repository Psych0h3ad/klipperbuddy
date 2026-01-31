# KlipperBuddy

A desktop application for Klipper printer management. Inspired by [Bambuddy](https://github.com/maziggy/bambuddy).

## Features

- **Network Auto-Discovery**: Automatically scan and discover Klipper printers on your local network
- **Fluidd/Mainsail Authentication**: Support for username/password and API key authentication
- **Real-time Monitoring**: Live printer status, temperatures, and print progress
- **Print History**: View and manage your print job history
- **File Management**: Browse and start prints from your G-code files
- **System Tray**: Minimize to system tray for background monitoring

## Installation

### Windows

1. Download `KlipperBuddy.exe` from the [Releases](https://github.com/Psych0h3ad/klipperbuddy/releases) page
2. Run the executable - no installation required

### From Source

```bash
# Clone the repository
git clone https://github.com/Psych0h3ad/klipperbuddy.git
cd klipperbuddy

# Install dependencies
pip install PyQt6 aiohttp

# Run the application
python klipperbuddy.py
```

## Usage

### Adding Printers

1. **Auto-Discovery**: Click "Scan" to automatically discover printers on your network
2. **Manual**: Click "+" to manually add a printer by entering its IP address and port

### Authentication

If your Fluidd/Mainsail instance requires authentication:
1. Click "+" or edit an existing printer
2. Enter your username/password or API key
3. Click "Test Auth" to verify credentials

### Printer Control

- **Status Tab**: View real-time printer status, temperatures, and position
- **Control Tab**: Pause, resume, or cancel prints; set temperatures; home axes
- **Files Tab**: Browse G-code files and start prints
- **History Tab**: View print job history

## Requirements

- Windows 10 or later
- Klipper printer with Moonraker API enabled
- Network connectivity to your printer

## Credits

- Inspired by [Bambuddy](https://github.com/maziggy/bambuddy) by maziggy
- Built with [PyQt6](https://www.riverbankcomputing.com/software/pyqt/)
- Uses [Moonraker API](https://moonraker.readthedocs.io/)

## License

MIT License - See [LICENSE](LICENSE) for details.

This project is inspired by Bambuddy but is an independent implementation for Klipper printers.
