# ⚡ KlipperBuddy

A cyberpunk-style desktop dashboard for monitoring multiple Klipper 3D printers.

Inspired by [Bambuddy](https://github.com/maziggy/bambuddy) - a self-hosted print management system for Bambu Lab printers.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-blue.svg)

## ✨ Features

- **🔍 Network Auto-Discovery** - Automatically scan and find Klipper printers on your network
- **📊 Multi-Printer Dashboard** - Monitor all your printers in one view with card-based layout
- **🌡️ Real-time Temperature Monitoring** - Track extruder, bed, and chamber temperatures
- **📈 Temperature Graph** - Real-time temperature plotting with history
- **📷 Camera Preview** - Quick access to webcam streams with browser integration
- **📊 Print Statistics** - Total print time, filament usage, print count, success rate
- **💻 System Information** - Klipper/Moonraker versions, OS info, disk usage
- **🔐 Authentication Support** - Works with Fluidd/Mainsail authentication (username/password, API key)
- **⚡ Cyberpunk UI** - Sleek dark theme with Tiffany Blue (#0ABAB5) accents
- **🔤 Play Font** - VORON-style typography for authentic look
- **💾 Configuration Persistence** - Printer settings saved automatically

## 🖼️ Design

- **Theme**: Dark black background (#0a0a0a)
- **Accent Color**: Tiffany Blue (#0ABAB5)
- **Style**: Cyberpunk/Neon with glow effects
- **Font**: Play (Google Fonts, OFL License)
- **Title Logo**: ToaHI font by Iwata

## 📥 Installation

### Windows (Recommended)

1. Go to [Releases](https://github.com/Psych0h3ad/klipperbuddy/releases)
2. Download `KlipperBuddy.exe`
3. Run the executable

### From Source

```bash
# Clone the repository
git clone https://github.com/Psych0h3ad/klipperbuddy.git
cd klipperbuddy

# Install dependencies
pip install PyQt6 PyQt6-Charts aiohttp

# Run
python klipperbuddy.py
```

## 🚀 Usage

1. **Launch KlipperBuddy**
2. **Scan Network** - Click "🔍 Scan Network" to discover printers automatically
3. **Or Add Manually** - Click "➕ Add Printer" to add a printer by IP address
4. **Monitor** - View all your printers' status in the dashboard
5. **View Details** - Click 📈 on a printer card to see temperature graph and statistics

### Supported Printers

Any 3D printer running:
- **Klipper** firmware with **Moonraker** API
- **Fluidd** or **Mainsail** web interface

## 🔧 Requirements

- Windows 10 or later
- Network access to your Klipper printers
- Moonraker API enabled on your printers (default port: 7125)

## 📋 API Endpoints Used

KlipperBuddy uses the following Moonraker API endpoints:

- `/printer/info` - Printer state and hostname
- `/printer/objects/query` - Temperature and print status
- `/server/database/item` - Fluidd/Mainsail configuration (printer name)
- `/server/history/totals` - Print statistics
- `/machine/system_info` - System information (OS, CPU)
- `/server/files/roots` - Disk usage
- `/server/webcams/list` - Webcam configuration
- `/access/login` - Authentication (if required)

## 🙏 Credits

- **[Bambuddy](https://github.com/maziggy/bambuddy)** - Inspiration for this project
- **[Moonraker](https://github.com/Arksine/moonraker)** - API server for Klipper
- **[Klipper](https://github.com/Klipper3d/klipper)** - 3D printer firmware
- **[Play Font](https://fonts.google.com/specimen/Play)** - Jonas Hecksher (OFL License)
- **ToaHI Font** - Iwata Corporation (title logo only)

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

This project is inspired by Bambuddy but is an independent implementation for Klipper printers.

### Asset Licenses

- **KlipperBuddy Source Code**: MIT License
- **P3D Logo**: © Yuto - All rights reserved
- **Play Font**: SIL Open Font License 1.1 - Embedded in application
- **ToaHI Font (title logo)**: Used under Iwata license for title/logo creation only (not embedded)
