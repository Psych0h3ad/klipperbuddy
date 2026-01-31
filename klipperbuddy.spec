# -*- mode: python ; coding: utf-8 -*-

import os
import sys

block_cipher = None

# Get the source directory
src_dir = os.path.join(os.path.dirname(os.path.abspath(SPEC)), 'src')

# Collect all Python files from src directory
datas = []
hiddenimports = [
    'PyQt6',
    'PyQt6.QtWidgets',
    'PyQt6.QtCore',
    'PyQt6.QtGui',
    'aiohttp',
    'zeroconf',
    'ui',
    'ui.main_window',
    'api',
    'api.moonraker_client',
    'models',
    'models.printer',
    'utils',
    'utils.network_scanner',
    'utils.auth_manager',
    'utils.config_manager',
]

a = Analysis(
    [os.path.join(src_dir, 'main.py')],
    pathex=[src_dir],
    binaries=[],
    datas=[
        (os.path.join(src_dir, 'ui'), 'ui'),
        (os.path.join(src_dir, 'api'), 'api'),
        (os.path.join(src_dir, 'models'), 'models'),
        (os.path.join(src_dir, 'utils'), 'utils'),
    ],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='KlipperBuddy',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
