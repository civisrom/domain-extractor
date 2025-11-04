# DomainExtractor.spec
# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_data_files
import sys
from pathlib import Path

block_cipher = None

# === Анализ ===
a = Analysis(
    ['domain_extractor.py'],
    pathex=[],
    binaries=[],
    datas=[
        # Конфиг и иконка — если есть
        ('domain_extractor_config.json', '.') if Path('domain_extractor_config.json').exists() else None,
        ('icon.ico', '.') if Path('icon.ico').exists() else None,
    ],
    hiddenimports=[
        'chardet',                    # ← ОБЯЗАТЕЛЬНО!
        'chardet.universaldetector',  # ← Иногда нужно явно
        'tkinter.dnd',                # Drag & Drop
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# Убираем None из datas
a.datas = [x for x in a.datas if x is not None]

# === PYZ ===
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# === EXE ===
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='DomainExtractor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # GUI
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico' if Path('icon.ico').exists() else None,
)

# === Папка (onedir) ===
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    name='DomainExtractor',
)
