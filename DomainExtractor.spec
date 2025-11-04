# DomainExtractor.spec
# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_data_files
from pathlib import Path
import os

block_cipher = None

# === Определяем файлы для datas ===
datas = []

# Добавляем config, если существует
config_path = Path('domain_extractor_config.json')
if config_path.exists():
    datas.append((str(config_path), '.'))

# Добавляем иконку, если существует
icon_path = Path('icon.ico')
if icon_path.exists():
    datas.append((str(icon_path), '.'))

# === Анализ ===
a = Analysis(
    ['domain_extractor.py'],
    pathex=[],
    binaries=[],
    datas=datas,  # ← Только валидные кортежи
    hiddenimports=[
        'chardet',
        'chardet.universaldetector',
        'tkinter.dnd',
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
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(icon_path) if icon_path.exists() else None,
)

# === COLLECT (onedir) ===
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    name='DomainExtractor',
)
