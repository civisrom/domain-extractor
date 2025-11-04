# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path

# Путь к текущей директории
spec_root = Path(SPECPATH)

# Анализ главного скрипта
a = Analysis(
    ['domain_extractor.py'],
    pathex=[str(spec_root)],
    binaries=[],
    datas=[
        # Добавляем конфиг, если он существует
        ('domain_extractor_config.json', '.') if (spec_root / 'domain_extractor_config.json').exists() else None,
        # Добавляем иконку (если есть)
        ('icon.ico', '.') if (spec_root / 'icon.ico').exists() else None,
    ],
    hiddenimports=[
        'chardet',
        'tkinter',
        'tkinter.ttk',
        'tkinter.filedialog',
        'tkinter.messagebox',
        'tkinter.scrolledtext',
        'tkinter.dnd',  # если используешь drag-and-drop
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

# Убираем None из datas
a.datas = [item for item in a.datas if item is not None]

# Создаём PYZ (сжатый Python код)
pyz = PYZ(a.pure, a.zipped_data, cipher=None)

# Создаём EXE
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    name='DomainExtractor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    console=False,  # GUI приложение
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico' if (spec_root / 'icon.ico').exists() else None,
)

# Собираем всё в одну папку (onedir)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='DomainExtractor',
)
