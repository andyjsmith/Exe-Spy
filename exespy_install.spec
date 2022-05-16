# -*- mode: python ; coding: utf-8 -*-


block_cipher = None

data = [
    ("exespy/img/*.png", "img"),
    ("exespy/img/*.ico", "img"),
    ("exespy/third_party_licenses.txt", "."),
    ("exespy/yara/compiled.yara.bin", "yara"),
]

a = Analysis(
    ["run.py"],
    pathex=["."],
    binaries=[],
    datas=data,
    hiddenimports=[],
    hookspath=[],
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
    [],
    exclude_binaries=True,
    name="exespy",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="exespy/img/icon.ico",
)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="exespy",
)
