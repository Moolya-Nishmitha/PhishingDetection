import PyInstaller.__main__

PyInstaller.__main__.run([
    'gui_pro.py',
    '--onefile',
    '--windowed',
    '--name=PhishingDetectionSystem',
])