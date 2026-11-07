@echo off
rem Klik ganda file ini untuk membuka GUI Indihome Universal Utility.
cd /d %~dp0
start "" pythonw zcu_gui.py
if errorlevel 1 (
    echo pythonw gagal dijalankan, mencoba dengan python biasa...
    python zcu_gui.py
    pause
)
