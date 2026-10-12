@echo off
REM Start NetGuard. Right-click > "Run as administrator" if Npcap was installed
REM with the "Administrators only" option, or when using the DNS forwarder on port 53
REM together with firewall changes.
cd /d "%~dp0"
net session >nul 2>&1
if %errorlevel%==0 (echo Running as Administrator.) else (echo Running as a standard user.)
py run.py %*
pause
