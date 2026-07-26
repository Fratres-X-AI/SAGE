@echo off
"C:\Program Files\Git\bin\bash.exe" "%~dp0pod_push_and_soak_max.sh"
if errorlevel 1 exit /b %ERRORLEVEL%
