@echo off
REM Launch the bugbounty MCP server on stdio (manual testing)
cd /d "%~dp0"
".venv\Scripts\python.exe" server.py
