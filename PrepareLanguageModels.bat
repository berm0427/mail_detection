@echo off
setlocal
set "PROJECT_ROOT=%~dp0"
set "PYTHON_EXE=C:\Users\berm0\Documents\Codex\2026-09-11\x20\work\analysis-venv\Scripts\python.exe"
set "MODEL_ROOT=C:\Users\berm0\Documents\Codex\2026-09-11\x20\work\models"
"%PYTHON_EXE%" "%PROJECT_ROOT%tools\setup_language_models.py" --root "%MODEL_ROOT%" --model translation
if errorlevel 1 (
  echo Language model preparation failed.
  exit /b 1
)
echo Language models are ready.
endlocal
