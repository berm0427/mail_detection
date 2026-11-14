@echo off
setlocal
cd /d "%~dp0"
set "TRAIN=%~1"
set "HOLDOUT=%~2"
set "TAG=%~3"
set "PYTHON=C:\Users\berm0\Documents\Codex\2026-09-11\x20\work\analysis-venv\Scripts\python.exe"

if "%TAG%"=="" (
  echo Usage: EmailTesterVerdictRetrainer.bat TRAIN_MANIFEST HOLDOUT_MANIFEST TAG [--apply]
  echo   Create the two manifests first:
  echo   python tools\split_holdout.py ALL_LABELLED.jsonl train.jsonl holdout.jsonl
  echo   TAG is the new version name, for example v5.
  echo   Without --apply the candidate is only trained and compared, never installed.
  pause
  exit /b 1
)
if not exist "%PYTHON%" (
  echo ERROR: Python environment was not found.
  echo %PYTHON%
  pause
  exit /b 1
)

echo ============================================================
echo DISE ML verdict retraining
echo Train:   %TRAIN%
echo Holdout: %HOLDOUT%
echo Tag:     %TAG%
echo ============================================================
"%PYTHON%" -u -B tools\retrain_ml_verdict.py "%TRAIN%" "%HOLDOUT%" --tag %TAG% %4 %5 %6
set "RESULT=%ERRORLEVEL%"
echo.
if "%RESULT%"=="0" (
  echo RESULT: finished. See models\candidates\%TAG%\promotion_report.json
) else (
  echo RESULT: stopped with error code %RESULT%. Nothing was installed.
)
pause
