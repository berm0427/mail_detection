@echo off
setlocal
cd /d "%~dp0"
set "DATASET_ZIP=%~1"
if not defined DATASET_ZIP set "DATASET_ZIP=C:\Users\berm0\Downloads\Korean_Synthetic_Phishing_Email_Dataset_v1.zip"
set "PYTHON=C:\Users\berm0\Documents\Codex\2026-09-11\x20\work\analysis-venv\Scripts\python.exe"

if not exist "%DATASET_ZIP%" (
  echo ERROR: Dataset ZIP was not found.
  echo %DATASET_ZIP%
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
echo DISE candidate model training
echo Dataset: %DATASET_ZIP%
echo Expected time: several minutes on CPU.
echo ============================================================
echo.

"%PYTHON%" -u -m tools.retrain_from_dataset_zip "%DATASET_ZIP%" "mail_body\training_data\korean_synthetic_v1" "models\candidates\dise-multilingual-user-candidate.json" --model-id dise-multilingual-user-candidate --semantic-model "C:\Users\berm0\Documents\Codex\2026-09-11\x20\work\models\multilingual-minilm-l12-v2" --semantic-folds 5 --independent-manifest "mail_body\test_data\user_real8_manifest.jsonl" --independent-report "models\candidates\dise-multilingual-user-candidate.report.json"
set "RESULT=%ERRORLEVEL%"

echo.
echo ============================================================
if "%RESULT%"=="0" (
  echo RESULT: Training and independent evaluation passed.
) else if "%RESULT%"=="2" (
  echo RESULT: Training completed, but independent evaluation failed.
  echo The candidate was NOT installed in the main GUI.
) else (
  echo RESULT: Training stopped with error code %RESULT%.
)
echo Report: mail_body\training_data\korean_synthetic_v1\RETRAIN_REPORT.json
echo ============================================================
echo.
pause
exit /b %RESULT%
