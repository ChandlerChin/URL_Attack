@echo off
setlocal
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 goto try_py
python code\verify_artifact.py
set "artifact_exit=%errorlevel%"
goto done
:try_py
where py >nul 2>nul
if errorlevel 1 goto missing
py -3 code\verify_artifact.py
set "artifact_exit=%errorlevel%"
goto done
:missing
echo Python was not found. Install Python and requirements.txt first.
set "artifact_exit=1"
:done
echo.
if not "%artifact_exit%"=="0" echo Artifact verification failed. See the errors above.
pause
exit /b %artifact_exit%
