@echo off
setlocal EnableDelayedExpansion

echo ============================================================
echo  mcp-hayabusa MCP Server -- Workstation Setup
echo ============================================================
echo.

:: ── 1. Detect Python by actually running it ────────────────────────────────
::    'where' finds the Windows Store alias which looks like python.exe but
::    opens the Store instead of running Python. Verify each candidate by
::    executing it with --version and checking exit code.
set PYTHON=
for %%C in (py python3 python python3.14 python3.13 python3.12 python3.11 python3.10 python3.9) do (
    if "!PYTHON!"=="" (
        %%C --version >nul 2>&1
        if !errorlevel! == 0 (
            set PYTHON=%%C
        )
    )
)

if "!PYTHON!"=="" (
    echo [ERROR] No working Python found. Install Python 3.10+ and re-run.
    echo         https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [OK] Python found: !PYTHON!
!PYTHON! --version
echo.

:: ── 2. Locate Claude Code CLI ────────────────────────────────────────────────
where claude >nul 2>&1
if !errorlevel! neq 0 (
    set CLAUDE_FOUND=0
    echo [WARN] Claude Code CLI not found on PATH. You'll need to register
    echo        the MCP server manually later. Install from: https://claude.ai/code
) else (
    set CLAUDE_FOUND=1
    echo [OK] Claude Code CLI found.
)
echo.

:: ── 3. Resolve repo root (directory this script lives in) ───────────────────
set REPO_DIR=%~dp0
if "%REPO_DIR:~-1%"=="\" set REPO_DIR=%REPO_DIR:~0,-1%
echo [OK] Repo: %REPO_DIR%
echo.

:: ── 4. Install Python dependencies ───────────────────────────────────────────
echo [*] Installing dependencies from requirements.txt...
!PYTHON! -m pip install -r "%REPO_DIR%\requirements.txt" --quiet
if !errorlevel! neq 0 (
    echo [ERROR] pip install failed. Check your Python environment.
    pause
    exit /b 1
)
echo [OK] Dependencies installed.
echo.

:: ── 5. Download the Hayabusa binary (skipped if already present) ────────────
if exist "%REPO_DIR%\hayabusa\hayabusa.exe" (
    echo [OK] Hayabusa binary already present, skipping download.
) else (
    echo [*] Downloading Hayabusa CLI ^(download_hayabusa.py^)...
    !PYTHON! "%REPO_DIR%\download_hayabusa.py"
    if !errorlevel! neq 0 (
        echo [ERROR] Hayabusa download failed. Check the output above.
        pause
        exit /b 1
    )
)
echo.

:: ── 6. Download ATT&CK technique mappings (skipped if already present) ──────
if exist "%REPO_DIR%\mappings\attck_techniques.json" (
    echo [OK] ATT&CK mappings already present, skipping download.
) else (
    echo [*] Downloading ATT&CK technique mappings ^(download_stix_data.py^)...
    !PYTHON! "%REPO_DIR%\download_stix_data.py"
    if !errorlevel! neq 0 (
        echo [ERROR] ATT&CK data download failed. Check the output above.
        pause
        exit /b 1
    )
)
echo.

:: ── 7. Allowed scan directory ─────────────────────────────────────────────────
echo [*] Configure allowed EVTX directory ^(scan_evtx can only read from here^):
set ALLOWED_DEFAULT=%REPO_DIR%\samples
set /p ALLOWED_DIR="    Path [%ALLOWED_DEFAULT%]: "
if not defined ALLOWED_DIR set "ALLOWED_DIR=%ALLOWED_DEFAULT%"

:: Reject characters that could break out of quoting in the commands below
:: (mkdir, claude mcp add). Checked via Python reading the value from the
:: environment directly, so the untrusted text is never re-embedded in a
:: quoted cmd.exe argument before it's known to be safe.
!PYTHON! -c "import os, sys; v = os.environ['ALLOWED_DIR']; bad = chr(34) + '&|^<>'; sys.exit(1 if any(c in v for c in bad) else 0)"
if !errorlevel! neq 0 (
    echo [ERROR] Path contains a disallowed character ^(" ^& ^| ^^ ^< ^>^).
    echo         Re-run setup.bat and enter a plain path.
    pause
    exit /b 1
)

if not exist "!ALLOWED_DIR!" (
    mkdir "!ALLOWED_DIR!"
    echo [OK] Created directory: !ALLOWED_DIR!
) else (
    echo [OK] Directory exists: !ALLOWED_DIR!
)
echo.

:: ── 8. Write run.bat from scratch ─────────────────────────────────────────────
::    Write the file fresh so repeated setup runs and unusual Python names both work.
set RUN_BAT=%REPO_DIR%\run.bat
(
    echo @echo off
    echo pushd "%%~dp0"
    echo !PYTHON! server.py
    echo popd
) > "!RUN_BAT!"
echo [OK] run.bat written using: !PYTHON!
echo.

:: ── 9. Register with Claude Code ──────────────────────────────────────────────
if "!CLAUDE_FOUND!"=="1" (
    echo [*] Registering MCP server with Claude Code ^(project scope^)...
    claude mcp add hayabusa "!RUN_BAT!" --scope project ^
      -e HAYABUSA_ALLOWED_DIRS="!ALLOWED_DIR!"

    if !errorlevel! == 0 (
        echo [OK] MCP server registered.
    ) else (
        echo [WARN] Registration may have failed. Run 'claude mcp list' to verify.
    )
) else (
    echo [*] Skipping registration -- claude CLI not found. Run manually:
    echo.
    echo     claude mcp add hayabusa "!RUN_BAT!" --scope project ^
    echo       -e HAYABUSA_ALLOWED_DIRS="!ALLOWED_DIR!"
)
echo.

:: ── 10. Smoke test ─────────────────────────────────────────────────────────────
echo [*] Running smoke test...
!PYTHON! "%REPO_DIR%\_smoke_test.py"
if !errorlevel! == 0 (
    echo [OK] Smoke test passed.
) else (
    echo [WARN] Smoke test returned errors -- check output above.
)
echo.

:: ── Done ─────────────────────────────────────────────────────────────────────
echo ============================================================
echo  Setup complete!
echo.
echo  Next steps:
echo    1. Open Claude Code in this directory:  claude
echo    2. Approve the server when prompted (first run only)
echo    3. Confirm with:  claude mcp list
echo    4. Drop an EVTX file: copy sample.evtx "!ALLOWED_DIR!"
echo ============================================================
echo.
pause
endlocal
