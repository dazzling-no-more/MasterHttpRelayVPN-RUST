@echo off
REM rahgozar launcher for Windows.
REM Runs the CLI once to initialize the MITM CA (may trigger a UAC prompt when
REM installing into the Windows trust store), then launches the UI.

setlocal
cd /d "%~dp0"

if not exist "rahgozar.exe" (
    echo error: rahgozar.exe not found next to this script.
    pause
    exit /b 1
)

echo Initializing MITM CA (a UAC prompt may appear)...
rahgozar.exe --install-cert
if errorlevel 1 (
    echo warning: CA install returned non-zero. The UI can still run,
    echo but HTTPS sites may show certificate warnings until the CA is trusted.
)

if not exist "rahgozar-ui.exe" (
    echo UI binary not found. Running CLI proxy instead.
    rahgozar.exe
    goto :eof
)

echo.
echo Starting rahgozar UI...
echo (A new window should open. If nothing appears, the UI crashed — the
echo  error is shown in this terminal below. Take a screenshot of it and
echo  open an issue on github.)
echo.

REM Run in-place (not via `start`) so if the UI dies on launch, its stderr
REM and non-zero exit code are visible in this window. Previously we used
REM `start "" "rahgozar-ui.exe"` which returns immediately and swallows any
REM launch-time crash (issue #7).
rahgozar-ui.exe
set UI_EXIT=%ERRORLEVEL%
if not "%UI_EXIT%"=="0" (
    echo.
    echo ---------------------------------------------------
    echo UI exited with error code %UI_EXIT%.
    echo.
    echo If this is the first time and you saw "egui_glow requires opengl 2.0+"
    echo or "PainterError" above, your machine doesn't have a usable OpenGL
    echo driver. Retrying once with the DirectX/Vulkan backend...
    echo.
    set RAHGOZAR_RENDERER=wgpu
    "%~dp0rahgozar-ui.exe"
    set UI_EXIT=%ERRORLEVEL%
    set RAHGOZAR_RENDERER=
    if not "%UI_EXIT%"=="0" (
        echo.
        echo ---------------------------------------------------
        echo UI still failed with error code %UI_EXIT% even with the DX/Vulkan
        echo backend. Likely causes:
        echo   - missing or outdated graphics drivers (try updating)
        echo   - running inside RDP or a VM without GPU acceleration
        echo   - antivirus blocking the exe — whitelist the folder and retry
        echo.
        echo You can still use rahgozar without the UI. Run the CLI directly:
        echo.
        echo     rahgozar.exe
        echo.
        echo Set your config in %%APPDATA%%\rahgozar\config\config.json (or
        echo place a config.json next to rahgozar.exe in this folder), then
        echo point your browser proxy at 127.0.0.1:8085 (HTTP) or
        echo 127.0.0.1:8086 (SOCKS5). The CLI is the same proxy without
        echo the UI shell, so all functionality is available.
        echo.
        echo Falling back to the CLI now so you can keep using the proxy.
        echo Press Ctrl+C in the CLI window to stop it.
        echo ---------------------------------------------------
        echo.
        rahgozar.exe
    )
)

endlocal
