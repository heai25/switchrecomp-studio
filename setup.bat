@echo off
setlocal
cd /d "%~dp0"
echo === switchrecomp setup ===
echo.

rem rustup installs cargo in %USERPROFILE%\.cargo\bin, which is not always on PATH
where cargo >nul 2>nul
if errorlevel 1 if exist "%USERPROFILE%\.cargo\bin\cargo.exe" set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
where cargo >nul 2>nul
if errorlevel 1 (
  echo Rust is not installed. Get it from https://rustup.rs then run setup.bat again.
  pause
  exit /b 1
)

rem Pin Microsoft's linker: devkitPro, MSYS2, Git and Cygwin put a Unix "link.exe" on PATH that rustc would call instead.
rem (switchrecomp.exe pins it the same way for the game builds it starts.)
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto :nolinker
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR goto :nolinker
set /p VCVER=<"%VSDIR%\VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt"
for /f "tokens=*" %%v in ("%VCVER%") do set "VCVER=%%v"
if exist "%VSDIR%\VC\Tools\MSVC\%VCVER%\bin\Hostx64\x64\link.exe" set "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER=%VSDIR%\VC\Tools\MSVC\%VCVER%\bin\Hostx64\x64\link.exe"
:nolinker
if not defined CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER (
  echo Visual Studio C++ build tools not found: install them with "Desktop development with C++", then run setup.bat again.
  pause
  exit /b 1
)
echo Linker: %CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER%

rem Short target folder: the MSVC linker fails on paths over 260 characters.
if "%CARGO_TARGET_DIR%"=="" set "CARGO_TARGET_DIR=%LOCALAPPDATA%\srt-tool"

echo Building switchrecomp and the SwitchRecomp app (first build downloads Kirikae and Cranelift, a few minutes)...
cargo build --release
if errorlevel 1 (
  echo.
  echo Build failed. Run "switchrecomp doctor" after fixing, or check that the
  echo Visual Studio C++ build tools are installed.
  pause
  exit /b 1
)

copy /y "%CARGO_TARGET_DIR%\release\switchrecomp.exe" "%~dp0switchrecomp.exe" >nul
copy /y "%CARGO_TARGET_DIR%\release\switchrecomp-app.exe" "%~dp0SwitchRecomp App.exe" >nul
if not exist games mkdir games
echo.
echo Built switchrecomp.exe (command line) and "SwitchRecomp App.exe" (the desktop app). Checking your machine:
echo.
"%~dp0switchrecomp.exe" doctor
echo.
echo Open "SwitchRecomp App.exe", or drag an NSP or a dump folder onto switchrecomp.exe.
pause
