@echo off
REM Build wrapper for hash-bench-gba (devkitARM + libtonc).
REM
REM Same TEMP-shuttle pattern as totp-gba — objcopy / gbafix occasionally
REM fail on I: drive directly, and mGBA may mmap-lock the target .gba, so
REM we always write to %TEMP%\ then copy.

setlocal enableextensions enabledelayedexpansion

REM Force Windows-style paths regardless of inherited (msys-style) values.
REM Pass-through tools (make / gcc) need DEVKITPRO with forward slashes;
REM cmd.exe needs backslashes for the existence check, so we recompute.
set DEVKITPRO=C:/devkitPro
set DEVKITARM=C:/devkitPro/devkitARM
set PATH=C:\devkitPro\msys2\usr\bin;C:\devkitPro\devkitARM\bin;C:\devkitPro\tools\bin;%PATH%

if not exist "C:\devkitPro\devkitARM\bin\arm-none-eabi-gcc.exe" (
    echo ERROR: devkitARM not found under C:\devkitPro\devkitARM.
    echo Install devkitPro from https://github.com/devkitPro/installer/releases
    exit /b 1
)

cd /d "%~dp0"

if "%1"=="clean" (
    make clean 2>nul
    del /f /q hash-bench-gba.gba 2>nul
    del /f /q hash-bench-gba.elf 2>nul
    exit /b 0
)

set OUTNAME=hash-bench-gba.gba

make 2>nul

if not exist hash-bench-gba.elf (
    echo.
    echo Build FAILED - no ELF produced.
    exit /b 1
)

set TMPGBA=%TEMP%\hash-bench-gba-build.gba
del /f /q "%TMPGBA%" 2>nul
arm-none-eabi-objcopy -O binary hash-bench-gba.elf "%TMPGBA%"
if errorlevel 1 (
    echo Build FAILED at objcopy step.
    exit /b 1
)
gbafix "%TMPGBA%" -thash-bench -c0000 -m00 >nul
if errorlevel 1 (
    echo Build FAILED at gbafix step.
    exit /b 1
)

if not exist "%~dp0artifacts" mkdir "%~dp0artifacts"
set FRESH_AT=
copy /Y "%TMPGBA%" "%~dp0artifacts\%OUTNAME%" >nul 2>&1 && set FRESH_AT=!FRESH_AT! artifacts\%OUTNAME%
copy /Y "%TMPGBA%" %OUTNAME%                  >nul 2>&1 && set FRESH_AT=!FRESH_AT! %OUTNAME%

echo.
if "!FRESH_AT!"=="" (
    echo WARNING: target appears mmap-locked by mGBA. Fresh ROM at:
    echo     %TMPGBA%
) else (
    echo Build OK. Fresh ROM at:!FRESH_AT!
)

endlocal
