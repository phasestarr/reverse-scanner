@echo off
setlocal

where cl >nul 2>nul
if %ERRORLEVEL%==0 (
    cl /nologo /O2 /W4 /D_CRT_SECURE_NO_WARNINGS /Fe:reverse_scanner.exe reverse_scanner.c
    if errorlevel 1 exit /b 1
    exit /b 0
)

where gcc >nul 2>nul
if %ERRORLEVEL%==0 (
    gcc -O2 -Wall -Wextra -municode -static -o reverse_scanner.exe reverse_scanner.c
    if errorlevel 1 exit /b 1
    exit /b 0
)

where clang >nul 2>nul
if %ERRORLEVEL%==0 (
    clang -O2 -Wall -Wextra -municode -static -o reverse_scanner.exe reverse_scanner.c
    if errorlevel 1 exit /b 1
    exit /b 0
)

if exist C:\msys64\ucrt64\bin\gcc.exe (
    set "PATH=C:\msys64\ucrt64\bin;%PATH%"
    C:\msys64\ucrt64\bin\gcc.exe -O2 -Wall -Wextra -municode -static -o reverse_scanner.exe reverse_scanner.c
    if errorlevel 1 exit /b 1
    exit /b 0
)

if exist C:\msys64\mingw64\bin\gcc.exe (
    set "PATH=C:\msys64\mingw64\bin;%PATH%"
    C:\msys64\mingw64\bin\gcc.exe -O2 -Wall -Wextra -municode -static -o reverse_scanner.exe reverse_scanner.c
    if errorlevel 1 exit /b 1
    exit /b 0
)

if exist C:\msys64\clang64\bin\clang.exe (
    set "PATH=C:\msys64\clang64\bin;%PATH%"
    C:\msys64\clang64\bin\clang.exe -O2 -Wall -Wextra -municode -static -o reverse_scanner.exe reverse_scanner.c
    if errorlevel 1 exit /b 1
    exit /b 0
)

echo No supported C compiler was found on PATH.
echo Install one of:
echo   - Visual Studio Build Tools with "Desktop development with C++", then open "Developer PowerShell for VS"
echo   - MSYS2 MinGW-w64 GCC, then add the compiler bin directory to PATH
exit /b 1
