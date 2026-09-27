@echo off
REM One-command build for Windows. Requires CMake and a C toolchain
REM (Visual Studio Build Tools or MinGW). Builds library, examples, tests,
REM then runs the tests.
setlocal
cd /d "%~dp0"

set "BUILD_DIR=build"

echo ^>^> configuring (%BUILD_DIR%)
cmake -B "%BUILD_DIR%" %* || goto :error

echo ^>^> building
cmake --build "%BUILD_DIR%" --config Release || goto :error

echo ^>^> testing
ctest --test-dir "%BUILD_DIR%" --build-config Release --output-on-failure || goto :error

echo ^>^> done. binaries are in %BUILD_DIR%\
exit /b 0

:error
echo build failed.
exit /b 1
