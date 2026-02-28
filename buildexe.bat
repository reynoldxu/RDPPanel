@echo off
:: ==========================================
:: 获取管理员权限
:: ==========================================
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

if '%errorlevel%' NEQ '0' (
    echo 正在请求管理员权限...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%~dp0"

:: ==========================================
:: 开始执行任务
:: ==========================================

echo [1/3] 正在清理旧的构建文件...
if exist "build" rd /s /q "build"
if exist "dist" rd /s /q "dist"
if exist "main.spec" del /f /q "main.spec"

echo [2/3] 正在开始 PyInstaller 打包流程...
:: 确保你已经安装了 pyinstaller
pyinstaller --noconfirm --onefile --console --add-data "templates;templates" main.py

echo [3/3] 正在清理构建残留...
if exist "build" rd /s /q "build"
:: 如果你需要保留生成的 exe，请不要删除 dist 文件夹
:: if exist "dist" rd /s /q "dist"
if exist "main.spec" del /f /q "main.spec"

echo ------------------------------------------
echo 任务全部完成！
pause