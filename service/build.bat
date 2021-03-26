@echo off
REM Copyright NetFoundry, Inc.
REM
REM Licensed under the Apache License, Version 2.0 (the "License");
REM you may not use this file except in compliance with the License.
REM You may obtain a copy of the License at
REM
REM https://www.apache.org/licenses/LICENSE-2.0
REM
REM Unless required by applicable law or agreed to in writing, software
REM distributed under the License is distributed on an "AS IS" BASIS,
REM WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
REM See the License for the specific language governing permissions and
REM limitations under the License.
REM
SET REPO_URL=https://github.com/openziti/ziti-tunnel-sdk-c.git
SET ZITI_TUNNEL_REPO_BRANCH=v0.14.0
REM override the c sdk used in the build - leave blank for the same as specified in the tunneler sdk
SET ZITI_SDK_C_BRANCH=
REM the number of TCP connections the tunneler sdk can have at any one time
SET TCP_MAX_CONNECTIONS=256
SET WINTUN_DL_URL=https://www.wintun.net/builds/wintun-0.10.2.zip

set SVC_ROOT_DIR=%~dp0
set CURDIR=%CD%

call %SVC_ROOT_DIR%set-env.bat

IF "%ZITI_DEBUG%"=="" (
    REM clear out if debug was run in the past
    SET ZITI_DEBUG_CMAKE=
) else (
    SET ZITI_DEBUG_CMAKE=-DCMAKE_BUILD_TYPE=Debug
    echo ZITI_DEBUG detected. will run cmake with: %ZITI_DEBUG_CMAKE%
)

cd /d %ZITI_TUNNEL_WIN_ROOT%

IF "%1"=="" (
    GOTO NO_ACTION_SUPPLIED
)

IF "%BUILD_VERSION%"=="" (
    GOTO BUILD_VERSION_ERROR
) else (
    echo Version file found. detected version: %BUILD_VERSION%
)

IF "%1"=="clean" (
    echo doing 'clean' build
    GOTO CLEAN
)
IF "%1"=="quick" (
    echo doing 'quick' build - no tunneler sdk/c sdk build
    GOTO QUICK
)
IF "%1"=="CI" (
    echo doing 'CI' build
    GOTO CI
)

GOTO UNKNOWN_OPTION

echo You should not be here. This is a bug. Please report
cd /d %CURDIR%
exit /b 1

:CI
echo fetching ziti-ci 2>&1
call %SVC_ROOT_DIR%/../get-ziti-ci.bat 2>&1
echo ziti-ci has been retrieved. running: ziti-ci version 2>&1
ziti-ci version 2>&1
echo ""

echo generating version info - this will get pushed from publish.bat in CI _if_ publish.bat started build.bat 2>&1
ziti-ci generate-build-info --noAddNoCommit --useVersion=false %SVC_ROOT_DIR%/ziti-tunnel/version.go main --verbose 2>&1

echo calling powershell script to update versions in UI and Installer 2>&1
powershell -file %ZITI_TUNNEL_WIN_ROOT%update-versions.ps1 2>&1
echo version info generated 2>&1
goto QUICK

:CLEAN
echo REMOVING old build folder if it exists at %TUNNELER_SDK_DIR%build
rmdir /s /q %TUNNELER_SDK_DIR%build
echo REMOVING ziti.dll at %SVC_ROOT_DIR%ziti.dll
del /q %SVC_ROOT_DIR%ziti.dll

:QUICK

if not exist %SVC_ROOT_DIR%wintun.dll (
    echo ------------------------------------------------------------------------------
    echo DOWNLOADING wintun.dll using powershell
    echo       from: %WINTUN_DL_URL%
    echo ------------------------------------------------------------------------------
    powershell "Invoke-WebRequest %WINTUN_DL_URL% -OutFile %SVC_ROOT_DIR%wintun.zip"
    powershell "Expand-Archive -Path %SVC_ROOT_DIR%wintun.zip -Force -DestinationPath %SVC_ROOT_DIR%wintun-extracted"
    echo    copying: %SVC_ROOT_DIR%wintun-extracted\wintun\bin\amd64\wintun.dll %SVC_ROOT_DIR%wintun.dll
    copy %SVC_ROOT_DIR%wintun-extracted\wintun\bin\amd64\wintun.dll %SVC_ROOT_DIR%wintun.dll
    echo   removing: %SVC_ROOT_DIR%wintun-extracted
    del /s /q %SVC_ROOT_DIR%wintun-extracted\
    rmdir %SVC_ROOT_DIR%wintun-extracted\
    echo   removing: %SVC_ROOT_DIR%wintun.zip
    del /s %SVC_ROOT_DIR%wintun.zip
)

echo changing to service folder: %SVC_ROOT_DIR%
cd %SVC_ROOT_DIR%

if exist %SVC_ROOT_DIR%ziti.dll (
    echo ------------------------------------------------------------------------------
    echo SKIPPED BUILDING ziti.dll because ziti.dll was found at %SVC_ROOT_DIR%ziti.dll
    echo ------------------------------------------------------------------------------
    GOTO GOBUILD
)

echo ------------------------------------------------------------------------------
echo BUILDING ziti.dll begins
echo ------------------------------------------------------------------------------

if exist %TUNNELER_SDK_DIR% (
    echo %TUNNELER_SDK_DIR% exists
    cd %TUNNELER_SDK_DIR%
    echo ------------------------------------------------------------------------------
    echo issuing git pull to pick up any changes
    echo ------------------------------------------------------------------------------
    git pull
    git submodule update --init --recursive
    SET ACTUAL_ERR=%ERRORLEVEL%
    echo ------------------------------------------------------------------------------
) else (
    echo ------------------------------------------------------------------------------
    echo %TUNNELER_SDK_DIR% not found
    echo     - cloning %REPO_URL%
    echo ------------------------------------------------------------------------------
    echo issuing mkdir %TUNNELER_SDK_DIR%
    mkdir %TUNNELER_SDK_DIR%

    echo changing to %TUNNELER_SDK_DIR%
    cd %TUNNELER_SDK_DIR%

    echo current directory is %CD% - should be %TUNNELER_SDK_DIR%
    echo.
    echo git clone %REPO_URL% %TUNNELER_SDK_DIR% --recurse-submodules
    echo.

    git clone %REPO_URL% %TUNNELER_SDK_DIR% --recurse-submodules
    SET ACTUAL_ERR=%ERRORLEVEL%
)
IF %ACTUAL_ERR% NEQ 0 (
    echo.
    echo Could not pull or clone git repo:%REPO_URL%
    echo.
    goto FAIL
)

echo in %cd% - checking out %ZITI_TUNNEL_REPO_BRANCH% branch: %ZITI_TUNNEL_REPO_BRANCH%
git checkout %ZITI_TUNNEL_REPO_BRANCH%
IF %ERRORLEVEL% NEQ 0 (
    SET ACTUAL_ERR=%ERRORLEVEL%
    echo.
    echo Could not checkout branch: %ZITI_TUNNEL_REPO_BRANCH%
    echo.
    goto FAIL
)

echo clone or checkout complete.

echo Updating submodules... if needed...
REM git config --get remote.origin.url
git submodule update --init --recursive
IF %ERRORLEVEL% NEQ 0 (
    SET ACTUAL_ERR=%ERRORLEVEL%
    echo.
    echo Could not update submodules
    echo.
    goto FAIL
)

if not exist %TUNNELER_SDK_DIR%build mkdir %TUNNELER_SDK_DIR%build
if not exist %TUNNELER_SDK_DIR%install mkdir %TUNNELER_SDK_DIR%install

echo Generating project files for tunneler sdk
if "%ZITI_SDK_C_BRANCH%"=="" (
    echo ZITI_SDK_C_BRANCH is not set - ZITI_SDK_C_BRANCH_CMD will be empty
    SET ZITI_SDK_C_BRANCH_CMD=%ZITI_SPACES:~2,1%
) else (
    echo SETTING ZITI_SDK_C_BRANCH_CMD to: -DZITI_SDK_C_BRANCH^=%ZITI_SDK_C_BRANCH%
    SET ZITI_SDK_C_BRANCH_CMD=-DZITI_SDK_C_BRANCH=%ZITI_SDK_C_BRANCH%
)

cmake -G Ninja -S %TUNNELER_SDK_DIR% -B %TUNNELER_SDK_DIR%build -DCMAKE_INSTALL_PREFIX=%TUNNELER_SDK_DIR%install %ZITI_SDK_C_BRANCH_CMD% -DTCP_MAX_CONNECTIONS=%TCP_MAX_CONNECTIONS% %ZITI_DEBUG_CMAKE%
cmake --build %TUNNELER_SDK_DIR%build --target install

SET ACTUAL_ERR=%ERRORLEVEL%
if %ACTUAL_ERR% NEQ 0 (
    echo.
    echo Build of %TUNNELER_SDK_DIR%build failed
    echo.
    goto FAIL
) else (
    echo.
    echo result of ninja build: %ACTUAL_ERR%
)

echo checking the CSDK
pushd %TUNNELER_SDK_DIR%build\_deps\ziti-sdk-c-src
git rev-parse --short HEAD > hash.txt
git rev-parse --abbrev-ref HEAD > branch.txt
set /p CSDK_BRANCH=<branch.txt
set /p CSDK_HASH=<hash.txt
del /q branch.txt
del /q hash.txt

cd %SVC_ROOT_DIR%

IF "%ZITI_DEBUG%"=="" (
    SET ZITI_LIB_UV_DLL=%TUNNELER_SDK_DIR%install\lib\libuv.dll
) else (
    SET ZITI_DEBUG_CMAKE=-DCMAKE_BUILD_TYPE=Debug
    echo ZITI_DEBUG detected. Copying debug lib into install...
    SET ZITI_LIB_UV_DLL=%TUNNELER_SDK_DIR%install\lib\Debug\libuv.dll
)

echo    copying libuv.dll to install folder (for go build) and to service root (for zip creation)
echo    copy /y %ZITI_LIB_UV_DLL% to %SVC_ROOT_DIR%
copy /y %ZITI_LIB_UV_DLL% %TUNNELER_SDK_DIR%install\lib\libuv.dll
copy /y %ZITI_LIB_UV_DLL% %SVC_ROOT_DIR%

echo    copying ziti.dll to service root (for zip creation)
echo copy /y %TUNNELER_SDK_DIR%install\lib\ziti.dll %SVC_ROOT_DIR%
copy /y %TUNNELER_SDK_DIR%install\lib\ziti.dll %SVC_ROOT_DIR%

echo COPIED libuv and ziti dlls to %SVC_ROOT_DIR%

:GOBUILD
echo building the go program
REM go build -race -a ./ziti-tunnel
go build -a ./ziti-tunnel
SET ACTUAL_ERR=%ERRORLEVEL%
if %ACTUAL_ERR% NEQ 0 (
    echo.
    echo Building ziti-tunnel failed
    echo.
    goto FAIL
) else (
    echo go build complete
)

echo creating the distribution zip file
zip ziti-tunnel-win.zip *.dll ziti*exe

GOTO END

:BUILD_VERSION_ERROR
echo The build version environment variable was not set - cannot proceed
cd %CURDIR%
exit /b 1

:UNKNOWN_OPTION
echo.
echo ERROR: The action supplied is not known: %1

:NO_ACTION_SUPPLIED
echo.
echo        Supply a build action: CI^|clean^|quick
echo.
cd /d %CURDIR%
exit /b 1

:FAIL
echo.
echo ACTUAL_ERR: %ACTUAL_ERR%
cd /d %CURDIR%
EXIT /B %ACTUAL_ERR%

:END
cd /d %CURDIR%

echo.
echo.
echo =====================================================
echo -- BUILD COMPLETE  : %date% %time%
echo --     tunneler sdk: %ZITI_TUNNEL_REPO_BRANCH%
echo --     c sdk       : %CSDK_BRANCH%
echo --                 : %CSDK_HASH%
echo --                 : %ZITI_SDK_C_BRANCH%
echo --                 : %ZITI_SDK_C_BRANCH_CMD%
echo =====================================================
