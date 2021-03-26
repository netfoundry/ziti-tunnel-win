echo "========================== build.ps1 begins =========================="
echo "Cleaning previous build folder if it exists"
rm .\build -r -fo -ErrorAction Ignore

$invocation = (Get-Variable MyInvocation).Value
$scriptPath = Split-Path $invocation.MyCommand.Path

echo "the branch is $env:GIT_BRANCH"

$zipLocal = "ziti-tunnel-service.zip"
$zipLocal = "${scriptPath}/../service/ziti-tunnel-win.zip"

echo ""
echo "unzipping $zipLocal to ${scriptPath}\build\service\"

Expand-Archive -Verbose -Force -LiteralPath $zipLocal "${scriptPath}\build\service\"

Push-Location ${scriptPath}\..
echo "Updating the version for UI and Installer"
.\update-versions.ps1

echo "Building the UI"
msbuild ZitiDesktopEdge.sln /property:Configuration=Release

Pop-Location

$ADVINST = "C:\Program Files (x86)\Caphyon\Advanced Installer 18.1\bin\x86\AdvancedInstaller.com"
$ADVPROJECT = "${scriptPath}\ZitiDesktopEdge.aip"
$installerVersion=(Get-Content -Path ${scriptPath}\..\version)
$action = '/SetVersion'

echo "issuing $ADVINST /edit $ADVPROJECT $action $installerVersion (service version: $serviceVersion) - see https://www.advancedinstaller.com/user-guide/set-version.html"
& $ADVINST /edit $ADVPROJECT $action $installerVersion

$action = '/build'
echo "Assembling installer using AdvancedInstaller at: $ADVINST $action $ADVPROJECT"
& $ADVINST $action $ADVPROJECT

$gituser=$(git config user.name)
if($gituser -eq "ziti-ci") {
  if(Test-Path ${scriptPath}\..\service\github_deploy_key) {
    copy $scriptPath\..\service\github_deploy_key .
  } else {
    echo "detected ziti-ci - but no gh_deploy_key. push may fail"
  }

  $b="$env:GIT_BRANCH"
  if( $b -match '(^main$|^release-next|^release-[0-9]*\.[0-9]*\.[0-9]*)' ) {
    echo "branch $b matches the required regex - adding committing and pushing"
    git add service/ziti-tunnel/version.go
    git add DesktopEdge/Properties/AssemblyInfo.cs
    git add ZitiUpdateService/Properties/AssemblyInfo.cs
    git add Installer/ZitiDesktopEdge.aip

    echo issuing status
    echo ========================================================
    git status 2>&1

    echo "GIT: trying git pull to see if it'll 'usually' work"
    git pull

    echo "GIT: git commit -m '[ci skip] committing updated version related files'"
    git commit -m "[ci skip] committing updated version related files" 2>&1

    echo "GIT: push"
    git push 2>&1
  } else {
    echo "branch $b does not match the regex. no commit/no push"
  }
} else {
  echo "detected user [${gituser}] which is not ziti-ci - skipping installer commit"
}
(Get-FileHash "${scriptPath}\Output\Ziti Desktop Edge Client-${installerVersion}.exe").Hash > "${scriptPath}\Output\Ziti Desktop Edge Client-${installerVersion}.exe.sha256"
echo "========================== build.ps1 competed =========================="
