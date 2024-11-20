@echo off

set VERSION=v1.0.0
set BUILD_TIME=%date% %time%
for /f "tokens=*" %%a in ('git rev-parse HEAD') do set COMMIT_SHA=%%a

set LDFLAGS=-X 'main.Version=%VERSION%' -X 'main.BuildTime=%BUILD_TIME%' -X 'main.CommitSHA=%COMMIT_SHA%' -w -s

mkdir release

set GOOS=windows
set GOARCH=amd64
go build -ldflags="%LDFLAGS%" -o release\zasset_windows_amd64.exe cmd\main.go

set GOOS=linux
set GOARCH=amd64
go build -ldflags="%LDFLAGS%" -o release\zasset_linux_amd64 cmd\main.go

xcopy /E /I config release\config
copy README.md release\

cd release
powershell Compress-Archive -Path zasset_windows_amd64.exe,config,README.md -DestinationPath zasset_windows_amd64.zip 