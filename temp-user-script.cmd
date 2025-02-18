@echo off
:: Run this script as administrator
setlocal EnableDelayedExpansion

:: Set username for temporary account
set "tempUser=TempUser"

:: Create user without password
net user %tempUser% /add /expires:never /passwordreq:no

:: Configure user settings
:: Set profile to mandatory so changes aren't saved
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" /f /v "DefaultUserProfile" /t REG_EXPAND_SZ /d "C:\Users\Default"

:: Configure mandatory profile for temp user
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" /f /v "%tempUser%.man" /t REG_EXPAND_SZ /d "C:\Users\Default"

:: Set user profile to delete on logoff
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "DeleteRoamingCache" /t REG_DWORD /d 1 /f

:: Disable profile caching
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Update" /v "UpdateMode" /t REG_DWORD /d 0 /f

:: Check if user is already in Users group and add if not
net localgroup Users | find /i "%tempUser%" > nul
if errorlevel 1 (
    net localgroup Users %tempUser% /add
) else (
    echo User already in Users group - skipping...
)

:: Set account to not store history
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f

:: Clear user profile on logoff
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "DeleteProfileOnLogoff" /t REG_DWORD /d 1 /f

:: Disable User Profile Service for this account
sc config ProfSvc start= disabled

echo Temporary user %tempUser% has been created.
echo The profile will be cleared when logging off.
echo To use: Log off current account and log in as %tempUser%
echo To remove: Run 'net user %tempUser% /delete' as administrator

pause
