ping -c 127.0.0.1
echo off
goto check_Permissions

:check_Permissions
    echo Ok im going to check to see if i have admin permissions as they are required. brb checking nao...

    net session >nul 2>&1
    if %errorLevel% == 0 (
        echo Success: awww yiess i has admin permissions confirmed.
	goto has_admin
    ) else (
        goto no_admin
    )

    pause >nul

:no_Admin
	Echo sorry brah i need admin permissions to complete the post build process.
	sleep 5  

:has_admin
REM print ok first things first, this script will check to see if you want to activate this box or not. After that it will change the timezone to central time, enable rdp access(in the fw as well), disable UAC install .net4 if needed and install citrix tools from sat-dc03's file stash and reboot the box.
REM pause
print ok first things first, this script will change the timezone to central time, enable rdp access(in the fw as well), disable UAC install .net4 if needed and install citrix tools from sat-dc03's file stash and reboot the box.
pause
REM skipping activate check for now as it needs work :goto activate_check
:detect_windows_ver

:activate_check
set activate=
SET /P activate=Hey bro do you wanna activate this box?
if /i {%ANSWER%}=={y} (set activate=1)
if /i {%ANSWER%}=={yes} (set activate=1)  
if /i {%ANSWER%}=={n} (set activate=0)
if /i {%ANSWER%}=={no} (set activate=0)  

    if %activate% == 0 (
        echo thats cool i wont activate then.
	goto detect_windows_ver
    )
    if %activate% == 1 (
        echo all activate the box then.
	goto detect_windows_ver
    )

:detect_windows_ver
	echo checking to see whatcha got under the hood of this hoe.
	ver | findstr /i "6\.1\." > nul
	IF %ERRORLEVEL% EQU 0 goto Win7_2k8r2
	ver | findstr /i "6\.3\." > nul
	IF %ERRORLEVEL% EQU 0 goto win81_win2k12r2 
	ver | findstr /i "6\.2\." > nul
	IF %ERRORLEVEL% EQU 0 goto win8_win2k12
	goto warn_and_exit

:Win7_2k8r2
REM ok this part is specific to windows 7 and 2008 r2 
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" /v IsInstalled /t REG_DWORD /d 00000000 /f
netsh firewall set service type = remotedesktop mode = enable
rmdir /S /Q C:\citrix_tools
mkdir C:\citrix_tools
copy \\sat-dc03\u\server-2012-.net\citrix_tools C:\citrix_tools
c:\citrix_tools\dotNetFx40_Full_x86_x64.exe/q /norestart /ChainingPackage "windows post build script v1.0"
msiexec /quiet /i c:\citrix_tools\installwizard.msi

goto end

:win81_win2k12r2 
REM ok this part is specific to windows 8.1 and 2012 r2
REM todo have windows dowload the files directly fron xs-n01 and mount the iso, install tools and then unmount the iso and then delete said iso"
REM http://technet.microsoft.com/en-us/library/hh848646.aspx http://technet.microsoft.com/en-us/library/hh848693.aspx http://technet.microsoft.com/en-us/library/hh848706.aspx
REM powershell --command 'http://xs-n01.thelaughingman.local/xs-tools-6.2.0-3.iso' -OutFile c:\xs-tools.iso
REM Mount-DiskImage -ImagePath "c:\xs-tools.iso"
TZUTIL /s "Central Standard Time"
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" /v IsInstalled /t REG_DWORD /d 00000000 /f
netsh firewall set service type = remotedesktop mode = enable
print ok, so far timezone has been set, rdp has been enabled, UAC has been killed and the firewall has been opened up, time to install .net and
powershell.exe "Install-WindowsFeature -Name net-framework-features,net-framework-core,net-framework-45-features,net-framework-45-core -Source \\sat-dc03\u\server-2012-.net\2012-r2\sxs"
#slmgr.vbs /skms derpette.smokythecat.com
#slmgr.vbs /ipk D2N9P-3P6X9-2R39C-7RTCD-MDVJX
#slmgr.vbs /ato
rmdir /Q /S C:\citrix_tools
mkdir C:\citrix_tools\
copy \\sat-dc03\u\server-2012-.net\citrix_tools C:\citrix_tools\
msiexec /quiet /i c:\citrix_tools\installwizard.msi


goto end

:win8_win2k12
REM ok this part is for win8 ( NOT 8.1)  and 2012 
REM todo have windows dowload the files directly fron xs-n01 and mount the iso, install tools and then unmount the iso and then delete said iso"
REM http://technet.microsoft.com/en-us/library/hh848646.aspx http://technet.microsoft.com/en-us/library/hh848693.aspx http://technet.microsoft.com/en-us/library/hh848706.aspx
REM powershell --command 'http://xs-n01.thelaughingman.local/xs-tools-6.2.0-3.iso' -OutFile c:\xs-tools.iso
REM Mount-DiskImage -ImagePath "c:\xs-tools.iso"
TZUTIL /s "Central Standard Time"
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" /v IsInstalled /t REG_DWORD /d 00000000 /f
netsh firewall set service type = remotedesktop mode = enable
powershell.exe "Install-WindowsFeature -Name net-framework-features,net-framework-core,net-framework-45-features,net-framework-45-core -Source \\sat-dc03\u\server-2012-.net\sxs"
rmdir /Q /S C:\citrix_tools
mkdir C:\citrix_tools\
copy \\sat-dc03\u\server-2012-.net\citrix_tools C:\citrix_tools\
msiexec /quiet /i c:\citrix_tools\installwizard.msi

goto end



:warn_and_exit
echo da fuq are you running? i cant tell what OS your running :(

:end  

print BRO THE BOX IS GETTING READY TO REBOOT!!!111
pause