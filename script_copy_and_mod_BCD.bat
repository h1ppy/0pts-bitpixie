@echo off
setlocal enabledelayedexpansion

:: Путь к SMB-шаре
set SMB_SHARE=B:

mountvol S: /s

:: Копирование EFI на SMB-шар
robocopy S:/EFI %SMB_SHARE%/EFI /MIR
echo Copied EFI to SMB share

cd \

bcdedit /export BCD_modded
echo Export successful

bcdedit /store BCD_modded /create /d "softreboot" /application startup>GUID.txt
echo GUID save successful

For /F "tokens=2 delims={}" %%i in (GUID.txt) do (set REBOOT_GUID=%%i)
del GUID.txt

echo GUID parsed into REBOOT_GUID successful

bcdedit /store BCD_modded /set {%REBOOT_GUID%} path "\shimx64.efi"
bcdedit /store BCD_modded /set {%REBOOT_GUID%} device boot
bcdedit /store BCD_modded /set {%REBOOT_GUID%} pxesoftreboot yes

echo Configured shimx64.efi and pxesoftreboot successful

bcdedit /store BCD_modded /set {default} recoveryenabled yes
bcdedit /store BCD_modded /set {default} recoverysequence {%REBOOT_GUID%}
bcdedit /store BCD_modded /set {default} path "\\"
bcdedit /store BCD_modded /set {default} winpe yes

echo Configured recoveryenabled, winpe, and boot path successful

bcdedit /store BCD_modded /displayorder {%REBOOT_GUID%} /addlast

echo BCD file successfully created!

:: Копирование BCD_modded на SMB-шар

move BCD_modded %SMB_SHARE%\Boot\BCD

echo Copied BCD_modded to SMB share

echo All operations completed successfully!
