@echo off
echo Looking for pattern 1
sp.exe C:\Dumps\ntoskrnl.exe "PAGE" "41 B8 FF 00 00 00 BF 06 00 00 00" "11 11 00 11 11 11 11 11 11 11 11"
pause
echo Looking for pattern 2
sp.exe C:\Dumps\ntoskrnl.exe "PAGE" "BA D0 07 00 00 B9 40 00 00 00" "11 11 11 11 11 11 11 11 11 11"
pause