
## What is new in 1.7

 - **W32pServiceTable viewer**

<img src="https://raw.githubusercontent.com/hfiref0x/WinObjEx64/master/Docs/Screenshots/W32pServiceTableView.png" width="600" />
 
W32pServiceTable is a service table of Win32k - a Windows User and GDI subsystem driver. It is a secondary system service table (where first is a ntoskrnl managed KiServiceTable). This table can be saved to text file from popup menu.

This feature available starting from Windows 10 1607 (RS1 14393) and require running program as administrator. Additionally Windows must be booted in the Debug mode (only for kldbgdrv version).

 - **Process list**

<img src="https://raw.githubusercontent.com/hfiref0x/WinObjEx64/master/Docs/Screenshots/ProcessList.png" width="600" />

Simple process list dialog. Display tree of running processes, their id, address of EPROCESS structure, user and domain name. Additionally this list uses highlighting similar to SysInternals Process Explorer. You can copy EPROCESS address value from popup menu. To view all process information program must run elevated.

 - **Callbacks viewer**

<img src="https://raw.githubusercontent.com/hfiref0x/WinObjEx64/master/Docs/Screenshots/CallbacksView.png" width="600" />

List of system wide driver callbacks and notify routines registered with the following API:

1. ObRegisterCallbacks
2. CmRegisterCallbacks
3. CmRegisterCallbacksEx
4. PsSetCreateProcessNotifyRoutine
5. PsSetCreateProcessNotifyRoutineEx
6. PsSetCreateProcessNotifyRoutineEx2
7. PsSetCreateThreadNotifyRoutine
8. PsSetCreateThreadNotifyRoutineEx
9. PsSetLoadImageNotifyRoutine
10. PsSetLoadImageNotifyRoutineEx
11. KeRegisterBugCheckCallback
12. KeRegisterBugCheckReasonCallback
13. IoRegisterShutdownNotification
14. IoRegisterLastChanceShutdownNotification
15. SeRegisterLogonSessionTerminatedRoutine
16. SeRegisterLogonSessionTerminatedRoutineEx
17. PoRegisterPowerSettingCallback
18. DbgSetDebugPrintCallback
19. IoRegisterFsRegistrationChange
20. IoRegisterFileSystem



 - **Callback object type viewer**

<img src="https://raw.githubusercontent.com/hfiref0x/WinObjEx64/master/Docs/Screenshots/CallbackObjectView.png" width="600" />

Viewer of registered callbacks for Callback object type. Drivers can create callbacks with ExCreateCallback API and register them with ExRegisterCallback.


 - **Improved OBJECT_TYPE view**

<img src="https://raw.githubusercontent.com/hfiref0x/WinObjEx64/master/Docs/Screenshots/ObjectTypeView.png" width="600" />

Improved display of structured dump for OBJECT_TYPE and substructure OBJECT_TYPE_INITIALIZER by including newly added Windows 10 fields.

