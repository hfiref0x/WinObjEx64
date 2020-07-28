[![Build status](https://ci.appveyor.com/api/projects/status/dxsbgm90sahgwbo0?svg=true)](https://ci.appveyor.com/project/hfiref0x/winobjex64)

# WinObjEx64
## Windows Object Explorer 64-bit

<img src="https://raw.githubusercontent.com/hfiref0x/WinObjEx64/master/Screenshots/MainWindow.png" width="600" />

WinObjEx64 is an advanced utility that lets you explore the Windows Object Manager namespace. For certain object types, you can double-click on it or use the "Properties..." toolbar button to get more information, such as description, attributes, resource usage etc. WinObjEx64 let you view and edit object-related security information if you have required access rights.

# System Requirements

WinObjEx64 does not require administrative privileges. However administrative privilege is required to view much of the namespace and to edit object-related security information.

WinObjEx64 works only on the following x64 Windows: Windows 7, Windows 8, Windows 8.1 and Windows 10, including Server variants.


# Features

<details>
  <summary>View list</summary>

- Explore all of Windows Object Manager namespace
	- Hierarchical objects tree

	- Symbolic links resolving

	- Version information for Section type objects that are backed by an image file

	- Additional information for WindowStation type objects

	- View objects details
		- Descriptions
		- Flags
		- Invalid attributes
		- Memory pool type
		- Object type specific information
		- Object-related structure memory dumps<sup>1</sup>
			- ALPC_PORT
			- CALLBACK_OBJECT
			-  DEVICE_OBJECT
			- DRIVER_OBJECT
			- DIRECTORY_OBJECT
			- FLT_SERVER_PORT_OBJECT
			- KEVENT
			- KMUTANT
			- KSEMAPHORE
			- KTIMER
			- KQUEUE (IoCompletion)
			- OBJECT_SYMBOLIC_LINK
			- OBJECT_TYPE
		- Opened handles
		- Statistics
		- Supported access rights
		- Process Trust label
		- And more...

	- Display in dump sub-structures such as<sup>1</sup>: 

		- ALPC_PORT_ATTRIBUTES
		- DEVICE_MAP
		- LDR_DATA_TABLE_ENTRY
		- OBJECT_TYPE_INITIALIZER
		- UNICODE_STRING
		- and many others

	- Edit object-related security information<sup>2</sup>

	- Detect driver object IRP modifications (as part of structure dump)<sup>1</sup>

	- Detect kernel object hooking (as part of structure dump)<sup>1</sup>

	- Search for objects by name and/or type

- System information viewer
	- Boot state and type
	- Code Integrity options
	- Mitigation flags
	- Windows version and build

- Loaded drivers list viewer
	- Ability to dump selected driver<sup>1</sup>
	- Export driver list to file in CSV format
	- Jump to driver file location
	- Recognize Kernel Shim Engine "shimmed" drivers<sup>1</sup>
	- View driver file properties

- Mailslots/Named pipes viewer
	- Display list of all registered mailslots/named pipes
	- Named pipes security information editor<sup>4</sup>
	- Object statistics

- Hierarchical process tree viewer<sup>2</sup>
	- Show process id, user name, EPROCESS addresses
	- Highlight processes by type similar to default Process Explorer highlighting
	- Show thread list for selected process
	- Show ETHREAD addresses
	- Show common properties for Process/Thread objects
		- Basic properties as for any other object type
		- Start time
		- Process type
		- Image file name
		- Command line
		- Current directory
		- Applied mitigation's
		- Protection
		- State of "Critical Process" flag
		- Security edit
	- Jump to process file location
	- Process/Thread token information
		- User name
		- User SID
		- AppContainer SID
		- Session
		- UIAccess
		- Elevation state
		- Integrity level
		- Privileges and groups
	- Show additional token properties for Process/Thread
		- Basic properties as for any other object type
		- List of security attributes
		- Security edit

- Software Licensing Cache viewer
	- Display list of registered licenses
	- Display license data
	- Dump license data of type SL_DATA_BINARY to file

- User Shared Data viewer
	- Display structured dump of most important parts of KUSER_SHARED_DATA

- System callbacks viewer<sup>1</sup>
	- Display address, module and callback specific information for callbacks registered with: 
		- PsSetCreateProcessNotifyRoutine
		- PsSetCreateProcessNotifyRoutineEx
		- PsSetCreateProcessNotifyRoutineEx2
		- PsSetCreateThreadNotifyRoutine
		- PsSetCreateThreadNotifyRoutineEx
		- PsSetLoadImageNotifyRoutine
		- PsSetLoadImageNotifyRoutineEx
		- KeRegisterBugCheckCallback
		- KeRegisterBugCheckReasonCallback
		- CmRegisterCallback
		- CmRegisterCallbackEx
		- IoRegisterShutdownNotification
		- IoRegisterLastChanceShutdownNotification
		- PoRegisterPowerSettingCallback
		- SeRegisterLogonSessionTerminatedRoutine
		- SeRegisterLogonSessionTerminatedRoutineEx
		- IoRegisterFsRegistrationChange
		- IopFsListsCallbacks
		- ObRegisterCallbacks
		- DbgSetDebugPrintCallback
		- DbgkLkmdRegisterCallback
		- PsRegisterAltSystemCallHandler
		- CodeIntegrity SeCiCallbacks
		- ExRegisterExtension

- Windows Object Manager private namespace viewer<sup>1</sup>
	- View basic namespace entry information
	- View boundary descriptor information
	- Show common properties for objects

- KiServiceTable viewer<sup>1</sup>
	- Show dump of Ntoskrnl-managed KiServiceTable (sometimes referenced as SSDT)
	- Jump to service entry module
	- Export list to file in CSV format

- W32pServiceTable viewer<sup>1</sup>
	- Show dump of Win32k-managed W32pServiceTable (sometimes referenced as Shadow SSDT)
	- Support Win32k import forwarding
	- Support Win32k ApiSets resolving
	- Jump to service entry module
	- Export list to file in CSV format

- Most of list/trees allows to copy object address and/or name to the clipboard

- Running on Wine/Wine-Staging is supported<sup>3</sup>

- Plugins subsystem for extending basic features
	- Available plugins that shipped with WinObjEx64 release:
		- ApiSetView - viewer for Windows ApiSetSchema internals, support loading ApiSet schema from file
		- Example plugin - example plugin for developers
		- Sonar - NDIS protocols viewer, display registered NDIS protocols and dumps some information about them
		- ImageScope - context plugin allowing to view more details in WinObjEx64 for Section type objects that are backed by image file (available through popup menu on object of Section type in WinObjEx64 main list)

- Documentation
	- Windows Callbacks
	- Plugins subsystem

1. This feature require driver support enabled, see "Driver support" part below.
2. This may require administrator privileges.
3. Most of additional Windows internals-specific features however will be unavailable due to obvious reasons.
4. Some named pipes may require administrator privileges to access.

### Driver support

WinObjEx64 supports two types of driver helpers:

1. Helper for read-only access to the kernel memory. Default version uses Kernel Local Debugging Driver (KLDBGDRV) from WinDbg. In order to use it (and thus enable all the above features) Windows must be booted in the debug mode (bcdedit -debug on) and WinObjEx64 must be run with administrator privileges. If you are using WinObjEx64 version with custom helper driver - Windows debug mode is not required. There are exist several drivers that can be used as helpers for WinObjEx64, by default it has only WinDbg type built-in.
2. Helper to access object handles. WinObjEx64 (any variant) support Process Explorer driver of version 1.5.2 to open process/threads. To enable this just load Process Explorer with administrator privileges simultaneously with WinObjEx64.

All driver helpers require WinObjEx64 to be run with administrative privileges.

</details>

# Build 

WinObjEx64 comes with full source code.
In order to build from source you need Microsoft Visual Studio 2015/2017/2019 and later versions.

## Instructions

* Select Platform ToolSet first for project in solution you want to build (Project->Properties->General): 
  * v120 for Visual Studio 2013;
  * v140 for Visual Studio 2015; 
  * v141 for Visual Studio 2017;
  * v142 for Visual Studio 2019.
* For v140 and above set Target Platform Version (Project->Properties->General):
  * If v140 then select 8.1;
  * If v141/v142 then select 10.
* Minimum required Windows SDK version 8.1
 
 
# What is new

[Whats New in 1.8.7](https://github.com/hfiref0x/WinObjEx64/blob/master/Compiled/WHATSNEW_187.md)

[Complete changelog](https://github.com/hfiref0x/WinObjEx64/blob/master/Source/CHANGELOG.txt)

# Authors


(c) 2015 - 2020 WinObjEx64 Project

Original WinObjEx (c) 2003 - 2005 Four-F
