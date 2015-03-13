/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       KLDBG.H
*
*  VERSION:     1.11
*
*  DATE:        10 Mar 2015
*
*  Common header file for the Kernel Debugger Driver support.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#define IOCTL_KD_PASS_THROUGH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1, METHOD_NEITHER, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define KLDBGDRV				L"kldbgdrv"
#define KLDBGDRVSYS				L"\\drivers\\kldbgdrv.sys"
#define RegControlKey			L"System\\CurrentControlSet\\Control"
#define RegStartOptionsValue	L"SystemStartOptions"

//enum with information flags used by ObGetObjectHeaderOffset
typedef enum _OBJ_HEADER_INFO_FLAG {
	HeaderCreatorInfoFlag = 0x1,
	HeaderNameInfoFlag = 0x2,
	HeaderHandleInfoFlag = 0x4,
	HeaderQuotaInfoFlag = 0x8,
	HeaderProcessInfoFlag = 0x10
} OBJ_HEADER_INFO_FLAG;

typedef struct _KLDBGCONTEXT {
	//we loaded driver?
	BOOL IsOurLoad;

	//kldbgdrv device handle
	HANDLE hDevice;

	//worker handle
	HANDLE hThreadWorker;

	//object list head
	LIST_ENTRY ObjectList;

	//address of invalid request handler
	PVOID IopInvalidDeviceRequest;

	//system range start
	ULONG_PTR SystemRangeStart;

	//object list lock
	CRITICAL_SECTION ListLock;

	//osversion 
	RTL_OSVERSIONINFOW osver;

} KLDBGCONTEXT, *PKLDBGCONTEXT;

//global context
KLDBGCONTEXT g_kdctx;

typedef struct _KLDBG {
	SYSDBG_COMMAND SysDbgRequest;
	PVOID OutputBuffer;
	DWORD OutputBufferSize;
}KLDBG, *PKLDBG;

typedef struct _OBJINFO {
	LIST_ENTRY ListEntry;
	LPWSTR ObjectName;
	ULONG_PTR HeaderAddress;
	ULONG_PTR ObjectAddress;
	OBJECT_HEADER_QUOTA_INFO ObjectQuotaHeader;
	OBJECT_HEADER ObjectHeader;
} OBJINFO, *POBJINFO;

typedef struct _OBJREF {
	LIST_ENTRY ListEntry;
	LPWSTR ObjectName;
	ULONG_PTR HeaderAddress;
	ULONG_PTR ObjectAddress;
} OBJREF, *POBJREF;

DWORD WINAPI kdQueryProc(
	_In_  LPVOID lpParameter
	);

POBJINFO ObQueryObject(
	_In_ LPWSTR lpDirectory,
	_In_ LPWSTR lpObjectName
	);

BOOL ObDumpTypeInfo(
	_In_ ULONG_PTR ObjectAddress,
	_Inout_ POBJECT_TYPE_COMPATIBLE ObjectTypeInfo
	);

LPWSTR ObQueryNameString(
	ULONG_PTR NameInfoAddress,
	PSIZE_T ReturnLength
	);

BOOL ObHeaderToNameInfoAddress(
	_In_ UCHAR ObjectInfoMask,
	_In_ ULONG_PTR ObjectAddress,
	_Inout_ PULONG_PTR HeaderAddress,
	_In_ OBJ_HEADER_INFO_FLAG InfoFlag
	);

BOOL ObListCreate(
	_Inout_ PLIST_ENTRY ListHead
	);

VOID ObListDestroy(
	_In_ PLIST_ENTRY ListHead
	);

POBJREF ObListFindByAddress(
	_In_ PLIST_ENTRY ListHead,
	_In_ ULONG_PTR	 ObjectAddress
	);

BOOL kdReadSystemMemory(
	_In_ ULONG_PTR Address,
	_Inout_ PVOID Buffer,
	_In_ ULONG BufferSize
	);

PVOID kdQueryIopInvalidDeviceRequest(
	VOID
	);

VOID kdInit(
	BOOL IsFullAdmin
	);

VOID kdShutdown(
	VOID
	);
