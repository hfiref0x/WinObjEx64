/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       KLDBG.H
*
*  VERSION:     1.52
*
*  DATE:        08 Jan 2018
*
*  Common header file for the Kernel Debugger Driver support.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define IOCTL_KD_PASS_THROUGH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1, METHOD_NEITHER, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#ifdef _USE_OWN_DRIVER 
#define KLDBGDRV                L"wodbgdrv"
#define KLDBGDRVSYS             L"\\drivers\\wodbgdrv.sys"
#else
#define KLDBGDRV                L"kldbgdrv"
#define KLDBGDRVSYS             L"\\drivers\\kldbgdrv.sys"
#endif

#define RegControlKey           L"System\\CurrentControlSet\\Control"
#define RegStartOptionsValue    L"SystemStartOptions"

#define OBJECT_SHIFT 8

typedef ULONG_PTR *PUTable;

//enum with information flags used by ObGetObjectHeaderOffset
typedef enum _OBJ_HEADER_INFO_FLAG {
    HeaderCreatorInfoFlag = 0x1,
    HeaderNameInfoFlag = 0x2,
    HeaderHandleInfoFlag = 0x4,
    HeaderQuotaInfoFlag = 0x8,
    HeaderProcessInfoFlag = 0x10
} OBJ_HEADER_INFO_FLAG;

typedef struct _KLDBGCONTEXT {

    //Is user full admin
    BOOL IsFullAdmin;

    //we loaded driver?
    BOOL IsOurLoad;

    //are we under Wine
    BOOL IsWine;

    //system object header cookie (win10+)
    UCHAR ObHeaderCookie;

    //index of directory type and root address
    USHORT DirectoryTypeIndex;
    ULONG_PTR DirectoryRootAddress;

    //kldbgdrv device handle
    HANDLE hDevice;

    //worker handle
    HANDLE hThreadWorker;

    //address of invalid request handler
    PVOID IopInvalidDeviceRequest;

    //address of PrivateNamespaceLookupTable
    PVOID ObpPrivateNamespaceLookupTable;

    //ntoskrnl base and size
    PVOID NtOsBase;
    ULONG NtOsSize;

    //value of nt!KiServiceLimit
    ULONG KiServiceLimit;

    //address of nt!KiServiceTable
    ULONG_PTR KiServiceTableAddress;

    //system range start
    ULONG_PTR SystemRangeStart;

    //object list head
    LIST_ENTRY ObjectList;

    //object list lock
    CRITICAL_SECTION ListLock;

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
    ULONG_PTR NamespaceDirectoryAddress; //point to OBJECT_DIRECTORY
    ULONG_PTR NamespaceId;
    UCHAR TypeIndex;
} OBJREF, *POBJREF;

DWORD WINAPI kdQueryProc(
    _In_  LPVOID lpParameter);

UCHAR ObDecodeTypeIndex(
    _In_ PVOID Object,
    _In_ UCHAR EncodedTypeIndex);

POBJINFO ObQueryObject(
    _In_ LPWSTR lpDirectory,
    _In_ LPWSTR lpObjectName);

BOOL ObDumpTypeInfo(
    _In_    ULONG_PTR ObjectAddress,
    _Inout_ POBJECT_TYPE_COMPATIBLE ObjectTypeInfo);

LPWSTR ObQueryNameString(
    _In_      ULONG_PTR NameInfoAddress,
    _Out_opt_ PSIZE_T ReturnLength);

BOOL ObHeaderToNameInfoAddress(
    _In_    UCHAR ObjectInfoMask,
    _In_    ULONG_PTR ObjectAddress,
    _Inout_ PULONG_PTR HeaderAddress,
    _In_    OBJ_HEADER_INFO_FLAG InfoFlag);

BOOL ObListCreate(
    _Inout_ PLIST_ENTRY ListHead,
    _In_    BOOL fNamespace);

VOID ObListDestroy(
    _In_ PLIST_ENTRY ListHead);

POBJREF ObListFindByAddress(
    _In_ PLIST_ENTRY ListHead,
    _In_ ULONG_PTR	 ObjectAddress);

BOOL kdReadSystemMemory(
    _In_    ULONG_PTR Address,
    _Inout_ PVOID Buffer,
    _In_    ULONG BufferSize);

_Success_(return == TRUE)
BOOL kdReadSystemMemoryEx(
    _In_ ULONG_PTR Address,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG NumberOfBytesRead);

BOOL kdAddressInNtOsImage(
    _In_ PVOID Address);

VOID kdInit(
    BOOL IsFullAdmin);

VOID kdShutdown(
    VOID);
