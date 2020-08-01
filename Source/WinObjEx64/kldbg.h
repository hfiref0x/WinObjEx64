/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       KLDBG.H
*
*  VERSION:     1.87
*
*  DATE:        29 July 2020
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
#ifdef _USE_WINIO
#define KLDBGDRV                L"EneTechIo"
#define KLDBGDRVSYS             L"\\drivers\\ene64drv.sys"
#else
#define KLDBGDRV                L"wodbgdrv"
#define KLDBGDRVSYS             L"\\drivers\\wodbgdrv.sys"
#endif
#else
#define KLDBGDRV                L"kldbgdrv"
#define KLDBGDRVSYS             L"\\drivers\\kldbgdrv.sys"
#endif

#define NT_REG_PREP             L"\\Registry\\Machine"
#define DRIVER_REGKEY           L"%wS\\System\\CurrentControlSet\\Services\\%wS"

#define OBJECT_SHIFT 8

#define KM_OBJECTS_ROOT_DIRECTORY  L"\\"

#define MM_SYSTEM_RANGE_START_7 0xFFFF080000000000
#define MM_SYSTEM_RANGE_START_8 0xFFFF800000000000

#define TEXT_SECTION ".text"
#define TEXT_SECTION_LEGNTH sizeof(TEXT_SECTION)

#define PAGE_SECTION "PAGE"
#define PAGE_SECTION_LEGNTH sizeof(PAGE_SECTION)

typedef ULONG_PTR *PUTable;

//enum with information flags used by ObGetObjectHeaderOffset
typedef enum _OBJ_HEADER_INFO_FLAG {
    HeaderCreatorInfoFlag = 0x1,
    HeaderNameInfoFlag = 0x2,
    HeaderHandleInfoFlag = 0x4,
    HeaderQuotaInfoFlag = 0x8,
    HeaderProcessInfoFlag = 0x10
} OBJ_HEADER_INFO_FLAG;

typedef struct _OBJECT_COLLECTION {
    LIST_ENTRY ListHead;
    HANDLE Heap;
} OBJECT_COLLECTION, *POBJECT_COLLECTION;

typedef struct _OBHEADER_COOKIE {
    UCHAR Value;
    BOOLEAN Valid;
} OBHEADER_COOKIE, * POBHEADER_COOKIE;

typedef struct _KSE_ENGINE_DUMP {
    BOOLEAN Valid;
    ULONG_PTR KseAddress;
    LIST_ENTRY ShimmedDriversDumpListHead;
} KSE_ENGINE_DUMP, * PKSE_ENGINE_DUMP;

typedef struct _KLDBGCONTEXT {

    //Is user full admin
    BOOL IsFullAdmin;

    //we loaded driver?
    BOOL IsOurLoad;

    //secureboot enabled?
    BOOL IsSecureBoot;

    //system object header cookie (win10+)
    OBHEADER_COOKIE ObHeaderCookie;

    //index of directory type and root address
    USHORT DirectoryTypeIndex;
    ULONG_PTR DirectoryRootAddress;

    //kldbgdrv device handle
    HANDLE DeviceHandle;

    //address of invalid request handler
    PVOID IopInvalidDeviceRequest;

    //address of ObpPrivateNamespaceLookupTable
    PVOID PrivateNamespaceLookupTable;

    //ntoskrnl base and size
    PVOID NtOsBase;
    ULONG NtOsSize;

    //ntoskrnl mapped image
    PVOID NtOsImageMap;

    //driver loading/open status
    ULONG DriverOpenLoadStatus;
    ULONG DriverOpenStatus;

    //syscall tables related info
    ULONG_PTR KeServiceDescriptorTableShadowPtr;
    KSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;

    //system range start
    ULONG_PTR SystemRangeStart;

    //objects collection
    OBJECT_COLLECTION ObCollection;

    //object list lock
    CRITICAL_SECTION ObCollectionLock;

    //kernel shim engine dump and auxl ptrs
    KSE_ENGINE_DUMP KseEngineDump;

} KLDBGCONTEXT, *PKLDBGCONTEXT;

extern KLDBGCONTEXT g_kdctx;
extern ULONG g_NtBuildNumber;

typedef struct _KLDBG {
    SYSDBG_COMMAND SysDbgRequest;
    PVOID Buffer;
    DWORD BufferSize;
}KLDBG, *PKLDBG;

typedef struct _OBJINFO {
    LIST_ENTRY ListEntry;
    LPWSTR ObjectName;
    ULONG_PTR HeaderAddress;
    ULONG_PTR ObjectAddress;
    OBJECT_HEADER_QUOTA_INFO ObjectQuotaHeader;
    OBJECT_HEADER ObjectHeader;
} OBJINFO, *POBJINFO;

typedef struct _OBJREFPNS {
    ULONG SizeOfBoundaryInformation;
    ULONG_PTR NamespaceDirectoryAddress; //point to OBJECT_DIRECTORY
    ULONG_PTR NamespaceLookupEntry; //point to OBJECT_NAMESPACE_ENTRY
} OBJREFPNS, *POBJREFPNS;

typedef struct _OBJREF {
    LIST_ENTRY ListEntry;
    LPWSTR ObjectName;
    ULONG_PTR HeaderAddress;
    ULONG_PTR ObjectAddress;
    UCHAR TypeIndex;
    OBJREFPNS PrivateNamespace;
} OBJREF, *POBJREF;

//
// Defines for Major Windows NT release builds
//

// Windows 7 RTM
#define NT_WIN7_RTM             7600

// Windows 7 SP1
#define NT_WIN7_SP1             7601

// Windows 8 RTM
#define NT_WIN8_RTM             9200

// Windows 8.1
#define NT_WIN8_BLUE            9600

// Windows 10 TH1
#define NT_WIN10_THRESHOLD1     10240

// Windows 10 TH2
#define NT_WIN10_THRESHOLD2     10586

// Windows 10 RS1
#define NT_WIN10_REDSTONE1      14393

// Windows 10 RS2
#define NT_WIN10_REDSTONE2      15063

// Windows 10 RS3
#define NT_WIN10_REDSTONE3      16299

// Windows 10 RS4
#define NT_WIN10_REDSTONE4      17134

// Windows 10 RS5
#define NT_WIN10_REDSTONE5      17763

// Windows 10 19H1
#define NT_WIN10_19H1           18362

// Windows 10 19H2
#define NT_WIN10_19H2           18363

// Windows 10 20H1
#define NT_WIN10_20H1           19041

// Windows 10 20H2
#define NT_WIN10_20H2           19042

// Windows 10 Active Develepment Branch (21H1)
#define NTX_WIN10_ADB           20180

//
// Defines for boundary descriptors
//

#define KNOWN_BOUNDARY_DESCRIPTOR_VERSION       1
#define MAX_BOUNDARY_DESCRIPTOR_NAME_ENTRIES    1
#define MAX_BOUNDARY_DESCRIPTOR_IL_ENTRIES      1

//
// Callbacks support.
//

//
// Actual limits, not variables.
//
#define PspNotifyRoutinesLimit                  64
#define PspCreateProcessNotifyRoutineExCount    64
#define PspCreateThreadNotifyRoutineCount       64
#define PspLoadImageNotifyRoutineCount          64
#define DbgkLmdCount                            8

typedef struct _NOTIFICATION_CALLBACKS {
    ULONG_PTR PspCreateProcessNotifyRoutine;
    ULONG_PTR PspCreateThreadNotifyRoutine;
    ULONG_PTR PspLoadImageNotifyRoutine;
    ULONG_PTR KeBugCheckCallbackHead;
    ULONG_PTR KeBugCheckReasonCallbackHead;
    ULONG_PTR CmCallbackListHead;
    ULONG_PTR IopNotifyShutdownQueueHead;
    ULONG_PTR IopNotifyLastChanceShutdownQueueHead;
    ULONG_PTR ObProcessCallbackHead;
    ULONG_PTR ObThreadCallbackHead;
    ULONG_PTR ObDesktopCallbackHead;
    ULONG_PTR SeFileSystemNotifyRoutinesHead;
    ULONG_PTR SeFileSystemNotifyRoutinesExHead;
    ULONG_PTR PopRegisteredPowerSettingCallbacks;
    ULONG_PTR RtlpDebugPrintCallbackList;
    ULONG_PTR IopFsNotifyChangeQueueHead;
    ULONG_PTR IopDiskFileSystemQueueHead;
    ULONG_PTR IopCdRomFileSystemQueueHead;
    ULONG_PTR IopTapeFileSystemQueueHead;
    ULONG_PTR IopNetworkFileSystemQueueHead;
    ULONG_PTR DbgkLmdCallbacks;
    ULONG_PTR PsAltSystemCallHandlers;
    ULONG_PTR CiCallbacks;
    ULONG_PTR ExpHostListHead;
} NOTIFICATION_CALLBACKS, *PNOTIFICATION_CALLBACKS;

extern NOTIFICATION_CALLBACKS g_SystemCallbacks;

typedef struct _W32K_API_SET_LOOKUP_PATTERN {
    ULONG Size;
    PVOID Data;
} W32K_API_SET_LOOKUP_PATTERN, *PW32K_API_SET_LOOKUP_PATTERN;

// return true to stop enumeration
typedef BOOL(CALLBACK *PENUMERATE_COLLECTION_CALLBACK)(
    _In_ POBJREF CollectionEntry,
    _In_opt_ PVOID Context
    );

// return true to stop enumeration
typedef BOOL(CALLBACK *PENUMERATE_BOUNDARY_DESCRIPTOR_CALLBACK)(
    _In_ OBJECT_BOUNDARY_ENTRY *Entry,
    _In_opt_ PVOID Context
    );

NTSTATUS ObCopyBoundaryDescriptor(
    _In_ OBJECT_NAMESPACE_ENTRY *NamespaceLookupEntry,
    _Out_ POBJECT_BOUNDARY_DESCRIPTOR *BoundaryDescriptor,
    _Out_opt_ PULONG BoundaryDescriptorSize);

NTSTATUS ObEnumerateBoundaryDescriptorEntries(
    _In_ OBJECT_BOUNDARY_DESCRIPTOR *BoundaryDescriptor,
    _In_opt_ PENUMERATE_BOUNDARY_DESCRIPTOR_CALLBACK Callback,
    _In_opt_ PVOID Context);

UCHAR ObDecodeTypeIndex(
    _In_ PVOID Object,
    _In_ UCHAR EncodedTypeIndex);

PVOID ObDumpDirectoryObjectVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version);

PVOID ObDumpObjectTypeVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version);

PVOID ObDumpAlpcPortObjectVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version);

PVOID ObDumpSymbolicLinkObjectVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version);

PVOID ObDumpDeviceMapVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version);

PVOID ObDumpDriverExtensionVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version);

POBJINFO ObQueryObject(
    _In_ LPWSTR lpDirectory,
    _In_ LPWSTR lpObjectName);

POBJINFO ObQueryObjectByAddress(
    _In_ ULONG_PTR ObjectAddress);

BOOL ObDumpTypeInfo(
    _In_    ULONG_PTR ObjectAddress,
    _Inout_ POBJECT_TYPE_COMPATIBLE ObjectTypeInfo);

BOOL ObHeaderToNameInfoAddress(
    _In_    UCHAR ObjectInfoMask,
    _In_    ULONG_PTR ObjectAddress,
    _Inout_ PULONG_PTR HeaderAddress,
    _In_    OBJ_HEADER_INFO_FLAG InfoFlag);

BOOL ObHeaderToNameInfoAddressEx(
    _In_ UCHAR ObjectInfoMask,
    _In_ ULONG_PTR ObjectAddress,
    _Inout_ PULONG_PTR HeaderAddress,
    _In_ BYTE DesiredHeaderBit);

BOOL ObCollectionCreate(
    _In_ POBJECT_COLLECTION Collection,
    _In_ BOOL fNamespace,
    _In_ BOOL Locked);

VOID ObCollectionDestroy(
    _In_ POBJECT_COLLECTION Collection);

BOOL ObCollectionEnumerate(
    _In_ POBJECT_COLLECTION Collection,
    _In_ PENUMERATE_COLLECTION_CALLBACK Callback,
    _In_opt_ PVOID Context);

POBJREF ObCollectionFindByAddress(
    _In_ POBJECT_COLLECTION Collection,
    _In_ ULONG_PTR ObjectAddress,
    _In_ BOOLEAN fNamespace);

PVOID ObGetCallbackBlockRoutine(
    _In_ PVOID CallbackBlock);

BOOLEAN kdConnectDriver(
    VOID);

PVOID kdQueryIopInvalidDeviceRequest(
    VOID);

BOOL kdFindKiServiceTable(
    _In_ ULONG_PTR MappedImageBase,
    _In_ ULONG_PTR KernelImageBase,
    _Out_ KSERVICE_TABLE_DESCRIPTOR* ServiceTable);

ULONG_PTR kdQueryWin32kApiSetTable(
    _In_ HMODULE hWin32k);

BOOL kdpReadSystemMemoryEx(
    _In_ ULONG_PTR Address,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG NumberOfBytesRead);

#ifdef _USE_OWN_DRIVER
#ifdef _USE_WINIO
#define kdReadSystemMemoryEx WinIoReadSystemMemoryEx
#else
#define kdReadSystemMemoryEx kdpReadSystemMemoryEx
#endif
#else 
#define kdReadSystemMemoryEx kdpReadSystemMemoryEx
#endif

#define kdReadSystemMemory(Address, Buffer, BufferSize) \
    kdReadSystemMemoryEx(Address, Buffer, BufferSize, NULL)

#ifdef _DEBUG
#define kdDebugPrint(f, ...) DbgPrint(f, __VA_ARGS__)
#else
#define kdDebugPrint(f, ...) 
#endif

VOID kdInit(
    _In_ BOOL IsFullAdmin);

VOID kdShutdown(
    VOID);

VOID kdReportReadError(
    _In_ LPWSTR FunctionName,
    _In_ ULONG_PTR KernelAddress,
    _In_ ULONG InputBufferLength,
    _In_ NTSTATUS Status,
    _In_ PIO_STATUS_BLOCK Iosb);

UCHAR kdGetInstructionLength(
    _In_ PVOID ptrCode,
    _Out_ PULONG ptrFlags);

BOOLEAN kdQueryKernelShims(
    _In_ PKLDBGCONTEXT Context,
    _In_ BOOLEAN RefreshList);

/*
* ObGetObjectFastReference
*
* Purpose:
*
* Return unbiased pointer.
*
*/
__forceinline PVOID ObGetObjectFastReference(
    _In_ EX_FAST_REF FastRef)
{
    return (PVOID)(FastRef.Value & ~MAX_FAST_REFS);
}

/*
* kdAddressInNtOsImage
*
* Purpose:
*
* Test if given address in range of ntoskrnl.
*
*/
__forceinline BOOL kdAddressInNtOsImage(
    _In_ PVOID Address)
{
    return IN_REGION(Address,
        g_kdctx.NtOsBase,
        g_kdctx.NtOsSize);
}

/*
* kdAdjustAddressToNtOsBase
*
* Purpose:
*
* Adjust address to address in ntos kernel image.
*
*/
__forceinline ULONG_PTR kdAdjustAddressToNtOsBase(
    _In_ ULONG_PTR CodeBase,
    _In_ ULONG_PTR Offset,
    _In_ ULONG InstructionLength,
    _In_ LONG Relative
)
{
    ULONG_PTR Address;

    Address = (ULONG_PTR)CodeBase + Offset + InstructionLength + Relative;
    Address = (ULONG_PTR)g_kdctx.NtOsBase + Address - (ULONG_PTR)g_kdctx.NtOsImageMap;

    return Address;
}
