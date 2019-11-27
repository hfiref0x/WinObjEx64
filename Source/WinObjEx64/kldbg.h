/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       KLDBG.H
*
*  VERSION:     1.82
*
*  DATE:        19 Nov 2019
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

#define OBJECT_SHIFT 8

#define KM_OBJECTS_ROOT_DIRECTORY  L"\\"

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

typedef struct _KLDBGCONTEXT {

    //Is debugging enabled
    BOOL ShowKdError;

    //Is user full admin
    BOOL IsFullAdmin;

    //we loaded driver?
    BOOL IsOurLoad;

    //secureboot enabled?
    BOOL IsSecureBoot;

    //system object header cookie (win10+)
    UCHAR ObHeaderCookie;

    //index of directory type and root address
    USHORT DirectoryTypeIndex;
    ULONG_PTR DirectoryRootAddress;

    //kldbgdrv device handle
    HANDLE hDevice;

    //address of invalid request handler
    PVOID IopInvalidDeviceRequest;

    //address of ObpPrivateNamespaceLookupTable
    PVOID PrivateNamespaceLookupTable;

    //ntoskrnl base and size
    PVOID NtOsBase;
    ULONG NtOsSize;

    //ntoskrnl mapped image
    PVOID NtOsImageMap;

    //win32 error value from SCM
    ULONG drvOpenLoadStatus;

    //syscall tables related info
    ULONG KiServiceLimit;
    ULONG W32pServiceLimit;
    ULONG_PTR KiServiceTableAddress;
    ULONG_PTR W32pServiceTableAddress;
    ULONG_PTR KeServiceDescriptorTableShadow;

    //system range start
    ULONG_PTR SystemRangeStart;

    //objects collection
    OBJECT_COLLECTION ObCollection;

    //object list lock
    CRITICAL_SECTION ListLock;

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
} NOTIFICATION_CALLBACKS, *PNOTIFICATION_CALLBACKS;

extern NOTIFICATION_CALLBACKS g_SystemCallbacks;

typedef struct _W32K_API_SET_ADAPTER_PATTERN {
    ULONG Size;
    PVOID Data;
} W32K_API_SET_ADAPTER_PATTERN, *PW32K_API_SET_ADAPTER_PATTERN;

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

POBJINFO ObQueryObject(
    _In_ LPWSTR lpDirectory,
    _In_ LPWSTR lpObjectName);

POBJINFO ObQueryObjectByAddress(
    _In_ ULONG_PTR ObjectAddress);

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

_Success_(return == TRUE)
BOOL kdFindKiServiceTables(
    _In_ ULONG_PTR MappedImageBase,
    _In_ ULONG_PTR KernelImageBase,
    _Out_opt_ ULONG_PTR *KiServiceTablePtr,
    _Out_opt_ ULONG *KiServiceLimit,
    _Out_opt_ ULONG_PTR *W32pServiceTable,
    _Out_opt_ ULONG *W32pServiceLimit);

ULONG_PTR kdQueryWin32kApiSetTable(
    _In_ HMODULE hWin32k);

BOOL kdReadSystemMemoryEx(
    _In_ ULONG_PTR Address,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG NumberOfBytesRead);

#define kdReadSystemMemory(Address, Buffer, BufferSize) \
    kdReadSystemMemoryEx(Address, Buffer, BufferSize, NULL)

BOOL __forceinline kdAddressInNtOsImage(
    _In_ PVOID Address);

VOID kdInit(
    _In_ BOOL IsFullAdmin);

BOOL kdIsDebugBoot(
    VOID);

VOID kdShutdown(
    VOID);

VOID kdShowError(
    _In_ ULONG InputBufferLength,
    _In_ NTSTATUS Status,
    _In_ PIO_STATUS_BLOCK Iosb);

UCHAR kdGetInstructionLength(
    _In_ PVOID ptrCode,
    _Out_ PULONG ptrFlags);
