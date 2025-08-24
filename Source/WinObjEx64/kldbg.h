/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2025
*
*  TITLE:       KLDBG.H
*
*  VERSION:     2.09
*
*  DATE:        19 Aug 2025
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

/******************************************************************************
*
* Object type versions
* 
* ALPC_PORT
* DEVICE_MAP
* DIRECTORY_OBJECT
* DRIVER_EXTENSION
* OBJECT_TYPE
* OBJECT_SYMBOLIC_LINK
* FLT_FILTER
* 
*******************************************************************************/

// Structure version from W7 (7600)
#define OBVERSION_ALPCPORT_V1  (1)
// Structure version from W8 (9200)
#define OBVERSION_ALPCPORT_V2  (2)
// Structure version from W8 BLUE (9600)
#define OBVERSION_ALPCPORT_V3  (3)
// Structure version from W10 (10240)
#define OBVERSION_ALPCPORT_V4  (4)

// Structure version from W7 (7600) until W10 RS1
#define OBVERSION_DEVICE_MAP_V1  (1)
// Structure version from W10 RS1 (14393) until W11
#define OBVERSION_DEVICE_MAP_V2  (2)
// Structure version from W11 (22000)
#define OBVERSION_DEVICE_MAP_V3  (3)

// Structure version for W7-W8 BLUE (7600..9600)
#define OBVERSION_DIRECTORY_V1 (1)
// Structure version for W10 (10240..14393)
#define OBVERSION_DIRECTORY_V2 (2)
// Structure version for W10 (15063+)
#define OBVERSION_DIRECTORY_V3 (3)

// Public structure
#define OBVERSION_DRIVER_EXTENSION_V1 (1)
// Private, W7 (7600..7601)
#define OBVERSION_DRIVER_EXTENSION_V2 (2)
// Private, W8 (9200)
#define OBVERSION_DRIVER_EXTENSION_V3 (3)
// Private, since W8 BLUE (9600+)
#define OBVERSION_DRIVER_EXTENSION_V4 (4)

// Structure version W7 (7600..7601)
#define OBVERSION_OBJECT_TYPE_V1 (1)
// Structure version W8-W10 (9200..10586)
#define OBVERSION_OBJECT_TYPE_V2 (2)
// Structure version W10RS1 (14393)
#define OBVERSION_OBJECT_TYPE_V3 (3)
// Structure version W10RS2 (15063+)
#define OBVERSION_OBJECT_TYPE_V4 (4)

// Structure version W7-W8 BLUE (7600 - 9600)
#define OBVERSION_OBJECT_SYMBOLIC_LINK_V1 (1)
// Structure version W10 TH1/TH2 (10240..10586)
#define OBVERSION_OBJECT_SYMBOLIC_LINK_V2 (2)
// Structure version W10 RS1 (14393)
#define OBVERSION_OBJECT_SYMBOLIC_LINK_V3 (3)
// Structure version W10 RS3..21H1 (15063..19044)
#define OBVERSION_OBJECT_SYMBOLIC_LINK_V4 (4)
// Structure version W11 (22000)
#define OBVERSION_OBJECT_SYMBOLIC_LINK_V5 (5)

// Structure version W7 (7600 - 7601)
#define OBVERSION_FLT_FILTER_V1 (1)
// Structure version since W8 (9200..9600)
#define OBVERSION_FLT_FILTER_V2 (2)
// Structure version since W10 (10240+)
#define OBVERSION_FLT_FILTER_V3 (3)
// Structure version since W11
#define OBVERSION_FLT_FILTER_V4 (4)
// Structure version since W11 25H2
#define OBVERSION_FLT_FILTER_V5 (5)

#define NT_REG_PREP             L"\\Registry\\Machine"
#define DRIVER_REGKEY           L"%wS\\System\\CurrentControlSet\\Services\\%wS"
#define OBTYPES_DIRECTORY       L"\\ObjectTypes"
#define OB_GLOBALROOT           L"\\GLOBAL??\\GLOBALROOT"
#define OB_GLOBALNAMESPACE      L"\\??"

#define OBJECT_SHIFT 8

#define KM_OBJECTS_ROOT_DIRECTORY  L"\\"
#define OBJ_NAME_PATH_SEPARATOR L'\\'
#define OBJ_NAME_PATH_SEPARATOR_SIZE sizeof(WCHAR)

#define OBJ_NAME_NORMALIZATION_SYMBOL L'?'

#define MM_SYSTEM_RANGE_START_7 0xFFFF080000000000
#define MM_SYSTEM_RANGE_START_8 0xFFFF800000000000

#define TEXT_SECTION ".text"
#define TEXT_SECTION_LENGTH sizeof(TEXT_SECTION)

#define PAGE_SECTION "PAGE"
#define PAGE_SECTION_LENGTH sizeof(PAGE_SECTION)

#define INIT_SECTION "INIT"
#define INIT_SECTION_LENGTH sizeof(INIT_SECTION)

typedef ULONG_PTR *PUTable;

#define OBP_ERROR_NAME_LITERAL L"<error>"
#define OBP_ERROR_NAME_LITERAL_SIZE (sizeof(OBP_ERROR_NAME_LITERAL) - sizeof(UNICODE_NULL))
#define OBP_ERROR_NONAME_LITERAL L"<noname>"
#define OBP_ERROR_NONAME_LITERAL_SIZE (sizeof(OBP_ERROR_NONAME_LITERAL) - sizeof(UNICODE_NULL))

#define WINE_DIRECTORY_QUERY_BUFFER_SIZE (64 * 1024)
#define OB_MAX_DIRECTORY_ENUM_ITER (64 * 1024)

//
// Predefined strings
//
#define OBP_ROOT            0
#define OBP_DIRECTORY       1
#define OBP_OBTYPES         2 
#define OBP_GLOBAL          3
#define OBP_GLOBALNAMESPACE 4  

//enum with information flags used by ObGetObjectHeaderOffset
typedef enum _OBJ_HEADER_INFO_FLAG {
    HeaderCreatorInfoFlag = 0x1,
    HeaderNameInfoFlag = 0x2,
    HeaderHandleInfoFlag = 0x4,
    HeaderQuotaInfoFlag = 0x8,
    HeaderProcessInfoFlag = 0x10
} OBJ_HEADER_INFO_FLAG;

typedef struct _OBHEADER_COOKIE {
    BOOLEAN Valid;
    UCHAR Value;
} OBHEADER_COOKIE, * POBHEADER_COOKIE;

typedef struct _ALPCPORT_TYPE_INDEX {
    BOOLEAN Valid;
    USHORT TypeIndex;
} ALPCPORT_TYPE_INDEX, *PALPCPORT_TYPE_INDEX;

typedef struct _EPROCESS_OFFSET {
    BOOLEAN Valid;
    ULONG OffsetValue;
} EPROCESS_OFFSET, * PEPROCESS_OFFSET;

typedef struct _KSE_ENGINE_DUMP {
    BOOLEAN Valid;
    ULONG_PTR KseAddress;
    LIST_ENTRY ShimmedDriversDumpListHead;
} KSE_ENGINE_DUMP, * PKSE_ENGINE_DUMP;

typedef struct _KLDBG_SYSTEM_ADDRESS {
    BOOLEAN Valid;
    ULONG_PTR Address;
} KLDBG_SYSTEM_ADDRESS, * PKLDBG_SYSTEM_ADDRESS;

typedef struct _OBTYPE_ENTRY {
    PUNICODE_STRING TypeName;
    ULONG PoolType;
    ULONG TypeIndex;
} OBTYPE_ENTRY, * POBTYPE_ENTRY;

typedef struct _OBTYPE_LIST {
    ULONG NumberOfTypes;
    PVOID Buffer;
    OBTYPE_ENTRY Types[ANYSIZE_ARRAY];
} OBTYPE_LIST, * POBTYPE_LIST;

//
// KLDBG private data.
//
typedef struct _KLDBGPDATA {

    FIRMWARE_TYPE FirmwareType;

    //system object header cookie (win10+)
    OBHEADER_COOKIE ObHeaderCookie;

    //address of invalid request handler
    PVOID IopInvalidDeviceRequest;

    //address of ObpPrivateNamespaceLookupTable
    PVOID PrivateNamespaceLookupTable;

    //syscall tables related info
    ULONG_PTR KeServiceDescriptorTableShadowPtr;
    KSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;

    //kernel shim engine dump and auxl ptrs
    KSE_ENGINE_DUMP KseEngineDump;

    //unloaded drivers array address
    KLDBG_SYSTEM_ADDRESS MmUnloadedDrivers; 

    //address of data in mapped ntoskrnl
    PVOID CmControlVector;

    //array of object type information
    POBTYPE_LIST ObjectTypesList;

    // ALPC Port type index
    ALPCPORT_TYPE_INDEX AlpcPortTypeIndex;

    //EPROCESS specific offsets
    EPROCESS_OFFSET PsUniqueProcessId;  
    EPROCESS_OFFSET PsProcessImageName; 

} KLDBGPDATA, * PKLDBGPDATA;

typedef struct _KLDBGCONTEXT {

    //Is user full admin
    BOOLEAN IsFullAdmin;

    //SecureBoot enabled?
    BOOLEAN IsSecureBoot;

    //VHD boot?
    BOOLEAN IsOsDiskVhd;

    //Debug privilege?
    BOOLEAN IsDebugPrivAssigned;

    union {
        struct {
            BOOLEAN Signature : 1;
            BOOLEAN ImageLoad : 1;
            BOOLEAN ExtensionPointDisable : 1;
            BOOLEAN ASLRPolicy : 1;
            BOOLEAN DynamicCode : 1;
            BOOLEAN Reserved : 3;
        } MitigationFlags;
    };

    //index of directory type and root address
    USHORT DirectoryTypeIndex;
    ULONG_PTR DirectoryRootObject;

    //ntoskrnl base and size
    PVOID NtOsBase;
    ULONG NtOsSize;

    //ntoskrnl mapped image
    PVOID NtOsImageMap;

    //system range start
    ULONG_PTR SystemRangeStart;

    //min/max user address
    ULONG_PTR MinimumUserModeAddress;
    ULONG_PTR MaximumUserModeAddress;

    PVOID NtOsSymContext;

    WDRV_CONTEXT DriverContext;

    PKLDBGPDATA Data;

} KLDBGCONTEXT, *PKLDBGCONTEXT;

extern KLDBGCONTEXT g_kdctx;
extern ULONG g_NtBuildNumber;

typedef struct _KLDBG {
    SYSDBG_COMMAND SysDbgRequest;
    PVOID Buffer;
    DWORD BufferSize;
}KLDBG, *PKLDBG;

typedef struct _OBEX_OBJECT_INFORMATION {
    ULONG_PTR HeaderAddress;
    ULONG_PTR ObjectAddress;
    OBJECT_HEADER_QUOTA_INFO ObjectQuotaHeader;
    OBJECT_HEADER ObjectHeader;
} OBEX_OBJECT_INFORMATION, * POBEX_OBJECT_INFORMATION;

typedef struct _OBJREFPNS {
    ULONG SizeOfBoundaryInformation;
    ULONG_PTR NamespaceDirectoryAddress; //point to OBJECT_DIRECTORY
    ULONG_PTR NamespaceLookupEntry; //point to OBJECT_NAMESPACE_ENTRY
} OBJREFPNS, *POBJREFPNS;

typedef struct _OBJREF {
    LIST_ENTRY ListEntry;
    UNICODE_STRING Name;
    ULONG_PTR HeaderAddress;
    ULONG_PTR ObjectAddress;
    UCHAR TypeIndex;
    WOBJ_OBJECT_TYPE ObjectTypeIndex;
    OBJREFPNS PrivateNamespace;
} OBJREF, *POBJREF;

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
#define PopCoalescingCallbackRoutineCount_V1    8
#define PopCoalescingCallbackRoutineCount_V2    32

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
    ULONG_PTR ExpCallbackListHead;
    ULONG_PTR PoCoalescingCallbacks;
    ULONG_PTR PspPicoProviderRoutines;
    ULONG_PTR KiNmiCallbackListHead;
    ULONG_PTR PspSiloMonitorList;
    ULONG_PTR EmpCallbackListHead;
    ULONG_PTR PnpDeviceClassNotifyList;
} NOTIFICATION_CALLBACKS, *PNOTIFICATION_CALLBACKS;

//
// Callbacks global.
// (defined in kldbg.c)
//
extern NOTIFICATION_CALLBACKS g_SystemCallbacks;

//
// Normalization symbol
// (defined in kldbg.c)
//
extern WCHAR g_ObNameNormalizationSymbol;

typedef struct _W32K_API_SET_LOOKUP_PATTERN {
    ULONG Size;
    PVOID Data;
} W32K_API_SET_LOOKUP_PATTERN, *PW32K_API_SET_LOOKUP_PATTERN;

typedef struct _W32K_API_SET_TABLE_HOST {
    PWCHAR HostName;
    PCHAR TableName;
    PCHAR TableSizeName;
    ULONG HostEntriesCount;
} W32K_API_SET_TABLE_HOST, * PW32K_API_SET_TABLE_HOST;

typedef struct _W32K_API_SET_TABLE_ENTRY {
    PVOID HostEntriesArray;
    W32K_API_SET_TABLE_HOST* Host;
} W32K_API_SET_TABLE_ENTRY, * PW32K_API_SET_TABLE_ENTRY;

typedef struct _W32K_API_SET_TABLE_ENTRY_V2 {
    PVOID HostEntriesArray;
    W32K_API_SET_TABLE_HOST* Host;
    W32K_API_SET_TABLE_HOST* AliasHost;
} W32K_API_SET_TABLE_ENTRY_V2, * PW32K_API_SET_TABLE_ENTRY_V2;

// return true to stop enumeration
typedef BOOL(CALLBACK* PENUMERATE_PRIVATE_NAMESPACE_CALLBACK)(
    _In_ POBJREF Entry,
    _In_opt_ PVOID Context
    );

// return true to stop enumeration
typedef BOOL(CALLBACK *PENUMERATE_BOUNDARY_DESCRIPTOR_CALLBACK)(
    _In_ OBJECT_BOUNDARY_ENTRY *Entry,
    _In_opt_ PVOID Context
    );

// return true to stop enumeration
typedef BOOL(CALLBACK* PENUMERATE_UNLOADED_DRIVERS_CALLBACK)(
    _In_ PUNLOADED_DRIVERS Entry,
    _In_opt_ PVOID Context
    );

PUNICODE_STRING ObGetPredefinedUnicodeString(
    _In_ ULONG Index);

NTSTATUS ObIsValidUnicodeString(
    _In_ PCUNICODE_STRING SourceString);

NTSTATUS ObIsValidUnicodeStringEx(
    _In_ PCUNICODE_STRING SourceString,
    _In_ DWORD dwFlags);

NTSTATUS ObCopyBoundaryDescriptor(
    _In_ _Notnull_ OBJECT_NAMESPACE_ENTRY* NamespaceLookupEntry,
    _Outptr_result_maybenull_ POBJECT_BOUNDARY_DESCRIPTOR* BoundaryDescriptor,
    _Out_opt_ PULONG BoundaryDescriptorSize);

NTSTATUS ObEnumerateBoundaryDescriptorEntries(
    _In_ OBJECT_BOUNDARY_DESCRIPTOR *BoundaryDescriptor,
    _In_ PENUMERATE_BOUNDARY_DESCRIPTOR_CALLBACK Callback,
    _In_opt_ PVOID Context);

BOOL ObEnumeratePrivateNamespaceTable(
    _In_ PENUMERATE_PRIVATE_NAMESPACE_CALLBACK Callback,
    _In_opt_ PVOID Context);

UCHAR ObDecodeTypeIndex(
    _In_ PVOID Object,
    _In_ UCHAR EncodedTypeIndex);

_Ret_maybenull_
PVOID ObDumpDirectoryObjectVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version);

_Ret_maybenull_
PVOID ObDumpObjectTypeVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version);

_Ret_maybenull_
PVOID ObDumpAlpcPortObjectVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version);

_Ret_maybenull_
PVOID ObDumpSymbolicLinkObjectVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version);

_Ret_maybenull_
PVOID ObDumpDeviceMapVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version);

_Ret_maybenull_
PVOID ObDumpDriverExtensionVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version);

_Ret_maybenull_
PVOID ObDumpFltFilterObjectVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version);

_Ret_maybenull_
POBEX_OBJECT_INFORMATION ObQueryObjectByAddress(
    _In_ ULONG_PTR ObjectAddress);

_Success_(return)
BOOL ObGetProcessImageFileName(
    _In_ ULONG_PTR ProcessObject,
    _Inout_ PUNICODE_STRING ImageFileName);

_Success_(return)
BOOL ObGetProcessId(
    _In_ ULONG_PTR ProcessObject,
    _Out_ PHANDLE UniqueProcessId);

_Success_(return)
BOOL ObHeaderToNameInfoAddress(
    _In_ UCHAR ObjectInfoMask,
    _In_ ULONG_PTR ObjectHeaderAddress,
    _Out_ PULONG_PTR HeaderInfoAddress,
    _In_ OBJ_HEADER_INFO_FLAG InfoFlag);

_Success_(return)
BOOL ObQueryNameStringFromAddress(
    _In_ HANDLE HeapHandle,
    _In_ ULONG_PTR NameInfoAddress,
    _Out_ PUNICODE_STRING NameString);

_Success_(return)
BOOL ObGetObjectAddressForDirectory(
    _In_ PUNICODE_STRING DirectoryName,
    _Out_ PULONG_PTR lpRootAddress,
    _Out_opt_ PUSHORT lpTypeIndex);

_Ret_maybenull_
POBEX_OBJECT_INFORMATION ObQueryObjectInDirectory(
    _In_ PUNICODE_STRING ObjectName,
    _In_ PUNICODE_STRING DirectoryName);

PVOID ObGetCallbackBlockRoutine(
    _In_ PVOID CallbackBlock);

_Success_(return)
BOOL ObQueryFullNamespacePath(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PUNICODE_STRING Path);

_Ret_maybenull_
POBJECT_DIRECTORY_INFORMATION ObQueryObjectDirectory(
    _In_ HANDLE DirectoryHandle,
    _Inout_ PULONG Context,
    _In_ BOOL IsWine,
    _Out_ PULONG ReturnLength);

_Ret_maybenull_
PVOID kdCreateObjectTypesList(
    VOID);

VOID kdReportErrorByFunction(
    _In_ LPCWSTR FunctionName,
    _In_ LPCWSTR ErrorMessage);

VOID kdReportReadErrorSimple(
    _In_ LPCWSTR FunctionName,
    _In_ ULONG_PTR KernelAddress,
    _In_ ULONG InputBufferLength);

VOID kdReportReadError(
    _In_ LPCWSTR FunctionName,
    _In_ ULONG_PTR KernelAddress,
    _In_ ULONG InputBufferLength,
    _In_ NTSTATUS Status,
    _In_ PIO_STATUS_BLOCK Iosb);

BOOLEAN kdIoDriverLoaded(
    VOID);

BOOLEAN kdConnectDriver(
    VOID);

PVOID kdQueryIopInvalidDeviceRequest(
    VOID);

BOOL kdFindKiServiceTable(
    _In_ ULONG_PTR MappedImageBase,
    _In_ ULONG_PTR KernelImageBase,
    _Inout_ KSERVICE_TABLE_DESCRIPTOR* ServiceTable);

BOOL kdReadSystemMemory2(
    _In_opt_ LPCWSTR CallerFunction,
    _In_ ULONG_PTR Address,
    _Inout_updates_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG NumberOfBytesRead);

#define kdReadSystemMemory(Address, Buffer, BufferSize) \
    kdReadSystemMemory2(__FUNCTIONW__, Address, Buffer, BufferSize, NULL)

#define kdReadSystemMemoryEx(Address, Buffer, BufferSize, NumberOfBytesRead) \
    kdReadSystemMemory2(NULL, Address, Buffer, BufferSize, NumberOfBytesRead)

#ifdef _DEBUG
#define kdDebugPrint(f, ...) DbgPrint(f, __VA_ARGS__)
#else
#define kdDebugPrint(f, ...) 
#endif

VOID kdInit(
    _In_ BOOLEAN IsFullAdmin);

VOID kdShutdown(
    VOID);

UCHAR kdGetInstructionLength(
    _In_ PVOID ptrCode,
    _Out_ PULONG ptrFlags);

VOID kdDestroyShimmedDriversList(
    _In_ PKSE_ENGINE_DUMP KseEngineDump);

BOOLEAN kdQueryKernelShims(
    _In_ PKLDBGCONTEXT Context,
    _In_ BOOLEAN RefreshList);

PVOID kdQueryCmControlVector(
    _In_ PKLDBGCONTEXT Context);

BOOL kdEnumerateMmUnloadedDrivers(
    _In_ PENUMERATE_UNLOADED_DRIVERS_CALLBACK Callback,
    _In_opt_ PVOID Context);

BOOLEAN kdIsSymAvailable(
    _In_opt_ SYMCONTEXT* SymContext);

BOOL kdGetFieldOffsetFromSymbol(
    _In_ KLDBGCONTEXT* Context,
    _In_ LPCWSTR SymbolName,
    _In_ LPCWSTR FieldName,
    _Out_ ULONG* Offset);

BOOL kdGetAddressFromSymbol(
    _In_ KLDBGCONTEXT* Context,
    _In_ LPCWSTR SymbolName,
    _Inout_ ULONG_PTR* Address);

BOOL kdGetAddressFromSymbolEx(
    _In_ PSYMCONTEXT SymContext,
    _In_ LPCWSTR SymbolName,
    _In_ PVOID ImageBase,
    _In_ ULONG_PTR ImageSize,
    _Inout_ ULONG_PTR* Address);

_Success_(return)
BOOLEAN kdDumpUnicodeString(
    _In_ PUNICODE_STRING InputString,
    _Out_ PUNICODE_STRING OutputString,
    _Out_opt_ PVOID* ReferenceStringBuffer,
    _In_ BOOLEAN IsKernelPointer);

USHORT kdGetAlpcPortTypeIndex();

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
    _In_opt_ PVOID Address)
{
    return IN_REGION(Address,
        g_kdctx.NtOsBase,
        g_kdctx.NtOsSize);
}

/*
* kdAddressInUserModeRange
*
* Purpose:
*
* Test if given address in user mode accessible range.
*
*/
__forceinline BOOL kdAddressInUserModeRange(
    _In_opt_ PVOID Address)
{
    return ((ULONG_PTR)Address >= g_kdctx.MinimumUserModeAddress &&
        (ULONG_PTR)Address < g_kdctx.MaximumUserModeAddress);
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
    return (ULONG_PTR)g_kdctx.NtOsBase + ((CodeBase + Offset + InstructionLength + Relative) 
        - (ULONG_PTR)g_kdctx.NtOsImageMap);
}
