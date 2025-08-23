/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2025
*
*  TITLE:       EXTRASCALLBACKS.C
*
*  VERSION:     2.09
*
*  DATE:        22 Aug 2025
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "extras.h"
#include "extras/extrasCallbacksPatterns.h"
#include "treelist/treelist.h"
#include "hde/hde64.h"
#include "ksymbols.h"

static HANDLE SysCbThreadHandle = NULL;
static FAST_EVENT SysCbInitializedEvent = FAST_EVENT_INIT;

//
// Scan limit constants.
//
#define SCAN_LIMIT_NEAR    64
#define SCAN_LIMIT_SMALL   128
#define SCAN_LIMIT_MEDIUM  256
#define SCAN_LIMIT_LARGE   512
#define SCAN_LIMIT_XLARGE  640
#define SCAN_LIMIT_XXLARGE 1024

#define CBDLG_TRACKSIZE_MIN_X 640
#define CBDLG_TRACKSIZE_MIN_Y 480

//
// Known CiCallbacks structure sizes (including marker tag), update this from time to time.
//
#define CBT_SIZE_REDSTONE5    0xD0
#define CBT_SIZE_19HX         0xD0
#define CBT_SIZE_VB_V1        0xD0
#define CBT_SIZE_VB_V2        0xE8
#define CBT_SIZE_FE_V1        0xF8
#define CBT_SIZE_CO_V1        0x100
#define CBT_SIZE_NI_V1        0xF8
#define CBT_SIZE_GE_V1        0x100 //same as CU/GA

typedef struct _CBT_MAPPING {
    ULONG Build;
    ULONG Tag;
    ULONG Size;
} CBT_MAPPING, * PCBT_MAPPING;

CBT_MAPPING g_CbtMapping[] = {
    { NT_WIN10_REDSTONE5, NTDDI_WIN10_RS5, CBT_SIZE_REDSTONE5 },
    { NT_WIN10_19H1, NTDDI_WIN10_19H1, CBT_SIZE_19HX },
    { NT_WIN10_19H2, NTDDI_WIN10_19H1, CBT_SIZE_19HX },

    { NT_WIN10_20H1, NTDDI_WIN10_VB, CBT_SIZE_VB_V1 },
    { NT_WIN10_20H1, NTDDI_WIN10_VB, CBT_SIZE_VB_V2 },

    { NT_WIN10_20H2, NTDDI_WIN10_VB, CBT_SIZE_VB_V1 },
    { NT_WIN10_20H2, NTDDI_WIN10_VB, CBT_SIZE_VB_V2 },

    { NT_WIN10_21H1, NTDDI_WIN10_VB, CBT_SIZE_VB_V1 },
    { NT_WIN10_21H1, NTDDI_WIN10_VB, CBT_SIZE_VB_V2 },

    { NT_WIN10_21H2, NTDDI_WIN10_VB, CBT_SIZE_VB_V1 },
    { NT_WIN10_21H2, NTDDI_WIN10_VB, CBT_SIZE_VB_V2 },
    { NT_WIN10_22H2, NTDDI_WIN10_VB, CBT_SIZE_VB_V2 },

    { NT_WINSRV_21H1, NTDDI_WIN10_FE, CBT_SIZE_FE_V1 },

    { NT_WIN11_21H2, NTDDI_WIN10_CO, CBT_SIZE_CO_V1 },
    { NT_WIN11_22H2, NTDDI_WIN10_NI, CBT_SIZE_NI_V1 },
    { NT_WIN11_23H2, NTDDI_WIN10_NI, CBT_SIZE_NI_V1 },
    { NT_WIN11_24H2, NTDDI_WIN11_GE, CBT_SIZE_GE_V1 },
    { NT_WIN11_25H2, NTDDI_WIN11_SE, CBT_SIZE_GE_V1 } //update on release
};

//
// CiCompareSigningLevels offset
//
#define CiCompareSigningLevels_Offset 0x40

ULONG g_CallbacksCount;

typedef struct _OBEX_CALLBACK_DISPATCH_ENTRY OBEX_CALLBACK_DISPATCH_ENTRY;

typedef ULONG_PTR(CALLBACK* POBEX_FINDCALLBACK_ROUTINE)(
    _In_ ULONG_PTR QueryFlags);

typedef VOID(CALLBACK* POBEX_DISPLAYCALLBACK_ROUTINE)(
    _In_ HWND TreeList,
    _In_ LPWSTR CallbackType,
    _In_ ULONG_PTR KernelVariableAddress,
    _In_ PRTL_PROCESS_MODULES Modules);

typedef NTSTATUS(CALLBACK* POBEX_QUERYCALLBACK_ROUTINE)(
    _In_ ULONG_PTR QueryFlags,
    _In_ POBEX_DISPLAYCALLBACK_ROUTINE DisplayRoutine,
    _In_opt_ POBEX_FINDCALLBACK_ROUTINE FindRoutine,
    _In_opt_ LPWSTR CallbackType,
    _In_ HWND TreeList,
    _In_ PRTL_PROCESS_MODULES Modules,
    _Inout_opt_ PULONG_PTR SystemCallbacksRef);

#define OBEX_FINDCALLBACK_ROUTINE(n) ULONG_PTR CALLBACK n(    \
    _In_ ULONG_PTR QueryFlags)

#define OBEX_QUERYCALLBACK_ROUTINE(n) NTSTATUS CALLBACK n(    \
    _In_ ULONG_PTR QueryFlags,                                \
    _In_ POBEX_DISPLAYCALLBACK_ROUTINE DisplayRoutine,        \
    _In_opt_ POBEX_FINDCALLBACK_ROUTINE FindRoutine,          \
    _In_opt_ LPWSTR CallbackType,                             \
    _In_ HWND TreeList,                                       \
    _In_ PRTL_PROCESS_MODULES Modules,                        \
    _Inout_opt_ PULONG_PTR SystemCallbacksRef)

#define OBEX_DISPLAYCALLBACK_ROUTINE(n) VOID CALLBACK n(     \
    _In_ HWND TreeList,                               \
    _In_ LPWSTR CallbackType,                         \
    _In_ ULONG_PTR KernelVariableAddress,             \
    _In_ PRTL_PROCESS_MODULES Modules)

//
// Generic upper bound to protect against corrupted kernel lists/arrays causing infinite loops.
//
#define MAX_LIST_ITERATIONS 0x10000

#define LIST_ITERATION_GUARD(it) \
    if ((it)++ >= MAX_LIST_ITERATIONS) { \
        logAdd(EntryTypeWarning, TEXT("List traversal limit reached")); \
        break; \
    }

//
// Returns TRUE if next Flink assigned, FALSE if not in kernel mode address range.
// Valid kernel pointers must be >= g_kdctx.SystemRangeStart.
//
#define SET_NEXT_FLINK_CHECK(ListEntryVar, NextFlinkExpr, MsgLiteral) \
    (((ULONG_PTR)(NextFlinkExpr) < g_kdctx.SystemRangeStart) ? \
        (logAdd(EntryTypeWarning, TEXT(MsgLiteral)), FALSE) : \
        ((ListEntryVar).Flink = (NextFlinkExpr), TRUE))

typedef struct _OBEX_CALLBACK_DISPATCH_ENTRY {
    ULONG_PTR QueryFlags;
    LPWSTR CallbackType;
    POBEX_QUERYCALLBACK_ROUTINE QueryRoutine;
    POBEX_DISPLAYCALLBACK_ROUTINE DisplayRoutine;
    POBEX_FINDCALLBACK_ROUTINE FindRoutine;
    PULONG_PTR SystemCallbacksRef;
} OBEX_CALLBACK_DISPATCH_ENTRY, * POBEX_CALLBACK_DISPATCH_ENTRY;

OBEX_QUERYCALLBACK_ROUTINE(QueryIopFsListsCallbacks);
OBEX_QUERYCALLBACK_ROUTINE(QueryCallbackGeneric);

OBEX_DISPLAYCALLBACK_ROUTINE(DumpPsCallbacks);
OBEX_DISPLAYCALLBACK_ROUTINE(DumpKeBugCheckCallbacks);
OBEX_DISPLAYCALLBACK_ROUTINE(DumpKeBugCheckReasonCallbacks);
OBEX_DISPLAYCALLBACK_ROUTINE(DumpCmCallbacks);
OBEX_DISPLAYCALLBACK_ROUTINE(DumpIoCallbacks);
OBEX_DISPLAYCALLBACK_ROUTINE(DumpObCallbacks);
OBEX_DISPLAYCALLBACK_ROUTINE(DumpSeFileSystemCallbacks);
OBEX_DISPLAYCALLBACK_ROUTINE(DumpPoCallbacks);
OBEX_DISPLAYCALLBACK_ROUTINE(DumpDbgPrintCallbacks);
OBEX_DISPLAYCALLBACK_ROUTINE(DumpIoFsRegistrationCallbacks);
OBEX_DISPLAYCALLBACK_ROUTINE(DumpIoFileSystemCallbacks);
OBEX_DISPLAYCALLBACK_ROUTINE(DumpDbgkLCallbacks);
OBEX_DISPLAYCALLBACK_ROUTINE(DumpPsAltSystemCallHandlers);
OBEX_DISPLAYCALLBACK_ROUTINE(DumpCiCallbacks);
OBEX_DISPLAYCALLBACK_ROUTINE(DumpExHostCallbacks);
OBEX_DISPLAYCALLBACK_ROUTINE(DumpExpCallbackListCallbacks);
OBEX_DISPLAYCALLBACK_ROUTINE(DumpPoCoalescingCallbacks);
OBEX_DISPLAYCALLBACK_ROUTINE(DumpPspPicoProviderRoutines);
OBEX_DISPLAYCALLBACK_ROUTINE(DumpKiNmiCallbackListHead);
OBEX_DISPLAYCALLBACK_ROUTINE(DumpPspSiloMonitorList);
OBEX_DISPLAYCALLBACK_ROUTINE(DumpEmpCallbackListHead);
OBEX_DISPLAYCALLBACK_ROUTINE(DumpPnpDeviceClassNotifyList);

OBEX_FINDCALLBACK_ROUTINE(FindPspCreateProcessNotifyRoutine);
OBEX_FINDCALLBACK_ROUTINE(FindPspCreateThreadNotifyRoutine);
OBEX_FINDCALLBACK_ROUTINE(FindPspLoadImageNotifyRoutine);
OBEX_FINDCALLBACK_ROUTINE(FindKeBugCheckCallbackHead);
OBEX_FINDCALLBACK_ROUTINE(FindKeBugCheckReasonCallbackHead);
OBEX_FINDCALLBACK_ROUTINE(FindCmCallbackHead);
OBEX_FINDCALLBACK_ROUTINE(FindIopNotifyShutdownQueueHeadHead);
OBEX_FINDCALLBACK_ROUTINE(FindPopRegisteredPowerSettingCallbacks);
OBEX_FINDCALLBACK_ROUTINE(FindSeFileSystemNotifyRoutinesHead);
OBEX_FINDCALLBACK_ROUTINE(FindIopFsNotifyChangeQueueHead);
OBEX_FINDCALLBACK_ROUTINE(FindObjectTypeCallbackListHeadByType);
OBEX_FINDCALLBACK_ROUTINE(FindRtlpDebugPrintCallbackList);
OBEX_FINDCALLBACK_ROUTINE(FindDbgkLmdCallbacks);
OBEX_FINDCALLBACK_ROUTINE(FindPsAltSystemCallHandlers);
OBEX_FINDCALLBACK_ROUTINE(FindCiCallbacksEx);
OBEX_FINDCALLBACK_ROUTINE(FindCiCallbacks);
OBEX_FINDCALLBACK_ROUTINE(FindExHostCallbacks);
OBEX_FINDCALLBACK_ROUTINE(FindExpCallbackListHead);
OBEX_FINDCALLBACK_ROUTINE(FindPoCoalescingCallbacks);
OBEX_FINDCALLBACK_ROUTINE(FindPspPicoProviderRoutines);
OBEX_FINDCALLBACK_ROUTINE(FindKiNmiCallbackListHead);
OBEX_FINDCALLBACK_ROUTINE(FindPspSiloMonitorList);
OBEX_FINDCALLBACK_ROUTINE(FindEmpCallbackListHead);
OBEX_FINDCALLBACK_ROUTINE(FindPnpDeviceClassNotifyList);

OBEX_CALLBACK_DISPATCH_ENTRY g_CallbacksDispatchTable[] = {
    {
        0, L"CreateProcess",
        QueryCallbackGeneric, DumpPsCallbacks, FindPspCreateProcessNotifyRoutine,
        &g_SystemCallbacks.PspCreateProcessNotifyRoutine
    },
    {
        0, L"CreateThread",
        QueryCallbackGeneric, DumpPsCallbacks, FindPspCreateThreadNotifyRoutine,
        &g_SystemCallbacks.PspCreateThreadNotifyRoutine
    },
    {
        0, L"LoadImage",
        QueryCallbackGeneric, DumpPsCallbacks, FindPspLoadImageNotifyRoutine,
        &g_SystemCallbacks.PspLoadImageNotifyRoutine
    },
    {
        0, L"KeBugCheck",
        QueryCallbackGeneric, DumpKeBugCheckCallbacks, FindKeBugCheckCallbackHead,
        &g_SystemCallbacks.KeBugCheckCallbackHead
    },
    {
        0, L"KeBugCheckReason",
        QueryCallbackGeneric, DumpKeBugCheckReasonCallbacks, FindKeBugCheckReasonCallbackHead,
        &g_SystemCallbacks.KeBugCheckReasonCallbackHead
    },
    {
        0, L"CmRegistry",
        QueryCallbackGeneric, DumpCmCallbacks, FindCmCallbackHead,
        &g_SystemCallbacks.CmCallbackListHead
    },
    {
        0, L"Shutdown",
        QueryCallbackGeneric, DumpIoCallbacks, FindIopNotifyShutdownQueueHeadHead,
        &g_SystemCallbacks.IopNotifyShutdownQueueHead
    },
    {
        1, L"LastChanceShutdown",
        QueryCallbackGeneric, DumpIoCallbacks, FindIopNotifyShutdownQueueHeadHead,
        &g_SystemCallbacks.IopNotifyLastChanceShutdownQueueHead
    },
    {
        ObjectTypeProcess, L"ObProcess",
        QueryCallbackGeneric, DumpObCallbacks, FindObjectTypeCallbackListHeadByType,
        &g_SystemCallbacks.ObProcessCallbackHead },
    {
        ObjectTypeThread, L"ObThread",
        QueryCallbackGeneric, DumpObCallbacks, FindObjectTypeCallbackListHeadByType,
        &g_SystemCallbacks.ObThreadCallbackHead
    },
    {
        ObjectTypeDesktop, L"ObDesktop",
        QueryCallbackGeneric, DumpObCallbacks, FindObjectTypeCallbackListHeadByType,
        &g_SystemCallbacks.ObDesktopCallbackHead
    },
    {
        0, L"SeFileSystem",
        QueryCallbackGeneric, DumpSeFileSystemCallbacks, FindSeFileSystemNotifyRoutinesHead,
        &g_SystemCallbacks.SeFileSystemNotifyRoutinesHead
    },
    {
        1, L"SeFileSystemEx",
        QueryCallbackGeneric, DumpSeFileSystemCallbacks, FindSeFileSystemNotifyRoutinesHead,
        &g_SystemCallbacks.SeFileSystemNotifyRoutinesExHead
    },
    {
        0, L"PowerSettings",
        QueryCallbackGeneric, DumpPoCallbacks, FindPopRegisteredPowerSettingCallbacks,
        &g_SystemCallbacks.PopRegisteredPowerSettingCallbacks
    },
    {
        0, L"DebugPrint",
        QueryCallbackGeneric, DumpDbgPrintCallbacks, FindRtlpDebugPrintCallbackList,
        &g_SystemCallbacks.RtlpDebugPrintCallbackList
    },
    {
        0, L"IoFsRegistration",
        QueryCallbackGeneric, DumpIoFsRegistrationCallbacks, FindIopFsNotifyChangeQueueHead,
        &g_SystemCallbacks.IopFsNotifyChangeQueueHead
    },
    {
        0, L"IoFileSystemType",
        QueryIopFsListsCallbacks, DumpIoFileSystemCallbacks, NULL,
        NULL
    },
    {
        0, L"DbgkLmd",
        QueryCallbackGeneric, DumpDbgkLCallbacks, FindDbgkLmdCallbacks,
        &g_SystemCallbacks.DbgkLmdCallbacks
    },
    {
        0, L"AltSystemCall",
        QueryCallbackGeneric, DumpPsAltSystemCallHandlers, FindPsAltSystemCallHandlers,
        &g_SystemCallbacks.PsAltSystemCallHandlers
    },
    {
        0, L"CiCallbacks",
        QueryCallbackGeneric, DumpCiCallbacks, FindCiCallbacks,
        &g_SystemCallbacks.CiCallbacks
    },
    {
        0, L"ExHostCallbacks",
        QueryCallbackGeneric, DumpExHostCallbacks, FindExHostCallbacks,
        &g_SystemCallbacks.ExpHostListHead
    },
    {
        0, L"ExpCallbackList",
        QueryCallbackGeneric, DumpExpCallbackListCallbacks, FindExpCallbackListHead,
        &g_SystemCallbacks.ExpCallbackListHead
    },
    {
        0, L"PowerCoalescing",
        QueryCallbackGeneric, DumpPoCoalescingCallbacks, FindPoCoalescingCallbacks,
        &g_SystemCallbacks.PoCoalescingCallbacks
    },
    {
        0, L"PicoProviderRoutines",
        QueryCallbackGeneric, DumpPspPicoProviderRoutines, FindPspPicoProviderRoutines,
        &g_SystemCallbacks.PspPicoProviderRoutines
    },
    {
        0, L"NmiCallbacks",
        QueryCallbackGeneric, DumpKiNmiCallbackListHead, FindKiNmiCallbackListHead,
        &g_SystemCallbacks.KiNmiCallbackListHead
    },
    {
        0, L"SiloMonitor",
        QueryCallbackGeneric, DumpPspSiloMonitorList, FindPspSiloMonitorList,
        &g_SystemCallbacks.PspSiloMonitorList
    },
    {
        0, L"EmpCallbacks",
        QueryCallbackGeneric, DumpEmpCallbackListHead, FindEmpCallbackListHead,
        &g_SystemCallbacks.EmpCallbackListHead
    },
    {
        0, L"PnpCallbacks",
        QueryCallbackGeneric, DumpPnpDeviceClassNotifyList, FindPnpDeviceClassNotifyList,
        &g_SystemCallbacks.PnpDeviceClassNotifyList
    }
};

//
// All available names for CiCallbacks. Unknown is expected to be XBOX callback.
//
static const WCHAR* CiCallbackNames[] = {
    L"CiSetFileCache", //0
    L"CiGetFileCache", //1
    L"CiQueryInformation", //2
    L"CiValidateImageHeader", //3
    L"CiValidateImageData", //4
    L"CiHashMemory", //5
    L"KappxIsPackageFile", //6
    L"CiCompareSigningLevels", //7
    L"CiValidateFileAsImageType", //8
    L"CiRegisterSigningInformation", //9
    L"CiUnregisterSigningInformation",//10
    L"CiInitializePolicy",//11
    L"CiReleaseContext",//12
    L"XciUnknownCallback",//13 XBOX
    L"CiGetStrongImageReference", //14
    L"CiHvciSetImageBaseAddress", //15
    L"CipQueryPolicyInformation", //16
    L"CiValidateDynamicCodePages", //17
    L"CiQuerySecurityPolicy", //18
    L"CiRevalidateImage", //19
    L"CiSetInformation",//20
    L"CiSetInformationProcess", //21
    L"CiGetBuildExpiryTime", //22
    L"CiCheckProcessDebugAccessPolicy", //23
    L"SIPolicyQueryPolicyInformation",//24
    L"SIPolicyQuerySecurityPolicy",//25
    L"CiSetUnlockInformation",//26
    L"CiGetCodeIntegrityOriginClaimForFileObject",//27
    L"CiDeleteCodeIntegrityOriginClaimMembers", //28
    L"CiDeleteCodeIntegrityOriginClaimForFileObject",//29
    L"CiHvciReportMmIncompatibility",//30
    L"CiCompareExistingSePool",//31
    L"CiSetCachedOriginClaim",//32,
    L"CipIsDeveloperModeEnabled"//33
};

typedef enum _CiNameIds {
    Id_CiSetFileCache = 0,
    Id_CiGetFileCache,
    Id_CiQueryInformation,
    Id_CiValidateImageHeader,
    Id_CiValidateImageData,
    Id_CiHashMemory,
    Id_KappxIsPackageFile,
    Id_CiCompareSigningLevels,
    Id_CiValidateFileAsImageType,
    Id_CiRegisterSigningInformation,
    Id_CiUnregisterSigningInformation,
    Id_CiInitializePolicy,
    Id_CiReleaseContext,
    Id_XciUnknownCallback,
    Id_CiGetStrongImageReference,
    Id_CiHvciSetImageBaseAddress,
    Id_CipQueryPolicyInformation,
    Id_CiValidateDynamicCodePages,
    Id_CiQuerySecurityPolicy,
    Id_CiRevalidateImage,
    Id_CiSetInformation,
    Id_CiSetInformationProcess,
    Id_CiGetBuildExpiryTime,
    Id_CiCheckProcessDebugAccessPolicy,
    Id_SIPolicyQueryPolicyInformation,
    Id_SIPolicyQuerySecurityPolicy,
    Id_CiSetUnlockInformation,
    Id_CiGetCodeIntegrityOriginClaimForFileObject,
    Id_CiDeleteCodeIntegrityOriginClaimMembers,
    Id_CiDeleteCodeIntegrityOriginClaimForFileObject,
    Id_CiHvciReportMmIncompatibility,
    Id_CiCompareExistingSePool,
    Id_CiSetCachedOriginClaim,
    Id_CipIsDeveloperModeEnabled
} CiNameIds;

//
// Callback name index arrays
//

//
// Windows 7
//
static const BYTE CiCallbackIndexes_Win7[] = {
    Id_CiValidateImageHeader,
    Id_CiValidateImageData,
    Id_CiQueryInformation
};

//
// Windows 8
//
static const BYTE CiCallbackIndexes_Win8[] = {
    Id_CiSetFileCache,
    Id_CiGetFileCache,
    Id_CiQueryInformation,
    Id_CiValidateImageHeader,
    Id_CiValidateImageData,
    Id_CiHashMemory,
    Id_KappxIsPackageFile
};

//
// Windows 8.1
//
static const BYTE CiCallbackIndexes_Win81[] = {
    Id_CiSetFileCache,
    Id_CiGetFileCache,
    Id_CiQueryInformation,
    Id_CiValidateImageHeader,
    Id_CiValidateImageData,
    Id_CiHashMemory,
    Id_KappxIsPackageFile,
    Id_CiCompareSigningLevels,
    Id_CiValidateFileAsImageType,
    Id_CiRegisterSigningInformation,
    Id_CiUnregisterSigningInformation,
    Id_CiInitializePolicy
};

//
// Windows 10 TH1/TH2
//
static const BYTE CiCallbackIndexes_Win10Threshold[] = {
    Id_CiSetFileCache,
    Id_CiGetFileCache,
    Id_CiQueryInformation,
    Id_CiValidateImageHeader,
    Id_CiValidateImageData,
    Id_CiHashMemory,
    Id_KappxIsPackageFile,
    Id_CiCompareSigningLevels,
    Id_CiValidateFileAsImageType,
    Id_CiRegisterSigningInformation,
    Id_CiUnregisterSigningInformation,
    Id_CiInitializePolicy,
    Id_CiReleaseContext,
    Id_XciUnknownCallback,
    Id_CiGetStrongImageReference,
    Id_CiHvciSetImageBaseAddress,
    Id_SIPolicyQueryPolicyInformation,
    Id_CiValidateDynamicCodePages
};

//
// Windows 10 RS1
//
static const BYTE CiCallbackIndexes_Win10RS1[] = {
    Id_CiSetFileCache,
    Id_CiGetFileCache,
    Id_CiQueryInformation,
    Id_CiValidateImageHeader,
    Id_CiValidateImageData,
    Id_CiHashMemory,
    Id_KappxIsPackageFile,
    Id_CiCompareSigningLevels,
    Id_CiValidateFileAsImageType,
    Id_CiRegisterSigningInformation,
    Id_CiUnregisterSigningInformation,
    Id_CiInitializePolicy,
    Id_CiReleaseContext,
    Id_XciUnknownCallback,
    Id_CiGetStrongImageReference,
    Id_CiHvciSetImageBaseAddress,
    Id_SIPolicyQueryPolicyInformation,
    Id_CiValidateDynamicCodePages,
    Id_SIPolicyQuerySecurityPolicy,
    Id_CiRevalidateImage
};

//
// Windows 10 RS2
//
static const BYTE CiCallbackIndexes_Win10RS2[] = {
    Id_CiSetFileCache,
    Id_CiGetFileCache,
    Id_CiQueryInformation,
    Id_CiValidateImageHeader,
    Id_CiValidateImageData,
    Id_CiHashMemory,
    Id_KappxIsPackageFile,
    Id_CiCompareSigningLevels,
    Id_CiValidateFileAsImageType,
    Id_CiRegisterSigningInformation,
    Id_CiUnregisterSigningInformation,
    Id_CiInitializePolicy,
    Id_CiReleaseContext,
    Id_XciUnknownCallback,
    Id_CiGetStrongImageReference,
    Id_CiHvciSetImageBaseAddress,
    Id_CipQueryPolicyInformation,
    Id_CiValidateDynamicCodePages,
    Id_SIPolicyQuerySecurityPolicy,
    Id_CiRevalidateImage,
    Id_CiSetUnlockInformation,
    Id_CiGetBuildExpiryTime
};

//
// Windows 10 RS3
//
static const BYTE CiCallbackIndexes_Win10RS3[] = {
    Id_CiSetFileCache,
    Id_CiGetFileCache,
    Id_CiQueryInformation,
    Id_CiValidateImageHeader,
    Id_CiValidateImageData,
    Id_CiHashMemory,
    Id_KappxIsPackageFile,
    Id_CiCompareSigningLevels,
    Id_CiValidateFileAsImageType,
    Id_CiRegisterSigningInformation,
    Id_CiUnregisterSigningInformation,
    Id_CiInitializePolicy,
    Id_CiReleaseContext,
    Id_XciUnknownCallback,
    Id_CiGetStrongImageReference,
    Id_CiHvciSetImageBaseAddress,
    Id_CipQueryPolicyInformation,
    Id_CiValidateDynamicCodePages,
    Id_CiQuerySecurityPolicy,
    Id_CiRevalidateImage,
    Id_CiSetInformation,
    Id_CiGetBuildExpiryTime
};

//
// Windows 10 RS4-21H2
//
static const BYTE CiCallbackIndexes_Win10RS4_21H2[] = {
    Id_CiSetFileCache,
    Id_CiGetFileCache,
    Id_CiQueryInformation,
    Id_CiValidateImageHeader,
    Id_CiValidateImageData,
    Id_CiHashMemory,
    Id_KappxIsPackageFile,
    Id_CiCompareSigningLevels,
    Id_CiValidateFileAsImageType,
    Id_CiRegisterSigningInformation,
    Id_CiUnregisterSigningInformation,
    Id_CiInitializePolicy,
    Id_CiReleaseContext,
    Id_XciUnknownCallback,
    Id_CiGetStrongImageReference,
    Id_CiHvciSetImageBaseAddress,
    Id_CipQueryPolicyInformation,
    Id_CiValidateDynamicCodePages,
    Id_CiQuerySecurityPolicy,
    Id_CiRevalidateImage,
    Id_CiSetInformation,
    Id_CiSetInformationProcess,
    Id_CiGetBuildExpiryTime,
    Id_CiCheckProcessDebugAccessPolicy
};

//
// Windows 10 21H2 updated / 22H2
//
static const BYTE CiCallbackIndexes_Win1021H2_V2[] = {
    Id_CiSetFileCache,
    Id_CiGetFileCache,
    Id_CiQueryInformation,
    Id_CiValidateImageHeader,
    Id_CiValidateImageData,
    Id_CiHashMemory,
    Id_KappxIsPackageFile,
    Id_CiCompareSigningLevels,
    Id_CiValidateFileAsImageType,
    Id_CiRegisterSigningInformation,
    Id_CiUnregisterSigningInformation,
    Id_CiInitializePolicy,
    Id_CiReleaseContext,
    Id_XciUnknownCallback,
    Id_CiGetStrongImageReference,
    Id_CiHvciSetImageBaseAddress,
    Id_CipQueryPolicyInformation,
    Id_CiValidateDynamicCodePages,
    Id_CiQuerySecurityPolicy,
    Id_CiRevalidateImage,
    Id_CiSetInformation,
    Id_CiSetInformationProcess,
    Id_CiGetBuildExpiryTime,
    Id_CiCheckProcessDebugAccessPolicy,
    Id_CiGetCodeIntegrityOriginClaimForFileObject,
    Id_CiDeleteCodeIntegrityOriginClaimMembers,
    Id_CiDeleteCodeIntegrityOriginClaimForFileObject
};

//
// Windows Server 2022
//
static const BYTE CiCallbacksIndexes_WinSrv21H2[] = {
    Id_CiSetFileCache,
    Id_CiGetFileCache,
    Id_CiQueryInformation,
    Id_CiValidateImageHeader,
    Id_CiValidateImageData,
    Id_CiHashMemory,
    Id_KappxIsPackageFile,
    Id_CiCompareSigningLevels,
    Id_CiValidateFileAsImageType,
    Id_CiRegisterSigningInformation,
    Id_CiUnregisterSigningInformation,
    Id_CiInitializePolicy,
    Id_CiReleaseContext,
    Id_XciUnknownCallback,
    Id_CiGetStrongImageReference,
    Id_CiHvciSetImageBaseAddress,
    Id_CipQueryPolicyInformation,
    Id_CiValidateDynamicCodePages,
    Id_CiQuerySecurityPolicy,
    Id_CiRevalidateImage,
    Id_CiSetInformation,
    Id_CiSetInformationProcess,
    Id_CiGetBuildExpiryTime,
    Id_CiCheckProcessDebugAccessPolicy,
    Id_CiGetCodeIntegrityOriginClaimForFileObject,
    Id_CiDeleteCodeIntegrityOriginClaimMembers,
    Id_CiDeleteCodeIntegrityOriginClaimForFileObject,
    Id_CiHvciReportMmIncompatibility,
    Id_CiCompareExistingSePool
};

//
// Windows 11 21H2
//
static const BYTE CiCallbackIndexes_Win11_21H1[] = {
    Id_CiSetFileCache,
    Id_CiGetFileCache,
    Id_CiQueryInformation,
    Id_CiValidateImageHeader,
    Id_CiValidateImageData,
    Id_CiHashMemory,
    Id_KappxIsPackageFile,
    Id_CiCompareSigningLevels,
    Id_CiValidateFileAsImageType,
    Id_CiRegisterSigningInformation,
    Id_CiUnregisterSigningInformation,
    Id_CiInitializePolicy,
    Id_CiReleaseContext,
    Id_XciUnknownCallback,
    Id_CiGetStrongImageReference,
    Id_CiHvciSetImageBaseAddress,
    Id_CipQueryPolicyInformation,
    Id_CiValidateDynamicCodePages,
    Id_CiQuerySecurityPolicy,
    Id_CiRevalidateImage,
    Id_CiSetInformation,
    Id_CiSetInformationProcess,
    Id_CiGetBuildExpiryTime,
    Id_CiCheckProcessDebugAccessPolicy,
    Id_CiGetCodeIntegrityOriginClaimForFileObject,
    Id_CiDeleteCodeIntegrityOriginClaimMembers,
    Id_CiDeleteCodeIntegrityOriginClaimForFileObject,
    Id_CiHvciReportMmIncompatibility,
    Id_CiCompareExistingSePool,
    Id_CiSetCachedOriginClaim
};

//
// Windows 11 22H2 - 25H2
//
static const BYTE CiCallbackIndexes_Win11_22H2_25H2[] = {
    Id_CiSetFileCache,
    Id_CiGetFileCache,
    Id_CiQueryInformation,
    Id_CiValidateImageHeader,
    Id_CiValidateImageData,
    Id_CiHashMemory,
    Id_KappxIsPackageFile,
    Id_CiCompareSigningLevels,
    Id_CiValidateFileAsImageType,
    Id_CiRegisterSigningInformation,
    Id_CiUnregisterSigningInformation,
    Id_CiInitializePolicy,
    Id_CiReleaseContext,
    Id_XciUnknownCallback,
    Id_CiGetStrongImageReference,
    Id_CiHvciSetImageBaseAddress,
    Id_CipQueryPolicyInformation,
    Id_CiQuerySecurityPolicy,
    Id_CiRevalidateImage,
    Id_CiSetInformation,
    Id_CiSetInformationProcess,
    Id_CiGetBuildExpiryTime,
    Id_CiCheckProcessDebugAccessPolicy,
    Id_CiGetCodeIntegrityOriginClaimForFileObject,
    Id_CiDeleteCodeIntegrityOriginClaimMembers,
    Id_CiDeleteCodeIntegrityOriginClaimForFileObject,
    Id_CiHvciReportMmIncompatibility,
    Id_CiCompareExistingSePool,
    Id_CiSetCachedOriginClaim,
    Id_CipIsDeveloperModeEnabled
};

typedef struct _CI_INDEX_MAP {
    ULONG MinBuild;
    ULONG MaxBuild;
    ULONG RequiredSize; // 0 = any size
    const BYTE* Table;
    ULONG Count;
} CI_INDEX_MAP, * PCI_INDEX_MAP;

static CI_INDEX_MAP g_CiIndexMap[] = {
    // Windows 7 (RTM..SP1)
    { NT_WIN7_RTM, NT_WIN7_SP1, 0, CiCallbackIndexes_Win7, RTL_NUMBER_OF(CiCallbackIndexes_Win7) },

    // Windows 8 / 8.1
    { NT_WIN8_RTM, NT_WIN8_RTM, 0, CiCallbackIndexes_Win8,  RTL_NUMBER_OF(CiCallbackIndexes_Win8)  },
    { NT_WIN8_BLUE, NT_WIN8_BLUE, 0, CiCallbackIndexes_Win81, RTL_NUMBER_OF(CiCallbackIndexes_Win81) },

    // TH1 / TH2
    { NT_WIN10_THRESHOLD1, NT_WIN10_THRESHOLD2, 0, CiCallbackIndexes_Win10Threshold, RTL_NUMBER_OF(CiCallbackIndexes_Win10Threshold) },

    // RS1
    { NT_WIN10_REDSTONE1, NT_WIN10_REDSTONE1, 0, CiCallbackIndexes_Win10RS1, RTL_NUMBER_OF(CiCallbackIndexes_Win10RS1) },

    // RS2
    { NT_WIN10_REDSTONE2, NT_WIN10_REDSTONE2, 0, CiCallbackIndexes_Win10RS2, RTL_NUMBER_OF(CiCallbackIndexes_Win10RS2) },

    // RS3
    { NT_WIN10_REDSTONE3, NT_WIN10_REDSTONE3, 0, CiCallbackIndexes_Win10RS3, RTL_NUMBER_OF(CiCallbackIndexes_Win10RS3) },

    // RS4 .. 19H2 (original table)
    { NT_WIN10_REDSTONE4, NT_WIN10_19H2, 0, CiCallbackIndexes_Win10RS4_21H2, RTL_NUMBER_OF(CiCallbackIndexes_Win10RS4_21H2) },

    // 20H1 .. 22H2 size-dependent (put size-specific first)
    { NT_WIN10_20H1, NT_WIN10_22H2, CBT_SIZE_VB_V2, CiCallbackIndexes_Win1021H2_V2, RTL_NUMBER_OF(CiCallbackIndexes_Win1021H2_V2) },
    { NT_WIN10_20H1, NT_WIN10_22H2, 0,             CiCallbackIndexes_Win10RS4_21H2, RTL_NUMBER_OF(CiCallbackIndexes_Win10RS4_21H2) },

    // Windows Server 2022 (same build band as 21H2 server)
    { NT_WINSRV_21H1, NT_WINSRV_21H1, 0, CiCallbacksIndexes_WinSrv21H2, RTL_NUMBER_OF(CiCallbacksIndexes_WinSrv21H2) },

    // Windows 11 21H2
    { NT_WIN11_21H2, NT_WIN11_21H2, 0, CiCallbackIndexes_Win11_21H1, RTL_NUMBER_OF(CiCallbackIndexes_Win11_21H1) },

    // Windows 11 22H2 .. 25H2
    { NT_WIN11_22H2, NT_WIN11_25H2, 0, CiCallbackIndexes_Win11_22H2_25H2, RTL_NUMBER_OF(CiCallbackIndexes_Win11_22H2_25H2) }
};

/*
* GetCiRoutineNameFromIndex
*
* Purpose:
*
* Return CiCallback name by index
*
*/
LPWSTR GetCiRoutineNameFromIndex(
    _In_ ULONG Index,
    _In_ ULONG_PTR CiCallbacksSize
)
{
    ULONG i, nameIndex;
    CI_INDEX_MAP* map = NULL;
    const BYTE* indexes;

    for (i = 0; i < RTL_NUMBER_OF(g_CiIndexMap); i++) {

        if ((g_NtBuildNumber >= g_CiIndexMap[i].MinBuild) &&
            (g_NtBuildNumber <= g_CiIndexMap[i].MaxBuild))
        {
            if (g_CiIndexMap[i].RequiredSize == 0 ||
                g_CiIndexMap[i].RequiredSize == CiCallbacksSize)
            {
                map = &g_CiIndexMap[i];
                break;
            }
        }
    }

    if (map == NULL)
        return T_CannotQuery;

    if (Index >= map->Count)
        return T_CannotQuery;

    indexes = map->Table;
    nameIndex = indexes[Index];

    if (nameIndex >= RTL_NUMBER_OF(CiCallbackNames))
        return T_CannotQuery;

    return (LPWSTR)CiCallbackNames[nameIndex];
}

/*
* ComputeAddressInsideNtOs
*
* Purpose:
*
* Returns kernel variable computed address within ntoskrnl image or zero in case of error.
*
*/
ULONG_PTR ComputeAddressInsideNtOs(
    _In_ ULONG_PTR CodeBase,
    _In_ ULONG_PTR Offset,
    _In_ ULONG InstructionLength,
    _In_ LONG Relative
)
{
    ULONG_PTR address;

    if (Relative == 0)
        return 0;

    address = kdAdjustAddressToNtOsBase(CodeBase, Offset, InstructionLength, Relative);

    if (!IN_REGION(address,
        g_kdctx.NtOsBase,
        g_kdctx.NtOsSize))
    {
        return 0;
    }

    return address;
}

/*
* FindCiCallbacksEx
*
* Purpose:
*
* Locate address of ntoskrnl SeCiCallbacks structure for Redstone5+.
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindCiCallbacksEx)
{
    BOOL bFound = FALSE;
    PBYTE ptrCode;
    ULONG_PTR cbSize = 0, ulTag = 0, Index = 0, kvarAddress = 0;
    LONG Rel = 0;
    hde64s hs;

    UNREFERENCED_PARAMETER(QueryFlags);

    //
    // NtCompareSigningLevels added in REDSTONE2 (15063)
    // It is a call to SeCiCallbacks[CiCompareSigningLevelsId]
    // Before REDSTONE5 it is called via wrapper SeCompareSigningLevels
    // From REDSTONE6 and above it is sometimes inlined.
    //

    ptrCode = (PBYTE)GetProcAddress((HMODULE)g_kdctx.NtOsImageMap,
        "SeCompareSigningLevels");

    if (ptrCode == NULL) {
        ptrCode = (PBYTE)GetProcAddress((HMODULE)g_kdctx.NtOsImageMap,
            "NtCompareSigningLevels");
    }

    if (ptrCode == NULL) {
        logAdd(EntryTypeWarning, TEXT("CompareSigningLevels ptr is not found"));
        return 0;
    }

    do {
        hde64_disasm((void*)(ptrCode + Index), &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == 7) { //mov     r8, cs:CiCompareSigningLevels
            if ((ptrCode[Index] == 0x4C) &&
                (ptrCode[Index + 1] == 0x8B) &&
                (ptrCode[Index + 2] == 0x05))
            {
                Rel = *(PLONG)(ptrCode + Index + 3);
                break;
            }
        }

        Index += hs.len;

    } while (Index < SCAN_LIMIT_NEAR);

    if (Rel == 0) {
        logAdd(EntryTypeWarning, TEXT("CiCallbacks relative offset is not found"));
        return 0;
    }

    kvarAddress = kdAdjustAddressToNtOsBase((ULONG_PTR)ptrCode, Index, hs.len, Rel);
    kvarAddress -= CiCompareSigningLevels_Offset;

    //
    // Read head - structure size.
    //
    if (!kdReadSystemMemory(kvarAddress, &cbSize, sizeof(cbSize))) {
        logAdd(EntryTypeWarning, TEXT("Failed to read CiCallbacks head"));
        return 0;
    }

    if (cbSize == 0 || cbSize > 0x1000) {
        logAdd(EntryTypeWarning, TEXT("CiCallbacks size is ambiguous"));
        return 0;
    }

    //
    // Read tail - marker tag.
    //
    if (!kdReadSystemMemory(kvarAddress + (cbSize - sizeof(ULONG_PTR)), &ulTag, sizeof(ulTag))) {
        logAdd(EntryTypeWarning, TEXT("Failed to read CiCallbacks tail"));
        return 0;
    }

    for (Index = 0; Index < RTL_NUMBER_OF(g_CbtMapping); Index++) {
        if (g_CbtMapping[Index].Build == g_NtBuildNumber) {
            bFound = TRUE;
            //
            // Validate for known table values.
            //
            if (cbSize == g_CbtMapping[Index].Size &&
                ulTag == g_CbtMapping[Index].Tag)
            {
                return kvarAddress;
            }
        }
    }

    if (bFound == FALSE)
        logAdd(EntryTypeWarning, TEXT("NtBuildNumber is not recognized"));

    return 0;
}

/*
* FindCiCallbacks
*
* Purpose:
*
* Locate address of ntoskrnl g_CiCallbacks/SeCiCallbacks structure.
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindCiCallbacks)
{
    ULONG_PTR kvarAddress = 0;

    PBYTE Signature = NULL, ptrCode = NULL, InstructionMatchPattern = NULL;
    ULONG SignatureSize = 0, InstructionMatchLength;
    ULONG InstructionExactMatchLength;
    PVOID SectionBase;
    ULONG SectionSize = 0, Index;
    LPCWSTR KVARName;
    LONG Rel = 0;
    hde64s hs;

    do {

        //
        // Symbols query.
        //
        if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {
            KVARName = (g_NtBuildNumber < NT_WIN8_RTM) ? (LPCWSTR)KVAR_g_CiCallbacks : (LPCWSTR)KVAR_SeCiCallbacks;
            kdGetAddressFromSymbol(&g_kdctx,
                KVARName,
                &kvarAddress);
        }

        //
        // Pattern searching.
        //
        if (kvarAddress == 0) {
            if (g_NtBuildNumber >= NT_WIN10_REDSTONE5) {
                kvarAddress = FindCiCallbacksEx(QueryFlags);
            }
            else {

                //
                // Locate PAGE image section as required variable is always in PAGE.
                //
                SectionBase = supLookupImageSectionByName(
                    PAGE_SECTION,
                    PAGE_SECTION_LENGTH,
                    g_kdctx.NtOsImageMap,
                    &SectionSize);

                if ((SectionBase == 0) || (SectionSize == 0))
                    break;

                InstructionMatchPattern = SeCiCallbacksMatchingPattern; //default matching pattern
                InstructionMatchLength = LEA_INSTRUCTION_LENGTH_7B;
                InstructionExactMatchLength = CI_CALLBACKS_3BYTE_INSTRUCTION_SIZE;

                switch (g_NtBuildNumber) {

                case NT_WIN7_SP1:
                    Signature = g_CiCallbacksPattern_7601;
                    SignatureSize = sizeof(g_CiCallbacksPattern_7601);
                    InstructionMatchPattern = g_CiCallbacksMatchingPattern;
                    break;

                case NT_WIN8_RTM:
                case NT_WIN8_BLUE:
                    Signature = SeCiCallbacksPattern_9200_9600;
                    SignatureSize = sizeof(SeCiCallbacksPattern_9200_9600);
                    break;

                case NT_WIN10_THRESHOLD1:
                case NT_WIN10_THRESHOLD2:
                    Signature = SeCiCallbacksPattern_10240_10586;
                    SignatureSize = sizeof(SeCiCallbacksPattern_10240_10586);
                    break;

                case NT_WIN10_REDSTONE1:
                    Signature = SeCiCallbacksPattern_14393;
                    SignatureSize = sizeof(SeCiCallbacksPattern_14393);
                    break;

                case NT_WIN10_REDSTONE2:
                case NT_WIN10_REDSTONE3:
                    Signature = SeCiCallbacksPattern_15063_16299;
                    SignatureSize = sizeof(SeCiCallbacksPattern_15063_16299);
                    break;

                case NT_WIN10_REDSTONE4:
                default:
                    Signature = SeCiCallbacksPattern_17134_17763;
                    SignatureSize = sizeof(SeCiCallbacksPattern_17134_17763);
                    break;
                }

                ptrCode = (PBYTE)supFindPattern(
                    (PBYTE)SectionBase,
                    SectionSize,
                    Signature,
                    SignatureSize);

                if (ptrCode == NULL)
                    break;

                if (g_NtBuildNumber <= NT_WIN7_SP1) {

                    //
                    // Find reference to g_CiCallbacks in code.
                    //

                    Index = 0; //pattern search include target instruction, do not skip

                }
                else {

                    //
                    // Find reference to SeCiCallbacks/g_CiCallbacks in code.
                    //

                    Index = SignatureSize; //skip signature instructions

                }

                do {
                    hde64_disasm((void*)(ptrCode + Index), &hs);
                    if (hs.flags & F_ERROR)
                        break;
                    //
                    // mov cs:g_CiCallbacks, rax (for Windows 7)
                    // lea rcx, SeCiCallbacks (for 8/10 TH/RS)
                    // mov cs:SeCiCallbacks (19H1-21H1)
                    //
                    if (hs.len == InstructionMatchLength) {

                        //
                        // Match block found.
                        //
                        if (RtlCompareMemory((VOID*)&ptrCode[Index], (VOID*)InstructionMatchPattern,
                            InstructionExactMatchLength) == InstructionExactMatchLength)
                        {
                            Rel = *(PLONG)(ptrCode + Index + InstructionExactMatchLength);
                            break;
                        }
                    }
                    Index += hs.len;

                } while (Index < SCAN_LIMIT_NEAR);

                kvarAddress = ComputeAddressInsideNtOs((ULONG_PTR)ptrCode, Index, hs.len, Rel);

            }
        }

    } while (FALSE);

    if (kvarAddress == 0)
        logAdd(EntryTypeWarning, TEXT("Could not locate CiCallbacks"));

    return kvarAddress;
}

/*
* IopFileSystemIsKnownPattern
*
* Purpose:
*
* Tests IoRegisterFileSystem function pattern to be known.
*
*/
BOOL IopFileSystemIsKnownPattern(
    _In_ PBYTE Buffer,
    _In_ ULONG Offset,
    _In_ ULONG InstructionSize
)
{
    BOOL bResult = FALSE;
    BYTE inst3byte;
    BYTE nextInstructionByte1, nextInstructionByte2;

    if (g_NtBuildNumber <= NT_WIN11_21H2) {
        inst3byte = 0x0D;
        nextInstructionByte1 = 0x48;
        nextInstructionByte2 = 0xE9;
    }
    else { //win11 22h1+

        switch (g_NtBuildNumber)
        {
        case NT_WIN11_22H2:
        case NT_WIN11_23H2:
            inst3byte = 0x15;
            nextInstructionByte1 = 0x0F;
            nextInstructionByte2 = 0xE9;
            break;

        case NT_WIN11_24H2:
        default:
            inst3byte = 0x15;
            nextInstructionByte1 = 0x0F;
            nextInstructionByte2 = 0xEB;
            break;
        }
    }

    if ((Buffer[Offset] == 0x48) &&
        (Buffer[Offset + 1] == 0x8D) &&
        (Buffer[Offset + 2] == inst3byte) &&
        ((Buffer[Offset + InstructionSize] == nextInstructionByte1) || (Buffer[Offset + InstructionSize] == nextInstructionByte2)))
    {
        bResult = TRUE;
    }

    return bResult;
}

/*
* LookupIopFileSystemQueueHeads_w7
*
* Purpose:
*
* Windows 7 version of IoRegisterFileSystem listheads lookup.
*
*/
ULONG LookupIopFileSystemQueueHeads_w7(
    _In_ PBYTE Buffer,
    _Inout_ ULONG_PTR* IopCdRomFileSystemQueueHead,
    _Inout_ ULONG_PTR* IopDiskFileSystemQueueHead,
    _Inout_ ULONG_PTR* IopTapeFileSystemQueueHead,
    _Inout_ ULONG_PTR* IopNetworkFileSystemQueueHead
)
{
    ULONG Index = 0, Count = 0;
    LONG Rel = 0;
    ULONG_PTR kvarAddress;
    hde64s hs;
    PBYTE ptrCode = Buffer;

    do {
        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == LEA_INSTRUCTION_LENGTH_7B) {
            //
            // lea  rdx, xxx                
            //
            if ((ptrCode[Index] == 0x48) &&
                (ptrCode[Index + 1] == 0x8D) &&
                (ptrCode[Index + 2] == 0x15))
            {
                Rel = *(PLONG)(ptrCode + Index + 3);
                if (Rel) {

                    kvarAddress = kdAdjustAddressToNtOsBase((ULONG_PTR)ptrCode, Index, hs.len, Rel);

                    if (kdAddressInNtOsImage((PVOID)kvarAddress)) {

                        switch (Count) {
                        case 0:
                            *IopNetworkFileSystemQueueHead = kvarAddress;
                            break;

                        case 1:
                            *IopCdRomFileSystemQueueHead = kvarAddress;
                            break;

                        case 2:
                            *IopDiskFileSystemQueueHead = kvarAddress;
                            break;

                        case 3:
                            *IopTapeFileSystemQueueHead = kvarAddress;
                            break;
                        }
                        Count += 1;
                        if (Count == 4)
                            break;
                    }
                }
            }

        }

        Index += hs.len;

    } while (Index < SCAN_LIMIT_LARGE);

    return Count;
}

/*
* LookupIopFileSystemQueueHeads_w8_11
*
* Purpose:
*
* Windows 8-11 version of IoRegisterFileSystem listheads lookup.
*
*/
ULONG LookupIopFileSystemQueueHeads_w8_11(
    _In_ PBYTE Buffer,
    _In_ BOOL Reorder,
    _Inout_ ULONG_PTR* IopCdRomFileSystemQueueHead,
    _Inout_ ULONG_PTR* IopDiskFileSystemQueueHead,
    _Inout_ ULONG_PTR* IopTapeFileSystemQueueHead,
    _Inout_ ULONG_PTR* IopNetworkFileSystemQueueHead
)
{
    ULONG Index = 0, Count = 0;
    LONG Rel = 0;
    ULONG_PTR kvarAddress;
    hde64s hs;
    PBYTE ptrCode = Buffer;

    do {
        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == 7) {

            if (IopFileSystemIsKnownPattern(ptrCode, Index, hs.len)) {
                Rel = *(PLONG)(ptrCode + Index + 3);
                if (Rel) {

                    kvarAddress = kdAdjustAddressToNtOsBase((ULONG_PTR)ptrCode, Index, hs.len, Rel);

                    if (kdAddressInNtOsImage((PVOID)kvarAddress)) {

                        if (Reorder)
                        {
                            switch (Count) {

                            case 0:
                                *IopNetworkFileSystemQueueHead = kvarAddress;
                                break;

                            case 1:
                                *IopCdRomFileSystemQueueHead = kvarAddress;
                                break;

                            case 2:
                                *IopDiskFileSystemQueueHead = kvarAddress;
                                break;

                            case 3:
                                *IopTapeFileSystemQueueHead = kvarAddress;
                                break;
                            }
                        }
                        else {

                            switch (Count) {
                            case 0:
                                *IopDiskFileSystemQueueHead = kvarAddress;
                                break;

                            case 1:
                                *IopCdRomFileSystemQueueHead = kvarAddress;
                                break;

                            case 2:
                                *IopNetworkFileSystemQueueHead = kvarAddress;
                                break;

                            case 3:
                                *IopTapeFileSystemQueueHead = kvarAddress;
                                break;
                            }
                        }
                        Count += 1;
                        if (Count == 4)
                            break;
                    }
                }
            }

        }

        Index += hs.len;

    } while (Index < SCAN_LIMIT_LARGE);

    return Count;
}

/*
* FindIopFileSystemQueueHeads
*
* Purpose:
*
* Return addresses of list heads for callbacks registered with:
*
*   IoRegisterFileSystem
*
*/
BOOL FindIopFileSystemQueueHeads(
    _Out_ ULONG_PTR* IopCdRomFileSystemQueueHead,
    _Out_ ULONG_PTR* IopDiskFileSystemQueueHead,
    _Out_ ULONG_PTR* IopTapeFileSystemQueueHead,
    _Out_ ULONG_PTR* IopNetworkFileSystemQueueHead
)
{
    BOOL bSymQuerySuccess = FALSE;
    ULONG Count = 0;
    ULONG_PTR kvarAddress = 0;
    PBYTE ptrCode;

    //
    // Assume failure.
    //
    *IopCdRomFileSystemQueueHead = 0;
    *IopDiskFileSystemQueueHead = 0;
    *IopTapeFileSystemQueueHead = 0;
    *IopNetworkFileSystemQueueHead = 0;

    if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {

        do {

            if (!kdGetAddressFromSymbol(&g_kdctx,
                KVAR_IopCdRomFileSystemQueueHead,
                &kvarAddress))
            {
                break;
            }

            *IopCdRomFileSystemQueueHead = kvarAddress;

            if (!kdGetAddressFromSymbol(&g_kdctx,
                KVAR_IopDiskFileSystemQueueHead,
                &kvarAddress))
            {
                break;
            }

            *IopDiskFileSystemQueueHead = kvarAddress;

            if (!kdGetAddressFromSymbol(&g_kdctx,
                KVAR_IopTapeFileSystemQueueHead,
                &kvarAddress))
            {
                break;
            }

            *IopTapeFileSystemQueueHead = kvarAddress;

            if (!kdGetAddressFromSymbol(&g_kdctx,
                KVAR_IopNetworkFileSystemQueueHead,
                &kvarAddress))
            {
                break;
            }

            *IopNetworkFileSystemQueueHead = kvarAddress;

            bSymQuerySuccess = TRUE;

        } while (FALSE);

    }

    if (bSymQuerySuccess)
        return TRUE;

    ptrCode = (PBYTE)GetProcAddress((HMODULE)g_kdctx.NtOsImageMap,
        "IoRegisterFileSystem");

    if (ptrCode == NULL)
        return 0;

    if (g_NtBuildNumber < NT_WIN8_RTM) {

        Count = LookupIopFileSystemQueueHeads_w7(ptrCode,
            IopCdRomFileSystemQueueHead,
            IopDiskFileSystemQueueHead,
            IopTapeFileSystemQueueHead,
            IopNetworkFileSystemQueueHead);
    }
    else {
        Count = LookupIopFileSystemQueueHeads_w8_11(ptrCode,
            (g_NtBuildNumber >= NT_WIN11_24H2),  // Since WIN11 24H2 pointer usage in this function is reordered.
            IopCdRomFileSystemQueueHead,
            IopDiskFileSystemQueueHead,
            IopTapeFileSystemQueueHead,
            IopNetworkFileSystemQueueHead);

    }

    return (Count == 4);
}

/*
* IopFsNotifyChangeIsKnownPattern
*
* Purpose:
*
* Tests IoUnregisterFsRegistrationChange function pattern to be known.
*
*/
BOOL IopFsNotifyChangeIsKnownPattern(
    _In_ PBYTE Buffer,
    _In_ ULONG Offset,
    _In_ ULONG InstructionSize
)
{
    BOOL bResult = FALSE;
    BYTE nextInstructionByte1;

    switch (g_NtBuildNumber) {
    case NT_WIN11_24H2:
    case NT_WIN11_25H2:
        nextInstructionByte1 = 0x48;
        break;
    default:
        nextInstructionByte1 = 0xEB;
        break;
    }

    //
    // lea  rax, IopFsNotifyChangeQueueHead
    // jmp  short / cmp rcx, rax
    //
    if ((Buffer[Offset] == 0x48) &&
        (Buffer[Offset + 1] == 0x8D) &&
        (Buffer[Offset + 2] == 0x05) &&
        (Buffer[Offset + InstructionSize] == nextInstructionByte1))
    {
        bResult = TRUE;
    }

    return bResult;
}

/*
* FindIopFsNotifyChangeQueueHead
*
* Purpose:
*
* Return address of list head for callbacks registered with:
*
*   IoRegisterFsRegistrationChange
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindIopFsNotifyChangeQueueHead)
{
    ULONG Index = 0;
    LONG Rel = 0;
    ULONG_PTR kvarAddress = 0;
    PBYTE ptrCode;
    hde64s hs;

    UNREFERENCED_PARAMETER(QueryFlags);

    if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {
        kdGetAddressFromSymbol(&g_kdctx,
            KVAR_IopFsNotifyChangeQueueHead,
            &kvarAddress);
    }

    if (kvarAddress == 0) {

        ptrCode = (PBYTE)GetProcAddress((HMODULE)g_kdctx.NtOsImageMap,
            "IoUnregisterFsRegistrationChange");

        if (ptrCode == NULL)
            return 0;

        do {
            hde64_disasm(ptrCode + Index, &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == 7) {

                if (IopFsNotifyChangeIsKnownPattern(
                    ptrCode,
                    Index,
                    hs.len))
                {
                    Rel = *(PLONG)(ptrCode + Index + 3);
                    break;
                }

            }

            Index += hs.len;

        } while (Index < SCAN_LIMIT_MEDIUM);

        kvarAddress = ComputeAddressInsideNtOs((ULONG_PTR)ptrCode, Index, hs.len, Rel);
    }

    return kvarAddress;
}

/*
* FindRtlpDebugPrintCallbackList
*
* Purpose:
*
* Return address of list head for callbacks registered with:
*
*   DbgSetDebugPrintCallback
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindRtlpDebugPrintCallbackList)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR kvarAddress = 0;
    PBYTE ptrCode;
    hde64s hs;

    UNREFERENCED_PARAMETER(QueryFlags);

    if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {
        kdGetAddressFromSymbol(&g_kdctx,
            KVAR_RtlpDebugPrintCallbackList,
            &kvarAddress);
    }

    if (kvarAddress == 0) {

        ptrCode = (PBYTE)GetProcAddress((HMODULE)g_kdctx.NtOsImageMap, "DbgSetDebugPrintCallback");
        if (ptrCode == NULL)
            return 0;

        //
        // Find DbgpInsertDebugPrintCallback pointer.
        //
        Index = 0;
        do {

            hde64_disasm(ptrCode + Index, &hs);
            if (hs.flags & F_ERROR)
                break;

            //jmp/call DbgpInsertDebugPrintCallback
            if (hs.len == 5) {
                if (hs.opcode == 0xE8 || hs.opcode == 0xE9)
                {
                    Rel = (LONG)hs.imm.imm32;
                    break;
                }
            }
            //jz
            if (hs.len == 6) {
                if (hs.opcode == 0x0F) {
                    Rel = (LONG)hs.imm.imm32;
                    break;
                }
            }

            Index += hs.len;

        } while (Index < SCAN_LIMIT_NEAR);

        if (Rel == 0) {
            logAdd(EntryTypeWarning, TEXT("DbgpInsertDebugPrintCallback relative offset is not found"));
            return 0;
        }

        ptrCode = ptrCode + Index + (hs.len) + Rel;
        Index = 0;
        Rel = 0;

        //
        // Complicated search. Not unique search patterns.
        //

        do {
            hde64_disasm(ptrCode + Index, &hs);
            if (hs.flags & F_ERROR)
                break;

            //
            // lea  reg, RtlpDebugPrintCallbackList
            //
            if (hs.len == LEA_INSTRUCTION_LENGTH_7B) {
                if ((ptrCode[Index] == 0x48) &&
                    (ptrCode[Index + 1] == 0x8D) &&
                    ((ptrCode[Index + 2] == 0x15) || (ptrCode[Index + 2] == 0x0D)) &&
                    (ptrCode[Index + hs.len] == 0x48))
                {
                    Rel = (LONG)hs.disp.disp32;
                    break;
                }
            }

            Index += hs.len;

        } while (Index < SCAN_LIMIT_LARGE);

        if (Rel == 0) {
            logAdd(EntryTypeWarning, TEXT("RtlpDebugPrintCallbackList relative offset is not found"));
            return 0;
        }

        kvarAddress = ComputeAddressInsideNtOs((ULONG_PTR)ptrCode, Index, hs.len, Rel);

    }

    return kvarAddress;
}

/*
* FindPopRegisteredPowerSettingCallbacks
*
* Purpose:
*
* Return address of list head for callbacks registered with:
*
*   PoRegisterPowerSettingCallback
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindPopRegisteredPowerSettingCallbacks)
{
    ULONG Index, ScanBytes;
    LONG Rel = 0;
    ULONG_PTR kvarAddress = 0;
    PBYTE ptrCode;
    hde64s hs;

    UNREFERENCED_PARAMETER(QueryFlags);

    if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {
        kdGetAddressFromSymbol(&g_kdctx,
            KVAR_PopRegisteredPowerSettingCallbacks,
            &kvarAddress);
    }

    if (kvarAddress == 0) {

        ptrCode = (PBYTE)GetProcAddress((HMODULE)g_kdctx.NtOsImageMap,
            "PoRegisterPowerSettingCallback");

        if (ptrCode == NULL)
            return 0;

        Index = 0;
        Rel = 0;

        ScanBytes = (g_NtBuildNumber < NT_WIN11_25H2) ? SCAN_LIMIT_LARGE : SCAN_LIMIT_XLARGE;

        do {
            hde64_disasm(ptrCode + Index, &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == 7) {
                //
                // lea      rcx, PopRegisteredPowerSettingCallbacks
                // mov      [rbx + 8], rax |
                // cmp      [rax], rcx
                //
                if ((ptrCode[Index] == 0x48) &&
                    (ptrCode[Index + 1] == 0x8D) &&
                    (ptrCode[Index + 2] == 0x0D) &&
                    (ptrCode[Index + 7] == 0x48))
                {
                    Rel = *(PLONG)(ptrCode + Index + 3);
                    break;
                }

            }

            Index += hs.len;

        } while (Index < ScanBytes);

        kvarAddress = ComputeAddressInsideNtOs((ULONG_PTR)ptrCode, Index, hs.len, Rel);

    }

    return kvarAddress;
}

/*
* FindSeFileSystemNotifyRoutinesHead
*
* Purpose:
*
* Return address of list head for callbacks registered with:
*
*   SeRegisterLogonSessionTerminatedRoutine
*   SeRegisterLogonSessionTerminatedRoutineEx
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindSeFileSystemNotifyRoutinesHead)
{
    BOOL Extended = (BOOL)(ULONG)QueryFlags;
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR kvarAddress = 0;
    LPSTR lpCallbackName;
    PBYTE ptrCode;
    hde64s hs;

    if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {
        kdGetAddressFromSymbol(&g_kdctx,
            (Extended) ? KVAR_SeFileSystemNotifyRoutinesExHead : KVAR_SeFileSystemNotifyRoutinesHead,
            &kvarAddress);
    }

    if (kvarAddress == 0) {
        //
        // Routines have similar design.
        //
        lpCallbackName = Extended ? "SeRegisterLogonSessionTerminatedRoutineEx" : "SeRegisterLogonSessionTerminatedRoutine";

        ptrCode = (PBYTE)GetProcAddress((HMODULE)g_kdctx.NtOsImageMap, lpCallbackName);
        if (ptrCode == NULL)
            return 0;

        Index = 0;
        Rel = 0;

        do {
            hde64_disasm(ptrCode + Index, &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == 7) {

                //
                // mov     rax, cs:SeFileSystemNotifyRoutines(Ex)Head
                //

                if ((ptrCode[Index] == 0x48) &&
                    (ptrCode[Index + 1] == 0x8B) &&
                    (ptrCode[Index + 2] == 0x05))
                {
                    Rel = *(PLONG)(ptrCode + Index + 3);
                    break;
                }

            }

            Index += hs.len;

        } while (Index < SCAN_LIMIT_SMALL);

        kvarAddress = ComputeAddressInsideNtOs((ULONG_PTR)ptrCode, Index, hs.len, Rel);

    }

    return kvarAddress;
}

/*
* FindObjectTypeCallbackListHeadByType
*
* Purpose:
*
* Return address of list head for callbacks registered with:
*
*   ObRegisterCallbacks
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindObjectTypeCallbackListHeadByType)
{
    ULONG_PTR ListHead = 0;
    ULONG ObjectSize, ObjectVersion = 0, CallbackListOffset = 0;
    LPWSTR TypeName = NULL;
    POBEX_OBJECT_INFORMATION CurrentObject = NULL;
    PVOID ObjectTypeInformation = NULL;
    UNICODE_STRING usName;

    union {
        union {
            OBJECT_TYPE_7* ObjectType_7;
            OBJECT_TYPE_8* ObjectType_8;
            OBJECT_TYPE_RS1* ObjectType_RS1;
            OBJECT_TYPE_RS2* ObjectType_RS2;
        } Versions;
        PVOID Ref;
    } ObjectType;

    switch ((WOBJ_OBJECT_TYPE)(ULONG)QueryFlags) {
    case ObjectTypeProcess: //PsProcessType
        TypeName = TEXT("Process");
        break;
    case ObjectTypeThread: //PsThreadType
        TypeName = TEXT("Thread");
        break;
    case ObjectTypeDesktop: //ExDesktopObjectType
        TypeName = TEXT("Desktop");
        break;
    default:
        //
        // We cannot process this object type.
        //
        return 0;
    }

    //
    // Get the reference to the object.
    //
    RtlInitUnicodeString(&usName, TypeName);
    CurrentObject = ObQueryObjectInDirectory(&usName,
        ObGetPredefinedUnicodeString(OBP_OBTYPES));

    if (CurrentObject == NULL)
        return 0;

    //
    // Dump object information version aware.
    //
    ObjectTypeInformation = ObDumpObjectTypeVersionAware(
        CurrentObject->ObjectAddress,
        &ObjectSize,
        &ObjectVersion);

    if (ObjectTypeInformation == NULL) {
        supHeapFree(CurrentObject);
        return 0;
    }

    ObjectType.Ref = ObjectTypeInformation;

    //
    // Flags in structure offset compatible fields.
    //
    if (ObjectType.Versions.ObjectType_7->TypeInfo.SupportsObjectCallbacks) {

        //
        // Calculate offset to structure field.
        //
        switch (ObjectVersion) {
        case OBVERSION_OBJECT_TYPE_V1:
            CallbackListOffset = FIELD_OFFSET(OBJECT_TYPE_7, CallbackList);
            break;

        case OBVERSION_OBJECT_TYPE_V2:
            CallbackListOffset = FIELD_OFFSET(OBJECT_TYPE_8, CallbackList);
            break;

        case OBVERSION_OBJECT_TYPE_V3:
            CallbackListOffset = FIELD_OFFSET(OBJECT_TYPE_RS1, CallbackList);
            break;

        default:
            CallbackListOffset = FIELD_OFFSET(OBJECT_TYPE_RS2, CallbackList);
            break;
        }

        ListHead = CurrentObject->ObjectAddress + CallbackListOffset;
    }

    supHeapFree(CurrentObject);
    supVirtualFree(ObjectTypeInformation);
    return ListHead;
}

/*
* FindIopNotifyShutdownQueueHeadHead
*
* Purpose:
*
* Return address of list head for callbacks registered with:
*
*   IoRegisterShutdownNotification
*   IoRegisterLastChanceShutdownNotification
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindIopNotifyShutdownQueueHeadHead)
{
    BOOL bLastChance = (BOOL)(ULONG)QueryFlags;
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR kvarAddress = 0;
    LPSTR lpCallbackName;
    PBYTE ptrCode;
    hde64s hs;

    if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {
        kdGetAddressFromSymbol(&g_kdctx,
            (bLastChance) ? KVAR_IopNotifyLastChanceShutdownQueueHead : KVAR_IopNotifyShutdownQueueHead,
            &kvarAddress);
    }

    if (kvarAddress == 0) {
        //
        // Routines have similar design.
        //
        lpCallbackName = (bLastChance) ? "IoRegisterLastChanceShutdownNotification" : "IoRegisterShutdownNotification";
        ptrCode = (PBYTE)GetProcAddress((HMODULE)g_kdctx.NtOsImageMap, lpCallbackName);
        if (ptrCode == NULL)
            return 0;

        Index = 0;
        Rel = 0;

        do {
            hde64_disasm(ptrCode + Index, &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == LEA_INSTRUCTION_LENGTH_7B) { //check if lea

                if (((ptrCode[Index] == 0x48) || (ptrCode[Index] == 0x4C)) &&
                    (ptrCode[Index + 1] == 0x8D))
                {
                    Rel = (LONG)hs.disp.disp32;
                    break;
                }

            }

            Index += hs.len;

        } while (Index < SCAN_LIMIT_SMALL);

        kvarAddress = ComputeAddressInsideNtOs((ULONG_PTR)ptrCode, Index, hs.len, Rel);

    }

    return kvarAddress;
}

/*
* FindCmCallbackHead
*
* Purpose:
*
* Return address of list head for callbacks registered with:
*
*   CmRegisterCallback
*   CmRegisterCallbackEx
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindCmCallbackHead)
{
    BOOL bFound = FALSE;
    ULONG Index, resultOffset = 0;
    LONG Rel = 0, FirstInstructionLength;
    ULONG_PTR kvarAddress = 0;
    PBYTE ptrCode;
    hde64s hs, hs_next;

    UNREFERENCED_PARAMETER(QueryFlags);

    if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {
        kdGetAddressFromSymbol(&g_kdctx,
            KVAR_CallbackListHead,
            &kvarAddress);
    }

    if (kvarAddress == 0) {
        ptrCode = (PBYTE)GetProcAddress((HMODULE)g_kdctx.NtOsImageMap, "CmUnRegisterCallback");
        if (ptrCode == NULL)
            return 0;

        Index = 0;
        Rel = 0;

        do {
            hde64_disasm(ptrCode + Index, &hs);
            if (hs.flags & F_ERROR)
                break;

            if (g_NtBuildNumber < NT_WIN11_25H2)
            {
                if (hs.len == 5) {
                    /*
                    ** lea     rdx, [rsp+20h] <-
                    ** lea     rcx, CallbackListHead
                    */
                    if ((ptrCode[Index] == 0x48) &&
                        (ptrCode[Index + 1] == 0x8D) &&
                        (ptrCode[Index + 2] == 0x54))
                    {
                        bFound = TRUE;
                    }
                }
            }
            else {
                if (hs.len == 8 &&
                    (hs.flags & F_PREFIX_REX) &&
                    (hs.flags & F_DISP32) &&
                    (hs.flags & F_MODRM))
                {
                    /*
                    ** lea     rdx, [rsp+0B8h+arg_8] <-
                    ** lea     rcx, CallbackListHead
                    */
                    if ((ptrCode[Index] == 0x48) &&
                        (ptrCode[Index + 1] == 0x8D) &&
                        (ptrCode[Index + 2] == 0x94))
                    {
                        bFound = TRUE;
                    }
                }

            }

            if (bFound)
            {
                hde64_disasm(ptrCode + Index + hs.len, &hs_next);
                if (hs_next.flags & F_ERROR)
                    break;
                if (hs_next.len == LEA_INSTRUCTION_LENGTH_7B) {

                    /*
                    ** lea     rdx, [rsp+20h]
                    ** lea     rcx, CallbackListHead <-
                    */
                    FirstInstructionLength = hs.len;

                    if ((ptrCode[Index + FirstInstructionLength] == 0x48) &&
                        (ptrCode[Index + FirstInstructionLength + 1] == 0x8D) &&
                        (ptrCode[Index + FirstInstructionLength + 2] == 0x0D))
                    {
                        resultOffset = Index + FirstInstructionLength + hs_next.len;
                        Rel = *(PLONG)(ptrCode + Index + FirstInstructionLength + 3);
                        break;
                    }
                }
            }

            Index += hs.len;

        } while (Index < SCAN_LIMIT_MEDIUM);

        if (resultOffset == 0) {
            logAdd(EntryTypeWarning, TEXT("CmCallbackHead offset is not found"));
            return 0;
        }

        kvarAddress = ComputeAddressInsideNtOs((ULONG_PTR)ptrCode, resultOffset, 0, Rel);
    }

    return kvarAddress;
}

/*
* FindKeBugCheckReasonCallbackHead
*
* Purpose:
*
* Return address of list head for callbacks registered with:
*
*   KeRegisterBugCheckReasonCallback
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindKeBugCheckReasonCallbackHead)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR kvarAddress = 0;
    PBYTE ptrCode;
    hde64s hs;

    UNREFERENCED_PARAMETER(QueryFlags);

    if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {
        kdGetAddressFromSymbol(&g_kdctx,
            KVAR_KeBugCheckReasonCallbackListHead,
            &kvarAddress);
    }

    if (kvarAddress == 0) {
        ptrCode = (PBYTE)GetProcAddress((HMODULE)g_kdctx.NtOsImageMap, "KeRegisterBugCheckReasonCallback");
        if (ptrCode == NULL)
            return 0;

        Index = 0;
        Rel = 0;

        do {
            hde64_disasm(ptrCode + Index, &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == LEA_INSTRUCTION_LENGTH_7B) { //check if lea

                if (((ptrCode[Index] == 0x48) || (ptrCode[Index] == 0x4C)) &&
                    (ptrCode[Index + 1] == 0x8D) &&
                    ((ptrCode[Index + hs.len] == 0x48) || (ptrCode[Index + hs.len] == 0x83)))
                {
                    Rel = (LONG)hs.disp.disp32;
                    break;
                }

            }

            Index += hs.len;

        } while (Index < SCAN_LIMIT_LARGE);

        kvarAddress = ComputeAddressInsideNtOs((ULONG_PTR)ptrCode, Index, hs.len, Rel);
    }

    return kvarAddress;
}

/*
* FindKeBugCheckCallbackHead
*
* Purpose:
*
* Return address of list head for callbacks registered with:
*
*   KeRegisterBugCheckCallback
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindKeBugCheckCallbackHead)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR kvarAddress = 0;
    PBYTE ptrCode;
    hde64s hs;

    UNREFERENCED_PARAMETER(QueryFlags);

    if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {
        kdGetAddressFromSymbol(&g_kdctx,
            KVAR_KeBugCheckCallbackListHead,
            &kvarAddress);
    }

    if (kvarAddress == 0) {
        ptrCode = (PBYTE)GetProcAddress((HMODULE)g_kdctx.NtOsImageMap, "KeRegisterBugCheckCallback");
        if (ptrCode == NULL)
            return 0;

        Index = 0;
        Rel = 0;

        do {
            hde64_disasm(ptrCode + Index, &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == LEA_INSTRUCTION_LENGTH_7B) { //check if lea + mov

                if (((ptrCode[Index] == 0x48) || (ptrCode[Index] == 0x4C)) &&
                    (ptrCode[Index + 1] == 0x8D) &&
                    (ptrCode[Index + hs.len] == 0x48))
                {
                    Rel = (LONG)hs.disp.disp32;
                    break;
                }

            }

            Index += hs.len;

        } while (Index < SCAN_LIMIT_LARGE);

        kvarAddress = ComputeAddressInsideNtOs((ULONG_PTR)ptrCode, Index, hs.len, Rel);
    }

    return kvarAddress;
}

/*
* FindPspLoadImageNotifyRoutine
*
* Purpose:
*
* Return array address of callbacks registered with:
*
*   PsSetLoadImageNotifyRoutine
*   PsSetLoadImageNotifyRoutineEx
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindPspLoadImageNotifyRoutine)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR kvarAddress = 0;
    PBYTE ptrCode;
    hde64s hs;

    UNREFERENCED_PARAMETER(QueryFlags);

    if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {
        kdGetAddressFromSymbol(&g_kdctx,
            KVAR_PspLoadImageNotifyRoutine,
            &kvarAddress);
    }

    if (kvarAddress == 0) {
        ptrCode = (PBYTE)GetProcAddress((HMODULE)g_kdctx.NtOsImageMap, "PsRemoveLoadImageNotifyRoutine");
        if (ptrCode == NULL)
            return 0;

        Index = 0;
        Rel = 0;

        do {
            hde64_disasm(ptrCode + Index, &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == LEA_INSTRUCTION_LENGTH_7B) { //check if lea

                if (((ptrCode[Index] == 0x48) || (ptrCode[Index] == 0x4C)) &&
                    (ptrCode[Index + 1] == 0x8D))
                {
                    Rel = (LONG)hs.disp.disp32;
                    break;
                }

            }

            Index += hs.len;

        } while (Index < SCAN_LIMIT_SMALL);

        kvarAddress = ComputeAddressInsideNtOs((ULONG_PTR)ptrCode, Index, hs.len, Rel);
    }

    return kvarAddress;
}

/*
* FindPspCreateThreadNotifyRoutine
*
* Purpose:
*
* Return array address of callbacks registered with:
*
*   PsSetCreateThreadNotifyRoutine
*   PsSetCreateThreadNotifyRoutineEx
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindPspCreateThreadNotifyRoutine)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR kvarAddress = 0;
    PBYTE ptrCode;
    hde64s hs;

    UNREFERENCED_PARAMETER(QueryFlags);

    if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {
        kdGetAddressFromSymbol(&g_kdctx,
            KVAR_PspCreateThreadNotifyRoutine,
            &kvarAddress);
    }

    if (kvarAddress == 0) {
        ptrCode = (PBYTE)GetProcAddress((HMODULE)g_kdctx.NtOsImageMap, "PsRemoveCreateThreadNotifyRoutine");

        if (ptrCode == NULL)
            return 0;

        Index = 0;
        Rel = 0;

        do {
            hde64_disasm(ptrCode + Index, &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == LEA_INSTRUCTION_LENGTH_7B) { //check if lea

                if (((ptrCode[Index] == 0x48) || (ptrCode[Index] == 0x4C)) &&
                    (ptrCode[Index + 1] == 0x8D))
                {
                    Rel = (LONG)hs.disp.disp32;
                    break;
                }

            }

            Index += hs.len;

        } while (Index < SCAN_LIMIT_SMALL);

        kvarAddress = ComputeAddressInsideNtOs((ULONG_PTR)ptrCode, Index, hs.len, Rel);
    }

    return kvarAddress;
}

/*
* FindDbgkLmdCallbacks
*
* Purpose:
*
* Return array address of callbacks registered with:
*
*   DbgkLkmdRegisterCallback
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindDbgkLmdCallbacks)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR kvarAddress = 0;
    PBYTE ptrCode;
    hde64s hs;

    UNREFERENCED_PARAMETER(QueryFlags);

    if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {
        kdGetAddressFromSymbol(&g_kdctx,
            KVAR_DbgkLmdCallbacks,
            &kvarAddress);
    }

    if (kvarAddress == 0) {
        ptrCode = (PBYTE)GetProcAddress((HMODULE)g_kdctx.NtOsImageMap, "DbgkLkmdUnregisterCallback");
        if (ptrCode == NULL)
            return 0;

        Index = 0;
        Rel = 0;

        //
        // Find DbgkLmdCallbacks pointer
        //
        do {
            hde64_disasm(ptrCode + Index, &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == LEA_INSTRUCTION_LENGTH_7B) { //check if lea

                //
                // lea     rcx, DbgkLmdCallbacks
                //
                if (((ptrCode[Index] == 0x4C) || (ptrCode[Index] == 0x48)) &&
                    (ptrCode[Index + 1] == 0x8D))
                {
                    Rel = (LONG)hs.disp.disp32;
                    break;
                }

            }

            Index += hs.len;

        } while (Index < SCAN_LIMIT_NEAR);

        kvarAddress = ComputeAddressInsideNtOs((ULONG_PTR)ptrCode, Index, hs.len, Rel);
    }

    return kvarAddress;
}

/*
* FindPspCreateProcessNotifyRoutine
*
* Purpose:
*
* Return array address of callbacks registered with:
*
*   PsSetCreateProcessNotifyRoutine
*   PsSetCreateProcessNotifyRoutineEx
*   PsSetCreateProcessNotifyRoutineEx2
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindPspCreateProcessNotifyRoutine)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR kvarAddress = 0;
    PBYTE ptrCode;
    hde64s hs;

    UNREFERENCED_PARAMETER(QueryFlags);

    if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {
        kdGetAddressFromSymbol(&g_kdctx,
            KVAR_PspCreateProcessNotifyRoutine,
            &kvarAddress);
    }

    if (kvarAddress == 0) {
        ptrCode = (PBYTE)GetProcAddress((HMODULE)g_kdctx.NtOsImageMap, "PsSetCreateProcessNotifyRoutine");
        if (ptrCode == NULL)
            return 0;

        //
        // Find PspSetCreateProcessNotifyRoutine pointer.
        //
        Index = 0;
        do {

            hde64_disasm(ptrCode + Index, &hs);
            if (hs.flags & F_ERROR)
                break;

            // Handle JMP/CALL rel32
            if ((hs.opcode == 0xE8 || hs.opcode == 0xE9) &&
                hs.len == 5)
            {
                Rel = (LONG)hs.imm.imm32;
                break;
            }
            // Handle JMP rel8 (Windows 8 RTM)
            else if (hs.opcode == 0xEB &&
                hs.len == 2)
            {
                Rel = (LONG)(INT8)hs.imm.imm8;
                break;
            }

            Index += hs.len;

        } while (Index < SCAN_LIMIT_NEAR);

        if (Rel == 0) {
            logAdd(EntryTypeWarning, TEXT("PspSetCreateProcessNotifyRoutine relative offset is not found"));
            return 0;
        }

        ptrCode = ptrCode + Index + (hs.len) + Rel;
        Index = 0;
        Rel = 0;

        do {
            hde64_disasm(ptrCode + Index, &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == LEA_INSTRUCTION_LENGTH_7B) { //check if lea

                if ((ptrCode[Index] == 0x4C) &&
                    (ptrCode[Index + 1] == 0x8D))
                {
                    Rel = (LONG)hs.disp.disp32;
                    break;
                }

            }

            Index += hs.len;

        } while (Index < SCAN_LIMIT_SMALL);

        kvarAddress = ComputeAddressInsideNtOs((ULONG_PTR)ptrCode, Index, hs.len, Rel);
    }

    return kvarAddress;
}

/*
* FindPsAltSystemCallHandlers
*
* Purpose:
*
* Return array address of callbacks registered with:
*
*   PsRegisterAltSystemCallHandler
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindPsAltSystemCallHandlers)
{
    ULONG Index, InstructionExactMatchLength;
    LONG Rel = 0;
    ULONG_PTR kvarAddress = 0;
    PBYTE ptrCode;
    hde64s hs;

    UNREFERENCED_PARAMETER(QueryFlags);

    if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {
        kdGetAddressFromSymbol(&g_kdctx,
            KVAR_PsAltSystemCallHandlers,
            &kvarAddress);
    }

    if (kvarAddress == 0) {
        ptrCode = (PBYTE)GetProcAddress((HMODULE)g_kdctx.NtOsImageMap, "PsRegisterAltSystemCallHandler");
        if (ptrCode == NULL)
            return 0;

        InstructionExactMatchLength = sizeof(PsAltSystemCallHandlersPattern);

        Index = 0;

        do {
            hde64_disasm((void*)(ptrCode + Index), &hs);
            if (hs.flags & F_ERROR)
                break;
            //
            // lea reg, PsAltSystemCallHandlers
            //
            if (hs.len == LEA_INSTRUCTION_LENGTH_7B) {

                //
                // Match block found.
                //
                if (RtlCompareMemory((VOID*)&ptrCode[Index],
                    (VOID*)PsAltSystemCallHandlersPattern,
                    InstructionExactMatchLength) == InstructionExactMatchLength)
                {
                    Rel = (LONG)hs.disp.disp32;
                    break;
                }
            }
            Index += hs.len;

        } while (Index < SCAN_LIMIT_SMALL);

        kvarAddress = ComputeAddressInsideNtOs((ULONG_PTR)ptrCode, Index, hs.len, Rel);
    }

    return kvarAddress;
}

/*
* FindExHostListCallbacks
*
* Purpose:
*
* Return address of list head for callbacks registered with:
*
*   ExRegisterExtension
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindExHostCallbacks)
{
    ULONG_PTR kvarAddress = 0;
    PBYTE   ptrCode;
    LONG    Rel = 0;
    ULONG   Index, c;
    hde64s  hs;

    ULONG SignatureSize = 0;
    PBYTE Signature = NULL;

    UNREFERENCED_PARAMETER(QueryFlags);

    if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {
        kdGetAddressFromSymbol(&g_kdctx,
            KVAR_ExpHostList,
            &kvarAddress);
    }

    if (kvarAddress == 0) {
        ptrCode = (PBYTE)GetProcAddress((HMODULE)g_kdctx.NtOsImageMap, "ExRegisterExtension");
        if (ptrCode == NULL)
            return 0;

        c = 0;
        Index = 0;

        //
        // Find ExpFindHost / ExpFindCompatibleHost
        //
        if (g_NtBuildNumber >= NT_WIN11_21H2) {

            //
            // For Windows 11 and above lookup for ExpFindHost parameters 
            // as the call of ExpFindHost maybe deep inside the ExRegisterExtension with
            // multiple other calls before.
            //
            switch (g_NtBuildNumber)
            {
            case NT_WIN11_21H2:
            case NT_WIN11_22H2:
                Signature = g_ExpFindHost22000_22621;
                SignatureSize = sizeof(g_ExpFindHost22000_22621);
                break;
            case NT_WIN11_23H2:
            case NT_WIN11_24H2:
            case NT_WIN11_25H2:
            default:
                Signature = g_ExpFindHost22631_27842;
                SignatureSize = sizeof(g_ExpFindHost22631_27842);
                break;

            }

            ptrCode = (PBYTE)supFindPattern(
                (PBYTE)ptrCode,
                SCAN_LIMIT_XXLARGE,
                Signature,
                SignatureSize);

            if (ptrCode == NULL)
                return 0;

            Index = SignatureSize;
            Rel = 0;

            do {
                hde64_disasm(ptrCode + Index, &hs);
                if (hs.flags & F_ERROR)
                    break;

                //
               // Find call instruction.
               //
                if (hs.len == 5 && hs.opcode == 0xE8) {
                    Rel = (LONG)hs.imm.imm32;
                    break;
                }

                Index += hs.len;

            } while (Index < SCAN_LIMIT_NEAR);

        }
        else {

            do {

                hde64_disasm(ptrCode + Index, &hs);
                if (hs.flags & F_ERROR)
                    break;

                //
                // Find second call instruction.
                //
                if (hs.len == 5 && hs.opcode == 0xE8)
                    c++;

                if (c > 1) {
                    Rel = (LONG)hs.imm.imm32;
                    break;
                }

                Index += hs.len;

            } while (Index < SCAN_LIMIT_LARGE);
        }

        if (Rel == 0) {
            logAdd(EntryTypeWarning, TEXT("ExpFindHost relative offset is not found"));
            return 0;
        }

        //
        // Examine ExpFindHost
        //
        ptrCode = ptrCode + Index + 5 + Rel;

        hde64_disasm(ptrCode, &hs);
        if (hs.flags & F_ERROR)
            return 0;

        if (hs.len == 7) {
            //
            // mov     rax, cs:ExpHostList
            //
            if (ptrCode[1] == 0x8B) {
                Rel = *(PLONG)(ptrCode + 3);
                kvarAddress = kdAdjustAddressToNtOsBase((ULONG_PTR)ptrCode,
                    0,
                    hs.len,
                    Rel);
            }
        }
    }

    return kvarAddress;
}

/*
* FindExpCallbackListHead
*
* Purpose:
*
* Returns the address of ExpCallbackListHead for callbacks registered with:
*
*   ExCreateCallback
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindExpCallbackListHead)
{
    ULONG Index;
    LONG Rel;
    PBYTE ptrCode;
    hde64s hs;

    UNREFERENCED_PARAMETER(QueryFlags);

    if (g_NtBuildNumber < NT_WIN8_BLUE)
        return 0;

    ptrCode = (PBYTE)GetProcAddress((HMODULE)g_kdctx.NtOsImageMap, "ExCreateCallback");
    if (ptrCode == NULL)
        return 0;

    Index = 0;
    Rel = 0;

    do {
        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == LEA_INSTRUCTION_LENGTH_7B
            && (hs.flags & (F_PREFIX_REX | F_DISP32 | F_MODRM)) == (F_PREFIX_REX | F_DISP32 | F_MODRM))
        {
            if (((ptrCode[Index] == 0x48) || (ptrCode[Index] == 0x4C)) &&
                (ptrCode[Index + 1] == 0x8D) &&
                ((ptrCode[Index + 2] == 0x15) || (ptrCode[Index + hs.len + 3] == 0x28))) // add/lea with +0x28 = offset of object's ExpCallbackList
            {
                Rel = (LONG)hs.disp.disp32;
                break;
            }
        }

        Index += hs.len;

    } while (Index < SCAN_LIMIT_LARGE);

    return ComputeAddressInsideNtOs((ULONG_PTR)ptrCode, Index, hs.len, Rel);
}

/*
* FindPoCoalescingCallbacks
*
* Purpose:
*
* Returns the address of PopCoalescingCallbackRoutine array or
* PopCoalRegistrationList list head for callbacks registered with:
*
*   PoRegisterCoalescingCallback
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindPoCoalescingCallbacks)
{
    ULONG Index;
    LONG Rel;
    PBYTE ptrCode;
    hde64s hs;
    LPCWSTR lpSymbolName;
    BYTE checkByte;
    ULONG_PTR kvarAddress = 0;

    UNREFERENCED_PARAMETER(QueryFlags);

    //
    // Not available before Windows 8.
    //
    if (g_NtBuildNumber < NT_WIN8_BLUE)
        return 0;

    if (g_NtBuildNumber < NT_WIN10_REDSTONE4) {
        lpSymbolName = KVAR_PopCoalescingCallbackRoutine;
        checkByte = 0x0D;
    }
    else {
        lpSymbolName = KVAR_PopCoalRegistrationList;
        checkByte = 0x15;
    }

    if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {
        kdGetAddressFromSymbol(&g_kdctx,
            lpSymbolName,
            &kvarAddress);
    }

    if (kvarAddress == 0) {
        ptrCode = (PBYTE)GetProcAddress((HMODULE)g_kdctx.NtOsImageMap, "PoRegisterCoalescingCallback");
        if (ptrCode == NULL)
            return 0;

        Index = 0;
        Rel = 0;

        do {

            hde64_disasm(ptrCode + Index, &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == LEA_INSTRUCTION_LENGTH_7B) { //check if lea

                if ((ptrCode[Index] == 0x48) &&
                    (ptrCode[Index + 1] == 0x8D) &&
                    (ptrCode[Index + 2] == checkByte)) //universal for both types of implementation
                {
                    Rel = (LONG)hs.disp.disp32;
                    break;
                }
            }

            Index += hs.len;

        } while (Index < SCAN_LIMIT_MEDIUM);

        kvarAddress = ComputeAddressInsideNtOs((ULONG_PTR)ptrCode, Index, hs.len, Rel);
    }

    return kvarAddress;
}

/*
* FindPspPicoProviderRoutines
*
* Purpose:
*
* Returns the address of PspPicoProviderRoutines array of callbacks registered with:
*
*   PsRegisterPicoProvider
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindPspPicoProviderRoutines)
{
    ULONG Index;
    LONG Rel;
    PBYTE ptrCode;
    hde64s hs;
    ULONG_PTR kvarAddress = 0;

    UNREFERENCED_PARAMETER(QueryFlags);

    //
    // Not available prior Win 10 and in Win10 TH2.
    //
    if (g_NtBuildNumber < NT_WIN10_THRESHOLD1 ||
        g_NtBuildNumber == NT_WIN10_THRESHOLD2)
    {
        return 0;
    }

    if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {
        kdGetAddressFromSymbol(&g_kdctx,
            KVAR_PspPicoProviderRoutines,
            &kvarAddress);
    }

    if (kvarAddress == 0) {
        ptrCode = (PBYTE)GetProcAddress((HMODULE)g_kdctx.NtOsImageMap, "PsRegisterPicoProvider");
        if (ptrCode == NULL)
            return 0;

        Index = 0;
        Rel = 0;

        do {

            hde64_disasm(ptrCode + Index, &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == 7) { //check if movups

                if ((ptrCode[Index] == 0x0F) &&
                    (ptrCode[Index + 1] == 0x11) &&
                    (ptrCode[Index + 2] == 0x05))
                {
                    Rel = *(PLONG)(ptrCode + Index + 3);
                    break;
                }
            }

            Index += hs.len;

        } while (Index < SCAN_LIMIT_MEDIUM);

        kvarAddress = ComputeAddressInsideNtOs((ULONG_PTR)ptrCode, Index, hs.len, Rel);
    }

    return kvarAddress;
}

/*
* FindKiNmiCallbackListHead
*
* Purpose:
*
* Returns the address of KiNmiCallbackListHead for callbacks registered with:
*
*   KeRegisterNmiCallback
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindKiNmiCallbackListHead)
{
    ULONG Index, c;
    LONG Rel;
    PBYTE ptrCode;
    hde64s hs;
    ULONG_PTR kvarAddress = 0;

    UNREFERENCED_PARAMETER(QueryFlags);

    //
    // Don't want to bother with support of such legacy code 
    // as we need support for only LTSB/C legacy stuff.
    //
    if (g_NtBuildNumber < NT_WIN10_THRESHOLD1)
        return 0;

    if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {
        kdGetAddressFromSymbol(&g_kdctx,
            KVAR_KiNmiCallbackListHead,
            &kvarAddress);
    }

    if (kvarAddress == 0) {
        ptrCode = (PBYTE)GetProcAddress((HMODULE)g_kdctx.NtOsImageMap, "KeDeregisterNmiCallback");
        if (ptrCode == NULL)
            return 0;

        Index = 0;
        Rel = 0;

        if (g_NtBuildNumber < NT_WIN10_REDSTONE3) {

            c = 0;

            do {

                hde64_disasm(&ptrCode[Index], &hs);
                if (hs.flags & F_ERROR)
                    break;

                if (hs.len == 7) {

                    if (ptrCode[Index] == 0x48 &&
                        ptrCode[Index + 1] == 0x8D &&
                        ptrCode[Index + 2] == 0x0D)
                    {
                        c += 1;
                    }
                }

                if (c > 2) {
                    Rel = *(PLONG)(ptrCode + Index + 3);
                    break;
                }

                Index += hs.len;

            } while (Index < SCAN_LIMIT_MEDIUM);
        }
        else {

            do {
                hde64_disasm(ptrCode + Index, &hs);
                if (hs.flags & F_ERROR)
                    break;

                //
                // Find KiDeregisterNmiSxCallback.
                //
                if (hs.len == 5 && hs.opcode == 0xE8) {
                    Rel = (LONG)hs.imm.imm32;
                    break;
                }

                Index += hs.len;

            } while (Index < SCAN_LIMIT_NEAR);

            if (Rel != 0) {

                ptrCode = ptrCode + Index + hs.len + Rel;
                Index = 0;
                Rel = 0;
                c = 0;

                //
                // Scan KiDeregisterNmiSxCallback.
                //
                do {

                    hde64_disasm(&ptrCode[Index], &hs);
                    if (hs.flags & F_ERROR)
                        break;

                    if (hs.len == 7) {

                        if (ptrCode[Index] == 0x48 &&
                            ptrCode[Index + 1] == 0x8D &&
                            ptrCode[Index + 2] == 0x0D)
                        {
                            c += 1;
                        }
                    }

                    //
                    // Second lea is ours.
                    //
                    if (c > 1) {
                        Rel = *(PLONG)(ptrCode + Index + 3);
                        break;
                    }

                    Index += hs.len;
                } while (Index < SCAN_LIMIT_SMALL);
            }
        }
        kvarAddress = ComputeAddressInsideNtOs((ULONG_PTR)ptrCode, Index, hs.len, Rel);
    }

    return kvarAddress;
}

/*
* FindPspSiloMonitorList
*
* Purpose:
*
* Returns the address of PspSiloMonitorList for callbacks registered with:
*
*   PsRegisterSiloMonitor
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindPspSiloMonitorList)
{
    ULONG Index;
    LONG Rel;
    PBYTE ptrCode;
    hde64s hs;
    ULONG_PTR kvarAddress = 0;

    UNREFERENCED_PARAMETER(QueryFlags);

    //
    // Not available prior Windows 10 RS3.
    //
    if (g_NtBuildNumber < NT_WIN10_REDSTONE3)
        return 0;

    if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {
        kdGetAddressFromSymbol(&g_kdctx,
            KVAR_PspSiloMonitorList,
            &kvarAddress);
    }

    if (kvarAddress == 0) {
        ptrCode = (PBYTE)GetProcAddress((HMODULE)g_kdctx.NtOsImageMap, "PsStartSiloMonitor");
        if (ptrCode == NULL)
            return 0;

        Index = 0;
        Rel = 0;

        //
        // Search for PspSiloMonitorList.
        //

        do {

            hde64_disasm(ptrCode + Index, &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == 7) {

                if (ptrCode[Index] == 0x48 &&
                    ptrCode[Index + 1] == 0x8D &&
                    ptrCode[Index + 2] == 0x0D &&
                    ptrCode[Index + hs.len] == 0x48)
                {
                    Rel = *(PLONG)(ptrCode + Index + 3);
                    break;
                }
            }

            Index += hs.len;

        } while (Index < SCAN_LIMIT_LARGE);

        kvarAddress = ComputeAddressInsideNtOs((ULONG_PTR)ptrCode, Index, hs.len, Rel);
    }

    return kvarAddress;
}

/*
* FindEmpCallbackListHead
*
* Purpose:
*
* Returns the address of EmpCallbackListHead for callbacks registered with:
*
*   EmProviderRegister
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindEmpCallbackListHead)
{
    ULONG Index;
    LONG Rel;
    PBYTE ptrCode;
    hde64s hs;
    ULONG_PTR kvarAddress = 0;

    PVOID SectionBase;
    ULONG SectionSize = 0, SignatureSize = 0;
    PBYTE Signature = NULL;

    UNREFERENCED_PARAMETER(QueryFlags);

    if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {
        kdGetAddressFromSymbol(&g_kdctx,
            KVAR_EmpCallbackListHead,
            &kvarAddress);
    }

    if (kvarAddress == 0) {

        //
        // Locate PAGE image section as required variable is always in PAGE.
        //
        SectionBase = supLookupImageSectionByName(
            PAGE_SECTION,
            PAGE_SECTION_LENGTH,
            g_kdctx.NtOsImageMap,
            &SectionSize);

        if ((SectionBase == 0) || (SectionSize == 0))
            return 0;

        if (g_NtBuildNumber < NT_WIN8_BLUE) {
            Signature = g_EmpSearchCallbackDatabase;
            SignatureSize = sizeof(g_EmpSearchCallbackDatabase);
        }
        else {
            if (g_NtBuildNumber <= NT_WIN11_23H2) {
                Signature = g_EmpSearchCallbackDatabase2;
                SignatureSize = sizeof(g_EmpSearchCallbackDatabase2);
            }
            else if (g_NtBuildNumber >= NT_WIN11_24H2) {
                Signature = g_EmpSearchCallbackDatabase3;
                SignatureSize = sizeof(g_EmpSearchCallbackDatabase3);
            }
            else {
                return 0; // this is general fuckup.
            }
        }

        ptrCode = (PBYTE)supFindPattern(
            (PBYTE)SectionBase,
            SectionSize,
            Signature,
            SignatureSize);

        if (ptrCode == NULL)
            return 0;

        Index = SignatureSize;
        Rel = 0;

        do {

            hde64_disasm(ptrCode + Index, &hs);
            if (hs.flags & F_ERROR)
                break;

            //
            // Find EmpSearchCallbackDatabase.
            //
            if (hs.len == 5 && hs.opcode == 0xE8) {
                Rel = (LONG)hs.imm.imm32;
                break;
            }

            Index += hs.len;

        } while (Index < SCAN_LIMIT_NEAR);

        if (Rel != 0) {

            ptrCode = ptrCode + Index + hs.len + Rel;
            Index = 0;
            Rel = 0;

            do {

                hde64_disasm(ptrCode + Index, &hs);
                if (hs.flags & F_ERROR)
                    break;

                if (hs.len == 7) {

                    if (ptrCode[Index] == 0x48) {
                        Rel = *(PLONG)(ptrCode + Index + 3);
                        break;
                    }
                }

                Index += hs.len;

            } while (Index < 32);

        }

        kvarAddress = ComputeAddressInsideNtOs((ULONG_PTR)ptrCode, Index, hs.len, Rel);
    }

    return kvarAddress;
}

/*
* FindPnpDeviceClassNotifyList
*
* Purpose:
*
* Returns the address of PnpDeviceClassNotifyList  for callbacks registered with:
*
*   IoRegisterPlugPlayNotification
*
*/
OBEX_FINDCALLBACK_ROUTINE(FindPnpDeviceClassNotifyList)
{
    ULONG Index;
    LONG Rel;
    PBYTE ptrCode;
    hde64s hs;
    ULONG_PTR kvarAddress = 0;

    ULONG SignatureSize = 0;
    PBYTE Signature = NULL;

    UNREFERENCED_PARAMETER(QueryFlags);

    if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {
        kdGetAddressFromSymbol(&g_kdctx,
            KVAR_PnpDeviceClassNotifyList,
            &kvarAddress);
    }

    if (kvarAddress == 0) {
        ptrCode = (PBYTE)GetProcAddress((HMODULE)g_kdctx.NtOsImageMap, "IoRegisterPlugPlayNotification");
        if (ptrCode == NULL)
            return 0;

        //
        // Find subpattern first.
        //

        switch (g_NtBuildNumber) {

        case NT_WIN7_RTM:
        case NT_WIN7_SP1:

            Signature = g_PnpDeviceClassNotifyList_SubPattern_7601;
            SignatureSize = sizeof(g_PnpDeviceClassNotifyList_SubPattern_7601);
            break;

        case NT_WIN8_RTM:
            Signature = g_PnpDeviceClassNotifyList_SubPattern_9200;
            SignatureSize = sizeof(g_PnpDeviceClassNotifyList_SubPattern_9200);
            break;

        default:
            Signature = g_PnpDeviceClassNofityList_SubPattern_9600_26080;
            SignatureSize = sizeof(g_PnpDeviceClassNofityList_SubPattern_9600_26080);
            break;
        }

        ptrCode = (PBYTE)supFindPattern(
            ptrCode,
            SCAN_LIMIT_XXLARGE,
            Signature,
            SignatureSize);

        if (ptrCode == NULL)
            return 0;

        Index = SignatureSize;
        Rel = 0;

        //
        // Find lea rcx, PnpDeviceClassNotifyList
        //

        do {

            hde64_disasm(ptrCode + Index, &hs);
            if (hs.flags & F_ERROR)
                break;

            if ((hs.len == LEA_INSTRUCTION_LENGTH_7B) &&
                (hs.flags & F_PREFIX_REX) &&
                (hs.flags & F_DISP32) &&
                (hs.flags & F_MODRM) &&
                (hs.opcode == 0x8D))
            {
                Rel = (LONG)hs.disp.disp32;
                break;
            }

            Index += hs.len;

        } while (Index < SCAN_LIMIT_NEAR);

        kvarAddress = ComputeAddressInsideNtOs((ULONG_PTR)ptrCode, Index, hs.len, Rel);
    }

    return kvarAddress;
}

/*
* AddRootEntryToList
*
* Purpose:
*
* Adds callback root entry to the treelist.
*
*/
HTREEITEM AddRootEntryToList(
    _In_ HWND TreeList,
    _In_ LPWSTR lpCallbackType
)
{
    return supTreeListAddItem(
        TreeList,
        NULL,
        TVIF_TEXT | TVIF_STATE,
        (UINT)0,
        (UINT)0,
        lpCallbackType,
        NULL);
}

/*
* AddParentEntryToList
*
* Purpose:
*
* Adds a parent entry for callbacks to the treelist.
*
*/
HTREEITEM AddParentEntryToList(
    _In_ HWND TreeList,
    _In_ HTREEITEM RootItem,
    _In_ ULONG_PTR CallbackObjectAddress,
    _In_ LPWSTR lpCallbackObjectType
)
{
    TL_SUBITEMS_FIXED TreeListSubItems;
    WCHAR szAddress[32];

    RtlSecureZeroMemory(&TreeListSubItems, sizeof(TreeListSubItems));
    TreeListSubItems.Count = 2;

    szAddress[0] = L'0';
    szAddress[1] = L'x';
    szAddress[2] = 0;
    u64tohex(CallbackObjectAddress, &szAddress[2]);
    TreeListSubItems.Text[0] = T_EmptyString;
    TreeListSubItems.Text[1] = lpCallbackObjectType;

    return supTreeListAddItem(
        TreeList,
        RootItem,
        TVIF_TEXT | TVIF_STATE,
        (UINT)0,
        (UINT)0,
        szAddress,
        &TreeListSubItems);
}

/*
* AddEntryToList
*
* Purpose:
*
* Adds callback entry to the treelist.
*
*/
VOID AddEntryToList(
    _In_ HWND TreeList,
    _In_ HTREEITEM RootItem,
    _In_ ULONG_PTR Function,
    _In_opt_ LPWSTR lpAdditionalInfo,
    _In_ PRTL_PROCESS_MODULES Modules
)
{
    ULONG moduleIndex = 0;
    TL_SUBITEMS_FIXED TreeListSubItems;
    WCHAR szAddress[32];
    WCHAR szBuffer[MAX_PATH + 1];

    RtlSecureZeroMemory(&TreeListSubItems, sizeof(TreeListSubItems));
    TreeListSubItems.Count = 2;

    szAddress[0] = L'0';
    szAddress[1] = L'x';
    szAddress[2] = 0;
    u64tohex(Function, &szAddress[2]);

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

    if (ntsupFindModuleEntryByAddress(
        Modules,
        (PVOID)Function,
        &moduleIndex))
    {
        if (MultiByteToWideChar(
            CP_ACP,
            0,
            (LPCSTR)&Modules->Modules[moduleIndex].FullPathName,
            -1,
            szBuffer,
            MAX_PATH) == 0)
        {
            _strcpy(szBuffer, TEXT("Unknown Module"));
        }
    }
    else {
        _strcpy(szBuffer, TEXT("Unknown Module"));
    }

    TreeListSubItems.Text[0] = szBuffer;
    if (lpAdditionalInfo) {
        TreeListSubItems.Text[1] = lpAdditionalInfo;
    }
    else {
        TreeListSubItems.Text[1] = T_EmptyString;
    }

    supTreeListAddItem(
        TreeList,
        RootItem,
        TVIF_TEXT | TVIF_STATE,
        (UINT)0,
        (UINT)0,
        szAddress,
        &TreeListSubItems);

    g_CallbacksCount += 1;
}

/*
* AddEmptyEntryToList
*
* Purpose:
*
* Adds empty callback entry to the treelist.
*
*/
VOID AddEmptyEntryToList(
    _In_ HWND TreeList,
    _In_ HTREEITEM RootItem,
    _In_opt_ LPWSTR lpAdditionalInfo
)
{
    TL_SUBITEMS_FIXED TreeListSubItems;
    WCHAR szAddress[32];

    RtlSecureZeroMemory(&TreeListSubItems, sizeof(TreeListSubItems));
    TreeListSubItems.Count = 2;

    szAddress[0] = L'0';
    szAddress[1] = L'x';
    u64tohex(0, &szAddress[2]);

    TreeListSubItems.Text[0] = T_EmptyString;
    if (lpAdditionalInfo) {
        TreeListSubItems.Text[1] = lpAdditionalInfo;
    }
    else {
        TreeListSubItems.Text[1] = T_EmptyString;
    }

    supTreeListAddItem(
        TreeList,
        RootItem,
        TVIF_TEXT | TVIF_STATE,
        (UINT)0,
        (UINT)0,
        szAddress,
        &TreeListSubItems);
}

/*
* DumpPsCallbacks
*
* Purpose:
*
* Read Psp* callback data from kernel and send it to output window.
*
*/
OBEX_DISPLAYCALLBACK_ROUTINE(DumpPsCallbacks)
{
    ULONG c;
    ULONG_PTR Address, Function;
    EX_FAST_REF Callbacks[PspNotifyRoutinesLimit];
    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, CallbackType);
    if (RootItem == 0)
        return;

    RtlSecureZeroMemory(Callbacks, sizeof(Callbacks));
    if (kdReadSystemMemory(KernelVariableAddress,
        &Callbacks, sizeof(Callbacks)))
    {
        for (c = 0; c < PspNotifyRoutinesLimit; c++) {

            if (Callbacks[c].Value) {

                Address = (ULONG_PTR)ObGetObjectFastReference(Callbacks[c]);
                Function = (ULONG_PTR)ObGetCallbackBlockRoutine((PVOID)Address);
                if (Function < g_kdctx.SystemRangeStart)
                    continue;

                AddEntryToList(TreeList,
                    RootItem,
                    Function,
                    NULL,
                    Modules);
            }
        }
    }
}

/*
* DumpDbgkLCallbacks
*
* Purpose:
*
* Read DbgkL* callback data from kernel and send it to output window.
*
*/
OBEX_DISPLAYCALLBACK_ROUTINE(DumpDbgkLCallbacks)
{
    ULONG c;
    ULONG_PTR Address, Function;
    EX_FAST_REF Callbacks[DbgkLmdCount];
    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, CallbackType);
    if (RootItem == 0)
        return;

    RtlSecureZeroMemory(Callbacks, sizeof(Callbacks));
    if (kdReadSystemMemory(KernelVariableAddress,
        &Callbacks, sizeof(Callbacks)))
    {
        for (c = 0; c < DbgkLmdCount; c++) {
            if (Callbacks[c].Value > g_kdctx.SystemRangeStart) {
                Address = (ULONG_PTR)ObGetObjectFastReference(Callbacks[c]);
                Function = (ULONG_PTR)ObGetCallbackBlockRoutine((PVOID)Address);
                if (Function < g_kdctx.SystemRangeStart)
                    continue;

                AddEntryToList(TreeList,
                    RootItem,
                    Function,
                    NULL,
                    Modules);
            }
        }
    }
}

/*
* DumpPsAltSystemCallHandlers
*
* Purpose:
*
* Read PsAltSystemCallHandlers data from kernel and send it to output window.
*
*/
OBEX_DISPLAYCALLBACK_ROUTINE(DumpPsAltSystemCallHandlers)
{
    ULONG i;
    ULONG_PTR AltSystemCallHandlers[MAX_ALT_SYSTEM_CALL_HANDLERS];
    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, CallbackType);
    if (RootItem == 0)
        return;

    RtlSecureZeroMemory(AltSystemCallHandlers, sizeof(AltSystemCallHandlers));
    if (kdReadSystemMemory(KernelVariableAddress,
        &AltSystemCallHandlers, sizeof(AltSystemCallHandlers)))
    {
        for (i = 0; i < MAX_ALT_SYSTEM_CALL_HANDLERS; i++) {
            if (AltSystemCallHandlers[i] > g_kdctx.SystemRangeStart) {

                AddEntryToList(TreeList,
                    RootItem,
                    AltSystemCallHandlers[i],
                    NULL,
                    Modules);
            }
        }
    }
}

/*
* DumpKeBugCheckCallbacks
*
* Purpose:
*
* Read KeBugCheck callback data from kernel and send it to output window.
*
*/
OBEX_DISPLAYCALLBACK_ROUTINE(DumpKeBugCheckCallbacks)
{
    ULONG_PTR ListHead = KernelVariableAddress;
    SIZE_T GuardIter = 0;
    LIST_ENTRY ListEntry;
    KBUGCHECK_CALLBACK_RECORD CallbackRecord;
    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, CallbackType);
    if (RootItem == 0)
        return;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemory(
        ListHead,
        &ListEntry,
        sizeof(LIST_ENTRY)))
    {
        return;
    }

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {
        LIST_ITERATION_GUARD(GuardIter);
        RtlSecureZeroMemory(&CallbackRecord, sizeof(CallbackRecord));

        if (!kdReadSystemMemory((ULONG_PTR)ListEntry.Flink,
            &CallbackRecord,
            sizeof(CallbackRecord)))
        {
            break;
        }

        AddEntryToList(TreeList,
            RootItem,
            (ULONG_PTR)CallbackRecord.CallbackRoutine,
            NULL,
            Modules);

        if (!SET_NEXT_FLINK_CHECK(ListEntry, CallbackRecord.Entry.Flink, "KeBugCheckCallbacks NULL Flink"))
            break;
    }
}

/*
* KeBugCheckReasonToString
*
* Purpose:
*
* Return Reason as text constant.
*
*/
LPWSTR KeBugCheckReasonToString(
    _In_ KBUGCHECK_CALLBACK_REASON Reason)
{
    switch (Reason) {
    case KbCallbackInvalid:
        return TEXT("KbCallbackInvalid");

    case KbCallbackReserved1:
        return TEXT("KbCallbackReserved1");

    case KbCallbackSecondaryDumpData:
        return TEXT("KbCallbackSecondaryDumpData");

    case KbCallbackDumpIo:
        return TEXT("KbCallbackDumpIo");

    case KbCallbackAddPages:
        return TEXT("KbCallbackAddPages");

    case KbCallbackSecondaryMultiPartDumpData:
        return TEXT("KbCallbackSecondaryMultiPartDumpData");

    case KbCallbackRemovePages:
        return TEXT("KbCallbackRemovePages");
    case KbCallbackTriageDumpData:
        return TEXT("KbCallbackTriageDumpData");

    }
    return NULL;
}

/*
* DumpKeBugCheckReasonCallbacks
*
* Purpose:
*
* Read KeBugCheckReason callback data from kernel and send it to output window.
*
*/
OBEX_DISPLAYCALLBACK_ROUTINE(DumpKeBugCheckReasonCallbacks)
{
    ULONG_PTR ListHead = KernelVariableAddress;
    SIZE_T GuardIter = 0;
    LIST_ENTRY ListEntry;
    KBUGCHECK_REASON_CALLBACK_RECORD CallbackRecord;
    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, CallbackType);
    if (RootItem == 0)
        return;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemory(
        ListHead,
        &ListEntry,
        sizeof(LIST_ENTRY)))
    {
        return;
    }

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {
        LIST_ITERATION_GUARD(GuardIter);
        RtlSecureZeroMemory(&CallbackRecord, sizeof(CallbackRecord));

        if (!kdReadSystemMemory((ULONG_PTR)ListEntry.Flink,
            &CallbackRecord,
            sizeof(CallbackRecord)))
        {
            break;
        }

        AddEntryToList(TreeList,
            RootItem,
            (ULONG_PTR)CallbackRecord.CallbackRoutine,
            KeBugCheckReasonToString(CallbackRecord.Reason),
            Modules);

        if (!SET_NEXT_FLINK_CHECK(ListEntry, CallbackRecord.Entry.Flink, "KeBugCheckReasonCallbacks NULL Flink"))
            break;
    }
}

/*
* DumpCmCallbacks
*
* Purpose:
*
* Read Cm Registry callback data from kernel and send it to output window.
*
*/
OBEX_DISPLAYCALLBACK_ROUTINE(DumpCmCallbacks)
{
    ULONG_PTR ListHead = KernelVariableAddress;
    SIZE_T GuardIter = 0;
    LIST_ENTRY ListEntry;
    CM_CALLBACK_CONTEXT_BLOCK CallbackRecord;
    HTREEITEM RootItem;
    WCHAR szCookie[100];

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, CallbackType);
    if (RootItem == 0)
        return;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemory(
        ListHead,
        &ListEntry,
        sizeof(LIST_ENTRY)))
    {
        return;
    }

    RtlSecureZeroMemory(&szCookie, sizeof(szCookie));

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {
        LIST_ITERATION_GUARD(GuardIter);
        RtlSecureZeroMemory(&CallbackRecord, sizeof(CallbackRecord));

        if (!kdReadSystemMemory((ULONG_PTR)ListEntry.Flink,
            &CallbackRecord,
            sizeof(CallbackRecord)))
        {
            break;
        }

        RtlStringCchPrintfSecure(szCookie,
            RTL_NUMBER_OF(szCookie),
            TEXT("Cookie: 0x%llX"),
            CallbackRecord.Cookie);

        AddEntryToList(TreeList,
            RootItem,
            (ULONG_PTR)CallbackRecord.Function,
            szCookie,
            Modules);

        if (!SET_NEXT_FLINK_CHECK(ListEntry, CallbackRecord.CallbackListEntry.Flink, "CmCallbacks NULL Flink"))
            break;
    }
}

/*
* DumpIoCallbacks
*
* Purpose:
*
* Read Io related callback data from kernel and send it to output window.
*
*/
OBEX_DISPLAYCALLBACK_ROUTINE(DumpIoCallbacks)
{
    ULONG_PTR ListHead = KernelVariableAddress;
    SIZE_T GuardIter = 0;
    LIST_ENTRY ListEntry;
    SHUTDOWN_PACKET EntryPacket;
    DEVICE_OBJECT DeviceObject;
    DRIVER_OBJECT DriverObject;
    PVOID Routine;
    LPWSTR lpDescription;
    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, CallbackType);
    if (RootItem == 0)
        return;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemory(
        ListHead,
        &ListEntry,
        sizeof(LIST_ENTRY)))
    {
        return;
    }

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {
        LIST_ITERATION_GUARD(GuardIter);
        RtlSecureZeroMemory(&EntryPacket, sizeof(EntryPacket));

        if (!kdReadSystemMemory(
            (ULONG_PTR)ListEntry.Flink,
            &EntryPacket,
            sizeof(EntryPacket)))
        {
            break;
        }

        Routine = EntryPacket.DeviceObject;
        lpDescription = TEXT("PDEVICE_OBJECT");

        //
        // Attempt to query owner of the device object.
        //
        if ((ULONG_PTR)EntryPacket.DeviceObject > g_kdctx.SystemRangeStart) {

            //
            // Read DEVICE_OBJECT.
            //
            RtlSecureZeroMemory(&DeviceObject, sizeof(DeviceObject));

            if (kdReadSystemMemory((ULONG_PTR)EntryPacket.DeviceObject,
                (PVOID)&DeviceObject,
                sizeof(DeviceObject)))
            {
                //
                // Read DRIVER_OBJECT.
                //
                RtlSecureZeroMemory(&DriverObject, sizeof(DriverObject));
                if (kdReadSystemMemory((ULONG_PTR)DeviceObject.DriverObject,
                    (PVOID)&DriverObject,
                    sizeof(DriverObject)))
                {
                    Routine = DriverObject.MajorFunction[IRP_MJ_SHUTDOWN];
                    lpDescription = TEXT("IRP_MJ_SHUTDOWN");
                }
            }
        }

        AddEntryToList(TreeList,
            RootItem,
            (ULONG_PTR)Routine,
            lpDescription,
            Modules);

        if (!SET_NEXT_FLINK_CHECK(ListEntry, EntryPacket.ListEntry.Flink, "IoShutdownCallbacks NULL Flink")) 
            break;
    }
}

VOID AddObCallbackEntry(
    _In_ HWND TreeList,
    _In_ HTREEITEM RootItem,
    _In_ LPWSTR CallbackType,
    _In_ PVOID Callback,
    _In_ OB_OPERATION CallbackOperation,
    _In_opt_ LPWSTR Altitude,
    _In_ SIZE_T AltitudeSize,
    _In_ PRTL_PROCESS_MODULES Modules
)
{
    LPWSTR lpText;
    SIZE_T Size;
    BOOL bAltitudePresent = (Altitude && AltitudeSize);

    Size = MAX_PATH * sizeof(WCHAR);
    if (bAltitudePresent)
        Size += AltitudeSize;

    lpText = (LPWSTR)supHeapAlloc(Size);
    if (lpText) {
        _strcpy(lpText, CallbackType);

        if (bAltitudePresent) {
            _strcat(lpText, TEXT(", Altitude: "));
            _strcat(lpText, Altitude);
        }

        if (CallbackOperation & OB_OPERATION_HANDLE_CREATE) _strcat(lpText, TEXT(", CreateHandle"));
        if (CallbackOperation & OB_OPERATION_HANDLE_DUPLICATE) _strcat(lpText, TEXT(", DuplicateHandle"));

        AddEntryToList(TreeList,
            RootItem,
            (ULONG_PTR)Callback,
            lpText,
            Modules);

        supHeapFree(lpText);
    }
}

/*
* DumpObCallbacks
*
* Purpose:
*
* Read Ob callback data from kernel and send it to output window.
*
*/
OBEX_DISPLAYCALLBACK_ROUTINE(DumpObCallbacks)
{
    ULONG_PTR ListHead = KernelVariableAddress;
    SIZE_T GuardIter = 0;
    LPWSTR lpAltitudeBuffer;
    SIZE_T AltitudeSize = 0;
    LIST_ENTRY ListEntry;
    OB_CALLBACK_CONTEXT_BLOCK CallbackEntry;
    OB_REGISTRATION RegEntry;
    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, CallbackType);
    if (RootItem == 0)
        return;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemory(
        ListHead,
        &ListEntry,
        sizeof(LIST_ENTRY)))
    {
        return;
    }

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {
        LIST_ITERATION_GUARD(GuardIter);

        lpAltitudeBuffer = NULL;
        RtlSecureZeroMemory(&CallbackEntry, sizeof(CallbackEntry));

        if (!kdReadSystemMemory((ULONG_PTR)ListEntry.Flink,
            &CallbackEntry,
            sizeof(OB_CALLBACK_CONTEXT_BLOCK)))
        {
            break;
        }

        //
        // Read Altitude.
        //
        RtlSecureZeroMemory(&RegEntry, sizeof(RegEntry));
        if (kdReadSystemMemory((ULONG_PTR)CallbackEntry.Registration,
            (PVOID)&RegEntry,
            sizeof(OB_REGISTRATION)))
        {
            AltitudeSize = 100 + (SIZE_T)RegEntry.Altitude.Length;
            lpAltitudeBuffer = (LPWSTR)supHeapAlloc(AltitudeSize);
            if (lpAltitudeBuffer) {
                if (!kdReadSystemMemory((ULONG_PTR)RegEntry.Altitude.Buffer,
                    (PVOID)lpAltitudeBuffer,
                    RegEntry.Altitude.Length))
                {
                    _strcpy(lpAltitudeBuffer, TEXT("Cannot read altitude"));
                }
            }
        }

        //
        // Output PreCallback.
        //
        if ((ULONG_PTR)CallbackEntry.PreCallback > g_kdctx.SystemRangeStart) {
            AddObCallbackEntry(TreeList,
                RootItem,
                TEXT("PreCallback"),
                CallbackEntry.PreCallback,
                CallbackEntry.Operations,
                lpAltitudeBuffer,
                AltitudeSize,
                Modules);
        }

        //
        // Output PostCallback.
        //
        if ((ULONG_PTR)CallbackEntry.PostCallback > g_kdctx.SystemRangeStart) {
            AddObCallbackEntry(TreeList,
                RootItem,
                TEXT("PostCallback"),
                CallbackEntry.PostCallback,
                CallbackEntry.Operations,
                lpAltitudeBuffer,
                AltitudeSize,
                Modules);
        }

        if (lpAltitudeBuffer) supHeapFree(lpAltitudeBuffer);
        if (!SET_NEXT_FLINK_CHECK(ListEntry, CallbackEntry.CallbackListEntry.Flink, "ObCallbacks NULL Flink"))
            break;
    }
}

/*
* DumpSeFileSystemCallbacks
*
* Purpose:
*
* Read Se related callback data from kernel and send it to output window.
*
*/
OBEX_DISPLAYCALLBACK_ROUTINE(DumpSeFileSystemCallbacks)
{
    ULONG_PTR Next;

    SEP_LOGON_SESSION_TERMINATED_NOTIFICATION SeEntry; // This structure is different for Ex variant but 
    // key callback function field is on the same offset.

    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, CallbackType);
    if (RootItem == 0)
        return;

    //
    // Read head.
    //
    RtlSecureZeroMemory(&SeEntry, sizeof(SeEntry));

    if (!kdReadSystemMemory(KernelVariableAddress,
        (PVOID)&SeEntry,
        sizeof(SeEntry)))
    {
        return;
    }

    //
    // Walk each entry in single linked list.
    //
    Next = (ULONG_PTR)SeEntry.Next;
    while (Next) {
        RtlSecureZeroMemory(&SeEntry, sizeof(SeEntry));
        if (!kdReadSystemMemory(Next,
            (PVOID)&SeEntry,
            sizeof(SeEntry)))
        {
            break;
        }

        AddEntryToList(TreeList,
            RootItem,
            (ULONG_PTR)SeEntry.CallbackRoutine,
            NULL,
            Modules);

        Next = (ULONG_PTR)SeEntry.Next;
    }
}

/*
* DumpPoCallbacks
*
* Purpose:
*
* Read Po callback data from kernel and send it to output window.
*
*/
OBEX_DISPLAYCALLBACK_ROUTINE(DumpPoCallbacks)
{
    LIST_ENTRY ListEntry;

    union {
        union {
            POP_POWER_SETTING_REGISTRATION_V1* v1;
            POP_POWER_SETTING_REGISTRATION_V2* v2;
        } Versions;
        PBYTE Ref;
    } CallbackData;

    ULONG ReadSize;
    ULONG_PTR ListHead = KernelVariableAddress;
    SIZE_T BufferSize, GuardIter = 0;
    LPWSTR GuidString;
    PVOID Buffer = NULL;
    PVOID CallbackRoutine = NULL;

    GUID EntryGuid;
    UNICODE_STRING ConvertedGuid;

    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, CallbackType);
    if (RootItem == 0)
        return;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Determinate size of structure to read.
    //
    ReadSize = (g_NtBuildNumber >= NT_WIN10_REDSTONE1) ? sizeof(POP_POWER_SETTING_REGISTRATION_V2) : sizeof(POP_POWER_SETTING_REGISTRATION_V1);

    do {
        //
        // Allocate read buffer with enough size.
        // 
        BufferSize = sizeof(POP_POWER_SETTING_REGISTRATION_V1) + sizeof(POP_POWER_SETTING_REGISTRATION_V2);
        Buffer = supHeapAlloc(BufferSize);
        if (Buffer == NULL)
            break;

        CallbackData.Ref = (PBYTE)Buffer;

        //
        // Read head.
        //
        if (!kdReadSystemMemory(
            ListHead,
            &ListEntry,
            sizeof(LIST_ENTRY)))
        {
            break;
        }

        //
        // Walk list entries.
        //
        while ((ULONG_PTR)ListEntry.Flink != ListHead) {
            LIST_ITERATION_GUARD(GuardIter);
            RtlSecureZeroMemory(Buffer, BufferSize);

            if (!kdReadSystemMemory((ULONG_PTR)ListEntry.Flink,
                Buffer,
                ReadSize))
            {
                break;
            }

            //
            // Is valid registration entry?
            //
            if (CallbackData.Versions.v1->Tag != PO_POWER_SETTINGS_REGISTRATION_TAG)
                break;

            if (ReadSize == sizeof(POP_POWER_SETTING_REGISTRATION_V2)) {
                CallbackRoutine = CallbackData.Versions.v2->Callback;
                EntryGuid = CallbackData.Versions.v2->Guid;
            }
            else {
                CallbackRoutine = CallbackData.Versions.v1->Callback;
                EntryGuid = CallbackData.Versions.v1->Guid;
            }

            if (CallbackRoutine) {

                if (NT_SUCCESS(RtlStringFromGUID(&EntryGuid, &ConvertedGuid)))
                    GuidString = ConvertedGuid.Buffer;
                else
                    GuidString = NULL;

                AddEntryToList(TreeList,
                    RootItem,
                    (ULONG_PTR)CallbackRoutine,
                    GuidString,
                    Modules);

                if (GuidString)
                    RtlFreeUnicodeString(&ConvertedGuid);

            }

            //
            // Next item address, ListEntry offset version independent.
            //
            if (!SET_NEXT_FLINK_CHECK(ListEntry, CallbackData.Versions.v1->Link.Flink, "PoCallbacks NULL Flink"))
                break;
        }

    } while (FALSE);

    if (Buffer) supHeapFree(Buffer);
}

/*
* DumpDbgPrintCallbacks
*
* Purpose:
*
* Read Dbg callback data from kernel and send it to output window.
*
*/
OBEX_DISPLAYCALLBACK_ROUTINE(DumpDbgPrintCallbacks)
{
    ULONG_PTR ListHead = KernelVariableAddress;
    ULONG_PTR RecordAddress;
    SIZE_T GuardIter = 0;
    LIST_ENTRY ListEntry;
    RTL_CALLBACK_REGISTER CallbackRecord;
    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, CallbackType);
    if (RootItem == 0)
        return;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemory(
        ListHead,
        &ListEntry,
        sizeof(ListEntry)))
    {
        return;
    }

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {
        LIST_ITERATION_GUARD(GuardIter);

        RtlSecureZeroMemory(&CallbackRecord, sizeof(CallbackRecord));
        RecordAddress = (ULONG_PTR)ListEntry.Flink - FIELD_OFFSET(RTL_CALLBACK_REGISTER, ListEntry);
        if (!kdReadSystemMemory((ULONG_PTR)RecordAddress,
            &CallbackRecord,
            sizeof(CallbackRecord)))
        {
            break;
        }

        if (CallbackRecord.DebugPrintCallback) {
            AddEntryToList(TreeList,
                RootItem,
                (ULONG_PTR)CallbackRecord.DebugPrintCallback,
                NULL,
                Modules);
        }

        if (!SET_NEXT_FLINK_CHECK(ListEntry, CallbackRecord.ListEntry.Flink, "DbgPrintCallbacks NULL Flink"))
            break;
    }
}

/*
* DumpIoFsRegistrationCallbacks
*
* Purpose:
*
* Read Io File System registration related callback data from kernel and send it to output window.
*
*/
OBEX_DISPLAYCALLBACK_ROUTINE(DumpIoFsRegistrationCallbacks)
{
    SIZE_T GuardIter = 0;
    LIST_ENTRY ListEntry;
    NOTIFICATION_PACKET CallbackRecord;
    ULONG_PTR ListHead = KernelVariableAddress;
    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, CallbackType);
    if (RootItem == 0)
        return;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemory(
        ListHead,
        &ListEntry,
        sizeof(LIST_ENTRY)))
    {
        return;
    }

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {
        LIST_ITERATION_GUARD(GuardIter);
        RtlSecureZeroMemory(&CallbackRecord, sizeof(CallbackRecord));

        if (!kdReadSystemMemory((ULONG_PTR)ListEntry.Flink,
            &CallbackRecord,
            sizeof(CallbackRecord)))
        {
            break;
        }

        if (CallbackRecord.NotificationRoutine) {
            AddEntryToList(TreeList,
                RootItem,
                (ULONG_PTR)CallbackRecord.NotificationRoutine,
                NULL,
                Modules);
        }

        if (!SET_NEXT_FLINK_CHECK(ListEntry, CallbackRecord.ListEntry.Flink, "IoFsRegistrationCallbacks NULL Flink"))
            break;
    }
}

/*
* DumpIoFileSystemCallbacks
*
* Purpose:
*
* Read Io File System related callback data from kernel and send it to output window.
*
*/
OBEX_DISPLAYCALLBACK_ROUTINE(DumpIoFileSystemCallbacks)
{
    BOOL bNeedFree;
    SIZE_T GuardIter = 0;
    LIST_ENTRY ListEntry, NextEntry;
    ULONG_PTR ListHead = KernelVariableAddress;
    ULONG_PTR DeviceObjectAddress = 0, BaseAddress = 0;
    DEVICE_OBJECT DeviceObject;
    DRIVER_OBJECT DriverObject;
    LPWSTR lpType;
    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, CallbackType);
    if (RootItem == 0)
        return;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemory(
        ListHead,
        &ListEntry,
        sizeof(LIST_ENTRY)))
    {
        return;
    }

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {
        LIST_ITERATION_GUARD(GuardIter);
        RtlSecureZeroMemory(&DeviceObject, sizeof(DeviceObject));

        DeviceObjectAddress = (ULONG_PTR)ListEntry.Flink - FIELD_OFFSET(DEVICE_OBJECT, Queue);

        //
        // Read DEVICE_OBJECT.
        //
        if (!kdReadSystemMemory(DeviceObjectAddress,
            &DeviceObject,
            sizeof(DeviceObject)))
        {
            break;
        }

        //
        // Additional info column default text.
        //
        lpType = TEXT("PDEVICE_OBJECT");
        BaseAddress = DeviceObjectAddress;
        bNeedFree = FALSE;

        //
        // Read DRIVER_OBJECT.
        //
        RtlSecureZeroMemory(&DriverObject, sizeof(DriverObject));
        if (kdReadSystemMemory((ULONG_PTR)DeviceObject.DriverObject,
            &DriverObject,
            sizeof(DriverObject)))
        {
            //
            // Determinate address to display.
            //
            BaseAddress = (ULONG_PTR)DriverObject.DriverInit;
            if (BaseAddress == 0) {
                BaseAddress = (ULONG_PTR)DriverObject.DriverStart;
            }

            lpType = NULL;

            //
            // Read DRIVER_OBJECT name.
            //
            if (DriverObject.DriverName.Length &&
                DriverObject.DriverName.MaximumLength &&
                DriverObject.DriverName.Buffer)
            {
                lpType = (LPWSTR)supHeapAlloc((SIZE_T)DriverObject.DriverName.Length + sizeof(UNICODE_NULL));
                if (lpType) {
                    bNeedFree = TRUE;
                    if (!kdReadSystemMemory((ULONG_PTR)DriverObject.DriverName.Buffer,
                        lpType,
                        (ULONG)DriverObject.DriverName.Length))
                    {
                        supHeapFree(lpType);
                        lpType = NULL;
                        bNeedFree = FALSE;
                    }
                }
            }
        }

        AddEntryToList(TreeList,
            RootItem,
            BaseAddress,
            lpType, //PDEVICE_OBJECT or DRIVER_OBJECT.DriverName
            Modules);

        if (bNeedFree)
            supHeapFree(lpType);

        //
        // Next ListEntry.
        //
        NextEntry.Blink = NextEntry.Flink = NULL;

        if (!kdReadSystemMemory(
            (ULONG_PTR)ListEntry.Flink,
            &NextEntry,
            sizeof(LIST_ENTRY)))
        {
            break;
        }

        if (!SET_NEXT_FLINK_CHECK(ListEntry, NextEntry.Flink, "IoFileSystemCallbacks NULL Flink"))
            break;
    }
}

/*
* DumpCiCallbacks
*
* Purpose:
*
* Read SeCiCallbacks/g_CiCallbacks related callback data from kernel and send it to output window.
*
*/
OBEX_DISPLAYCALLBACK_ROUTINE(DumpCiCallbacks)
{
    HTREEITEM RootItem;
    PULONG_PTR CallbacksData, DataPtr;
    LPWSTR CallbackName;
    ULONG_PTR CallbacksSize = 0, EffectiveSize;
    ULONG i, c;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, CallbackType);
    if (RootItem == 0)
        return;

    if (g_NtBuildNumber <= NT_WIN7_SP1) {
        CallbacksSize = 3 * sizeof(ULONG_PTR);

        CallbacksData = (PULONG_PTR)supVirtualAlloc((SIZE_T)CallbacksSize);
        if (CallbacksData) {

            if (kdReadSystemMemory(KernelVariableAddress,
                CallbacksData,
                (ULONG)CallbacksSize))
            {
                c = (ULONG)(CallbacksSize / sizeof(ULONG_PTR));
                for (i = 0; i < c; i++) {

                    CallbackName = GetCiRoutineNameFromIndex(i, 0);
                    if (CallbacksData[i]) {
                        AddEntryToList(TreeList,
                            RootItem,
                            CallbacksData[i],
                            CallbackName,
                            Modules);
                    }
                }
            }
            supVirtualFree(CallbacksData);
        }
    }
    else {
        //
        // Probe size element.
        //
        if (!kdReadSystemMemory(KernelVariableAddress,
            &CallbacksSize,
            sizeof(ULONG_PTR)))
        {
            return;
        }

        //
        // Check size.
        //
        if ((CallbacksSize == 0) || (CallbacksSize > PAGE_SIZE))
            return;

        CallbacksData = (PULONG_PTR)supVirtualAlloc((SIZE_T)CallbacksSize);
        if (CallbacksData) {

            if (kdReadSystemMemory(KernelVariableAddress,
                CallbacksData,
                (ULONG)CallbacksSize))
            {
                /*
                * Windows 10/11 x64 structure layout
                *
                * CI_CALLBACKS
                *
                * +0   ULONG_PTR StructureSize (in bytes)
                * +8   PTR Callback1
                * ...
                * +N   PTR CallbackN
                * +N+8 ULONG_PTR Marker
                *
                */
                EffectiveSize = CallbacksSize;
                DataPtr = CallbacksData;

                // skip sizeof element
                DataPtr++;
                EffectiveSize -= sizeof(ULONG_PTR);

                if (g_NtBuildNumber >= NT_WIN10_REDSTONE1)
                    EffectiveSize -= sizeof(ULONG_PTR); //exclude final marker

                c = (ULONG)(EffectiveSize / sizeof(ULONG_PTR));

                for (i = 0; i < c; i++) {
                    CallbackName = GetCiRoutineNameFromIndex(i, CallbacksSize);
                    if (*DataPtr) {
                        AddEntryToList(TreeList,
                            RootItem,
                            *DataPtr,
                            CallbackName,
                            Modules);
                    }
                    DataPtr++;
                }
            }

            supVirtualFree(CallbacksData);
        }
    }
}

/*
* DumpExHostCallbacks
*
* Purpose:
*
* Read ExHostList related callback data from kernel and send it to output window.
*
*/
OBEX_DISPLAYCALLBACK_ROUTINE(DumpExHostCallbacks)
{
    ULONG HostEntrySize;
    SIZE_T GuardIter = 0;
    ULONG_PTR ListHead = KernelVariableAddress;
    ULONG_PTR* HostTableDump;
    ULONG NumberOfCallbacks, i;
    PVOID NotificationRoutine;
    PVOID FunctionTable, HostEntryBuffer = NULL;
    LIST_ENTRY ListEntry;
    HTREEITEM RootItem;

    union {
        union {
            EX_HOST_ENTRY_V1* v1;
            EX_HOST_ENTRY_V2* v2;
        } Versions;
        PBYTE Ref;
    } hostEntry;

    do {
        // Starting build 26080 (25H2) the structures were updated
        HostEntrySize = (g_NtBuildNumber < NT_WIN11_25H2) ? sizeof(EX_HOST_ENTRY_V1) : sizeof(EX_HOST_ENTRY_V2);
        HostEntryBuffer = supHeapAlloc(HostEntrySize);
        if (HostEntryBuffer == NULL)
            break;

        hostEntry.Ref = (PBYTE)HostEntryBuffer;

        //
        // Add callback root entry to the treelist.
        //
        RootItem = AddRootEntryToList(TreeList, CallbackType);
        if (RootItem == 0)
            break;

        ListEntry.Flink = ListEntry.Blink = NULL;

        //
        // Read head.
        //
        if (!kdReadSystemMemory(
            ListHead,
            &ListEntry,
            sizeof(LIST_ENTRY)))
        {
            break;
        }

        //
        // Walk list entries.
        //
        while ((ULONG_PTR)ListEntry.Flink != ListHead) {
            LIST_ITERATION_GUARD(GuardIter);
            //
            // Since this buffer now allocated, on a first call it will be empty. Zero it when iteration is over.
            //
            if (!kdReadSystemMemory((ULONG_PTR)ListEntry.Flink,
                HostEntryBuffer,
                HostEntrySize))
            {
                break;
            }

            // read extension function table
            if (g_NtBuildNumber < NT_WIN11_25H2) {
                NumberOfCallbacks = hostEntry.Versions.v1->HostParameters.HostInformation.FunctionCount;
                NotificationRoutine = hostEntry.Versions.v1->HostParameters.NotificationRoutine;
                FunctionTable = hostEntry.Versions.v1->FunctionTable;
            }
            else
            {
                NumberOfCallbacks = hostEntry.Versions.v2->ExtensionTableFunctionCount;
                NotificationRoutine = hostEntry.Versions.v2->NotificationRoutine;
                FunctionTable = hostEntry.Versions.v2->FunctionTable;
            }

            //
            // Find not an empty host table.
            //
            if (NumberOfCallbacks) {

                if (NotificationRoutine) {
                    AddEntryToList(TreeList,
                        RootItem,
                        (ULONG_PTR)NotificationRoutine,
                        L"NotificationRoutine",
                        Modules);

                }

                //
                // Read function table.
                //
                if (FunctionTable) {
                    HostTableDump = (ULONG_PTR*)supHeapAlloc(NumberOfCallbacks * sizeof(PVOID));
                    if (HostTableDump) {
                        if (kdReadSystemMemory(
                            (ULONG_PTR)FunctionTable,
                            HostTableDump,
                            NumberOfCallbacks * sizeof(PVOID)))
                        {

                            for (i = 0; i < NumberOfCallbacks; i++) {
                                if (HostTableDump[i]) {
                                    AddEntryToList(TreeList,
                                        RootItem,
                                        (ULONG_PTR)HostTableDump[i],
                                        L"Callback",
                                        Modules);
                                }
                            }

                        }
                        supHeapFree(HostTableDump);
                    }
                }
            }

            //
            // ListEntry is on the same offset.
            //
            if (!SET_NEXT_FLINK_CHECK(ListEntry, hostEntry.Versions.v1->ListEntry.Flink, "ExHostCallbacks NULL Flink"))
                break;

            RtlSecureZeroMemory(HostEntryBuffer, HostEntrySize);
        }

    } while (FALSE);

    if (HostEntryBuffer)
        supHeapFree(HostEntryBuffer);
}

/*
* DumpExpCallbackListCallbacks
*
* Purpose:
*
* Read ExCreateCallback created objects from kernel and send them to output window.
*
*/
OBEX_DISPLAYCALLBACK_ROUTINE(DumpExpCallbackListCallbacks)
{
    LIST_ENTRY ListEntry, NextEntry, RegistrationsListEntry;
    CALLBACK_OBJECT_V2 CallbackObject;
    CALLBACK_REGISTRATION CallbackRegistration;
    SIZE_T GuardIter = 0, GuardSubIter;
    ULONG_PTR ListHead = KernelVariableAddress, RegistrationsListHead;
    ULONG_PTR CallbackObjectAddress;
    HTREEITEM RootItem, SubItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, CallbackType);
    if (RootItem == 0)
        return;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemory(
        ListHead,
        &ListEntry,
        sizeof(LIST_ENTRY)))
    {
        return;
    }

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {
        LIST_ITERATION_GUARD(GuardIter);
        RtlSecureZeroMemory(&CallbackObject, sizeof(CallbackObject));

        CallbackObjectAddress = (ULONG_PTR)ListEntry.Flink - FIELD_OFFSET(CALLBACK_OBJECT_V2, ExpCallbackList);

        if (!kdReadSystemMemory(CallbackObjectAddress,
            &CallbackObject,
            sizeof(CallbackObject))
            ||
            CallbackObject.Signature != EX_CALLBACK_SIGNATURE)
        {
            break;
        }

        SubItem = AddParentEntryToList(
            TreeList,
            RootItem,
            CallbackObjectAddress,
            TEXT("Callback object"));
        if (SubItem == 0)
            break;

        //
        // Walk RegisteredCallbacks list entry.
        //
        GuardSubIter = 0;
        RegistrationsListHead = CallbackObjectAddress + FIELD_OFFSET(CALLBACK_OBJECT_V2, RegisteredCallbacks);
        RegistrationsListEntry.Flink = CallbackObject.RegisteredCallbacks.Flink;
        while ((ULONG_PTR)RegistrationsListEntry.Flink != RegistrationsListHead) {
            LIST_ITERATION_GUARD(GuardSubIter);
            //
            // Read callback registration data.
            //
            RtlSecureZeroMemory(&CallbackRegistration, sizeof(CallbackRegistration));
            if (!kdReadSystemMemory((ULONG_PTR)RegistrationsListEntry.Flink,
                (PVOID)&CallbackRegistration,
                sizeof(CallbackRegistration)))
            {
                break;
            }

            AddEntryToList(TreeList,
                SubItem,
                (ULONG_PTR)CallbackRegistration.CallbackFunction,
                TEXT("Callback registration"),
                Modules);

            if (!SET_NEXT_FLINK_CHECK(RegistrationsListEntry, CallbackRegistration.Link.Flink, "ExpCallbackRegistrationsList(1) NULL Flink"))
                break;
        }

        //
        // Next ListEntry.
        //
        NextEntry.Blink = NextEntry.Flink = NULL;

        if (!kdReadSystemMemory(
            (ULONG_PTR)ListEntry.Flink,
            &NextEntry,
            sizeof(LIST_ENTRY)))
        {
            break;
        }

        if (!SET_NEXT_FLINK_CHECK(ListEntry, NextEntry.Flink, "ExpCallbackRegistrationsList(2) NULL Flink"))
            break;
    }
}

/*
* DumpPoCoalescingCallbacks
*
* Purpose:
*
* Read PoRegisterCoalescingCallback created objects from kernel and send them to output window.
*
*/
OBEX_DISPLAYCALLBACK_ROUTINE(DumpPoCoalescingCallbacks)
{
    ULONG CallbacksCount, i;
    SIZE_T GuardIter = 0;
    ULONG_PTR ListHead = KernelVariableAddress;
    ULONG_PTR objectFastRef, callbackAddress;
    LIST_ENTRY ListEntry;

    union {
        PO_COALESCING_CALLBACK_V1 v1;
        PO_COALESCING_CALLBACK_V2 v2;
    } callbackObject;

    EX_FAST_REF Callbacks[PopCoalescingCallbackRoutineCount_V2];
    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, CallbackType);
    if (RootItem == 0)
        return;

    //
    // Before Win10 RS4 this list implemented as the array of the fixed size.
    //
    if (g_NtBuildNumber < NT_WIN10_REDSTONE4) {
        RtlSecureZeroMemory(Callbacks, sizeof(Callbacks));

        //
        // Before Win10 RS3 this list is limited to 8 callbacks.
        // In Win10 RS3 this list increased up to 32 callbacks.
        //
        CallbacksCount = (g_NtBuildNumber < NT_WIN10_REDSTONE3) ? PopCoalescingCallbackRoutineCount_V1 : PopCoalescingCallbackRoutineCount_V2;
        if (kdReadSystemMemory(KernelVariableAddress,
            &Callbacks,
            CallbacksCount * sizeof(EX_FAST_REF)))
        {
            for (i = 0; i < CallbacksCount; i++) {
                if (Callbacks[i].Value) {
                    objectFastRef = (ULONG_PTR)ObGetObjectFastReference(Callbacks[i]);
                    RtlSecureZeroMemory(&callbackObject, sizeof(callbackObject));

                    if (kdReadSystemMemory(objectFastRef,
                        &callbackObject.v1,
                        sizeof(callbackObject.v1)))
                    {
                        AddEntryToList(TreeList,
                            RootItem,
                            (ULONG_PTR)callbackObject.v1.Callback,
                            L"CoalescingCallback",
                            Modules);
                    }
                }
            }
        }
    }
    else
    {
        ListEntry.Flink = ListEntry.Blink = NULL;

        //
        // Read head.
        //
        if (!kdReadSystemMemory(
            ListHead,
            &ListEntry,
            sizeof(LIST_ENTRY)))
        {
            return;
        }

        //
        // Walk list entries.
        //
        while ((ULONG_PTR)ListEntry.Flink != ListHead) {
            LIST_ITERATION_GUARD(GuardIter);
            RtlSecureZeroMemory(&callbackObject, sizeof(callbackObject));

            callbackAddress = (ULONG_PTR)ListEntry.Flink - FIELD_OFFSET(PO_COALESCING_CALLBACK_V2, Link);
            if (!kdReadSystemMemory(callbackAddress,
                &callbackObject.v2,
                sizeof(callbackObject.v2)))
            {
                break;
            }

            AddEntryToList(TreeList,
                RootItem,
                (ULONG_PTR)callbackObject.v2.Callback,
                L"CoalescingCallback",
                Modules);

            if (!SET_NEXT_FLINK_CHECK(ListEntry, callbackObject.v2.Link.Flink, "CoalescingCallback NULL Flink"))
                break;
        }
    }
}

LPWSTR PspPicoProviderNameFromIndex(
    _In_ SIZE_T Index
)
{
    LPWSTR LxpNames[] = {
        L"PicoSystemCallDispatch",
        L"PicoThreadExit",
        L"PicoProcessExit",
        L"PicoDispatchException",
        L"PicoProcessTerminate",
        L"PicoWalkUserStack",
        L"LxpProtectedRanges",
        L"PicoGetAllocatedProcessImageName"
    };

    if (Index >= RTL_NUMBER_OF(LxpNames))
        return T_Unknown;

    return LxpNames[Index];
}

/*
* DumpPspPicoProviderRoutines
*
* Purpose:
*
* Read PspPicoProviderRoutines data from kernel and send them to output window.
*
*/
OBEX_DISPLAYCALLBACK_ROUTINE(DumpPspPicoProviderRoutines)
{
    SIZE_T i, c;
    PULONG_PTR picoRoutines;
    SIZE_T dataSize;
    HTREEITEM RootItem;

    if (!supIsLxssAvailable())
        return;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, CallbackType);
    if (RootItem == 0)
        return;

    dataSize = 0;
    if (kdReadSystemMemory(KernelVariableAddress,
        &dataSize,
        sizeof(dataSize)))
    {
        if (dataSize < 2 * sizeof(SIZE_T) ||
            dataSize > PAGE_SIZE)
        {
            return;
        }

        dataSize -= sizeof(SIZE_T); //exclude size element

        picoRoutines = (PULONG_PTR)supHeapAlloc(ALIGN_UP(dataSize, PULONG_PTR));
        if (picoRoutines) {
            if (kdReadSystemMemory(KernelVariableAddress + sizeof(SIZE_T),
                picoRoutines,
                (ULONG)dataSize))
            {
                c = dataSize / sizeof(ULONG_PTR);
                for (i = 0; i < c; i++) {
                    if (picoRoutines[i] > g_kdctx.SystemRangeStart) {
                        AddEntryToList(TreeList,
                            RootItem,
                            (ULONG_PTR)picoRoutines[i],
                            PspPicoProviderNameFromIndex(i),
                            Modules);
                    }
                }
            }
            supHeapFree(picoRoutines);
        }
    }
}

/*
* DumpKiNmiCallbackListHead
*
* Purpose:
*
* Read NMI callback list from kernel and send them to output window.
*
*/
OBEX_DISPLAYCALLBACK_ROUTINE(DumpKiNmiCallbackListHead)
{
    SIZE_T GuardIter = 0;
    ULONG_PTR Next;
    KNMI_HANDLER_CALLBACK NmiEntry;
    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, CallbackType);
    if (RootItem == 0)
        return;

    //
    // Read head.
    //
    RtlSecureZeroMemory(&NmiEntry, sizeof(NmiEntry));

    if (!kdReadSystemMemory(KernelVariableAddress,
        (PVOID)&NmiEntry,
        sizeof(NmiEntry)))
    {
        return;
    }

    //
    // Walk each entry in single linked list.
    //
    Next = (ULONG_PTR)NmiEntry.Next;
    while (Next) {
        LIST_ITERATION_GUARD(GuardIter);
        RtlSecureZeroMemory(&NmiEntry, sizeof(NmiEntry));

        if (!kdReadSystemMemory(Next,
            (PVOID)&NmiEntry,
            sizeof(NmiEntry)))
        {
            break;
        }

        AddEntryToList(TreeList,
            RootItem,
            (ULONG_PTR)NmiEntry.Callback,
            NULL,
            Modules);

        Next = (ULONG_PTR)NmiEntry.Next;
    }
}

/*
* DumpPspSiloMonitorList
*
* Purpose:
*
* Read Silo monitor callbacks from kernel and send them to output window.
*
*/
OBEX_DISPLAYCALLBACK_ROUTINE(DumpPspSiloMonitorList)
{
    SIZE_T GuardIter = 0;
    ULONG_PTR ListHead = KernelVariableAddress;
    LIST_ENTRY ListEntry;
    HTREEITEM RootItem;
    SERVER_SILO_MONITOR SiloMonitor;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, CallbackType);
    if (RootItem == 0)
        return;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemory(
        ListHead,
        &ListEntry,
        sizeof(LIST_ENTRY)))
    {
        return;
    }

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {
        LIST_ITERATION_GUARD(GuardIter);
        RtlSecureZeroMemory(&SiloMonitor, sizeof(SiloMonitor));

        if (!kdReadSystemMemory(
            (ULONG_PTR)ListEntry.Flink,
            &SiloMonitor,
            sizeof(SiloMonitor)))
        {
            break;
        }

        if (SiloMonitor.CreateCallback != NULL) {
            AddEntryToList(TreeList,
                RootItem,
                (ULONG_PTR)SiloMonitor.CreateCallback,
                L"CreateCallback",
                Modules);
        }

        if (SiloMonitor.TerminateCallback != NULL) {
            AddEntryToList(TreeList,
                RootItem,
                (ULONG_PTR)SiloMonitor.TerminateCallback,
                L"TerminateCallback",
                Modules);
        }

        if (!SET_NEXT_FLINK_CHECK(ListEntry, SiloMonitor.ListEntry.Flink, "SiloMonitor NULL Flink"))
            break;
    }
}

/*
* DumpEmpCallbackListHead
*
* Purpose:
*
* Read Errata Manager callbacks from kernel and send them to output window.
*
*/
OBEX_DISPLAYCALLBACK_ROUTINE(DumpEmpCallbackListHead)
{
    SIZE_T GuardIter = 0;
    LPWSTR GuidString;
    ULONG_PTR ListHead = KernelVariableAddress, Next, RecordAddress;
    SINGLE_LIST_ENTRY Head;
    HTREEITEM RootItem;
    EMP_CALLBACK_DB_RECORD CallbackRecord;
    UNICODE_STRING ConvertedGuid;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, CallbackType);
    if (RootItem == 0)
        return;

    //
    // Read head.
    //
    Head.Next = NULL;
    if (!kdReadSystemMemory(
        ListHead,
        &Head,
        sizeof(SINGLE_LIST_ENTRY)))
    {
        return;
    }

    Next = (ULONG_PTR)Head.Next;
    while (Next) {
        LIST_ITERATION_GUARD(GuardIter);
        RtlSecureZeroMemory(&CallbackRecord, sizeof(CallbackRecord));
        RecordAddress = (ULONG_PTR)Next - FIELD_OFFSET(EMP_CALLBACK_DB_RECORD, List);

        if (!kdReadSystemMemory(RecordAddress, &CallbackRecord, sizeof(CallbackRecord)))
            break;

        if (NT_SUCCESS(RtlStringFromGUID(&CallbackRecord.CallbackId, &ConvertedGuid)))
            GuidString = ConvertedGuid.Buffer;
        else
            GuidString = NULL;

        if (CallbackRecord.CallbackFunc) {
            AddEntryToList(TreeList,
                RootItem,
                (ULONG_PTR)CallbackRecord.CallbackFunc,
                GuidString,
                Modules);
        }
        else {
            AddEmptyEntryToList(TreeList,
                RootItem,
                GuidString);
        }

        if (GuidString)
            RtlFreeUnicodeString(&ConvertedGuid);

        Next = (ULONG_PTR)CallbackRecord.List.Next;
    }
}

/*
* DumpPnpDeviceClassNotifyList
*
* Purpose:
*
* Dump Pnp manager notify list from kernel and send them to output window.
*
*/
OBEX_DISPLAYCALLBACK_ROUTINE(DumpPnpDeviceClassNotifyList)
{
    SIZE_T GuardIter = 0;
    ULONG_PTR ListHead = KernelVariableAddress;
    LPWSTR GuidString;
    LIST_ENTRY ListEntry;
    HTREEITEM RootItem;
    DEVICE_CLASS_NOTIFY_ENTRY NotifyEntry;
    UNICODE_STRING ConvertedGuid;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, CallbackType);
    if (RootItem == 0)
        return;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemory(
        ListHead,
        &ListEntry,
        sizeof(LIST_ENTRY)))
    {
        return;
    }

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {
        LIST_ITERATION_GUARD(GuardIter);
        RtlSecureZeroMemory(&NotifyEntry, sizeof(NotifyEntry));

        if (!kdReadSystemMemory(
            (ULONG_PTR)ListEntry.Flink,
            &NotifyEntry,
            sizeof(NotifyEntry)))
        {
            break;
        }

        if (NotifyEntry.CallbackRoutine != NULL) {
            if (NT_SUCCESS(RtlStringFromGUID(&NotifyEntry.ClassGuid, &ConvertedGuid)))
                GuidString = ConvertedGuid.Buffer;
            else
                GuidString = NULL;

            AddEntryToList(TreeList,
                RootItem,
                (ULONG_PTR)NotifyEntry.CallbackRoutine,
                GuidString,
                Modules);

            if (GuidString)
                RtlFreeUnicodeString(&ConvertedGuid);
        }

        if (!SET_NEXT_FLINK_CHECK(ListEntry, NotifyEntry.ListEntry.Flink, "PnpDeviceClassNotifyList NULL Flink"))
            break;
    }
}

/*
* QueryIopFsListsCallbacks
*
* Purpose:
*
* Query and list Io Fs lists callbacks.
*
*/
OBEX_QUERYCALLBACK_ROUTINE(QueryIopFsListsCallbacks)
{
    UNREFERENCED_PARAMETER(QueryFlags);
    UNREFERENCED_PARAMETER(CallbackType);
    UNREFERENCED_PARAMETER(FindRoutine);
    UNREFERENCED_PARAMETER(SystemCallbacksRef);

    if ((g_SystemCallbacks.IopCdRomFileSystemQueueHead == 0) ||
        (g_SystemCallbacks.IopDiskFileSystemQueueHead == 0) ||
        (g_SystemCallbacks.IopTapeFileSystemQueueHead == 0) ||
        (g_SystemCallbacks.IopNetworkFileSystemQueueHead == 0))
    {
        if (!FindIopFileSystemQueueHeads(&g_SystemCallbacks.IopCdRomFileSystemQueueHead,
            &g_SystemCallbacks.IopDiskFileSystemQueueHead,
            &g_SystemCallbacks.IopTapeFileSystemQueueHead,
            &g_SystemCallbacks.IopNetworkFileSystemQueueHead))
        {
            kdReportErrorByFunction(__FUNCTIONW__, TEXT("Could not locate all Iop ListHeads"));
            return STATUS_NOT_FOUND;
        }
    }

    if (g_SystemCallbacks.IopDiskFileSystemQueueHead) {
        DisplayRoutine(TreeList,
            TEXT("IoDiskFs"),
            g_SystemCallbacks.IopDiskFileSystemQueueHead,
            Modules);
    }
    if (g_SystemCallbacks.IopCdRomFileSystemQueueHead) {
        DisplayRoutine(TreeList,
            TEXT("IoCdRomFs"),
            g_SystemCallbacks.IopCdRomFileSystemQueueHead,
            Modules);
    }
    if (g_SystemCallbacks.IopNetworkFileSystemQueueHead) {
        DisplayRoutine(TreeList,
            TEXT("IoNetworkFs"),
            g_SystemCallbacks.IopNetworkFileSystemQueueHead,
            Modules);
    }
    if (g_SystemCallbacks.IopTapeFileSystemQueueHead) {
        DisplayRoutine(TreeList,
            TEXT("IoTapeFs"),
            g_SystemCallbacks.IopTapeFileSystemQueueHead,
            Modules);
    }
    return STATUS_SUCCESS;
}

/*
* QueryCallbackGeneric
*
* Purpose:
*
* Query and list kernel mode data for most types of callbacks/notifies.
*
*/
OBEX_QUERYCALLBACK_ROUTINE(QueryCallbackGeneric)
{
    ULONG_PTR QueryAddress = 0;

    //
    // All parameters must be valid for this variant of Query callback.
    //
    if ((DisplayRoutine == NULL) ||
        (FindRoutine == NULL) ||
        (SystemCallbacksRef == NULL) ||
        (CallbackType == NULL))
    {
        return STATUS_INVALID_PARAMETER;
    }

    __try {

        QueryAddress = *SystemCallbacksRef;

        if (QueryAddress == 0)
            QueryAddress = FindRoutine(QueryFlags);

        *SystemCallbacksRef = QueryAddress;

    }
    __except (WOBJ_EXCEPTION_FILTER_LOG) {
        return GetExceptionCode();
    }

    __try {
        if (QueryAddress) {
            DisplayRoutine(
                TreeList,
                CallbackType,
                QueryAddress,
                Modules);
        }
        else
            return STATUS_NOT_FOUND;
    }
    __except (WOBJ_EXCEPTION_FILTER_LOG) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

/*
* DisplayCallbacksList
*
* Purpose:
*
* Find callbacks pointers and list them to output window.
*
*/
VOID DisplayCallbacksList(
    _In_ HWND TreeList,
    _In_ HWND StatusBar)
{
    ULONG i;
    NTSTATUS QueryStatus;
    PRTL_PROCESS_MODULES Modules = NULL;
    PWSTR lpStatusMsg;
    WCHAR szText[200];

    do {
        if (g_kdctx.NtOsImageMap == NULL) {
            lpStatusMsg = TEXT("Error, ntoskrnl image is not mapped!");
            supStatusBarSetText(StatusBar, 1, lpStatusMsg);
            break;
        }

        Modules = (PRTL_PROCESS_MODULES)supGetLoadedModulesList(NULL);
        if (Modules == NULL) {
            lpStatusMsg = TEXT("Could not allocate memory for modules list!");
            supStatusBarSetText(StatusBar, 1, lpStatusMsg);
            break;
        }

        //
        // List callbacks.
        //
        for (i = 0; i < RTL_NUMBER_OF(g_CallbacksDispatchTable); i++) {
            QueryStatus = g_CallbacksDispatchTable[i].QueryRoutine(
                g_CallbacksDispatchTable[i].QueryFlags,
                g_CallbacksDispatchTable[i].DisplayRoutine,
                g_CallbacksDispatchTable[i].FindRoutine,
                g_CallbacksDispatchTable[i].CallbackType,
                TreeList,
                Modules,
                g_CallbacksDispatchTable[i].SystemCallbacksRef);

            if (!NT_SUCCESS(QueryStatus)) {

                if (QueryStatus == STATUS_NOT_FOUND) {
#ifdef _DEBUG
                    RtlStringCchPrintfSecure(szText,
                        RTL_NUMBER_OF(szText),
                        TEXT("Callback type %ws was not found"),
                        g_CallbacksDispatchTable[i].CallbackType);

                    logAdd(EntryTypeWarning, szText);
#endif
                }
                else {
                    RtlStringCchPrintfSecure(szText,
                        RTL_NUMBER_OF(szText),
                        TEXT("Callback type %ws, error 0x%lX"),
                        g_CallbacksDispatchTable[i].CallbackType,
                        QueryStatus);

                    logAdd(EntryTypeError, szText);
                    supStatusBarSetText(StatusBar, 1, (LPWSTR)&szText);
                }
            }
        }

        //
        // Show total number of callbacks.
        //
        _strcpy(szText, TEXT("Total listed callbacks: "));
        ultostr(g_CallbacksCount, _strend(szText));
        supStatusBarSetText(StatusBar, 0, (LPWSTR)&szText);

    } while (FALSE);

    if (Modules) supHeapFree(Modules);
    SetFocus(TreeList);
}

/*
* SysCbDialogHandlePopupMenu
*
* Purpose:
*
* Treelist popup construction
*
*/
VOID SysCbDialogHandlePopupMenu(
    _In_ HWND hwndDlg,
    _In_ EXTRASCONTEXT* pDlgContext,
    _In_ LPARAM lParam
)
{
    UINT uPos = 0;
    HMENU hMenu;
    POINT pt1;

    if (GetCursorPos(&pt1) == FALSE)
        return;

    hMenu = CreatePopupMenu();
    if (hMenu) {
        if (supTreeListAddCopyValueItem(hMenu,
            pDlgContext->TreeList,
            ID_OBJECT_COPY,
            uPos++,
            lParam,
            &pDlgContext->tlSubItemHit))
        {
            InsertMenu(hMenu, uPos++, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
        }
        InsertMenu(hMenu, uPos++, MF_BYCOMMAND, ID_VIEW_REFRESH, T_VIEW_REFRESH);
        TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, pt1.x, pt1.y, 0, hwndDlg, NULL);
        DestroyMenu(hMenu);
    }
}

/*
* SysCbDialogResize
*
* Purpose:
*
* WM_SIZE handler.
*
*/
INT_PTR SysCbDialogResize(
    _In_ HWND hwndDlg,
    _In_ HWND hwndStatusBar,
    _In_ HWND hwndTreeList
)
{
    RECT r, szr;

    RtlSecureZeroMemory(&r, sizeof(RECT));
    RtlSecureZeroMemory(&szr, sizeof(RECT));

    GetClientRect(hwndDlg, &r);
    GetClientRect(hwndStatusBar, &szr);

    SendMessage(hwndStatusBar, WM_SIZE, 0, 0);

    SetWindowPos(hwndTreeList, 0, 0, 0,
        r.right,
        r.bottom - szr.bottom,
        SWP_NOZORDER);

    return 1;
}

/*
* SysCbDialogContentRefresh
*
* Purpose:
*
* Refresh callback list handler.
*
*/
VOID SysCbDialogContentRefresh(
    _In_ HWND hwndDlg,
    _In_ EXTRASCONTEXT* pDlgContext,
    _In_ BOOL fResetContent
)
{
    UNREFERENCED_PARAMETER(hwndDlg);
    if (fResetContent)
        TreeList_ClearTree(pDlgContext->TreeList);
    g_CallbacksCount = 0;
    supTreeListEnableRedraw(pDlgContext->TreeList, FALSE);
    DisplayCallbacksList(pDlgContext->TreeList, pDlgContext->StatusBar);
    supTreeListEnableRedraw(pDlgContext->TreeList, TRUE);
}

/*
* SysCbDialogOnInit
*
* Purpose:
*
* WM_INITDIALOG handler.
*
*/
VOID SysCbDialogOnInit(
    _In_ HWND hwndDlg,
    _In_  LPARAM lParam
)
{
    EXTRASCONTEXT* pDlgContext = (EXTRASCONTEXT*)lParam;
    RECT rc;
    HDITEM hdritem;
    INT SbParts[] = { 200, -1 };

    SetProp(hwndDlg, T_DLGCONTEXT, (HANDLE)lParam);

    pDlgContext->hwndDlg = hwndDlg;
    pDlgContext->StatusBar = GetDlgItem(hwndDlg, ID_EXTRASLIST_STATUSBAR);
    SendMessage(pDlgContext->StatusBar, SB_SETPARTS, 2, (LPARAM)&SbParts);

    extrasSetDlgIcon(pDlgContext);
    SetWindowText(hwndDlg, TEXT("System Callbacks"));

    GetClientRect(g_hwndMain, &rc);
    pDlgContext->TreeList = CreateWindowEx(WS_EX_STATICEDGE, WC_TREELIST, NULL,
        WS_VISIBLE | WS_CHILD | WS_TABSTOP | TLSTYLE_COLAUTOEXPAND | TLSTYLE_LINKLINES, 12, 14,
        rc.right - 24, rc.bottom - 24, hwndDlg, NULL, NULL, NULL);

    if (pDlgContext->TreeList) {
        RtlSecureZeroMemory(&hdritem, sizeof(hdritem));
        hdritem.mask = HDI_FORMAT | HDI_TEXT | HDI_WIDTH;
        hdritem.fmt = HDF_LEFT | HDF_BITMAP_ON_RIGHT | HDF_STRING;
        hdritem.cxy = 160;
        hdritem.pszText = TEXT("Routine Address");
        TreeList_InsertHeaderItem(pDlgContext->TreeList, 0, &hdritem);

        hdritem.cxy = 300;
        hdritem.pszText = TEXT("Module");
        TreeList_InsertHeaderItem(pDlgContext->TreeList, 1, &hdritem);

        hdritem.cxy = 200;
        hdritem.pszText = TEXT("Additional Information");
        TreeList_InsertHeaderItem(pDlgContext->TreeList, 2, &hdritem);

        SysCbDialogContentRefresh(hwndDlg, pDlgContext, FALSE);
    }

    supCenterWindowSpecifyParent(hwndDlg, g_hwndMain);
    SendMessage(hwndDlg, WM_SIZE, 0, 0);
}

/*
* SysCbDialogProc
*
* Purpose:
*
* Callbacks Dialog window procedure.
*
*/
INT_PTR CALLBACK SysCbDialogProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    EXTRASCONTEXT* pDlgContext;

    switch (uMsg) {

    case WM_INITDIALOG:
        SysCbDialogOnInit(hwndDlg, lParam);
        break;

    case WM_GETMINMAXINFO:
        if (lParam) {
            supSetMinMaxTrackSize((PMINMAXINFO)lParam,
                CBDLG_TRACKSIZE_MIN_X,
                CBDLG_TRACKSIZE_MIN_Y,
                TRUE);
        }
        break;

    case WM_SIZE:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            SysCbDialogResize(hwndDlg, pDlgContext->StatusBar, pDlgContext->TreeList);
        }
        break;

    case WM_CLOSE:
        pDlgContext = (EXTRASCONTEXT*)RemoveProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            extrasRemoveDlgIcon(pDlgContext);
            supHeapFree(pDlgContext);
        }
        DestroyWindow(hwndDlg);
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    case WM_COMMAND:
        switch (GET_WM_COMMAND_ID(wParam, lParam)) {
        case IDCANCEL:
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            break;

        case ID_OBJECT_COPY:
            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
            if (pDlgContext) {

                supTreeListCopyItemValueToClipboard(pDlgContext->TreeList,
                    pDlgContext->tlSubItemHit);

            }
            break;

        case ID_VIEW_REFRESH:
            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
            if (pDlgContext) {
                SysCbDialogContentRefresh(hwndDlg, pDlgContext, TRUE);
            }
            break;

        }
        break;

    case WM_CONTEXTMENU:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            SysCbDialogHandlePopupMenu(hwndDlg, pDlgContext, lParam);
        }
        break;

    }

    return FALSE;
}

/*
* extrasSysCbDialogWorkerThread
*
* Purpose:
*
* Callbacks Dialog worker thread.
*
*/
DWORD extrasSysCbDialogWorkerThread(
    _In_ PVOID Parameter
)
{
    HWND hwndDlg;
    BOOL bResult;
    MSG message;
    EXTRASCONTEXT* pDlgContext = (EXTRASCONTEXT*)Parameter;
    HACCEL acceleratorTable;

    hwndDlg = CreateDialogParam(
        g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_CALLBACKS),
        0,
        &SysCbDialogProc,
        (LPARAM)pDlgContext);

    acceleratorTable = LoadAccelerators(g_WinObj.hInstance, MAKEINTRESOURCE(IDR_ACCELERATOR1));

    supSetFastEvent(&SysCbInitializedEvent);

    do {

        bResult = GetMessage(&message, NULL, 0, 0);
        if (bResult == -1)
            break;

        if (IsDialogMessage(hwndDlg, &message)) {
            TranslateAccelerator(hwndDlg, acceleratorTable, &message);
        }
        else {
            TranslateMessage(&message);
            DispatchMessage(&message);
        }

    } while (bResult != 0);

    supResetFastEvent(&SysCbInitializedEvent);

    if (acceleratorTable)
        DestroyAcceleratorTable(acceleratorTable);

    if (SysCbThreadHandle) {
        NtClose(SysCbThreadHandle);
        SysCbThreadHandle = NULL;
    }

    return 0;
}

/*
* extrasCreateCallbacksDialog
*
* Purpose:
*
* Create and initialize Callbacks Dialog.
*
*/
VOID extrasCreateCallbacksDialog(
    VOID
)
{
    EXTRASCONTEXT* pDlgContext;

    if (!SysCbThreadHandle) {
        pDlgContext = (EXTRASCONTEXT*)supHeapAlloc(sizeof(EXTRASCONTEXT));
        if (pDlgContext) {
            pDlgContext->tlSubItemHit = -1;
            SysCbThreadHandle = supCreateDialogWorkerThread(extrasSysCbDialogWorkerThread, pDlgContext, 0);
            if (SysCbThreadHandle == NULL) {
                supHeapFree(pDlgContext);
                return;
            }
            supWaitForFastEvent(&SysCbInitializedEvent, NULL);
        }
    }
}
