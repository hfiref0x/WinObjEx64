/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2021
*
*  TITLE:       SUP.H
*
*  VERSION:     1.90
*
*  DATE:        28 May 2021
*
*  Common header file for the program support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#include <cfgmgr32.h>
#include <setupapi.h>

#define T_DEVICE_PROCEXP152 L"\\Device\\ProcExp152"
#define PE_DEVICE_TYPE 0x8335

#define IOCTL_PE_OPEN_PROCESS_TOKEN     CTL_CODE(PE_DEVICE_TYPE, 0x3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PE_OPEN_PROCESS           CTL_CODE(PE_DEVICE_TYPE, 0xF, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define INITIAL_BUFFER_SIZE (256) * (1024)

//
// Defined in sup.c
//
extern HWND g_hwndBanner;

typedef struct _SAPIDB {
    LIST_ENTRY ListHead;
    HANDLE     sapiHeap;
} SAPIDB, *PSAPIDB;

typedef struct _SCMDB {
    ULONG NumberOfEntries;
    PVOID Entries;
} SCMDB, *PSCMDB;

typedef struct _ENUMICONINFO {
    HICON hIcon;
    INT cx, cy;
} ENUMICONINFO, *PENUMICONINFO;

typedef	struct _PHL_ENTRY {
    LIST_ENTRY ListEntry;
    HANDLE ProcessHandle;
    HANDLE UniqueProcessId;
    PVOID DataPtr;
} PHL_ENTRY, *PPHL_ENTRY;

typedef struct _OBEX_PROCESS_LOOKUP_ENTRY {
    HANDLE hProcess;
    union {
        PUCHAR EntryPtr;
        PSYSTEM_PROCESSES_INFORMATION ProcessInformation;
    };
} OBEX_PROCESS_LOOKUP_ENTRY, *POBEX_PROCESS_LOOKUP_ENTRY;

typedef struct _OBEX_THREAD_LOOKUP_ENTRY {
    HANDLE hThread;
    PVOID EntryPtr;
} OBEX_THREAD_LOOKUP_ENTRY, *POBEX_THREAD_LOOKUP_ENTRY;

typedef struct _ALPCPORT_ENUM_CONTEXT {
    _In_ LPCWSTR ObjectFullName;
    _Out_ HANDLE ObjectHandle;
} ALPCPORT_ENUM_CONTEXT, * PALPCPORT_ENUM_CONTEXT;

typedef struct _PS_HANDLE_DUMP_ENUM_CONTEXT {
    _In_ USHORT ObjectTypeIndex;
    _In_ ULONG_PTR ObjectAddress;
    _In_ HWND ListView;
    _In_ HIMAGELIST ImageList;
    _In_ PVOID ProcessList;
} PS_HANDLE_DUMP_ENUM_CONTEXT, *PPS_HANDLE_DUMP_ENUM_CONTEXT;

// return true to stop enumeration
typedef BOOL(CALLBACK* PENUMERATE_SL_CACHE_VALUE_DESCRIPTORS_CALLBACK)(
    _In_ SL_KMEM_CACHE_VALUE_DESCRIPTOR* CacheDescriptor,
    _In_opt_ PVOID Context
    );

// return true to stop enumeration
typedef BOOL(CALLBACK* PENUMERATE_HANDLE_DUMP_CALLBACK)(
    _In_ SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* HandleEntry,
    _In_opt_ PVOID UserContext
    );

typedef NTSTATUS(NTAPI* PNTOBJECTOPENPROCEDURE)(
    _Out_ PHANDLE ObjectHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

typedef struct _PROCESS_MITIGATION_POLICIES_ALL {
    PROCESS_MITIGATION_DEP_POLICY DEPPolicy;
    PROCESS_MITIGATION_ASLR_POLICY ASLRPolicy;
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY_W10 DynamicCodePolicy;
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY StrictHandleCheckPolicy;
    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY_W10 SystemCallDisablePolicy;
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ExtensionPointDisablePolicy;
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY_W10 ControlFlowGuardPolicy;
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_W10 SignaturePolicy;
    PROCESS_MITIGATION_FONT_DISABLE_POLICY_W10 FontDisablePolicy;
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY_W10 ImageLoadPolicy;
    PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY_W10 SystemCallFilterPolicy;
    PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY_W10 PayloadRestrictionPolicy;
    PROCESS_MITIGATION_CHILD_PROCESS_POLICY_W10 ChildProcessPolicy;
    PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY_W10 SideChannelIsolationPolicy;
    PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY_W10 UserShadowStackPolicy;
} PROCESS_MITIGATION_POLICIES_ALL, *PPROCESS_MITIGATION_POLICIES;

typedef struct _PROCESS_MITIGATION_POLICY_RAW_DATA {
    PROCESS_MITIGATION_POLICY Policy;
    ULONG Value;
} PROCESS_MITIGATION_POLICY_RAW_DATA, *PPROCESS_MITIGATION_POLICY_RAW_DATA;

#define GET_BIT(Integer, Bit) (((Integer) >> (Bit)) & 0x1)
#define SET_BIT(Integer, Bit) ((Integer) |= 1 << (Bit))
#define CLEAR_BIT(Integer, Bit) ((Integer) &= ~(1 << (Bit)))

typedef struct _ENUMCHILDWNDDATA {
    RECT Rect;
    INT nCmdShow;
} ENUMCHILDWNDDATA, *PENUMCHILDWNDDATA;

typedef struct _LANGANDCODEPAGE {
    WORD wLanguage;
    WORD wCodePage;
} LANGANDCODEPAGE, *LPTRANSLATE;

typedef struct _SAPIDBENTRY {
    LIST_ENTRY ListEntry;
    LPWSTR lpDeviceName;
    LPWSTR lpDeviceDesc;
} SAPIDBENTRY, *PSAPIDBENTRY;

extern SAPIDB g_sapiDB;
extern SCMDB g_scmDB;
extern POBJECT_TYPES_INFORMATION g_pObjectTypesInfo;

#define PathFileExists(lpszPath) (GetFileAttributes(lpszPath) != (DWORD)-1)

typedef struct tagVERBLOCK {
    WORD wTotLen;
    WORD wValLen;
    WORD wType;
    WCHAR szKey[1];
} VERBLOCK;

typedef struct tagVERHEAD {
    WORD wTotLen;
    WORD wValLen;
    WORD wType;
    WCHAR szKey[(sizeof("VS_VERSION_INFO") + 3) & ~3];
    VS_FIXEDFILEINFO vsf;
} VERHEAD;

#define VER2_SIG 'X2EF'

#define DWORDUP(x) (((x)+3)&~3)

//
// Use shared NTSUP forward.
//

#define supGetSystemInfoEx ntsupGetSystemInfoEx
#define supVirtualAllocEx ntsupVirtualAllocEx
#define supVirtualAlloc ntsupVirtualAlloc
#define supVirtualFree ntsupVirtualFree
#define supEnablePrivilege ntsupEnablePrivilege
#define supGetCurrentProcessToken ntsupGetCurrentProcessToken
#define supQuerySystemRangeStart ntsupQuerySystemRangeStart
#define supQueryUserModeAccessibleRange ntsupQueryUserModeAccessibleRange
#define supIsProcess32bit ntsupIsProcess32bit
#define supQueryThreadWin32StartAddress ntsupQueryThreadWin32StartAddress
#define supOpenDirectory ntsupOpenDirectory
#define supQueryProcessName ntsupQueryProcessName
#define supQueryProcessEntryById ntsupQueryProcessEntryById
#define supQueryProcessInformation ntsupQueryProcessInformation
#define supQueryObjectInformation ntsupQueryObjectInformation
#define supWriteBufferToFile ntsupWriteBufferToFile
#define supQueryHVCIState ntsupQueryHVCIState
#define supLookupImageSectionByName ntsupLookupImageSectionByName
#define supFindPattern ntsupFindPattern
#define supOpenProcess ntsupOpenProcess
#define supOpenThread ntsupOpenThread
#define supCICustomKernelSignersAllowed ntsupCICustomKernelSignersAllowed
#define supPrivilegeEnabled ntsupPrivilegeEnabled
#define supListViewEnableRedraw(ListView, fEnable) SendMessage(ListView, WM_SETREDRAW, (WPARAM)fEnable, (LPARAM)0)

ULONG supConvertFromPteProtectionMask(
    _In_ ULONG ProtectionMask);

BOOL supInitMSVCRT(
    VOID);

#ifndef _DEBUG
FORCEINLINE PVOID supHeapAlloc(
    _In_ SIZE_T Size);

FORCEINLINE BOOL supHeapFree(
    _In_ PVOID Memory);
#else
PVOID supHeapAlloc(
    _In_ SIZE_T Size);

BOOL supHeapFree(
    _In_ PVOID Memory);
#endif

VOID supTreeListEnableRedraw(
    _In_ HWND TreeList,
    _In_ BOOL fEnable);

HTREEITEM supTreeListAddItem(
    _In_ HWND TreeList,
    _In_opt_ HTREEITEM hParent,
    _In_ UINT mask,
    _In_ UINT state,
    _In_ UINT stateMask,
    _In_opt_ LPWSTR pszText,
    _In_opt_ PVOID subitems);

BOOL supInitTreeListForDump(
    _In_  HWND  hwndParent,
    _Out_ HWND* pTreeListHwnd);

VOID supShowHelp(
    _In_ HWND ParentWindow);

BOOL supQueryObjectFromHandleEx(
    _In_ PSYSTEM_HANDLE_INFORMATION_EX HandlesDump,
    _In_ HANDLE Object,
    _Out_opt_ ULONG_PTR* Address,
    _Out_opt_ USHORT* TypeIndex);

BOOL supQueryObjectFromHandle(
    _In_ HANDLE Object,
    _Out_ ULONG_PTR* Address,
    _Out_opt_ USHORT* TypeIndex);

HICON supGetMainIcon(
    _In_ LPWSTR lpFileName,
    _In_ INT cx,
    _In_ INT cy);

void supCopyMemory(
    _Inout_ void* dest,
    _In_ size_t ccdest,
    _In_ const void* src,
    _In_ size_t ccsrc);

BOOLEAN supUserIsFullAdmin(
    VOID);

VOID supCenterWindow(
    _In_ HWND hwnd);

VOID supCenterWindowPerScreen(
    _In_ HWND hwnd);

VOID supSetWaitCursor(
    _In_ BOOL fSet);

VOID supUpdateLoadBannerText(
    _In_ HWND hwndBanner,
    _In_ LPCWSTR lpText,
    _In_ BOOL UseList);

VOID supCloseLoadBanner(
    _In_ HWND hwndBanner);

HWND supDisplayLoadBanner(
    _In_opt_ HWND hwndParent,
    _In_ LPCWSTR lpMessage,
    _In_opt_ LPCWSTR lpCaption,
    _In_ BOOL UseList);

HIMAGELIST supLoadImageList(
    _In_ HINSTANCE hInst,
    _In_ UINT FirstId,
    _In_ UINT LastId);

UINT supGetObjectNameIndexByTypeIndex(
    _In_ PVOID Object,
    _In_ UCHAR TypeIndex);

VOID supRunAsAdmin(
    VOID);

BOOL supListViewCopyItemValueToClipboard(
    _In_ HWND hwndListView,
    _In_ INT iItem,
    _In_ INT iSubItem);

BOOL supListViewAddCopyValueItem(
    _In_ HMENU hMenu,
    _In_ HWND hwndLv,
    _In_ UINT uId,
    _In_opt_ UINT uPos,
    _In_ POINT* lpPoint,
    _Out_ INT* pItemHit,
    _Out_ INT* pColumnHit);

VOID supSetMenuIcon(
    _In_ HMENU hMenu,
    _In_ UINT Item,
    _In_ ULONG_PTR IconData);

VOID supSetGotoLinkTargetToolButtonState(
    _In_ HWND hwnd,
    _In_opt_ HWND hwndlv,
    _In_opt_ INT iItem,
    _In_ BOOL bForce,
    _In_ BOOL bForceEnable);

WOBJ_OBJECT_TYPE supObjectListGetObjectType(
    _In_ HWND hwndList,
    _In_ INT iItem);

VOID supCreateToolbarButtons(
    _In_ HWND hWndToolbar);

VOID supInit(
    _In_ BOOLEAN IsFullAdmin);

VOID supShutdown(
    VOID);

PVOID supGetObjectTypesInfo(
    VOID);

VOID supShowProperties(
    _In_ HWND hwndDlg,
    _In_ LPWSTR lpFileName);

VOID supClipboardCopy(
    _In_ LPWSTR lpText,
    _In_ SIZE_T cbText);

LPWSTR supGetItemText(
    _In_ HWND ListView,
    _In_ INT nItem,
    _In_ INT nSubItem,
    _Out_opt_ PSIZE_T lpSize);

LPWSTR supGetItemText2(
    _In_ HWND ListView,
    _In_ INT nItem,
    _In_ INT nSubItem,
    _In_ WCHAR* pszText,
    _In_ UINT cchText);

BOOL supQuerySectionFileInfo(
    _In_opt_ HANDLE RootDirectoryHandle,
    _In_ PUNICODE_STRING ObjectName,
    _Inout_	LPWSTR Buffer,
    _In_ DWORD ccBuffer);

BOOL supQueryTypeInfo(
    _In_ LPWSTR lpTypeName,
    _Inout_	LPWSTR Buffer,
    _In_ DWORD ccBuffer);

BOOL supQueryDriverDescription(
    _In_ LPWSTR lpDriverName,
    _Inout_	LPWSTR Buffer,
    _In_ DWORD ccBuffer);

BOOL supQueryDeviceDescription(
    _In_ LPWSTR lpDeviceName,
    _Inout_	LPWSTR Buffer,
    _In_ DWORD ccBuffer);

BOOL supQueryWinstationDescription(
    _In_ LPWSTR lpWindowStationName,
    _Inout_	LPWSTR Buffer,
    _In_ DWORD ccBuffer);

PVOID supGetTokenInfo(
    _In_ HANDLE TokenHandle,
    _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
    _Out_opt_ PULONG ReturnLength);

PVOID supGetLoadedModulesList(
    _Out_opt_ PULONG ReturnLength);

PVOID supGetLoadedModulesList2(
    _Out_opt_ PULONG ReturnLength);

PVOID supGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_opt_ PULONG ReturnLength);

NTSTATUS supOpenDeviceObject(
    _Out_ PHANDLE ObjectHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS supOpenDeviceObjectEx(
    _Out_ PHANDLE ObjectHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS supOpenDirectoryForObject(
    _Out_ PHANDLE DirectoryHandle,
    _In_ LPWSTR lpObjectName,
    _In_ LPWSTR lpDirectory);

BOOL supDumpSyscallTableConverted(
    _In_ ULONG_PTR ServiceTableAddress,
    _In_ ULONG ServiceLimit,
    _Out_ PUTable* Table);

BOOL supCreateSCMSnapshot(
    _In_ ULONG ServiceType,
    _Out_opt_ SCMDB* Snapshot);

VOID supFreeSCMSnapshot(
    _In_opt_ SCMDB* Snapshot);

BOOL sapiCreateSetupDBSnapshot(
    VOID);

VOID sapiFreeSnapshot(
    VOID);

BOOL supSaveDialogExecute(
    _In_ HWND OwnerWindow,
    _Inout_ LPWSTR SaveFileName,
    _In_ LPWSTR lpDialogFilter);

VOID supSetListViewSettings(
    _In_ HWND hwndLV,
    _In_ DWORD dwExtendedStyle,
    _In_ BOOL fIgnoreGlobalSettings,
    _In_ BOOL fSetTheme,
    _In_opt_ HIMAGELIST hImageList,
    _In_ INT iImageList);

HICON supGetStockIcon(
    _In_ SHSTOCKICONID siid,
    _In_ UINT uFlags);

BOOL supGetWin32FileName(
    _In_ LPWSTR FileName,
    _Inout_ LPWSTR Win32FileName,
    _In_ SIZE_T ccWin32FileName);

BOOLEAN supIsWine(
    VOID);

BOOLEAN supQuerySecureBootState(
    _Out_ PBOOLEAN pbSecureBoot);

HWINSTA supOpenWindowStationFromContext(
    _In_ PROP_OBJECT_INFO* Context,
    _In_ BOOL fInherit,
    _In_ ACCESS_MASK dwDesiredAccess);

NTSTATUS supQueryObjectTrustLabel(
    _In_ HANDLE hObject,
    _Out_ PULONG ProtectionType,
    _Out_ PULONG ProtectionLevel);

NTSTATUS supIsLocalSystem(
    _In_ HANDLE hToken,
    _Out_ PBOOL pbResult);

BOOL supRunAsLocalSystem(
    _In_ HWND hwndParent);

VOID supUpdateLvColumnHeaderImage(
    _In_ HWND ListView,
    _In_ INT NumberOfColumns,
    _In_ INT UpdateColumn,
    _In_ INT ImageIndex);

INT supGetMaxOfTwoU64FromHex(
    _In_ HWND ListView,
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort,
    _In_ BOOL Inverse);

INT supGetMaxOfTwoLongFromString(
    _In_ HWND ListView,
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort,
    _In_ BOOL Inverse);

INT supGetMaxOfTwoULongFromString(
    _In_ HWND ListView,
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort,
    _In_ BOOL Inverse);

INT supGetMaxCompareTwoFixedStrings(
    _In_ HWND ListView,
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort,
    _In_ BOOL Inverse);

NTSTATUS supOpenNamedObjectByType(
    _Out_ HANDLE* ObjectHandle,
    _In_ ULONG TypeIndex,
    _In_ LPWSTR ObjectDirectory,
    _In_ LPWSTR ObjectName,
    _In_ ACCESS_MASK DesiredAccess);

HANDLE supOpenObjectFromContext(
    _In_ PROP_OBJECT_INFO* Context,
    _In_ OBJECT_ATTRIBUTES* ObjectAttributes,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ NTSTATUS* Status);

BOOL supCloseObjectFromContext(
    _In_ PROP_OBJECT_INFO* Context,
    _In_ HANDLE hObject);

VOID supShowLastError(
    _In_ HWND hWnd,
    _In_ LPWSTR Source,
    _In_ DWORD LastError);

LPWSTR supFormatNtError(
    _In_ NTSTATUS NtError);

PSID supQueryTokenUserSid(
    _In_ HANDLE ProcessToken);

PSID supQueryProcessSid(
    _In_ HANDLE ProcessHandle);

VOID supCopyTreeListSubItemValue(
    _In_ HWND TreeList,
    _In_ UINT ValueIndex);

VOID supJumpToFile(
    _In_ LPWSTR lpFilePath);

PVOID supBSearch(
    _In_ PCVOID key,
    _In_ PCVOID base,
    _In_ SIZE_T num,
    _In_ SIZE_T size,
    _In_ int(*cmp)(
        _In_ PCVOID key,
        _In_ PCVOID elt
        ));

_Success_(return != FALSE)
BOOL supGetProcessDepState(
    _In_ HANDLE hProcess,
    _Out_ PPROCESS_MITIGATION_DEP_POLICY DepPolicy);

_Success_(return != FALSE)
BOOL supGetProcessMitigationPolicy(
    _In_ HANDLE hProcess,
    _In_ PROCESS_MITIGATION_POLICY Policy,
    _In_ SIZE_T Size,
    _Out_writes_bytes_(Size) PVOID Buffer);

NTSTATUS supOpenProcessEx(
    _In_ HANDLE UniqueProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle);

NTSTATUS supOpenProcessTokenEx(
    _In_ HANDLE ProcessHandle,
    _Out_ PHANDLE TokenHandle);

BOOL supPrintTimeConverted(
    _In_ PLARGE_INTEGER Time,
    _In_ WCHAR* lpszBuffer,
    _In_ SIZE_T cchBuffer);

BOOL supGetListViewItemParam(
    _In_ HWND hwndListView,
    _In_ INT itemIndex,
    _Out_ PVOID* outParam);

VOID supSetMinMaxTrackSize(
    _In_ PMINMAXINFO MinMaxInfo,
    _In_ INT MinX,
    _In_ INT MinY,
    _In_ BOOL Scaled);

BOOL WINAPI supCallbackShowChildWindow(
    _In_ HWND hwnd,
    _In_ LPARAM lParam);

LPWSTR supGetSidNameUse(
    _In_ SID_NAME_USE SidNameUse);

LPWSTR supIntegrityToString(
    _In_ DWORD IntegrityLevel);

BOOL supLookupSidUserAndDomainEx(
    _In_ PSID Sid,
    _In_ LSA_HANDLE PolicyHandle,
    _Out_ LPWSTR* lpSidUserAndDomain);

BOOL supLookupSidUserAndDomain(
    _In_ PSID Sid,
    _Out_ LPWSTR* lpSidUserAndDomain);

NTSTATUS supLsaOpenMachinePolicy(
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PLSA_HANDLE PolicyHandle);

PSYSTEM_HANDLE_INFORMATION_EX supHandlesCreateFilteredAndSortedList(
    _In_ ULONG_PTR FilterUniqueProcessId,
    _In_ BOOLEAN fObject);

BOOL supHandlesQueryObjectAddress(
    _In_ PSYSTEM_HANDLE_INFORMATION_EX SortedHandleList,
    _In_ HANDLE ObjectHandle,
    _Out_ PULONG_PTR ObjectAddress);

BOOL supHandlesFreeList(
    PSYSTEM_HANDLE_INFORMATION_EX SortedHandleList);

BOOL supPHLCreate(
    _Inout_ PLIST_ENTRY ListHead,
    _In_ PBYTE ProcessList,
    _Out_ PULONG NumberOfProcesses,
    _Out_ PULONG NumberOfThreads);

VOID supPHLFree(
    _In_ PLIST_ENTRY ListHead,
    _In_ BOOLEAN fClose);

HANDLE supPHLGetEntry(
    _In_ PLIST_ENTRY ListHead,
    _In_ HANDLE UniqueProcessId);

PVOID supSLCacheRead(
    VOID);

BOOLEAN supSLCacheEnumerate(
    _In_ PVOID CacheData,
    _In_opt_ PENUMERATE_SL_CACHE_VALUE_DESCRIPTORS_CALLBACK Callback,
    _In_opt_ PVOID Context);

HRESULT supShellExecInExplorerProcessEx(
    _In_ PCWSTR pszFile,
    _In_opt_ PCWSTR pszArguments);

HRESULT WINAPI supShellExecInExplorerProcess(
    _In_ PCWSTR pszFile);

VOID supShowNtStatus(
    _In_ HWND hWnd,
    _In_ LPWSTR lpText,
    _In_ NTSTATUS Status);

UINT supGetDPIValue(
    _In_opt_ HWND hWnd);

BOOLEAN supLoadIconForObjectType(
    _In_ HWND hwndDlg,
    _In_ PROP_OBJECT_INFO * Context,
    _In_ HIMAGELIST ImageList,
    _In_ BOOLEAN IsShadow);

VOID supDestroyIconForObjectType(
    _In_ PROP_OBJECT_INFO * Context);

NTSTATUS supOpenTokenByParam(
    _In_ CLIENT_ID * ClientId,
    _In_ OBJECT_ATTRIBUTES * ObjectAttributes,
    _In_ ACCESS_MASK TokenDesiredAccess,
    _In_ BOOL IsThreadToken,
    _Out_ PHANDLE TokenHandle);

BOOL supRegDeleteKeyRecursive(
    _In_ HKEY hKeyRoot,
    _In_ LPWSTR lpSubKey);

INT supAddListViewColumn(
    _In_ HWND ListViewHwnd,
    _In_ INT ColumnIndex,
    _In_ INT SubItemIndex,
    _In_ INT OrderIndex,
    _In_ INT ImageIndex,
    _In_ INT Format,
    _In_ LPWSTR Text,
    _In_ INT Width);

INT supListViewBaseComparer(
    _In_ HWND ListViewHandle,
    _In_ BOOL InverseSort,
    _In_ LPARAM FirstItem,
    _In_ LPARAM SecondItem,
    _In_ LPARAM ColumnToSort);

ULONG supHashString(
    _In_ PCWSTR String,
    _In_ ULONG Length);

ULONG supHashStringAnsi(
    _In_ PCSTR String,
    _In_ ULONG Length);

ULONG supHashUnicodeString(
    _In_ CONST UNICODE_STRING * String);

NTSTATUS supCreateSystemAdminAccessSD(
    _Out_ PSECURITY_DESCRIPTOR * SecurityDescriptor,
    _Out_ PACL * DefaultAcl);

VOID supSetProcessMitigationImagesPolicy();

ULONG supGetTimeAsSecondsSince1970(
    VOID);

BOOL supRichEdit32Load();

VOID supReportAbnormalTermination(
    _In_ LPWSTR FunctionName);

VOID supReportException(
    _In_ ULONG ExceptionCode,
    _In_opt_ PEXCEPTION_POINTERS ExceptionPointers);

BOOL supGetVersionInfoFromSection(
    _In_ HANDLE SectionHandle,
    _Out_opt_ PDWORD VersionInfoSize,
    _Out_ LPVOID * VersionData);

VOID supReportAPIError(
    _In_ LPWSTR FunctionName,
    _In_ NTSTATUS NtStatus);

BOOLEAN supIsFileImageSection(
    _In_ ULONG AllocationAttributes);

BOOLEAN supIsDriverShimmed(
    _In_ PKSE_ENGINE_DUMP KseEngineDump,
    _In_ PVOID DriverBaseAddress);

BOOL supListViewExportToFile(
    _In_ LPWSTR FileName,
    _In_ HWND WindowHandle,
    _In_ HWND ListView);

VOID supStatusBarSetText(
    _In_ HWND hwndStatusBar,
    _In_ WPARAM partIndex,
    _In_ LPWSTR lpText);

VOID supJumpToFileListView(
    _In_ HWND hwndList,
    _In_ INT iFileNameColumn);

VOID supQueryAlpcPortObjectTypeIndex(
    _In_ PVOID PortGlobal);

BOOL supEnumHandleDump(
    _In_ PSYSTEM_HANDLE_INFORMATION_EX HandleDump,
    _In_ PENUMERATE_HANDLE_DUMP_CALLBACK EnumCallback,
    _In_ PVOID UserContext);

NTSTATUS supOpenPortObjectByName(
    _Out_ PHANDLE ObjectHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_opt_ PHANDLE ReferenceHandle,
    _In_ LPCWSTR ObjectName);

NTSTATUS supOpenPortObjectFromContext(
    _Out_ PHANDLE ObjectHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PROP_OBJECT_INFO * Context);

NTSTATUS supQueryProcessImageFileNameWin32(
    _In_ HANDLE UniqueProcessId,
    _Out_ PUNICODE_STRING * ProcessImageFileName);

PSID supGetSidFromAce(
    _In_ PACE_HEADER AceHeader);

NTSTATUS supQuerySecurityInformation(
    _In_ HANDLE ObjectHandle,
    _In_ SECURITY_INFORMATION SecurityInformationClass,
    _Out_ PVOID * Buffer,
    _Out_opt_ PULONG ReturnLength);

typedef VOID(CALLBACK* pfnPopupMenuHandler)(
    _In_ HWND hwndDlg,
    _In_ LPPOINT lpPoint,
    _In_opt_ PVOID lpUserParam
    );

VOID supHandleContextMenuMsgForListView(
    _In_ HWND hwndDlg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam,
    _In_ HWND hwndControl,
    _In_ pfnPopupMenuHandler MenuHandler,
    _In_opt_ PVOID lpUserParam);

ULONG supAddLVColumnsFromArray(
    _In_ HWND ListView,
    _In_ PLVCOLUMNS_DATA ColumnsData,
    _In_ ULONG NumberOfColumns);

VOID supShowInitError(
    _In_ DWORD ErrorType);

wchar_t* supExtractFileName(
    _In_ const wchar_t* lpFullPath);

VOID supObjectDumpHandlePopupMenu(
    _In_ HWND hwndDlg);

VOID supObDumpShowError(
    _In_ HWND hwndDlg,
    _In_opt_ LPWSTR lpMessageText);

NTSTATUS supGetFirmwareType(
    _Out_ PFIRMWARE_TYPE FirmwareType);

NTSTATUS supIsBootDriveVHD(
    _Out_ PBOOLEAN IsVHD);

LPWSTR supPathAddBackSlash(
    _In_ LPWSTR lpszPath);
