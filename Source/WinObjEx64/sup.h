/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       SUP.H
*
*  VERSION:     1.82
*
*  DATE:        11 Nov 2019
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

// return true to stop enumeration
typedef BOOL(CALLBACK *PENUMERATE_SL_CACHE_VALUE_DESCRIPTORS_CALLBACK)(
    _In_ SL_KMEM_CACHE_VALUE_DESCRIPTOR *CacheDescriptor,
    _In_opt_ PVOID Context
    );

typedef PVOID(*PMEMALLOCROUTINE)(
    _In_ SIZE_T NumberOfBytes);

typedef BOOL(*PMEMFREEROUTINE)(
    _In_ PVOID Memory);

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
} PROCESS_MITIGATION_POLICIES_ALL, *PPROCESS_MITIGATION_POLICIES;

typedef struct _PROCESS_MITIGATION_POLICY_RAW_DATA {
    PROCESS_MITIGATION_POLICY Policy;
    ULONG Value;
} PROCESS_MITIGATION_POLICY_RAW_DATA, *PPROCESS_MITIGATION_POLICY_RAW_DATA;

#define GET_BIT(Integer, Bit) (((Integer) >> (Bit)) & 0x1)
#define SET_BIT(Integer, Bit) ((Integer) |= 1 << (Bit))
#define CLEAR_BIT(Integer, Bit) ((Integer) &= ~(1 << (Bit)))

//
// Conversion buffer size
//
#define DBUFFER_SIZE                 512

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

BOOL supInitNtdllCRT(
    _In_ BOOL IsWine);

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

PVOID supVirtualAllocEx(
    _In_ SIZE_T Size,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect);

PVOID supVirtualAlloc(
    _In_ SIZE_T Size);

BOOL supVirtualFree(
    _In_ PVOID Memory);

BOOL supInitTreeListForDump(
    _In_  HWND  hwndParent,
    _Out_ HWND *pTreeListHwnd);

VOID supShowHelp(
    _In_ HWND ParentWindow);

BOOL supQueryObjectFromHandle(
    _In_ HANDLE Object,
    _Out_ ULONG_PTR *Address,
    _Out_opt_ USHORT *TypeIndex);

BOOL supQueryObjectFromHandleDump(
    _In_ HANDLE Object,
    _In_ PSYSTEM_HANDLE_INFORMATION_EX HandleDump,
    _Out_ ULONG_PTR *Address,
    _Out_opt_ USHORT *TypeIndex);

HICON supGetMainIcon(
    _In_ LPWSTR lpFileName,
    _In_ INT cx,
    _In_ INT cy);

void supCopyMemory(
    _Inout_ void *dest,
    _In_ size_t ccdest,
    _In_ const void *src,
    _In_ size_t ccsrc);

BOOL supUserIsFullAdmin(
    VOID);

VOID supCenterWindow(
    _In_ HWND hwnd);

VOID supSetWaitCursor(
    _In_ BOOL fSet);

HWND supDisplayLoadBanner(
    _In_ HWND hwndParent,
    _In_ LPWSTR lpMessage);

HIMAGELIST supLoadImageList(
    _In_ HINSTANCE hInst,
    _In_ UINT FirstId,
    _In_ UINT LastId);

UINT supGetObjectNameIndexByTypeIndex(
    _In_ PVOID Object,
    _In_ UCHAR TypeIndex);

VOID supRunAsAdmin(
    VOID);

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

BOOL supIsSymlink(
    _In_ HWND hwndList,
    _In_ INT iItem);

VOID supCreateToolbarButtons(
    _In_ HWND hWndToolbar);

VOID supInit(
    _In_ BOOL IsFullAdmin);

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

BOOL supEnablePrivilege(
    _In_ DWORD PrivilegeName,
    _In_ BOOL fEnable);

LPWSTR supGetItemText(
    _In_ HWND ListView,
    _In_ INT nItem,
    _In_ INT nSubItem,
    _Out_opt_ PSIZE_T lpSize);

LPWSTR supGetItemText2(
    _In_ HWND ListView,
    _In_ INT nItem,
    _In_ INT nSubItem,
    _In_ WCHAR *pszText,
    _In_ UINT cchText);

BOOL supQueryLinkTarget(
    _In_opt_ HANDLE hRootDirectory,
    _In_ PUNICODE_STRING ObjectName,
    _Inout_	LPWSTR Buffer,
    _In_ DWORD cbBuffer);

BOOL supQuerySectionFileInfo(
    _In_opt_ HANDLE hRootDirectory,
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

BOOL supQueryProcessName(
    _In_ ULONG_PTR dwProcessId,
    _In_ PVOID ProcessList,
    _Inout_	LPWSTR Buffer,
    _In_ DWORD ccBuffer);

BOOL supQueryThreadWin32StartAddress(
    _In_ HANDLE ThreadHandle,
    _Out_ PULONG_PTR Win32StartAddress);

BOOL supQueryProcessNameByEPROCESS(
    _In_ ULONG_PTR ValueOfEPROCESS,
    _In_ PVOID ProcessList,
    _Inout_ LPWSTR Buffer,
    _In_ DWORD ccBuffer);

PVOID supFindModuleEntryByName(
    _In_ PRTL_PROCESS_MODULES pModulesList,
    _In_ LPCSTR ModuleName);

BOOL supFindModuleNameByAddress(
    _In_ PRTL_PROCESS_MODULES pModulesList,
    _In_ PVOID Address,
    _Inout_	LPWSTR Buffer,
    _In_ DWORD ccBuffer);

ULONG supFindModuleEntryByAddress(
    _In_ PRTL_PROCESS_MODULES pModulesList,
    _In_ PVOID Address);

PVOID supGetTokenInfo(
    _In_ HANDLE TokenHandle,
    _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
    _Out_opt_ PULONG ReturnLength);

PVOID supGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_opt_ PULONG ReturnLength);

PVOID supGetSystemInfoEx(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_opt_ PULONG ReturnLength,
    _In_ PMEMALLOCROUTINE MemAllocRoutine,
    _In_ PMEMFREEROUTINE MemFreeRoutine);

HANDLE supOpenDirectory(
    _In_ LPWSTR lpDirectory);

HANDLE supOpenDirectoryForObject(
    _In_ LPWSTR lpObjectName,
    _In_ LPWSTR lpDirectory);

BOOL supDumpSyscallTableConverted(
    _In_ ULONG_PTR ServiceTableAddress,
    _In_ ULONG ServiceLimit,
    _Out_ PUTable *Table);

BOOL supCreateSCMSnapshot(
    _In_ ULONG ServiceType,
    _Out_opt_ SCMDB *Snapshot);

VOID supFreeSCMSnapshot(
    _In_opt_ SCMDB *Snapshot);

BOOL sapiCreateSetupDBSnapshot(
    VOID);

VOID sapiFreeSnapshot(
    VOID);

VOID supQueryKnownDlls(
    VOID);

BOOL supSaveDialogExecute(
    _In_ HWND OwnerWindow,
    _Inout_ LPWSTR SaveFileName,
    _In_ LPWSTR lpDialogFilter);

ULONG_PTR supWriteBufferToFile(
    _In_ PWSTR lpFileName,
    _In_ PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOL Flush,
    _In_ BOOL Append);

BOOL supIsProcess32bit(
    _In_ HANDLE hProcess);

ULONG_PTR supQuerySystemRangeStart(
    VOID);

BOOL supGetWin32FileName(
    _In_ LPWSTR FileName,
    _Inout_ LPWSTR Win32FileName,
    _In_ SIZE_T ccWin32FileName);

BOOLEAN supIsWine(
    VOID);

BOOL supQuerySecureBootState(
    _In_ PBOOLEAN pbSecureBoot);

HWINSTA supOpenWindowStationFromContext(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ BOOL fInherit,
    _In_ ACCESS_MASK dwDesiredAccess);

HWINSTA supOpenWindowStationFromContextEx(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ BOOL fInherit,
    _In_ ACCESS_MASK dwDesiredAccess);

BOOL supQueryObjectTrustLabel(
    _In_ HANDLE hObject,
    _Out_ PULONG ProtectionType,
    _Out_ PULONG ProtectionLevel);

NTSTATUS supIsLocalSystem(
    _In_ HANDLE hToken,
    _Out_ PBOOL pbResult);

BOOL supRunAsLocalSystem(
    _In_ HWND hwndParent);

HANDLE supGetCurrentProcessToken(
    VOID);

PVOID supLookupImageSectionByName(
    _In_ CHAR* SectionName,
    _In_ ULONG SectionNameLength,
    _In_ PVOID DllBase,
    _Out_ PULONG SectionSize);

PVOID supFindPattern(
    _In_ CONST PBYTE Buffer,
    _In_ SIZE_T BufferSize,
    _In_ CONST PBYTE Pattern,
    _In_ SIZE_T PatternSize);

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

HANDLE supOpenObjectFromContext(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ OBJECT_ATTRIBUTES *ObjectAttributes,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ NTSTATUS *Status);

BOOL supCloseObjectFromContext(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HANDLE hObject);

VOID supShowLastError(
    _In_ HWND hWnd,
    _In_ LPWSTR Source,
    _In_ DWORD LastError);

PSID supQueryTokenUserSid(
    _In_ HANDLE hProcessToken);

PSID supQueryProcessSid(
    _In_ HANDLE hProcess);

VOID supCopyTreeListSubItemValue(
    _In_ HWND TreeList,
    _In_ UINT ValueIndex);

VOID supCopyListViewSubItemValue(
    _In_ HWND ListView,
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

NTSTATUS supOpenProcess(
    _In_ HANDLE UniqueProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle);

NTSTATUS supOpenProcessEx(
    _In_ HANDLE UniqueProcessId,
    _Out_ PHANDLE ProcessHandle);

NTSTATUS supOpenProcessTokenEx(
    _In_ HANDLE ProcessHandle,
    _Out_ PHANDLE TokenHandle);

NTSTATUS supOpenThread(
    _In_ PCLIENT_ID ClientId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ThreadHandle);

BOOL supPrintTimeConverted(
    _In_ PLARGE_INTEGER Time,
    _In_ WCHAR *lpszBuffer,
    _In_ SIZE_T cchBuffer);

BOOL supGetListViewItemParam(
    _In_ HWND hwndListView,
    _In_ INT itemIndex,
    _Out_ PVOID *outParam);

BOOL WINAPI supCallbackShowChildWindow(
    _In_ HWND hwnd,
    _In_ LPARAM lParam);

LPWSTR supIntegrityToString(
    _In_ DWORD IntegrityLevel);

BOOL supLookupSidUserAndDomain(
    _In_ PSID Sid,
    _Out_ LPWSTR *lpSidUserAndDomain);

BOOL supQueryProcessEntryById(
    _In_ HANDLE UniqueProcessId,
    _In_ PVOID ProcessList,
    _Out_ PSYSTEM_PROCESSES_INFORMATION *Entry);

BOOL supHandlesQueryObjectAddress(
    _In_ PSYSTEM_HANDLE_INFORMATION_EX SortedHandleList,
    _In_ HANDLE ObjectHandle,
    _Out_ PULONG_PTR ObjectAddress);

PSYSTEM_HANDLE_INFORMATION_EX supHandlesCreateFilteredAndSortedList(
    _In_ ULONG_PTR FilterUniqueProcessId,
    _In_ BOOLEAN fObject);

BOOL supHandlesFreeList(
    PSYSTEM_HANDLE_INFORMATION_EX SortedHandleList);

NTSTATUS supCICustomKernelSignersAllowed(
    _Out_ PBOOLEAN bAllowed);

VOID supPHLFree(
    _In_ PLIST_ENTRY ListHead,
    _In_ BOOLEAN fClose);

HANDLE supPHLGetEntry(
    _In_ PLIST_ENTRY ListHead,
    _In_ HANDLE UniqueProcessId);

BOOL supPHLCreate(
    _Inout_ PLIST_ENTRY ListHead,
    _In_ PBYTE ProcessList,
    _Out_ PULONG NumberOfProcesses,
    _Out_ PULONG NumberOfThreads);

PVOID supSLCacheRead(
    VOID);

BOOLEAN supSLCacheEnumerate(
    _In_ PVOID CacheData,
    _In_opt_ PENUMERATE_SL_CACHE_VALUE_DESCRIPTORS_CALLBACK Callback,
    _In_opt_ PVOID Context);

HFONT supCreateFontIndirect(
    _In_ LPWSTR FaceName);

HRESULT WINAPI supShellExecInExplorerProcess(
    _In_ PCWSTR pszFile);

NTSTATUS supPrivilegeEnabled(
    _In_ HANDLE ClientToken,
    _In_ ULONG Privilege,
    _Out_ LPBOOL pfResult);

VOID supShowNtStatus(
    _In_ HWND hWnd,
    _In_ LPWSTR lpText,
    _In_ NTSTATUS Status);

UINT supGetDPIValue(
    _In_opt_ HWND hWnd);

BOOLEAN supLoadIconForObjectType(
    _In_ HWND hwndDlg,
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HIMAGELIST ImageList,
    _In_ BOOLEAN IsShadow);

VOID supDestroyIconForObjectType(
    _In_ PROP_OBJECT_INFO *Context);

NTSTATUS supOpenTokenByParam(
    _In_ CLIENT_ID *ClientId,
    _In_ OBJECT_ATTRIBUTES *ObjectAttributes,
    _In_ ACCESS_MASK TokenDesiredAccess,
    _In_ BOOL IsThreadToken,
    _Out_ PHANDLE TokenHandle);
