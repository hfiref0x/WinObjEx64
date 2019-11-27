/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       PLUGINMNGR.H
*
*  VERSION:     1.82
*
*  DATE:        02 Nov 2019
*
*  Common header file for the plugin manager.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// Plugin init routine name.
//
#define WINOBJEX_PLUGIN_EXPORT "PluginInit"

#define ID_MENU_PLUGINS       60000
#define WINOBJEX_MAX_PLUGINS  ID_MENU_PLUGINS + 20

//
// VERSION_INFO "FileDescription" value used for validating plugin.
//
#define WINOBJEX_PLUGIN_DESCRIPTION TEXT("WinObjEx64 Plugin")

typedef BOOL(CALLBACK *pfnReadSystemMemoryEx)(
    _In_ ULONG_PTR Address,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG NumberOfBytesRead);

typedef UCHAR (CALLBACK *pfnGetInstructionLength)(
    _In_ PVOID ptrCode,
    _Out_ PULONG ptrFlags);

typedef PVOID(*pfnGetSystemInfoEx)(
    _In_ ULONG SystemInformationClass,
    _Out_opt_ PULONG ReturnLength,
    _In_ PMEMALLOCROUTINE MemAllocRoutine,
    _In_ PMEMFREEROUTINE MemFreeRoutine);

typedef PVOID(*pfnFindModuleEntryByName)(
    _In_ PVOID pModulesList,
    _In_ LPCSTR ModuleName);

typedef ULONG(*pfnFindModuleEntryByAddress)(
    _In_ PVOID pModulesList,
    _In_ PVOID Address);

typedef BOOL(*pfnFindModuleNameByAddress)(
    _In_ PVOID pModulesList,
    _In_ PVOID Address,
    _Inout_	LPWSTR Buffer,
    _In_ DWORD ccBuffer);

typedef BOOL(*pfnGetWin32FileName)(
    _In_ LPWSTR FileName,
    _Inout_ LPWSTR Win32FileName,
    _In_ SIZE_T ccWin32FileName);

typedef INT(*pfnuiGetMaxOfTwoU64FromHex)(
    _In_ HWND ListView,
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort,
    _In_ BOOL Inverse);

typedef INT(*pfnuiGetMaxCompareTwoFixedStrings)(
    _In_ HWND ListView,
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort,
    _In_ BOOL Inverse);

typedef VOID(*pfnuiCopyTreeListSubItemValue)(
    _In_ HWND TreeList,
    _In_ UINT ValueIndex);

typedef VOID(*pfnuiCopyListViewSubItemValue)(
    _In_ HWND ListView,
    _In_ UINT ValueIndex);

typedef VOID(*pfnuiShowFileProperties)(
    _In_ HWND hwndDlg,
    _In_ LPWSTR lpFileName);

typedef UINT(*pfnuiGetDPIValue)(
    _In_opt_ HWND hWnd);

typedef struct _WINOBJEX_PARAM_BLOCK {
    HWND ParentWindow;
    HINSTANCE hInstance;
    ULONG_PTR SystemRangeStart;
    RTL_OSVERSIONINFOW osver;

    //sys
    pfnReadSystemMemoryEx ReadSystemMemoryEx;
    pfnGetInstructionLength GetInstructionLength;
    pfnGetSystemInfoEx GetSystemInfoEx;
    pfnFindModuleEntryByName FindModuleEntryByName;
    pfnFindModuleEntryByAddress FindModuleEntryByAddress;
    pfnFindModuleNameByAddress FindModuleNameByAddress;
    pfnGetWin32FileName GetWin32FileName;

    //ui
    pfnuiGetMaxOfTwoU64FromHex uiGetMaxOfTwoU64FromHex;
    pfnuiGetMaxCompareTwoFixedStrings uiGetMaxCompareTwoFixedStrings;
    pfnuiCopyTreeListSubItemValue uiCopyTreeListSubItemValue;
    pfnuiCopyListViewSubItemValue uiCopyListViewSubItemValue;
    pfnuiShowFileProperties uiShowFileProperties;
    pfnuiGetDPIValue uiGetDPIValue;

} WINOBJEX_PARAM_BLOCK, *PWINOBJEX_PARAM_BLOCK;

typedef NTSTATUS(CALLBACK *pfnStartPlugin)(
    _In_ PWINOBJEX_PARAM_BLOCK ParamBlock
    );

typedef void(CALLBACK *pfnStopPlugin)(
    VOID
    );

typedef struct _WINOBJEX_PLUGIN WINOBJEX_PLUGIN;

typedef enum _WINOBJEX_PLUGIN_STATE {
    PluginInitialization = 0,
    PluginStopped = 1,
    PluginRunning = 2,
    PluginError = 3,
    MaxPluginState
} WINOBJEX_PLUGIN_STATE;

typedef void(CALLBACK *pfnStateChangeCallback)(
    _In_ WINOBJEX_PLUGIN *PluginData,
    _In_ WINOBJEX_PLUGIN_STATE NewState,
    _In_ PVOID Reserved
    );

typedef struct _WINOBJEX_PLUGIN {
    BOOLEAN NeedAdmin;
    BOOLEAN NeedDriver;
    BOOLEAN SupportWine;
    WINOBJEX_PLUGIN_STATE State;
    WORD MajorVersion;
    WORD MinorVersion;
    WCHAR Description[64];
    pfnStartPlugin StartPlugin;
    pfnStopPlugin StopPlugin;
    pfnStateChangeCallback StateChangeCallback;
} WINOBJEX_PLUGIN, *PWINOBJEX_PLUGIN;

typedef struct _WINOBJEX_PLUGIN_INTERNAL {
    LIST_ENTRY ListEntry;
    UINT Id;
    WINOBJEX_PLUGIN Plugin;
} WINOBJEX_PLUGIN_INTERNAL, *PWINOBJEX_PLUGIN_INTERNAL;

typedef BOOLEAN(CALLBACK *pfnPluginInit)(
    _Out_ PWINOBJEX_PLUGIN PluginData
    );

VOID PluginManagerCreate(_In_ HWND MainWindow);
VOID PluginManagerDestroy();
WINOBJEX_PLUGIN_INTERNAL *PluginManagerGetEntryById(
    _In_ UINT Id);

VOID PluginManagerProcessEntry(
    _In_ HWND ParentWindow,
    _In_ UINT Id);
