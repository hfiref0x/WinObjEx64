/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       PLUGIN_DEF.H
*
*  VERSION:     1.01
*
*  DATE:        02 Nov 2019
*
*  Common header file for the plugin subsystem definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

typedef PVOID(*PMEMALLOCROUTINE)(
    _In_ SIZE_T NumberOfBytes);

typedef BOOL(*PMEMFREEROUTINE)(
    _In_ PVOID Memory);

typedef BOOL(CALLBACK *pfnReadSystemMemoryEx)(
    _In_ ULONG_PTR Address,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG NumberOfBytesRead);

typedef UCHAR(CALLBACK *pfnGetInstructionLength)(
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
    _Reserved_ PVOID Reserved
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
