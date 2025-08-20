/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2025
*
*  TITLE:       EXTAPI.C
*
*  VERSION:     2.09
*
*  DATE:        19 Aug 2025
*
*  Support unit for pre Windows 10 missing APIs.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

EXTENDED_API_SET g_ExtApiSet;

#define RESOLVE_API(set, mod, field, type, name) \
    set->field = (type)GetProcAddress(mod, name); \
    if (set->field) set->NumberOfAPI += 1;

/*
* ExApiSetInit
*
* Purpose:
*
* Initializes newest Windows version specific function pointers.
*
* Called once during supInit
*
*/
NTSTATUS ExApiSetInit(
    VOID
)
{
    NTSTATUS Status;
    HMODULE hNtdll, hUser32;
    PEXTENDED_API_SET set = &g_ExtApiSet;

    RtlSecureZeroMemory(&g_ExtApiSet, sizeof(g_ExtApiSet));

    hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
    if (hNtdll) {
        // Available since Windows 10 TH1.
        RESOLVE_API(set, hNtdll, NtOpenPartition, pfnNtOpenPartition, "NtOpenPartition");
        // Available since Windows 10 REDSTONE 1.
        RESOLVE_API(set, hNtdll, NtOpenRegistryTransaction, pfnNtOpenRegistryTransaction, "NtOpenRegistryTransaction");
    }

    //
    // User32 API introduced with Windows 8.
    //
    hUser32 = GetModuleHandle(TEXT("user32.dll"));
    if (hUser32) {
        RESOLVE_API(set, hUser32, IsImmersiveProcess, pfnIsImmersiveProcess, "IsImmersiveProcess");
        RESOLVE_API(set, hUser32, GetAwarenessFromDpiAwarenessContext, pfnGetAwarenessFromDpiAwarenessContext, "GetAwarenessFromDpiAwarenessContext");
        RESOLVE_API(set, hUser32, GetDpiForSystem, pfnGetDpiForSystem, "GetDpiForSystem");
        RESOLVE_API(set, hUser32, GetDpiForWindow, pfnGetDpiForWindow, "GetDpiForWindow");
        RESOLVE_API(set, hUser32, GetThreadDpiAwarenessContext, pfnGetThreadDpiAwarenessContext, "GetThreadDpiAwarenessContext");
    }

    Status = (g_ExtApiSet.NumberOfAPI == EXTAPI_ALL_MAPPED) ?
        STATUS_SUCCESS : STATUS_NOT_ALL_ASSIGNED;

    return Status;
}
