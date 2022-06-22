/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2022
*
*  TITLE:       EXTAPI.C
*
*  VERSION:     2.00
*
*  DATE:        19 Jun 2022
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

    RtlSecureZeroMemory(&g_ExtApiSet, sizeof(g_ExtApiSet));


    hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
    if (hNtdll) {
        //
        // New Partition API introduced in Windows 10 TH1.
        //
        g_ExtApiSet.NtOpenPartition = (pfnNtOpenPartition)GetProcAddress(hNtdll, "NtOpenPartition");

        if (g_ExtApiSet.NtOpenPartition) {
            g_ExtApiSet.NumberOfAPI += 1;
        }

        //
        // Available since Windows 10 REDSTONE 1.
        //
        g_ExtApiSet.NtOpenRegistryTransaction = (pfnNtOpenRegistryTransaction)GetProcAddress(hNtdll, "NtOpenRegistryTransaction");

        if (g_ExtApiSet.NtOpenRegistryTransaction) {
            g_ExtApiSet.NumberOfAPI += 1;
        }
    }

    //
    // User32 API introduced with Windows 8.
    //
    hUser32 = GetModuleHandle(TEXT("user32.dll"));
    if (hUser32) {
        g_ExtApiSet.IsImmersiveProcess = (pfnIsImmersiveProcess)GetProcAddress(hUser32, "IsImmersiveProcess");
        if (g_ExtApiSet.IsImmersiveProcess) {
            g_ExtApiSet.NumberOfAPI += 1;
        }
        g_ExtApiSet.GetAwarenessFromDpiAwarenessContext =
            (pfnGetAwarenessFromDpiAwarenessContext)GetProcAddress(hUser32, "GetAwarenessFromDpiAwarenessContext");
        if (g_ExtApiSet.GetAwarenessFromDpiAwarenessContext) {
            g_ExtApiSet.NumberOfAPI += 1;
        }
        g_ExtApiSet.GetDpiForSystem = (pfnGetDpiForSystem)GetProcAddress(hUser32, "GetDpiForSystem");
        if (g_ExtApiSet.GetDpiForSystem) {
            g_ExtApiSet.NumberOfAPI += 1;
        }
        g_ExtApiSet.GetDpiForWindow = (pfnGetDpiForWindow)GetProcAddress(hUser32, "GetDpiForWindow");
        if (g_ExtApiSet.GetDpiForWindow) {
            g_ExtApiSet.NumberOfAPI += 1;
        }
        g_ExtApiSet.GetThreadDpiAwarenessContext = (pfnGetThreadDpiAwarenessContext)
            GetProcAddress(hUser32, "GetThreadDpiAwarenessContext");
        if (g_ExtApiSet.GetThreadDpiAwarenessContext) {
            g_ExtApiSet.NumberOfAPI += 1;
        }

    }

    Status = (g_ExtApiSet.NumberOfAPI == EXTAPI_ALL_MAPPED) ?
        STATUS_SUCCESS : STATUS_NOT_ALL_ASSIGNED;

    return Status;
}
