/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2020
*
*  TITLE:       EXTAPI.C
*
*  VERSION:     1.86
*
*  DATE:        26 May 2020
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

    //
    // New Partition API introduced in Windows 10.
    //
    hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
    if (hNtdll) {
        g_ExtApiSet.NtOpenPartition = (pfnNtOpenPartition)GetProcAddress(hNtdll, "NtOpenPartition");

        if (g_ExtApiSet.NtOpenPartition) {
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
