/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2019
*
*  TITLE:       EXTAPI.C
*
*  VERSION:     1.82
*
*  DATE:        02 Nov 2019
*
*  Support unit for pre Windows 10 missing API and experimental features.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

EXTENDED_API_SET g_ExtApiSet;

#if defined(__cplusplus)
extern "C" {
#endif

    HWINSTA StubNtUserOpenWindowStation(
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_ ACCESS_MASK DesiredAccess);

    extern DWORD dwNtUserOpenWindowStation;

#ifdef __cplusplus
}
#endif

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
    HMODULE hNtdll, hUser32, hWin32u;

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

    //
    // Win32k Native API now available in win32u.dll (same as ntdll stubs) since Windows 10 RS1.
    //
    if (g_WinObj.osver.dwBuildNumber >= 14393) {

        hWin32u = GetModuleHandle(TEXT("win32u.dll"));
        if (hWin32u == NULL) {
            hWin32u = LoadLibraryEx(TEXT("win32u.dll"), NULL, 0); //in \\KnownDlls
        }
        if (hWin32u) {
            g_ExtApiSet.NtUserOpenWindowStation = (pfnNtUserOpenWindowStation)GetProcAddress(hWin32u,
                "NtUserOpenWindowStation");

            if (g_ExtApiSet.NtUserOpenWindowStation) {
                g_ExtApiSet.NumberOfAPI += 1;
            }
        }
    }
    else {

        g_ExtApiSet.NtUserOpenWindowStation = (pfnNtUserOpenWindowStation)&StubNtUserOpenWindowStation;
        g_ExtApiSet.NumberOfAPI += 1;

        //
        // If win32u unavailable use hardcode and select proper syscall id.
        //
        switch (g_WinObj.osver.dwBuildNumber) {

        case 7600:
        case 7601:
        case 9200:
            dwNtUserOpenWindowStation = 4256;
            break;
        case 9600:
            dwNtUserOpenWindowStation = 4257;
            break;
        case 10240:
        case 10586:
            dwNtUserOpenWindowStation = 4258;
            break;
        default:
            dwNtUserOpenWindowStation = 4256;
            break;
        }

    }

    Status = (g_ExtApiSet.NumberOfAPI == EXTAPI_ALL_MAPPED) ?
        STATUS_SUCCESS : STATUS_NOT_ALL_ASSIGNED;

    return Status;
}
