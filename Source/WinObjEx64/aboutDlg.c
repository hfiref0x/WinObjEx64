/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       ABOUTDLG.C
*
*  VERSION:     1.74
*
*  DATE:        27 May 2019
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#define OEMRESOURCE
#include "global.h"
#include "msvcver.h"

#undef _WINE_NB_DEBUG

HWND g_hwndGlobals;
WNDPROC g_GlobalsEditOriginalWndProc;

/*
* AboutDialogInit
*
* Purpose:
*
* Displays program version and system information
*
*/
VOID AboutDialogInit(
    HWND hwndDlg
)
{
    BOOLEAN  bSecureBoot = FALSE;
    ULONG    returnLength;
    NTSTATUS status;
    HANDLE   hImage;
    WCHAR    szBuffer[MAX_PATH];

    PCHAR    wine_ver, wine_str;

    SYSTEM_BOOT_ENVIRONMENT_INFORMATION sbei;
    SYSTEM_VHD_BOOT_INFORMATION *psvbi;

    SetDlgItemText(hwndDlg, ID_ABOUT_PROGRAM, PROFRAM_NAME_AND_TITLE);
    SetDlgItemText(hwndDlg, ID_ABOUT_BUILDINFO, PROGRAM_VERSION);

    //
    // Set dialog icon.
    //
    hImage = LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDI_ICON_MAIN), IMAGE_ICON, 48, 48, LR_SHARED);
    if (hImage) {
        SendMessage(GetDlgItem(hwndDlg, ID_ABOUT_ICON), STM_SETIMAGE, IMAGE_ICON, (LPARAM)hImage);
        DestroyIcon((HICON)hImage);
    }

    //
    // Remove class icon if any.
    //
    SetClassLongPtr(hwndDlg, GCLP_HICON, (LONG_PTR)NULL);

    //
    // Set compiler version and name.
    //
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    _strcpy(szBuffer, VC_VER);
    if (szBuffer[0] == 0) {
        _strcpy(szBuffer, TEXT("MSVC ("));
        ultostr(_MSC_FULL_VER, _strend(szBuffer));
        _strcat(szBuffer, TEXT(")"));
    }
#if defined(__cplusplus)
    _strcat(szBuffer, TEXT(" compiled as C++"));
#else
    _strcat(szBuffer, TEXT(" compiled as C"));
#endif

    SetDlgItemText(hwndDlg, ID_ABOUT_COMPILERINFO, szBuffer);

    //
    // Set build date and time.
    //
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    MultiByteToWideChar(CP_ACP, 0, __DATE__, (INT)_strlen_a(__DATE__), _strend(szBuffer), 40);
    _strcat(szBuffer, TEXT(" "));
    MultiByteToWideChar(CP_ACP, 0, __TIME__, (INT)_strlen_a(__TIME__), _strend(szBuffer), 40);
    SetDlgItemText(hwndDlg, ID_ABOUT_BUILDDATE, szBuffer);

#ifdef _WINE_NB_DEBUG
    g_WinObj.IsWine = TRUE;
    wine_ver = "4.9";
#endif

    //
    // Fill OS name.
    //
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    if (g_WinObj.IsWine) {
        _strcpy(szBuffer, TEXT("Reported as "));
    }

    rtl_swprintf_s(_strend(szBuffer), 100, TEXT("Windows NT %1u.%1u (build %u"),
        g_WinObj.osver.dwMajorVersion, g_WinObj.osver.dwMinorVersion, g_WinObj.osver.dwBuildNumber);
    if (g_WinObj.osver.szCSDVersion[0]) {
        _strcat(szBuffer, TEXT(", "));
        _strcat(szBuffer, g_WinObj.osver.szCSDVersion);
    }
    _strcat(szBuffer, TEXT(")"));

    //
    // Fill boot options.
    //   
    if (g_WinObj.IsWine) {
#ifndef _WINE_NB_DEBUG
        wine_ver = (PCHAR)wine_get_version();
#endif
        wine_str = (PCHAR)supHeapAlloc(_strlen_a(wine_ver) + MAX_PATH);
        if (wine_str) {
            _strcpy_a(wine_str, "Wine ");
            _strcat_a(wine_str, wine_ver);
            _strcat_a(wine_str, " emulation");
            SetDlgItemTextA(hwndDlg, ID_ABOUT_OSNAME, wine_str);
            supHeapFree(wine_str);
        }
        SetDlgItemText(hwndDlg, ID_ABOUT_ADVINFO, szBuffer);

    }
    else {
        SetDlgItemText(hwndDlg, ID_ABOUT_OSNAME, szBuffer);

        RtlSecureZeroMemory(&sbei, sizeof(sbei));
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));

        //
        // Query KD debugger enabled.
        //
        if (kdIsDebugBoot()) {
            _strcpy(szBuffer, TEXT("Debug, "));
        }

        //
        // Query VHD boot state if possible.
        //
        psvbi = (SYSTEM_VHD_BOOT_INFORMATION*)supHeapAlloc(PAGE_SIZE);
        if (psvbi) {
            status = NtQuerySystemInformation(SystemVhdBootInformation, psvbi, PAGE_SIZE, &returnLength);
            if (NT_SUCCESS(status)) {
                if (psvbi->OsDiskIsVhd) {
                    _strcat(szBuffer, TEXT("VHD, "));
                }
            }
            supHeapFree(psvbi);
        }

        //
        // Query firmware mode and SecureBoot state for UEFI.
        //
        status = NtQuerySystemInformation(SystemBootEnvironmentInformation, &sbei, sizeof(sbei), &returnLength);
        if (NT_SUCCESS(status)) {

            if (sbei.FirmwareType == FirmwareTypeUefi) {
                _strcat(szBuffer, TEXT("UEFI"));
            }
            else {
                if (sbei.FirmwareType == FirmwareTypeBios) {
                    _strcat(szBuffer, TEXT("BIOS"));
                }
                else {
                    _strcat(szBuffer, TEXT("Unknown"));
                }
            }

            if (sbei.FirmwareType == FirmwareTypeUefi) {
                bSecureBoot = FALSE;
                if (supQuerySecureBootState(&bSecureBoot)) {
                    _strcat(szBuffer, TEXT(" with"));
                    if (bSecureBoot == FALSE) {
                        _strcat(szBuffer, TEXT("out"));
                    }
                    _strcat(szBuffer, TEXT(" SecureBoot"));
                }
                g_kdctx.IsSecureBoot = bSecureBoot;
            }
        }
        else {
            _strcpy(szBuffer, TEXT("Unknown"));
        }
        SetDlgItemText(hwndDlg, ID_ABOUT_ADVINFO, szBuffer);
    }

    SetFocus(GetDlgItem(hwndDlg, IDOK));
}

/*
* AboutDialogCollectGlobals
*
* Purpose:
*
* Build globals list (g_kdctx + g_WinObj).
*
*/
VOID AboutDialogCollectGlobals(
    _In_ HWND hwndParent,
    _In_ LPWSTR lpDestBuffer
)
{
    BOOLEAN bAllowed;

    //
    // Copy os name as is.
    //
    GetDlgItemText(hwndParent, ID_ABOUT_OSNAME, lpDestBuffer, MAX_PATH);

    _strcat(lpDestBuffer, TEXT("\r\n"));

    _strcat(lpDestBuffer, TEXT("IsSecureBoot: "));
    ultostr(g_kdctx.IsSecureBoot, _strend(lpDestBuffer));
    _strcat(lpDestBuffer, TEXT("\r\n"));

    _strcat(lpDestBuffer, TEXT("EnableExperimentalFeatures: "));
    ultostr(g_WinObj.EnableExperimentalFeatures, _strend(lpDestBuffer));
    _strcat(lpDestBuffer, TEXT("\r\n"));

    _strcat(lpDestBuffer, TEXT("IsWine: "));
    ultostr(g_WinObj.IsWine, _strend(lpDestBuffer));
    _strcat(lpDestBuffer, TEXT("\r\n"));

    _strcat(lpDestBuffer, TEXT("drvOpenLoadStatus: "));
    ultostr(g_kdctx.drvOpenLoadStatus, _strend(lpDestBuffer));
    if (g_kdctx.drvOpenLoadStatus == 0) {
        _strcat(lpDestBuffer, TEXT(" (reported as OK)"));
    }
    _strcat(lpDestBuffer, TEXT("\r\n"));

    _strcat(lpDestBuffer, TEXT("IsFullAdmin: "));
    ultostr(g_kdctx.IsFullAdmin, _strend(lpDestBuffer));
    _strcat(lpDestBuffer, TEXT("\r\n"));

    _strcat(lpDestBuffer, TEXT("IsOurLoad: "));
    ultostr(g_kdctx.IsOurLoad, _strend(lpDestBuffer));
    _strcat(lpDestBuffer, TEXT("\r\n"));

    _strcat(lpDestBuffer, TEXT("DirectoryRootAddress: 0x"));
    u64tohex(g_kdctx.DirectoryRootAddress, _strend(lpDestBuffer));
    _strcat(lpDestBuffer, TEXT("\r\n"));

    _strcat(lpDestBuffer, TEXT("DirectoryTypeIndex: "));
    ultostr(g_kdctx.DirectoryTypeIndex, _strend(lpDestBuffer));
    _strcat(lpDestBuffer, TEXT("\r\n"));

    _strcat(lpDestBuffer, TEXT("hDevice: 0x"));
    u64tostr((ULONG_PTR)g_kdctx.hDevice, _strend(lpDestBuffer));
    _strcat(lpDestBuffer, TEXT("\r\n"));

    _strcat(lpDestBuffer, TEXT("IopInvalidDeviceRequest: 0x"));
    u64tostr((ULONG_PTR)g_kdctx.IopInvalidDeviceRequest, _strend(lpDestBuffer));
    _strcat(lpDestBuffer, TEXT("\r\n"));

    _strcat(lpDestBuffer, TEXT("KiServiceLimit: 0x"));
    ultohex(g_kdctx.KiServiceLimit, _strend(lpDestBuffer));
    _strcat(lpDestBuffer, TEXT("\r\n"));

    _strcat(lpDestBuffer, TEXT("KiServiceTableAddress: 0x"));
    u64tohex(g_kdctx.KiServiceTableAddress, _strend(lpDestBuffer));
    _strcat(lpDestBuffer, TEXT("\r\n"));

    _strcat(lpDestBuffer, TEXT("NtOsBase: 0x"));
    u64tohex((ULONG_PTR)g_kdctx.NtOsBase, _strend(lpDestBuffer));
    _strcat(lpDestBuffer, TEXT("\r\n"));

    _strcat(lpDestBuffer, TEXT("NtOsSize: 0x"));
    ultohex(g_kdctx.NtOsSize, _strend(lpDestBuffer));
    _strcat(lpDestBuffer, TEXT("\r\n"));

    _strcat(lpDestBuffer, TEXT("ObHeaderCookie: 0x"));
    ultohex((ULONG)g_kdctx.ObHeaderCookie, _strend(lpDestBuffer));
    _strcat(lpDestBuffer, TEXT("\r\n"));

    _strcat(lpDestBuffer, TEXT("PrivateNamespaceLookupTable: 0x"));
    u64tohex((ULONG_PTR)g_kdctx.PrivateNamespaceLookupTable, _strend(lpDestBuffer));
    _strcat(lpDestBuffer, TEXT("\r\n"));

    _strcat(lpDestBuffer, TEXT("SystemRangeStart: 0x"));
    u64tohex((ULONG_PTR)g_kdctx.SystemRangeStart, _strend(lpDestBuffer));
    _strcat(lpDestBuffer, TEXT("\r\n"));

    if (NT_SUCCESS(supCICustomKernelSignersAllowed(&bAllowed))) {
        _strcat(lpDestBuffer, TEXT("Licensed for Custom Kernel Signers: "));
        if (bAllowed)
            _strcat(lpDestBuffer, TEXT("yes\r\n"));
        else
            _strcat(lpDestBuffer, TEXT("no\r\n"));
    }
}

/*
* GlobalsCustomWindowProc
*
* Purpose:
*
* Globals custom window procedure.
*
*/
LRESULT CALLBACK GlobalsCustomWindowProc(
    _In_ HWND hwnd,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    HFONT hFont;

    switch (uMsg) {
    case WM_CLOSE:
        hFont = (HFONT)GetProp(hwnd, T_PROP_FONT);
        if (hFont) {
            DeleteObject(hFont);
        }
        RemoveProp(hwnd, T_PROP_FONT);
        g_hwndGlobals = NULL;
        break;
    default:
        break;
    }
    return CallWindowProc(g_GlobalsEditOriginalWndProc, hwnd, uMsg, wParam, lParam);
}

/*
* AboutDialogShowGlobals
*
* Purpose:
*
* Output global variables to multiline edit window.
*
*/
INT_PTR AboutDialogShowGlobals(
    _In_ HWND hwndParent)
{
    HWND hwnd;
    LPWSTR lpGlobalInfo;
    HFONT hFont = NULL;

    if (g_hwndGlobals == NULL) {      

        hwnd = CreateWindowEx(
            0,
            WC_EDIT,
            TEXT("WinObjEx64 Globals"),
            WS_OVERLAPPEDWINDOW | WS_VSCROLL | ES_MULTILINE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            640,
            480,
            hwndParent,
            0,
            g_WinObj.hInstance,
            NULL);

        if (hwnd) {
            hFont = supCreateFontIndirect(T_DEFAULT_AUX_FONT);
            if (hFont) {
                SendMessage(hwnd, WM_SETFONT, (WPARAM)hFont, 0);
                SetProp(hwnd, T_PROP_FONT, hFont);
            }
            g_GlobalsEditOriginalWndProc = (WNDPROC)GetWindowLongPtr(hwnd, GWLP_WNDPROC);
            if (g_GlobalsEditOriginalWndProc) {
                SetWindowLongPtr(hwnd, GWLP_WNDPROC, (LONG_PTR)&GlobalsCustomWindowProc);
            }
        }
        g_hwndGlobals = hwnd;
    }
    else {
        SetActiveWindow(g_hwndGlobals);
    }

    //
    // Set text to window.
    //
    if (g_hwndGlobals) {
        lpGlobalInfo = (LPWSTR)supVirtualAlloc(PAGE_SIZE);
        if (lpGlobalInfo) {
            AboutDialogCollectGlobals(hwndParent, lpGlobalInfo);
            SetWindowText(g_hwndGlobals, lpGlobalInfo);
            SendMessage(g_hwndGlobals, EM_SETREADONLY, (WPARAM)1, 0);
            supVirtualFree(lpGlobalInfo);
        }
        ShowWindow(g_hwndGlobals, SW_SHOWNORMAL);
    }

    return 1;
}

/*
* AboutDialogProc
*
* Purpose:
*
* About Dialog Window Dialog Procedure
*
* During WM_INITDIALOG centers window and initializes system info
*
*/
INT_PTR CALLBACK AboutDialogProc(
    _In_ HWND   hwndDlg,
    _In_ UINT   uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    UNREFERENCED_PARAMETER(lParam);

    switch (uMsg) {

    case WM_INITDIALOG:
        supCenterWindow(hwndDlg);
        AboutDialogInit(hwndDlg);
        break;

    case WM_COMMAND:

        switch (LOWORD(wParam)) {
        case IDOK:
        case IDCANCEL:
            return EndDialog(hwndDlg, S_OK);
            break;
        case IDC_ABOUT_GLOBALS:
            return AboutDialogShowGlobals(hwndDlg);
            break;
        default:
            break;
        }

    default:
        break;
    }
    return 0;
}
