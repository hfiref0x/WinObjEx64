/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       ABOUTDLG.C
*
*  VERSION:     1.52
*
*  DATE:        08 Jan 2018
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

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

    SYSTEM_BOOT_ENVIRONMENT_INFORMATION sbei;

    SetDlgItemText(hwndDlg, ID_ABOUT_PROGRAM, PROFRAM_NAME_AND_TITLE);
    SetDlgItemText(hwndDlg, ID_ABOUT_BUILDINFO, PROGRAM_VERSION);

    hImage = LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDI_ICON_MAIN), IMAGE_ICON, 48, 48, LR_SHARED);
    if (hImage) {
        SendMessage(GetDlgItem(hwndDlg, ID_ABOUT_ICON), STM_SETIMAGE, IMAGE_ICON, (LPARAM)hImage);
        DestroyIcon(hImage);
    }

    //remove class icon if any
    SetClassLongPtr(hwndDlg, GCLP_HICON, (LONG_PTR)NULL);

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

#if ((_MSC_VER == 1910) || (_MSC_VER == 1911) || (_MSC_VER == 1912))//2017
#if (_MSC_FULL_VER == 191025017)
    _strcpy(szBuffer, L"MSVC 2017");
#else
    _strcpy(szBuffer, L"MSVC 2017");
#endif
#else
#if (_MSC_VER == 1900) //2015
#if (_MSC_FULL_VER == 190023026) //2015 RTM
    _strcpy(szBuffer, L"MSVC 2015");
#elif (_MSC_FULL_VER == 190023506) // 2015 Update 1
    _strcpy(szBuffer, L"MSVC 2015 Update 1");
#elif (_MSC_FULL_VER == 190023918) // 2015 Update 2
    _strcpy(szBuffer, L"MSVC 2015 Update 2");
#elif (_MSC_FULL_VER == 190024210) // 2015 Update 3
    _strcpy(szBuffer, L"MSVC 2015 Update 3");
#elif (_MSC_FULL_VER == 190024215) // 2015 Update 3 with Cumulative Servicing Release
    _strcpy(szBuffer, L"MSVC 2015 Update 3 CSR");
#endif
#else
#if (_MSC_VER == 1800) //2013
#if (_MSC_FULL_VER == 180040629)
    _strcpy(szBuffer, L"MSVC 2013 Update 5");
#elif (_MSC_FULL_VER == 180031101)
    _strcpy(szBuffer, L"MSVC 2013 Update 4");
#elif (_MSC_FULL_VER == 180030723)
    _strcpy(szBuffer, L"MSVC 2013 Update 3");
#elif (_MSC_FULL_VER == 180030501)
    _strcpy(szBuffer, L"MSVC 2013 Update 2");
#elif (_MSC_FULL_VER < 180021005)
    _strcpy(szBuffer, L"MSVC 2013 Preview/Beta/RC");
#else
    _strcpy(szBuffer, L"MSVC 2013");
#endif
#else
    _strcpy(szBuffer, L"Unknown Compiler");
#endif
#endif
#endif
    if (szBuffer[0] == 0) {
        ultostr(_MSC_FULL_VER, szBuffer);
    }
    SetDlgItemText(hwndDlg, ID_ABOUT_COMPILERINFO, szBuffer);

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    MultiByteToWideChar(CP_ACP, 0, __DATE__, (INT)_strlen_a(__DATE__), _strend(szBuffer), 40);
    _strcat(szBuffer, TEXT(" "));
    MultiByteToWideChar(CP_ACP, 0, __TIME__, (INT)_strlen_a(__TIME__), _strend(szBuffer), 40);
    SetDlgItemText(hwndDlg, ID_ABOUT_BUILDDATE, szBuffer);

    // fill OS name
    wsprintf(szBuffer, TEXT("Windows NT %1u.%1u (build %u"),
        g_WinObj.osver.dwMajorVersion, g_WinObj.osver.dwMinorVersion, g_WinObj.osver.dwBuildNumber);
    if (g_WinObj.osver.szCSDVersion[0]) {
        wsprintf(_strend(szBuffer), TEXT(", %ws)"), g_WinObj.osver.szCSDVersion);
    }
    else {
        _strcat(szBuffer, TEXT(")"));
    }
    SetDlgItemText(hwndDlg, ID_ABOUT_OSNAME, szBuffer);

    // fill boot options
    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
    RtlSecureZeroMemory(&sbei, sizeof(sbei));
    status = NtQuerySystemInformation(SystemBootEnvironmentInformation, &sbei, sizeof(sbei), &returnLength);
    if (NT_SUCCESS(status)) {
        wsprintf(szBuffer, TEXT("%ws mode"),
            ((sbei.FirmwareType == FirmwareTypeUefi) ? TEXT("UEFI") : ((sbei.FirmwareType == FirmwareTypeBios) ? TEXT("BIOS") : TEXT("Unknown"))));

        if (sbei.FirmwareType == FirmwareTypeUefi) {
            bSecureBoot = FALSE;
            if (supQuerySecureBootState(&bSecureBoot)) {
                wsprintf(_strend(szBuffer), TEXT(" with%ws SecureBoot"), (bSecureBoot == TRUE) ? TEXT("") : TEXT("out"));
            }
        }
    }
    else {
        _strcpy(szBuffer, TEXT("Unknown"));
    }
    SetDlgItemText(hwndDlg, ID_ABOUT_ADVINFO, szBuffer);

    SetFocus(GetDlgItem(hwndDlg, IDOK));
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
        if ((LOWORD(wParam) == IDOK) || (LOWORD(wParam) == IDCANCEL))
            EndDialog(hwndDlg, S_OK);
        break;

    default:
        break;
    }
    return 0;
}
