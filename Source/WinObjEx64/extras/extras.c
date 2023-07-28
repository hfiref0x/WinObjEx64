/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2023
*
*  TITLE:       EXTRAS.C
*
*  VERSION:     2.03
*
*  DATE:        27 Jul 2023
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "extras.h"
#include "extrasHandlers.h"

/*
* extrasHandleSettingsChange
*
* Purpose:
*
* Handle global settings change.
*
*/
VOID extrasHandleSettingsChange(
    EXTRASCONTEXT* Context
)
{
    DWORD lvExStyle;

    lvExStyle = ListView_GetExtendedListViewStyle(Context->ListView);
    if (g_WinObj.ListViewDisplayGrid)
        lvExStyle |= LVS_EX_GRIDLINES;
    else
        lvExStyle &= ~LVS_EX_GRIDLINES;

    ListView_SetExtendedListViewStyle(Context->ListView, lvExStyle);
}

/*
* extrasSimpleListResize
*
* Purpose:
*
* Common resize handler for list only dialogs.
*
*/
VOID extrasSimpleListResize(
    _In_ HWND hwndDlg
)
{
    RECT r, szr;
    HWND hwnd, hwndStatusBar;

    RtlSecureZeroMemory(&r, sizeof(RECT));
    RtlSecureZeroMemory(&szr, sizeof(RECT));

    hwnd = GetDlgItem(hwndDlg, ID_EXTRASLIST);
    hwndStatusBar = GetDlgItem(hwndDlg, ID_EXTRASLIST_STATUSBAR);
    GetClientRect(hwndDlg, &r);
    GetClientRect(hwndStatusBar, &szr);

    SendMessage(hwndStatusBar, WM_SIZE, 0, 0);

    SetWindowPos(hwnd, 0, 0, 0,
        r.right,
        r.bottom - szr.bottom,
        SWP_NOZORDER);
}

/*
* extrasSetDlgIcon
*
* Purpose:
*
* Set dialog icon.
*
*/
VOID extrasSetDlgIcon(
    _In_ EXTRASCONTEXT* Context
)
{
    HANDLE hIcon;

    hIcon = LoadImage(g_WinObj.hInstance,
        MAKEINTRESOURCE(IDI_ICON_MAIN), IMAGE_ICON, 
        32, 32, 
        0);

    if (hIcon) {
        SendMessage(Context->hwndDlg, WM_SETICON, (WPARAM)ICON_SMALL, (LPARAM)hIcon);
        SendMessage(Context->hwndDlg, WM_SETICON, (WPARAM)ICON_BIG, (LPARAM)hIcon);
        Context->DialogIcon = (HICON)hIcon;
    }
}

/*
* extrasRemoveDlgIcon
*
* Purpose:
*
* Remove dialog icon.
*
*/
VOID extrasRemoveDlgIcon(
    _In_ EXTRASCONTEXT* Context
)
{
    if (Context->DialogIcon) {
        DestroyIcon(Context->DialogIcon);
        Context->DialogIcon = NULL;
    }
}

/*
* extrasProcessElevationRequiredDialogs
*
* Purpose:
*
* Run elevation required dialog.
* If client is not elevated - request elevation.
*
*/
VOID extrasProcessElevationRequiredDialogs(
    _In_ WORD DialogId
)
{
    WCHAR szText[200];

    if (g_WinObj.IsWine)
        return;

    if (g_kdctx.IsFullAdmin == FALSE) {
        supRunAsAdmin();
        return;
    }

    if (!kdConnectDriver()) {      

        RtlStringCchPrintfSecure(szText,
            RTL_NUMBER_OF(szText),
            TEXT("Could not connect to driver, feature is unavailable.\nDriver load status: 0x%lX\nDriver open status: 0x%lX"),
            g_kdctx.DriverContext.LoadStatus,
            g_kdctx.DriverContext.OpenStatus);

        MessageBox(g_hwndMain,
            szText, 
            PROGRAM_NAME, 
            MB_ICONINFORMATION);

        return;
    }

    switch (DialogId) {
    case ID_EXTRAS_DRIVERS:
        //
        // Since 24H2 as it restricts NTQSI output.
        //
        extrasCreateDriversDialog(DrvModeNormal);
        break;
    case ID_EXTRAS_W32PSERVICETABLE:
        //
        // Since 24H2 as it requires driver usage to access kmod apiset table.
        //
        extrasCreateSSDTDialog(SST_Win32k);
        break;
    case ID_EXTRAS_PRIVATENAMESPACES:
        extrasCreatePNDialog();
        break;
    case ID_EXTRAS_CALLBACKS:
        extrasCreateCallbacksDialog();
        break;
    case ID_EXTRAS_UNLOADEDDRIVERS:
        extrasCreateDriversDialog(DrvModeUnloaded);
        break;
    case ID_EXTRAS_SSDT:
        extrasCreateSSDTDialog(SST_Ntos);
        break;
    }
}

/*
* extrasShowDialogById
*
* Purpose:
*
* Display dialog by it identifier.
*
*/
VOID extrasShowDialogById(
    _In_ WORD DialogId
)
{
    BOOL fullAdminAccessRequired = ((g_NtBuildNumber > NT_WIN11_22H2) &&
        (g_kdctx.IsFullAdmin == FALSE) &&
        (g_WinObj.IsWine == FALSE));

    switch (DialogId) {

    case ID_EXTRAS_PIPES:
    case ID_EXTRAS_MAILSLOTS:
        if (DialogId == ID_EXTRAS_MAILSLOTS)
            extrasCreateIpcDialog(IpcModeMailSlots);
        else
            extrasCreateIpcDialog(IpcModeNamedPipes);
        break;

    case ID_EXTRAS_USERSHAREDDATA:
        extrasCreateUsdDialog();
        break;

    case ID_EXTRAS_SSDT:
    case ID_EXTRAS_UNLOADEDDRIVERS:
    case ID_EXTRAS_PRIVATENAMESPACES:
    case ID_EXTRAS_CALLBACKS:
        extrasProcessElevationRequiredDialogs(DialogId);
        break;

    case ID_EXTRAS_W32PSERVICETABLE:
        if (fullAdminAccessRequired) {
            extrasProcessElevationRequiredDialogs(DialogId);
        }
        else {
            extrasCreateSSDTDialog(SST_Win32k);
        }
        break;

    case ID_EXTRAS_DRIVERS:    
        if (fullAdminAccessRequired) {
            extrasProcessElevationRequiredDialogs(DialogId);
        }
        else {
            extrasCreateDriversDialog(DrvModeNormal);
        }
        break;

    case ID_EXTRAS_PROCESSLIST:
        extrasCreatePsListDialog();
        break;

    case ID_EXTRAS_SOFTWARELICENSECACHE:
        extrasCreateSLCacheDialog();
        break;

    case ID_EXTRAS_CMCONTROLVECTOR:
        extrasCreateCmOptDialog();
        break;

    }
}
