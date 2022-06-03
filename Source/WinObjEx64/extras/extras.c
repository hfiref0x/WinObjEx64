/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2022
*
*  TITLE:       EXTRAS.C
*
*  VERSION:     1.94
*
*  DATE:        31 May 2022
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "extras.h"
#include "extrasUSD.h"
#include "extrasPN.h"
#include "extrasSSDT.h"
#include "extrasDrivers.h"
#include "extrasIPC.h"
#include "extrasPSList.h"
#include "extrasCallbacks.h"
#include "extrasSL.h"
#include "extrasCmOpt.h"

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
* extrasShowDialogById
*
* Purpose:
*
* Display dialog by it identifier.
*
*/
VOID extrasShowDialogById(
    _In_ HWND ParentWindow,
    _In_ WORD DialogId)
{
    switch (DialogId) {

    case ID_EXTRAS_PIPES:
    case ID_EXTRAS_MAILSLOTS:
        if (DialogId == ID_EXTRAS_MAILSLOTS)
            extrasCreateIpcDialog(ParentWindow, IpcModeMailSlots);
        else
            extrasCreateIpcDialog(ParentWindow, IpcModeNamedPipes);
        break;

    case ID_EXTRAS_USERSHAREDDATA:
        extrasCreateUsdDialog(ParentWindow);
        break;

    case ID_EXTRAS_PRIVATENAMESPACES:
        //
        // Feature require driver usage and not supported in 10586.
        //
        if (g_NtBuildNumber != NT_WIN10_THRESHOLD2) {
            if (kdConnectDriver()) {
                extrasCreatePNDialog(ParentWindow);
            }
            else {
                MessageBox(ParentWindow, T_DRIVER_REQUIRED, NULL, MB_ICONINFORMATION);
            }
        }
        break;

    case ID_EXTRAS_SSDT:
    case ID_EXTRAS_W32PSERVICETABLE:
        //
        // This feature require driver usage.
        //
#ifndef _DEBUG
        if (kdConnectDriver()) {
#endif
            if (DialogId == ID_EXTRAS_SSDT)
                extrasCreateSSDTDialog(ParentWindow, SST_Ntos);
            else
                extrasCreateSSDTDialog(ParentWindow, SST_Win32k);

#ifndef _DEBUG
        }
#endif
        break;

    case ID_EXTRAS_DRIVERS:
    case ID_EXTRAS_UNLOADEDDRIVERS:
        //
        // Unsupported in Wine.
        // Drivers list is empty or contains user mode dlls/application itself.
        //
        if (g_WinObj.IsWine == FALSE) {
            if (DialogId == ID_EXTRAS_DRIVERS)
                extrasCreateDriversDialog(ParentWindow, DDM_Normal);
            else
                extrasCreateDriversDialog(ParentWindow, DDM_Unloaded);
        }
        break;

    case ID_EXTRAS_PROCESSLIST:
        extrasCreatePsListDialog(ParentWindow);
        break;

    case ID_EXTRAS_CALLBACKS:
        if (kdConnectDriver()) {
            extrasCreateCallbacksDialog(ParentWindow);
        }
        else {
            MessageBox(ParentWindow, T_DRIVER_REQUIRED, NULL, MB_ICONINFORMATION);
        }
        break;

    case ID_EXTRAS_SOFTWARELICENSECACHE:
        extrasCreateSLCacheDialog(ParentWindow);
        break;

    case ID_EXTRAS_CMCONTROLVECTOR:
        extrasCreateCmOptDialog(ParentWindow);
        break;


    default:
        break;
    }
}
