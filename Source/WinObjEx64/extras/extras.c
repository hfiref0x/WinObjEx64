/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       EXTRAS.C
*
*  VERSION:     1.70
*
*  DATE:        30 Nov 2018
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

/*
* extrasSimpleListResize
*
* Purpose:
*
* Common resize handler for list only dialogs.
*
*/
VOID extrasSimpleListResize(
    _In_ HWND hwndDlg,
    _In_ HWND hwndSzGrip
)
{
    RECT r1;
    HWND hwnd;
    INT  cy;

    RtlSecureZeroMemory(&r1, sizeof(r1));

    hwnd = GetDlgItem(hwndDlg, ID_EXTRASLIST);
    GetClientRect(hwndDlg, &r1);

    cy = r1.bottom - 16;
    if (hwndSzGrip != 0)
        cy -= GRIPPER_SIZE;

    SetWindowPos(hwnd, 0, 0, 0,
        r1.right - 16,
        cy,
        SWP_NOMOVE | SWP_NOZORDER);

    supSzGripWindowOnResize(hwndDlg, hwndSzGrip);
}

/*
* extrasDlgHandleNotify
*
* Purpose:
*
* Common WM_NOTIFY processing for list only dialogs.
*
*/
VOID extrasDlgHandleNotify(
    _In_ LPNMLISTVIEW nhdr,
    _In_ EXTRASCONTEXT *Context,
    _In_ DlgCompareFunction CompareFunc,
    _In_opt_ CustomNotifyFunction CustomHandler,
    _In_opt_ PVOID CustomParameter
)
{
    INT nImageIndex;

    if ((nhdr == NULL) || (Context == NULL) || (CompareFunc == NULL))
        return;

    if (nhdr->hdr.idFrom != ID_EXTRASLIST)
        return;

    switch (nhdr->hdr.code) {

    case LVN_COLUMNCLICK:

        Context->bInverseSort = !Context->bInverseSort;
        Context->lvColumnToSort = ((NMLISTVIEW *)nhdr)->iSubItem;
        ListView_SortItemsEx(Context->ListView, CompareFunc, Context->lvColumnToSort);

        nImageIndex = ImageList_GetImageCount(g_ListViewImages);
        if (Context->bInverseSort)
            nImageIndex -= 2; //sort down/up images are always at the end of g_ListViewImages
        else
            nImageIndex -= 1;

        supUpdateLvColumnHeaderImage(
            Context->ListView,
            Context->lvColumnCount,
            Context->lvColumnToSort,
            nImageIndex);

        break;

    default:
        break;
    }

    if (CustomHandler) {
        CustomHandler(nhdr, Context, CustomParameter);
    }
}

/*
* extrasSetDlgIcon
*
* Purpose:
*
* Extras dialog icon.
*
*/
VOID extrasSetDlgIcon(
    _In_ HWND hwndDlg
)
{
    HANDLE hIcon;

    hIcon = LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDI_ICON_MAIN), IMAGE_ICON, 0, 0, LR_SHARED);
    if (hIcon) {
        SetClassLongPtr(hwndDlg, GCLP_HICON, (LONG_PTR)hIcon);
        DestroyIcon((HICON)hIcon);
    }
}

/*
* extrasShowIPCDialog
*
* Purpose:
*
* Display Pipe/Mailslots Properties Dialog.
*
*/
VOID extrasShowIPCDialog(
    _In_ HWND hwndParent,
    _In_ ULONG CallerId
)
{
    if (CallerId == ID_EXTRAS_MAILSLOTS) 
        extrasCreateIpcDialog(hwndParent, IpcModeMailSlots);
    else if (CallerId == ID_EXTRAS_PIPES)
        extrasCreateIpcDialog(hwndParent, IpcModeNamedPipes);
}

/*
* extrasShowUserSharedDataDialog
*
* Purpose:
*
* Display KUserSharedData dump dialog.
*
*/
VOID extrasShowUserSharedDataDialog(
    _In_ HWND hwndParent
)
{
    extrasCreateUsdDialog(hwndParent);
}

/*
* extrasShowPrivateNamespacesDialog
*
* Purpose:
*
* Display PrivateNamespaces dialog.
*
*/
VOID extrasShowPrivateNamespacesDialog(
    _In_ HWND hwndParent
)
{
    extrasCreatePNDialog(hwndParent);
}

/*
* extrasShowSSDTDialog
*
* Purpose:
*
* Display KiServiceTable (SSDT) dialog.
*
*/
VOID extrasShowSSDTDialog(
    _In_ HWND hwndParent,
    _In_ ULONG CallerId
)
{
    if (CallerId == ID_EXTRAS_SSDT)
        extrasCreateSSDTDialog(hwndParent, SST_Ntos);
    else if (CallerId == ID_EXTRAS_W32PSERVICETABLE)
        extrasCreateSSDTDialog(hwndParent, SST_Win32k);
}

/*
* extrasShowDriversDialog
*
* Purpose:
*
* Display Drivers list dialog.
*
*/
VOID extrasShowDriversDialog(
    _In_ HWND hwndParent
)
{
    extrasCreateDriversDialog(hwndParent);
}

/*
* extrasShowPsListDialog
*
* Purpose:
*
* Display Process list dialog.
*
*/
VOID extrasShowPsListDialog(
    _In_ HWND hwndParent
)
{
    extrasCreatePsListDialog(hwndParent);
}

/*
* extrasShowCallbacksDialog
*
* Purpose:
*
* Display Callbacks dialog.
*
*/
VOID extrasShowCallbacksDialog(
    _In_ HWND hwndParent
)
{
    extrasCreateCallbacksDialog(hwndParent);
}
