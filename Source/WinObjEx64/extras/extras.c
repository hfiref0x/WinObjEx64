/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       EXTRAS.C
*
*  VERSION:     1.60
*
*  DATE:        24 Oct 2018
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
        DestroyIcon(hIcon);
    }
}

/*
* extrasShowPipeDialog
*
* Purpose:
*
* Display Pipe Properties Dialog.
*
*/
VOID extrasShowPipeDialog(
    _In_ HWND hwndParent
)
{
    extrasCreateIpcDialog(hwndParent, IpcModeNamedPipes);
}

/*
* extrasShowMailslotsDialog
*
* Purpose:
*
* Display Mailslots Properties Dialog.
*
*/
VOID extrasShowMailslotsDialog(
    _In_ HWND hwndParent
)
{
    extrasCreateIpcDialog(hwndParent, IpcModeMailshots);
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
    _In_ HWND hwndParent
)
{
    extrasCreateSSDTDialog(hwndParent);
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
