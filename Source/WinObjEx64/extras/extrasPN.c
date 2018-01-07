/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       EXTRASPN.C
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
#include "extras.h"
#include "extrasPN.h"

EXTRASCONTEXT DlgContext;

#ifdef _USE_OWN_DRIVER
#define T_NAMESPACEQUERYFAILED TEXT("Unable to list namespaces! Make sure you run this program as Admin.")
#else
#define T_NAMESPACEQUERYFAILED TEXT("Unable to list namespaces! Make sure you run this program as Admin and Windows is in a DEBUG mode.")
#endif

/*
* PNListCompareFunc
*
* Purpose:
*
* Main window listview comparer function.
*
*/
INT CALLBACK PNListCompareFunc(
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort
)
{
    LPWSTR lpItem1 = NULL, lpItem2 = NULL;
    INT    nResult = 0;

    lpItem1 = supGetItemText(DlgContext.ListView, (INT)lParam1, (INT)lParamSort, NULL);
    lpItem2 = supGetItemText(DlgContext.ListView, (INT)lParam2, (INT)lParamSort, NULL);

    if ((lpItem1 == NULL) && (lpItem2 == NULL)) {
        nResult = 0;
        goto Done;
    }
    if ((lpItem1 == NULL) && (lpItem2 != NULL)) {
        nResult = (DlgContext.bInverseSort) ? 1 : -1;
        goto Done;
    }
    if ((lpItem2 == NULL) && (lpItem1 != NULL)) {
        nResult = (DlgContext.bInverseSort) ? -1 : 1;
        goto Done;
    }

    if (DlgContext.bInverseSort)
        nResult = _strcmpi(lpItem2, lpItem1);
    else
        nResult = _strcmpi(lpItem1, lpItem2);

Done:
    if (lpItem1) supHeapFree(lpItem1);
    if (lpItem2) supHeapFree(lpItem2);

    return nResult;
}

/*
* PNDlgQueryInfo
*
* Purpose:
*
* Query and ouput private namespaces info.
*
*/
BOOL PNDlgQueryInfo(
    VOID
)
{
    INT           index;
    UINT          ConvertedTypeIndex;
    LIST_ENTRY    PrivateObjectList;
    BOOL          bResult = FALSE;
    POBJREF       ObjectInfo;
    PLIST_ENTRY   Entry;
    LVITEM        lvitem;
    LPCWSTR       TypeName;
    WCHAR         szBuffer[MAX_PATH + 1];

    RtlSecureZeroMemory(&PrivateObjectList, sizeof(LIST_ENTRY));
    bResult = ObListCreate(&PrivateObjectList, TRUE);
    if (bResult == FALSE) {
        return bResult;
    }

    ObjectInfo = NULL;
    Entry = PrivateObjectList.Flink;
    while ((Entry != NULL) && (Entry != &PrivateObjectList)) {

        ObjectInfo = CONTAINING_RECORD(Entry, OBJREF, ListEntry);

        ConvertedTypeIndex = supGetObjectNameIndexByTypeIndex(
            (PVOID)ObjectInfo->ObjectAddress, ObjectInfo->TypeIndex);

        TypeName = g_lpObjectNames[ConvertedTypeIndex];

        //Name
        RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
        lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
        lvitem.iSubItem = 0;
        lvitem.iItem = MAXINT;
        lvitem.iImage = ConvertedTypeIndex;
        lvitem.pszText = ObjectInfo->ObjectName;
        index = ListView_InsertItem(DlgContext.ListView, &lvitem);

        //Type
        lvitem.mask = LVIF_TEXT;
        lvitem.iSubItem = 1;
        lvitem.pszText = (LPWSTR)TypeName;
        lvitem.iItem = index;
        ListView_SetItem(DlgContext.ListView, &lvitem);

        //Namespace id
        lvitem.iSubItem = 2;
        lvitem.iItem = index;
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

        _strcpy(szBuffer, TEXT("Ns"));
        u64tostr(ObjectInfo->NamespaceId, _strend(szBuffer));
        lvitem.pszText = szBuffer;
        ListView_SetItem(DlgContext.ListView, &lvitem);

        Entry = Entry->Flink;
    }
    ObListDestroy(&PrivateObjectList);
    return bResult;
}

/*
* PNDlgHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for PNDialog listview.
*
*/
VOID PNDlgHandleNotify(
    LPNMLISTVIEW	nhdr
)
{
    LVCOLUMN col;
    INT      c, k;

    if (nhdr == NULL)
        return;

    if (nhdr->hdr.idFrom != ID_NAMESPACELIST)
        return;

    switch (nhdr->hdr.code) {

    case LVN_COLUMNCLICK:

        DlgContext.bInverseSort = !DlgContext.bInverseSort;
        DlgContext.lvColumnToSort = ((NMLISTVIEW *)nhdr)->iSubItem;
        ListView_SortItemsEx(DlgContext.ListView, &PNListCompareFunc, DlgContext.lvColumnToSort);

        RtlSecureZeroMemory(&col, sizeof(col));
        col.mask = LVCF_IMAGE;
        col.iImage = -1;

        for (c = 0; c < DlgContext.lvColumnCount; c++)
            ListView_SetColumn(DlgContext.ListView, c, &col);

        k = ImageList_GetImageCount(g_ListViewImages);
        if (DlgContext.bInverseSort)
            col.iImage = k - 2;
        else
            col.iImage = k - 1;

        ListView_SetColumn(DlgContext.ListView, ((NMLISTVIEW *)nhdr)->iSubItem, &col);
        break;

    default:
        break;
    }
}

/*
* PNDialogProc
*
* Purpose:
*
* Private Namespace Dialog window procedure.
*
*/
INT_PTR CALLBACK PNDialogProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam
)
{
    LPNMLISTVIEW nhdr = (LPNMLISTVIEW)lParam;

    switch (uMsg) {
    case WM_NOTIFY:
        PNDlgHandleNotify(nhdr);
        break;

    case WM_INITDIALOG:
        supCenterWindow(hwndDlg);
        break;

    case WM_CLOSE:
        DestroyWindow(hwndDlg);
        g_WinObj.AuxDialogs[WOBJ_PNDLG_IDX] = NULL;
        return TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDCANCEL) {
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

/*
* extrasCreatePNDialog
*
* Purpose:
*
* Create and initialize Private Namespaces Dialog.
*
*/
VOID extrasCreatePNDialog(
    _In_ HWND hwndParent
)
{
    LVCOLUMN col;
    WCHAR    szBuffer[MAX_PATH];

    //allow only one dialog
    if (g_WinObj.AuxDialogs[WOBJ_PNDLG_IDX]) {
        SetActiveWindow(g_WinObj.AuxDialogs[WOBJ_PNDLG_IDX]);
        return;
    }

    RtlSecureZeroMemory(&DlgContext, sizeof(DlgContext));
    DlgContext.hwndDlg = CreateDialogParam(g_WinObj.hInstance, MAKEINTRESOURCE(IDD_DIALOG_PNAMESPACE),
        hwndParent, &PNDialogProc, 0);

    if (DlgContext.hwndDlg == NULL) {
        return;
    }

    g_WinObj.AuxDialogs[WOBJ_PNDLG_IDX] = DlgContext.hwndDlg;

    DlgContext.ListView = GetDlgItem(DlgContext.hwndDlg, ID_NAMESPACELIST);
    if (DlgContext.ListView) {
        ListView_SetImageList(DlgContext.ListView, g_ListViewImages, LVSIL_SMALL);
        ListView_SetExtendedListViewStyle(DlgContext.ListView,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

        //create ObjectList columns
        RtlSecureZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
        col.iSubItem++;
        col.pszText = TEXT("Name");
        col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;
        col.iImage = ImageList_GetImageCount(g_ListViewImages) - 1;
        col.cx = 400;
        ListView_InsertColumn(DlgContext.ListView, col.iSubItem, &col);

        col.iSubItem++;
        col.pszText = TEXT("Type");
        col.iOrder = 1;
        col.iImage = -1;
        col.cx = 100;
        ListView_InsertColumn(DlgContext.ListView, col.iSubItem, &col);

        col.iSubItem++;
        col.pszText = TEXT("Namespace");
        col.iOrder = 2;
        col.iImage = -1;
        col.cx = 100;
        ListView_InsertColumn(DlgContext.ListView, col.iSubItem, &col);

        //remember columns count
        DlgContext.lvColumnCount = col.iSubItem;

        if (PNDlgQueryInfo()) {
            ListView_SortItemsEx(DlgContext.ListView, &PNListCompareFunc, 0);
            RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
            _strcpy(szBuffer, TEXT("Total Object(s): "));
            ultostr((ULONG)ListView_GetItemCount(DlgContext.ListView), _strend(szBuffer));
            SetDlgItemText(DlgContext.hwndDlg, ID_PNAMESPACESINFO, szBuffer);
        }
        else {
            SetDlgItemText(DlgContext.hwndDlg, ID_PNAMESPACESINFO, T_NAMESPACEQUERYFAILED);
        }
    }
}
