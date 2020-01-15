/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       FINDDLG.C
*
*  VERSION:     1.83
*
*  DATE:        05 Jan 2020
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "findDlg.h"

HWND FindDlgList;
HWND FindDlgStatusBar = 0;
HWND FindDialog = 0;

static LONG sizes_init = 0, dx1, dx2, dx3, dx4, dx5, dx6, dx7, dx8, dx9, dx10, dx11, dx12, dx13;

//local FindDlg variable controlling sorting direction
BOOL bFindDlgSortInverse = FALSE;

// local FindDlg variable to hold selected column
LONG FindDlgSortColumn = 0;


/*
* FindDlgCompareFunc
*
* Purpose:
*
* FindDlg listview comparer function.
*
*/
INT CALLBACK FindDlgCompareFunc(
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort
)
{
    return supListViewBaseComparer(FindDlgList,
        bFindDlgSortInverse,
        lParam1,
        lParam2,
        lParamSort);
}

/*
* FindDlgAddListItem
*
* Purpose:
*
* Add item to listview.
*
*/
VOID FindDlgAddListItem(
    _In_ HWND	hList,
    _In_ LPWSTR	ObjectName,
    _In_ LPWSTR	TypeName
)
{
    INT     lvItemIndex;
    LVITEM  lvItem;

    RtlSecureZeroMemory(&lvItem, sizeof(lvItem));

    lvItem.mask = LVIF_TEXT | LVIF_IMAGE;
    lvItem.pszText = ObjectName;
    lvItem.iImage = ObManagerGetImageIndexByTypeName(TypeName);
    lvItem.iItem = MAXINT;
    lvItemIndex = ListView_InsertItem(hList, &lvItem);

    lvItem.mask = LVIF_TEXT;
    lvItem.iSubItem = 1;
    lvItem.pszText = TypeName;
    lvItem.iItem = lvItemIndex;
    ListView_SetItem(hList, &lvItem);
}

/*
* FindDlgResize
*
* Purpose:
*
* FindDlg WM_SIZE handler, remember control position and move them according new window coordinates.
*
*/
VOID FindDlgResize(
    _In_ HWND hwndDlg
)
{
    RECT  r1, r2;
    HWND  hwnd;
    POINT p0;

    GetClientRect(hwndDlg, &r2);

    if (sizes_init == 0) {
        sizes_init = 1;
        RtlSecureZeroMemory(&r1, sizeof(r1));
        GetWindowRect(GetDlgItem(hwndDlg, ID_SEARCH_GROUPBOXOPTIONS), &r1);
        dx1 = r2.right - (r1.right - r1.left);
        dx2 = r1.bottom - r1.top;
        RtlSecureZeroMemory(&r1, sizeof(r1));
        GetWindowRect(GetDlgItem(hwndDlg, ID_SEARCH_GROUPBOX), &r1);
        dx3 = r2.bottom - (r1.bottom - r1.top);

        RtlSecureZeroMemory(&r1, sizeof(r1));
        GetWindowRect(GetDlgItem(hwndDlg, ID_SEARCH_LIST), &r1);
        dx4 = r2.right - (r1.right - r1.left);
        dx5 = r2.bottom - (r1.bottom - r1.top);

        RtlSecureZeroMemory(&r1, sizeof(r1));
        GetWindowRect(GetDlgItem(hwndDlg, ID_SEARCH_NAME), &r1);
        dx6 = r2.right - (r1.right - r1.left);
        dx7 = r1.bottom - r1.top;

        RtlSecureZeroMemory(&r1, sizeof(r1));
        GetWindowRect(GetDlgItem(hwndDlg, ID_SEARCH_TYPE), &r1);
        p0.x = r1.left;
        p0.y = r1.top;
        ScreenToClient(hwndDlg, &p0);
        dx8 = r2.right - p0.x;
        dx9 = p0.y;

        RtlSecureZeroMemory(&r1, sizeof(r1));
        GetWindowRect(GetDlgItem(hwndDlg, ID_SEARCH_FIND), &r1);
        p0.x = r1.left;
        p0.y = r1.top;
        ScreenToClient(hwndDlg, &p0);
        dx10 = r2.right - p0.x;
        dx11 = p0.y;

        RtlSecureZeroMemory(&r1, sizeof(r1));
        GetWindowRect(GetDlgItem(hwndDlg, ID_SEARCH_TYPELABEL), &r1);
        p0.x = r1.left;
        p0.y = r1.top;
        ScreenToClient(hwndDlg, &p0);
        dx12 = r2.right - p0.x;
        dx13 = p0.y;
    }

    //resize groupbox search options
    hwnd = GetDlgItem(hwndDlg, ID_SEARCH_GROUPBOXOPTIONS);
    if (hwnd) {
        SetWindowPos(hwnd, 0, 0, 0, r2.right - dx1, dx2, SWP_NOMOVE | SWP_NOZORDER);
    }

    //resize groupbox results
    hwnd = GetDlgItem(hwndDlg, ID_SEARCH_GROUPBOX);
    if (hwnd) {
        SetWindowPos(hwnd, 0, 0, 0, r2.right - dx1, r2.bottom - dx3, SWP_NOMOVE | SWP_NOZORDER);
    }

    //resize listview
    hwnd = GetDlgItem(hwndDlg, ID_SEARCH_LIST);
    if (hwnd) {
        SetWindowPos(hwnd, 0, 0, 0, r2.right - dx4, r2.bottom - dx5, SWP_NOMOVE | SWP_NOZORDER);
    }

    //resize edit
    hwnd = GetDlgItem(hwndDlg, ID_SEARCH_NAME);
    if (hwnd) {
        SetWindowPos(hwnd, 0, 0, 0, r2.right - dx6, dx7, SWP_NOMOVE | SWP_NOZORDER);
    }

    //resize combobox
    hwnd = GetDlgItem(hwndDlg, ID_SEARCH_TYPE);
    if (hwnd) {
        SetWindowPos(hwnd, 0, r2.right - dx8, dx9, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    }

    hwnd = GetDlgItem(hwndDlg, ID_SEARCH_FIND);
    if (hwnd) {
        SetWindowPos(hwnd, 0, r2.right - dx10, dx11, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    }

    //resize Type label
    hwnd = GetDlgItem(hwndDlg, ID_SEARCH_TYPELABEL);
    if (hwnd) {
        SetWindowPos(hwnd, 0, r2.right - dx12, dx13, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    }

    SendMessage(FindDlgStatusBar, WM_SIZE, 0, 0);

    RedrawWindow(hwndDlg, NULL, 0, RDW_ERASE | RDW_INVALIDATE | RDW_ERASENOW);
}

/*
* FindDlgHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for FindDlg listview.
*
*/
VOID FindDlgHandleNotify(
    _In_ LPNMLISTVIEW nhdr
)
{
    INT      nImageIndex;
    LPWSTR   lpItemText;

    if (nhdr->hdr.idFrom != ID_SEARCH_LIST)
        return;

    switch (nhdr->hdr.code) {

    case LVN_ITEMCHANGED:
        if (!(nhdr->uNewState & LVIS_SELECTED))
            break;

        lpItemText = supGetItemText(nhdr->hdr.hwndFrom, nhdr->iItem, 0, NULL);
        if (lpItemText) {
            ListToObject(lpItemText);
            supHeapFree(lpItemText);
        }
        break;

    case LVN_COLUMNCLICK:
        bFindDlgSortInverse = !bFindDlgSortInverse;
        FindDlgSortColumn = ((NMLISTVIEW*)nhdr)->iSubItem;
        ListView_SortItemsEx(FindDlgList, &FindDlgCompareFunc, FindDlgSortColumn);

        nImageIndex = ImageList_GetImageCount(g_ListViewImages);
        if (bFindDlgSortInverse)
            nImageIndex -= 2;
        else
            nImageIndex -= 1;

        supUpdateLvColumnHeaderImage(
            FindDlgList,
            FINDLIST_COLUMN_COUNT,
            FindDlgSortColumn,
            nImageIndex);

        break;

    default:
        break;
    }
}

/*
* FindDlgProc
*
* Purpose:
*
* Find Dialog window procedure.
*
*/
INT_PTR CALLBACK FindDlgProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam
)
{
    WCHAR           searchString[MAX_PATH + 1], typeName[MAX_PATH + 1];
    LPWSTR          pnameStr = (LPWSTR)searchString, ptypeStr = (LPWSTR)typeName;
    PFO_LIST_ITEM   flist, plist;
    ULONG           cci;
    LPNMLISTVIEW    nhdr = (LPNMLISTVIEW)lParam;

    switch (uMsg) {
    case WM_NOTIFY:
        FindDlgHandleNotify(nhdr);
        break;

    case WM_GETMINMAXINFO:
        if (lParam) {
            ((PMINMAXINFO)lParam)->ptMinTrackSize.x = 548;
            ((PMINMAXINFO)lParam)->ptMinTrackSize.y = 230;
        }
        break;

    case WM_INITDIALOG:
        supCenterWindow(hwndDlg);
        FindDlgResize(hwndDlg);
        break;

    case WM_SIZE:
        FindDlgResize(hwndDlg);
        break;

    case WM_CLOSE:
        DestroyWindow(hwndDlg);
        FindDialog = NULL;
        g_WinObj.AuxDialogs[wobjFindDlgId] = NULL;
        return TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDCANCEL) {
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            return TRUE;
        }

        if (LOWORD(wParam) == ID_SEARCH_FIND) {

            supSetWaitCursor(TRUE);
            EnableWindow(GetDlgItem(hwndDlg, ID_SEARCH_FIND), FALSE);

            //
            // Update status bar.
            //
            _strcpy(searchString, TEXT("Searching..."));
            SetDlgItemText(hwndDlg, ID_SEARCH_STATUSBAR, searchString);

            ListView_DeleteAllItems(FindDlgList);

            RtlSecureZeroMemory(&searchString, sizeof(searchString));
            RtlSecureZeroMemory(&typeName, sizeof(typeName));

            GetDlgItemText(hwndDlg, ID_SEARCH_NAME, (LPWSTR)&searchString, MAX_PATH);
            GetDlgItemText(hwndDlg, ID_SEARCH_TYPE, (LPWSTR)&typeName, MAX_PATH);

            flist = NULL;

            if (searchString[0] == 0)
                pnameStr = NULL;
            if (typeName[0] == L'*')
                ptypeStr = 0;

            FindObject(KM_OBJECTS_ROOT_DIRECTORY, pnameStr, ptypeStr, &flist);

            cci = 0;
            while (flist != NULL) {
                FindDlgAddListItem(FindDlgList, flist->ObjectName, flist->ObjectType);
                plist = flist->Prev;
                supHeapFree(flist);
                flist = plist;
                cci++;
            }

            //
            // Update status bar with results.
            //
            ultostr(cci, searchString);
            _strcat(searchString, TEXT(" matching object(s)."));
            SetDlgItemText(hwndDlg, ID_SEARCH_STATUSBAR, searchString);

            ListView_SortItemsEx(FindDlgList, &FindDlgCompareFunc, FindDlgSortColumn);

            supSetWaitCursor(FALSE);
            EnableWindow(GetDlgItem(hwndDlg, ID_SEARCH_FIND), TRUE);
        }

        break;
    }
    return FALSE;
}

/*
* FindDlgAddTypes
*
* Purpose:
*
* Enumerate object types and fill combobox with them.
*
*/
VOID FindDlgAddTypes(
    _In_ HWND hwnd
)
{
    ULONG  i;
    HWND   hComboBox;
    SIZE_T sz;
    LPWSTR lpType;

    POBJECT_TYPE_INFORMATION  pObject;

    hComboBox = GetDlgItem(hwnd, ID_SEARCH_TYPE);
    if (hComboBox == NULL)
        return;

    SendMessage(hComboBox, CB_RESETCONTENT, (WPARAM)0, (LPARAM)0);

    if (g_pObjectTypesInfo == NULL) {
        SendMessage(hComboBox, CB_ADDSTRING, (WPARAM)0, (LPARAM)L"*");
        SendMessage(hComboBox, CB_SETCURSEL, (WPARAM)0, (LPARAM)0);
        return;
    }

    __try {
        //type collection available, list it
        if (g_WinObj.IsWine) {
            pObject = OBJECT_TYPES_FIRST_ENTRY_WINE(g_pObjectTypesInfo);
        }
        else {
            pObject = OBJECT_TYPES_FIRST_ENTRY(g_pObjectTypesInfo);
        }

        for (i = 0; i < g_pObjectTypesInfo->NumberOfTypes; i++) {
            sz = pObject->TypeName.MaximumLength + sizeof(UNICODE_NULL);
            lpType = (LPWSTR)supHeapAlloc(sz);
            if (lpType) {

                _strncpy(lpType,
                    sz / sizeof(WCHAR),
                    pObject->TypeName.Buffer,
                    pObject->TypeName.Length / sizeof(WCHAR));

                SendMessage(hComboBox, CB_ADDSTRING, (WPARAM)0, (LPARAM)lpType);
                supHeapFree(lpType);
            }
            pObject = OBJECT_TYPES_NEXT_ENTRY(pObject);
        }
        SendMessage(hComboBox, CB_ADDSTRING, (WPARAM)0, (LPARAM)L"*");
        SendMessage(hComboBox, CB_SETCURSEL, (WPARAM)0, (LPARAM)0);
    }
    __except (WOBJ_EXCEPTION_FILTER) {
        return;
    }
}

/*
* FindDlgCreate
*
* Purpose:
*
* Create and initialize Find Dialog.
*
*/
VOID FindDlgCreate(
    _In_ HWND hwndParent
)
{
    HICON hIcon;

    //
    // Allow only one search dialog per time.
    //
    ENSURE_DIALOG_UNIQUE(g_WinObj.AuxDialogs[wobjFindDlgId]);

    FindDialog = CreateDialogParam(g_WinObj.hInstance, MAKEINTRESOURCE(IDD_DIALOG_SEARCH), hwndParent, &FindDlgProc, 0);
    if (FindDialog == NULL)
        return;

    g_WinObj.AuxDialogs[wobjFindDlgId] = FindDialog;

    FindDlgStatusBar = GetDlgItem(FindDialog, ID_SEARCH_STATUSBAR);

    //
    // Set dialog icon, because we use shared dlg template this icon must be
    // removed after use, see aboutDlg/propDlg.
    //
    hIcon = (HICON)LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDI_ICON_MAIN), IMAGE_ICON, 0, 0, LR_SHARED);
    if (hIcon) {
        SetClassLongPtr(g_WinObj.AuxDialogs[wobjFindDlgId], GCLP_HICON, (LONG_PTR)hIcon);
        DestroyIcon(hIcon);
    }

    FindDlgList = GetDlgItem(FindDialog, ID_SEARCH_LIST);
    if (FindDlgList) {
        bFindDlgSortInverse = FALSE;
        ListView_SetImageList(FindDlgList, g_ListViewImages, LVSIL_SMALL);

        ListView_SetExtendedListViewStyle(
            FindDlgList,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

        SetWindowTheme(FindDlgList, TEXT("Explorer"), NULL);

        //
        // Add listview columns.
        //

        supAddListViewColumn(FindDlgList, 0, 0, 0,
            ImageList_GetImageCount(g_ListViewImages) - 1,
            LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
            TEXT("Name"), 300);

        supAddListViewColumn(FindDlgList, 1, 1, 1,
            I_IMAGENONE,
            LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
            TEXT("Type"), 100);

    }
    FindDlgAddTypes(FindDialog);
}
