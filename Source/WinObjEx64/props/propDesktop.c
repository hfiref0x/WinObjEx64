/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       PROPDESKTOP.C
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
#include "propDlg.h"
#include "extras.h"

//number of columns, revise this unit code after any change to this number
#define DESKTOPLIST_COLUMN_COUNT 3

typedef struct _DLG_ENUM_CALLBACK_CONTEXT {
    PROP_OBJECT_INFO *ObjectContext;
    EXTRASCONTEXT *DialogContext;
} DLG_ENUM_CALLBACK_CONTEXT, *PDLG_ENUM_CALLBACK_CONTEXT;

/*
* DesktopListEnumProc
*
* Purpose:
*
* EnumDesktops callback.
*
*/
BOOL CALLBACK DesktopListEnumProc(
    _In_ LPWSTR lpszDesktop,
    _In_ LPARAM lParam
)
{
    BOOL              bSucc;
    INT	              nIndex;
    DWORD             bytesNeeded, dwDesktopHeapSize;
    LPWSTR            lpName, StringSid;
    PSID              pSID;
    SIZE_T            sz;
    HDESK             hDesktop;
    LVITEM            lvitem;
    WCHAR             szBuffer[MAX_PATH];

    DLG_ENUM_CALLBACK_CONTEXT *enumParam = (DLG_ENUM_CALLBACK_CONTEXT*)lParam;
    if (enumParam == NULL) {
        return FALSE;
    }

    // Desktop\\Object+0
    sz = (3 + _strlen(lpszDesktop) + _strlen(enumParam->ObjectContext->lpObjectName)) * sizeof(WCHAR);
    lpName = (LPWSTR)supHeapAlloc(sz);
    if (lpName == NULL)
        return 0;

    _strcpy(lpName, enumParam->ObjectContext->lpObjectName);
    _strcat(lpName, TEXT("\\"));
    _strcat(lpName, lpszDesktop);

    //Name
    RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
    lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
    lvitem.iImage = 0;
    lvitem.iSubItem = 0;
    lvitem.pszText = lpName;
    lvitem.iItem = MAXINT;
    nIndex = ListView_InsertItem(enumParam->DialogContext->ListView, &lvitem);

    supHeapFree(lpName);

    //
    // Query desktop objects information.
    //
    bSucc = FALSE;
    StringSid = NULL;
    hDesktop = OpenDesktop(lpszDesktop, 0, FALSE, DESKTOP_READOBJECTS);
    if (hDesktop) {

        //
        // Query SID.
        //
        bytesNeeded = 0;
        GetUserObjectInformation(hDesktop, UOI_USER_SID, NULL, 0, &bytesNeeded);

        //
        // User associated with desktop present, query sid.
        //
        if (bytesNeeded) {
            //
            // Allocate memory for sid.
            //
            pSID = supHeapAlloc(bytesNeeded);
            if (pSID) {
                if (GetUserObjectInformation(hDesktop,
                    UOI_USER_SID, pSID, bytesNeeded, &bytesNeeded))
                {
                    bSucc = ConvertSidToStringSid(pSID, &StringSid);
                }
                supHeapFree(pSID);
            }
        }

        //
        // Add SID string to the list.
        //
        if (bSucc && StringSid) {
            lvitem.mask = LVIF_TEXT;
            lvitem.iSubItem = 1;
            lvitem.pszText = StringSid;
            lvitem.iItem = nIndex;
            ListView_SetItem(enumParam->DialogContext->ListView, &lvitem);
            LocalFree(StringSid);
        }

        //
        // Add Desktop Heap Size, returned in KBytes.
        //
        dwDesktopHeapSize = 0;
        if (GetUserObjectInformation(hDesktop,
            UOI_HEAPSIZE,
            &dwDesktopHeapSize,
            sizeof(dwDesktopHeapSize),
            &bytesNeeded))
        {
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            ultostr(dwDesktopHeapSize / 1024, szBuffer);
            _strcat(szBuffer, TEXT(" Mb"));

            lvitem.mask = LVIF_TEXT;
            lvitem.iSubItem = 2;
            lvitem.pszText = szBuffer;
            lvitem.iItem = nIndex;
            ListView_SetItem(enumParam->DialogContext->ListView, &lvitem);
        }
        CloseDesktop(hDesktop);
    }
    return TRUE;
}

/*
* DesktopListSetInfo
*
* Purpose:
*
* Query information and fill listview.
* Called each time when page became visible.
*
*/
VOID DesktopListSetInfo(
    _In_ HWND hwndDlg,
    _In_ PROP_OBJECT_INFO *Context,
    _In_ EXTRASCONTEXT *pDlgContext
)
{
    BOOL    bResult = FALSE;
    HWINSTA hObject;

    DLG_ENUM_CALLBACK_CONTEXT enumParam;

    ListView_DeleteAllItems(pDlgContext->ListView);

    if (g_WinObj.EnableExperimentalFeatures)
        hObject = supOpenWindowStationFromContextEx(Context, FALSE, WINSTA_ENUMDESKTOPS);
    else
        hObject = supOpenWindowStationFromContext(Context, FALSE, WINSTA_ENUMDESKTOPS);
    
    if (hObject) {

        enumParam.ObjectContext = Context;
        enumParam.DialogContext = pDlgContext;

        EnumDesktops(hObject, DesktopListEnumProc, (LPARAM)&enumParam);

        if (g_WinObj.EnableExperimentalFeatures) {
            NtClose((HANDLE)hObject);
        }
        else {
            CloseWindowStation(hObject);
        }
        bResult = TRUE;
    }
    ShowWindow(GetDlgItem(hwndDlg, ID_DESKTOPSNOTALL), (bResult == FALSE) ? SW_SHOW : SW_HIDE);
}

/*
* DesktopListCreate
*
* Purpose:
*
* Initialize listview for desktop list.
* Called once.
*
*/
VOID DesktopListCreate(
    _In_ HWND hwndDlg,
    _In_ EXTRASCONTEXT *pDlgContext
)
{
    LVCOLUMN col;
    HICON    hImage;

    pDlgContext->ListView = GetDlgItem(hwndDlg, ID_DESKTOPSLIST);
    if (pDlgContext->ListView == NULL)
        return;

    pDlgContext->ImageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 8, 8);
    if (pDlgContext->ImageList) {

        //desktop image
        hImage = (HICON)LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDI_ICON_DESKTOP), 
            IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);

        if (hImage) {
            ImageList_ReplaceIcon(pDlgContext->ImageList, -1, hImage);
            DestroyIcon(hImage);
        }

        //sort images
        hImage = (HICON)LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDI_ICON_SORTUP), 
            IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);

        if (hImage) {
            ImageList_ReplaceIcon(pDlgContext->ImageList, -1, hImage);
            DestroyIcon(hImage);
        }
        hImage = (HICON)LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDI_ICON_SORTDOWN), 
            IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);

        if (hImage) {
            ImageList_ReplaceIcon(pDlgContext->ImageList, -1, hImage);
            DestroyIcon(hImage);
        }

        ListView_SetImageList(pDlgContext->ListView, pDlgContext->ImageList, LVSIL_SMALL);
    }

    ListView_SetExtendedListViewStyle(
        pDlgContext->ListView,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

    SetWindowTheme(pDlgContext->ListView, TEXT("Explorer"), NULL);

    RtlSecureZeroMemory(&col, sizeof(col));
    col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
    col.iSubItem = 1;
    col.pszText = TEXT("Name");
    col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;
    col.iOrder = 0;
    col.iImage = 2;
    col.cx = 200;
    ListView_InsertColumn(pDlgContext->ListView, col.iSubItem, &col);

    col.iImage = I_IMAGENONE;

    col.iSubItem = 2;
    col.pszText = TEXT("SID");
    col.iOrder = 1;
    col.cx = 100;
    ListView_InsertColumn(pDlgContext->ListView, col.iSubItem, &col);

    col.iSubItem = 3;
    col.pszText = TEXT("Heap Size");
    col.iOrder = 2;
    col.cx = 100;
    ListView_InsertColumn(pDlgContext->ListView, col.iSubItem, &col);

    pDlgContext->lvColumnCount = DESKTOPLIST_COLUMN_COUNT;
}

/*
* DesktopListCompareFunc
*
* Purpose:
*
* Desktop page listview comparer function.
*
*/
INT CALLBACK DesktopListCompareFunc(
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lpContextParam
)
{
    INT    nResult = 0;
    LPWSTR lpItem1 = NULL, lpItem2 = NULL;

    LPARAM lvColumnToSort;

    EXTRASCONTEXT *pDlgContext;

    pDlgContext = (EXTRASCONTEXT*)lpContextParam;
    if (pDlgContext == NULL)
        return 0;

    lvColumnToSort = (LPARAM)pDlgContext->lvColumnToSort;

    lpItem1 = supGetItemText(pDlgContext->ListView, (INT)lParam1, (INT)lvColumnToSort, NULL);
    lpItem2 = supGetItemText(pDlgContext->ListView, (INT)lParam2, (INT)lvColumnToSort, NULL);

    if ((lpItem1 == NULL) && (lpItem2 == NULL)) {
        nResult = 0;
        goto Done;
    }
    if ((lpItem1 == NULL) && (lpItem2 != NULL)) {
        nResult = (pDlgContext->bInverseSort) ? 1 : -1;
        goto Done;
    }
    if ((lpItem2 == NULL) && (lpItem1 != NULL)) {
        nResult = (pDlgContext->bInverseSort) ? -1 : 1;
        goto Done;
    }

    if (pDlgContext->bInverseSort)
        nResult = _strcmpi(lpItem2, lpItem1);
    else
        nResult = _strcmpi(lpItem1, lpItem2);

Done:
    if (lpItem1) supHeapFree(lpItem1);
    if (lpItem2) supHeapFree(lpItem2);
    return nResult;
}

/*
* DesktopListHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for Desktop page listview.
*
*/
VOID DesktopListHandleNotify(
    _In_ HWND           hwndDlg,
    _In_ LPNMLISTVIEW   nhdr
)
{
    INT      nImageIndex;
    SIZE_T   sz, i, l;
    LPWSTR   lpItemText, lpName;

    EXTRASCONTEXT *pDlgContext;

    if (nhdr == NULL) {
        return;
    }

    if (nhdr->hdr.idFrom != ID_DESKTOPSLIST) {
        return;
    }

    switch (nhdr->hdr.code) {

    case LVN_COLUMNCLICK:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            pDlgContext->bInverseSort = !pDlgContext->bInverseSort;
            pDlgContext->lvColumnToSort = ((NMLISTVIEW *)nhdr)->iSubItem;

            ListView_SortItemsEx(
                pDlgContext->ListView,
                &DesktopListCompareFunc,
                pDlgContext);

            if (pDlgContext->bInverseSort)
                nImageIndex = 1;
            else
                nImageIndex = 2;

            supUpdateLvColumnHeaderImage(
                pDlgContext->ListView,
                pDlgContext->lvColumnCount,
                pDlgContext->lvColumnToSort,
                nImageIndex);
        }
        break;

    case NM_DBLCLK:
        //
        // A very basic support for this type.
        // Desktop described by win32k PDESKTOP structure which is totally undocumented.
        //
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {

            sz = 0;
            lpItemText = supGetItemText(
                pDlgContext->ListView,
                ListView_GetSelectionMark(pDlgContext->ListView),
                0,
                &sz);

            if (lpItemText) {
                l = 0;
                for (i = 0; i < sz; i++)
                    if (lpItemText[i] == L'\\')
                        l = i + 1;
                lpName = &lpItemText[l];

                propCreateDialog(
                    hwndDlg,
                    lpName,
                    g_ObjectTypes[ObjectTypeDesktop].Name,
                    NULL,
                    NULL);

                supHeapFree(lpItemText);
            }
        }
        break;

    default:
        break;
    }
}

/*
* DesktopListDialogProc
*
* Purpose:
*
* Desktop list page.
*
* WM_INITDIALOG - Initialize listview.
* WM_NOTIFY - Handle list view notifications.
* WM_SHOWWINDOW - Collect desktop info and fill list.
* WM_DESTROY - Free image list.
*
*/
INT_PTR CALLBACK DesktopListDialogProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    LPNMLISTVIEW      nhdr = NULL;
    PROPSHEETPAGE    *pSheet;
    PROP_OBJECT_INFO *Context = NULL;
    EXTRASCONTEXT    *pDlgContext = NULL;

    switch (uMsg) {

    case WM_SHOWWINDOW:
        if (wParam) {
            Context = (PROP_OBJECT_INFO*)GetProp(hwndDlg, T_PROPCONTEXT);
            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
            if ((Context) && (pDlgContext)) {

                DesktopListSetInfo(hwndDlg, Context, pDlgContext);
                if (pDlgContext->ListView) {

                    ListView_SortItemsEx(
                        pDlgContext->ListView,
                        &DesktopListCompareFunc,
                        pDlgContext);
                }
                return 1;
            }
        }
        break;

    case WM_NOTIFY:
        nhdr = (LPNMLISTVIEW)lParam;
        DesktopListHandleNotify(hwndDlg, nhdr);
        return 1;
        break;

    case WM_DESTROY:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            if (pDlgContext->ImageList) {
                ImageList_Destroy(pDlgContext->ImageList);
            }
            supHeapFree(pDlgContext);
        }
        RemoveProp(hwndDlg, T_DLGCONTEXT);
        RemoveProp(hwndDlg, T_PROPCONTEXT);
        break;

    case WM_INITDIALOG:
        pSheet = (PROPSHEETPAGE*)lParam;
        if (pSheet) {
            SetProp(hwndDlg, T_PROPCONTEXT, (HANDLE)pSheet->lParam);
            pDlgContext = (EXTRASCONTEXT*)supHeapAlloc(sizeof(EXTRASCONTEXT));
            if (pDlgContext) {
                SetProp(hwndDlg, T_DLGCONTEXT, (HANDLE)pDlgContext);
                DesktopListCreate(hwndDlg, pDlgContext);
            }
        }
        return 1;
        break;

    }
    return 0;
}
