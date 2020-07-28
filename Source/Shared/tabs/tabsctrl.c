/*++

Copyright (c) 2015 (see AUTHORS.txt).

Module Name:

    tabctrl.cpp

Abstract:

    Set of functions used with tab component.

    VERSION 2.0 (01.02.2015)
    
    WinObjEx64 version.

--*/

#define OEMRESOURCE
#include "tabsctrl.h"

INT_PTR CALLBACK TabDefaultWndProc(
    _In_ HWND hwnd,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(uMsg);
    UNREFERENCED_PARAMETER(wParam);
    UNREFERENCED_PARAMETER(lParam);
    return 0;
}

//resize window handler
VOID TabResizeTabWindow(
    _In_ PTABHDR hdr
)
{
    HWND hParentWnd;
    RECT tr, dr;

    hParentWnd = GetParent(hdr->hwndTab);

    RtlZeroMemory(&tr, sizeof(RECT));
    RtlZeroMemory(&dr, sizeof(RECT));

    TabCtrl_AdjustRect(hdr->hwndTab, FALSE, &tr);
    if (GetClientRect(hdr->hwndTab, &dr)) {

        SetWindowPos(hdr->hwndDisplay,
            HWND_TOP,
            dr.left + tr.left,
            dr.top + tr.top,
            dr.right - dr.left + tr.right - tr.left,
            dr.bottom - dr.top + tr.bottom - tr.top,
            SWP_SHOWWINDOW);

    }

    if (hdr->OnResize != NULL)
        hdr->OnResize(hdr);
}

PTABENTRY TabGetItem(
    _In_ PTABHDR hdr,
    _In_ INT nIndex
)
{
    PTABENTRY tabEntry;
    PLIST_ENTRY Entry;

    Entry = hdr->tabsHead.Flink;
    while ((Entry != NULL) && (Entry != &hdr->tabsHead)) {

        tabEntry = CONTAINING_RECORD(Entry, TABENTRY, ListEntry);
        if (nIndex == tabEntry->TabIndex)
            return tabEntry;

        Entry = Entry->Flink;
    }
    return NULL;
}

//on tab selection change proc
VOID TabOnSelChanged(
    _In_ PTABHDR hdr
)
{
    INT nCurrentTab;
    PTABENTRY tabEntry;

    //get currently selected page
    nCurrentTab = TabCtrl_GetCurSel(hdr->hwndTab);
    if (nCurrentTab < 0)
        return;

    //destroy previous window
    if (hdr->hwndDisplay != NULL) {
        DestroyWindow(hdr->hwndDisplay);
        hdr->hwndDisplay = 0;
    }

    if (hdr->OnSelChange != NULL)
        hdr->OnSelChange(hdr, nCurrentTab);

    tabEntry = TabGetItem(hdr, nCurrentTab);
    if (tabEntry == NULL)
        return;

    hdr->hwndDisplay = CreateDialogParam(hdr->hInstance,
        MAKEINTRESOURCE(tabEntry->ResId),
        GetParent(hdr->hwndTab),
        tabEntry->DlgProc,
        (LPARAM)tabEntry->UserParam);

    if (hdr->hwndDisplay) {
        TabResizeTabWindow(hdr);
    }

}

VOID TabDestroyControl(
    _In_ PTABHDR hdr
)
{
    TABCALLBACK_FREEMEM pFree;
    if (hdr) {
        pFree = hdr->FreeMem;
        pFree(hdr);
    }
}

BOOL TabAddPage(
    _In_ PTABHDR hdr,
    _In_ INT ResId,
    _In_opt_ DLGPROC DlgProc,
    _In_ LPTSTR szCaption,
    _In_ INT iImage,
    _In_ LPARAM lParam
)
{
    PTABENTRY tabEntry;
    TC_ITEM tie;
    INT tabIndex;

    tabEntry = (PTABENTRY)hdr->MemAlloc(sizeof(TABENTRY));
    if (tabEntry == NULL)
        return FALSE;

    RtlSecureZeroMemory(&tie, sizeof(TC_ITEM));
    tie.mask = TCIF_TEXT;

    if (hdr->hImageList != NULL) {
        tie.mask |= TCIF_IMAGE;
        tie.iImage = iImage;
    }

    if (lParam) {
        tie.mask |= TCIF_PARAM;
        tie.lParam = lParam;
    }

    tie.pszText = szCaption;

    tabIndex = TabCtrl_InsertItem(hdr->hwndTab, hdr->tabsCount, &tie);
    if (tabIndex < 0) {
        hdr->FreeMem(tabEntry);
        return FALSE;
    }

    tabEntry->TabIndex = tabIndex;
    hdr->tabsCount++;

    if (DlgProc == NULL) {
        tabEntry->DlgProc = (DLGPROC)&TabDefaultWndProc;
    }
    else {
        tabEntry->DlgProc = DlgProc;
    }
    tabEntry->ResId = ResId;
    tabEntry->UserParam = (PVOID)lParam;
    InsertHeadList(&hdr->tabsHead, &tabEntry->ListEntry);
    return TRUE;
}

BOOL TabDeletePage(
    _In_ PTABHDR hdr,
    _In_ INT TabIndex
)
{
    BOOL bResult;
    PTABENTRY tabEntry;

    bResult = TabCtrl_DeleteItem(hdr->hwndTab, TabIndex);
    if (bResult) {
        hdr->tabsCount--;

        tabEntry = TabGetItem(hdr, TabIndex);
        if (tabEntry) {
            RemoveEntryList(&tabEntry->ListEntry);
            hdr->FreeMem(tabEntry);
        }

        if (TabCtrl_GetCurSel(hdr->hwndTab) < 0) {
            TabCtrl_SetCurSel(hdr->hwndTab, 0);
        }
        TabOnSelChanged(hdr);
    }
    return bResult;
}

PTABHDR TabCreateControl(
    _In_ HINSTANCE hInstance,
    _In_ HWND hParentWnd,
    _In_opt_ HIMAGELIST hImageList,
    _In_ TABSELCHANGECALLBACK OnSelChangeTab,
    _In_ TABRESIZECALLBACK OnResizeTab,
    _In_ TABCALLBACK_ALLOCMEM MemAlloc,
    _In_ TABCALLBACK_FREEMEM MemFree
)
{
    RECT rcTab;
    HWND hwndTab;
    PTABHDR result;
    LONG dwDlgBase;

    RECT rc;

    GetClientRect(hParentWnd, &rc);

    hwndTab = CreateWindowEx(0, WC_TABCONTROL, 0,
        TCS_FIXEDWIDTH | WS_CHILD | WS_VISIBLE,
        rc.left + 2, rc.top + 2, rc.right, rc.bottom,
        hParentWnd, 0, hInstance, 0);

    if (hwndTab == NULL)
        return NULL;

    // Set the font of the tabs to a more typical system GUI font.
    SendMessage(hwndTab, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), 0);

    result = (PTABHDR)MemAlloc(sizeof(TABHDR));
    if (result == NULL)
        return NULL;

    dwDlgBase = GetDialogBaseUnits();

    result->cxMargin = LOWORD(dwDlgBase) / 4;
    result->cyMargin = HIWORD(dwDlgBase) / 8;
    result->hwndTab = hwndTab;
    result->hInstance = hInstance;
    result->tabsCount = 0;
    result->OnResize = OnResizeTab;
    result->OnSelChange = OnSelChangeTab;
    result->MemAlloc = MemAlloc;
    result->FreeMem = MemFree;

    InitializeListHead(&result->tabsHead);

    if (hImageList != NULL) {
        TabCtrl_SetImageList(result->hwndTab, hImageList);
        result->hImageList = hImageList;
    }

    SetRectEmpty(&rcTab);
    GetWindowRect(result->hwndTab, &rcTab);

    TabCtrl_AdjustRect(result->hwndTab, TRUE, &rcTab);

    OffsetRect(&rcTab, result->cxMargin - rcTab.left, result->cyMargin - rcTab.top);
    CopyRect(&result->rcDisplay, &rcTab);

    TabCtrl_AdjustRect(result->hwndTab, FALSE, &result->rcDisplay);

    SetWindowPos(result->hwndTab, 0,
        rcTab.left, rcTab.top,
        rcTab.right - rcTab.left,
        rcTab.bottom - rcTab.top,
        SWP_NOZORDER);

    return result;
}

//OnTabControlChange event handler
VOID TabOnChangeTab(
    _In_ PTABHDR hdr,
    _In_ LPNMHDR pnmhdr
)
{
    if ((pnmhdr == NULL) || (hdr == NULL))
        return;

    if (pnmhdr->hwndFrom != hdr->hwndTab)
        return;

#pragma warning(push)
#pragma warning(disable: 26454)
    if (pnmhdr->code == TCN_SELCHANGE) {
#pragma warning(pop)
        EnableWindow(hdr->hwndTab, FALSE);//lock change
        TabOnSelChanged(hdr); //call actual handler
        EnableWindow(hdr->hwndTab, TRUE); //unlock
    }
}
