/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2025
*
*  TITLE:       FINDDLG.C
*
*  VERSION:     2.09
*
*  DATE:        21 Aug 2025
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

// Define custom message for search completion
#define WM_FINDOBJECT_SEARCHCOMPLETE (WM_USER + 100)

// Search parameters structure
typedef struct _FIND_SEARCH_PARAMS {
    HWND hwndDlg;
    BOOLEAN UseName;
    BOOLEAN UseType;
    WCHAR NameString[MAX_PATH * 2];
    WCHAR TypeString[MAX_PATH * 2];
} FIND_SEARCH_PARAMS, * PFIND_SEARCH_PARAMS;

#define FINDDLG_TRACKSIZE_MIN_X 548
#define FINDDLG_TRACKSIZE_MIN_Y 230

static HANDLE FindDialogThreadHandle = NULL;
static FAST_EVENT FindDialogInitializedEvent = FAST_EVENT_INIT;

typedef struct _FINDDLG_CONTEXT {
    //
    // Dialog controls and resources.
    //
    HWND DialogWindow;
    HWND StatusBar;
    HWND SearchList;
    HICON DialogIcon;

    INT ColumnCount;

    //
    // ListView selection.
    //
    INT iSelectedItem;
    INT iColumnHit;

    // ListView settings.
    INT SortColumn;
    BOOL SortInverse;

    //
    // Resize.
    //
    LONG sizes_init;
    LONG dx1;
    LONG dx2;
    LONG dx3;
    LONG dx4;
    LONG dx5;
    LONG dx6;
    LONG dx7;
    LONG dx8;
    LONG dx9;
    LONG dx10;
    LONG dx11;
    LONG dx12;
    LONG dx13;

    //
    // Search state
    //
    BOOLEAN SearchCancelled;
    HANDLE SearchThread;
} FINDDLG_CONTEXT, * PFINDDLGCONTEXT;

static FINDDLG_CONTEXT g_FindDlgContext;

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
    SIZE_T cbLen;
    LPWSTR lpType;
    HWND hComboBox = GetDlgItem(hwnd, ID_SEARCH_TYPE);

    POBTYPE_LIST objectTypesList = g_kdctx.Data->ObjectTypesList;
    POBTYPE_ENTRY objectEntry;

    SendMessage(hComboBox, CB_RESETCONTENT, 0, 0);

    if (objectTypesList == NULL) {
        SendMessage(hComboBox, CB_ADDSTRING, 0, (LPARAM)L"*");
        SendMessage(hComboBox, CB_SETCURSEL, 0, 0);
        return;
    }

    supDisableRedraw(hComboBox);

    for (i = 0; i < objectTypesList->NumberOfTypes; i++) {
        objectEntry = &objectTypesList->Types[i];
        cbLen = objectEntry->TypeName->MaximumLength + sizeof(UNICODE_NULL);
        lpType = (LPWSTR)supHeapAlloc(cbLen);
        if (lpType) {
            _strncpy(lpType,
                cbLen / sizeof(WCHAR),
                objectEntry->TypeName->Buffer,
                objectEntry->TypeName->Length / sizeof(WCHAR));

            SendMessage(hComboBox, CB_ADDSTRING, 0, (LPARAM)lpType);
            supHeapFree(lpType);
        }
    }

    SendMessage(hComboBox, CB_ADDSTRING, 0, (LPARAM)L"*");
    SendMessage(hComboBox, CB_SETCURSEL, 0, 0);
    supEnableRedraw(hComboBox);
}

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
    return supListViewBaseComparer(g_FindDlgContext.SearchList,
        g_FindDlgContext.SortInverse,
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
    _In_ HWND hList,
    _In_ PUNICODE_STRING ObjectName,
    _In_ PUNICODE_STRING TypeName
)
{
    BOOL bNeedFree = FALSE;
    INT lvItemIndex;
    LVITEM lvItem;
    LPWSTR lpName;

    UNICODE_STRING normalizedString;

    bNeedFree = supNormalizeUnicodeStringForDisplay(g_obexHeap, ObjectName, &normalizedString);
    if (bNeedFree)
        lpName = normalizedString.Buffer;
    else
        lpName = ObjectName->Buffer;

    RtlSecureZeroMemory(&lvItem, sizeof(lvItem));

    lvItem.mask = LVIF_TEXT | LVIF_IMAGE;
    lvItem.pszText = lpName;
    lvItem.iImage = ObManagerGetImageIndexByTypeName(TypeName->Buffer);
    lvItem.iItem = MAXINT;
    lvItemIndex = ListView_InsertItem(hList, &lvItem);
    if (lvItemIndex >= 0) {
        lvItem.mask = LVIF_TEXT;
        lvItem.iSubItem = 1;
        lvItem.pszText = TypeName->Buffer;
        lvItem.iItem = lvItemIndex;
        ListView_SetItem(hList, &lvItem);
    }
    if (bNeedFree)
        supFreeDuplicatedUnicodeString(g_obexHeap, &normalizedString, FALSE);
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
    _In_ HWND hwndDlg,
    _In_ FINDDLG_CONTEXT* Context
)
{
    RECT  r1, r2;
    HWND  hwnd;
    POINT p0;
    HDWP hDeferPos;

    GetClientRect(hwndDlg, &r2);

    if (Context->sizes_init == 0) {
        Context->sizes_init = 1;

        RtlSecureZeroMemory(&r1, sizeof(r1));
        GetWindowRect(GetDlgItem(hwndDlg, ID_SEARCH_GROUPBOXOPTIONS), &r1);
        Context->dx1 = r2.right - (r1.right - r1.left);
        Context->dx2 = r1.bottom - r1.top;

        RtlSecureZeroMemory(&r1, sizeof(r1));
        GetWindowRect(GetDlgItem(hwndDlg, ID_SEARCH_GROUPBOX), &r1);
        Context->dx3 = r2.bottom - (r1.bottom - r1.top);

        RtlSecureZeroMemory(&r1, sizeof(r1));
        GetWindowRect(GetDlgItem(hwndDlg, ID_SEARCH_LIST), &r1);
        Context->dx4 = r2.right - (r1.right - r1.left);
        Context->dx5 = r2.bottom - (r1.bottom - r1.top);

        RtlSecureZeroMemory(&r1, sizeof(r1));
        GetWindowRect(GetDlgItem(hwndDlg, ID_SEARCH_NAME), &r1);
        Context->dx6 = r2.right - (r1.right - r1.left);
        Context->dx7 = r1.bottom - r1.top;

        RtlSecureZeroMemory(&r1, sizeof(r1));
        GetWindowRect(GetDlgItem(hwndDlg, ID_SEARCH_TYPE), &r1);
        p0.x = r1.left;
        p0.y = r1.top;
        ScreenToClient(hwndDlg, &p0);
        Context->dx8 = r2.right - p0.x;
        Context->dx9 = p0.y;

        RtlSecureZeroMemory(&r1, sizeof(r1));
        GetWindowRect(GetDlgItem(hwndDlg, ID_SEARCH_FIND), &r1);
        p0.x = r1.left;
        p0.y = r1.top;
        ScreenToClient(hwndDlg, &p0);
        Context->dx10 = r2.right - p0.x;
        Context->dx11 = p0.y;

        RtlSecureZeroMemory(&r1, sizeof(r1));
        GetWindowRect(GetDlgItem(hwndDlg, ID_SEARCH_TYPELABEL), &r1);
        p0.x = r1.left;
        p0.y = r1.top;
        ScreenToClient(hwndDlg, &p0);
        Context->dx12 = r2.right - p0.x;
        Context->dx13 = p0.y;
    }

    // Start batch window positioning for better performance
    hDeferPos = BeginDeferWindowPos(7);
    if (!hDeferPos) return;

    //resize groupbox search options
    hwnd = GetDlgItem(hwndDlg, ID_SEARCH_GROUPBOXOPTIONS);
    if (hwnd) {
        hDeferPos = DeferWindowPos(hDeferPos, hwnd, 0,
            0, 0,
            r2.right - Context->dx1, Context->dx2,
            SWP_NOMOVE | SWP_NOZORDER);
        if (!hDeferPos) return;
    }

    //resize groupbox results
    hwnd = GetDlgItem(hwndDlg, ID_SEARCH_GROUPBOX);
    if (hwnd) {
        hDeferPos = DeferWindowPos(hDeferPos, hwnd, 0,
            0, 0,
            r2.right - Context->dx1, r2.bottom - Context->dx3,
            SWP_NOMOVE | SWP_NOZORDER);
        if (!hDeferPos) return;
    }

    //resize listview
    hwnd = GetDlgItem(hwndDlg, ID_SEARCH_LIST);
    if (hwnd) {
        hDeferPos = DeferWindowPos(hDeferPos, hwnd, 0,
            0, 0,
            r2.right - Context->dx4, r2.bottom - Context->dx5,
            SWP_NOMOVE | SWP_NOZORDER);
        if (!hDeferPos) return;
    }

    //resize edit
    hwnd = GetDlgItem(hwndDlg, ID_SEARCH_NAME);
    if (hwnd) {
        hDeferPos = DeferWindowPos(hDeferPos, hwnd, 0,
            0, 0,
            r2.right - Context->dx6, Context->dx7,
            SWP_NOMOVE | SWP_NOZORDER);
        if (!hDeferPos) return;
    }

    //reposition combobox
    hwnd = GetDlgItem(hwndDlg, ID_SEARCH_TYPE);
    if (hwnd) {
        hDeferPos = DeferWindowPos(hDeferPos, hwnd, 0,
            r2.right - Context->dx8, Context->dx9,
            0, 0,
            SWP_NOSIZE | SWP_NOZORDER);
        if (!hDeferPos) return;
    }

    //reposition find button
    hwnd = GetDlgItem(hwndDlg, ID_SEARCH_FIND);
    if (hwnd) {
        hDeferPos = DeferWindowPos(hDeferPos, hwnd, 0,
            r2.right - Context->dx10, Context->dx11,
            0, 0,
            SWP_NOSIZE | SWP_NOZORDER);
        if (!hDeferPos) return;
    }

    //reposition Type label
    hwnd = GetDlgItem(hwndDlg, ID_SEARCH_TYPELABEL);
    if (hwnd) {
        hDeferPos = DeferWindowPos(hDeferPos, hwnd, 0,
            r2.right - Context->dx12, Context->dx13,
            0, 0,
            SWP_NOSIZE | SWP_NOZORDER);
        if (!hDeferPos) return;
    }

    // Apply all positioning changes at once
    EndDeferWindowPos(hDeferPos);

    // Update status bar separately (it needs special handling)
    SendMessage(Context->StatusBar, WM_SIZE, 0, 0);

    InvalidateRect(hwndDlg, NULL, FALSE);
}

/*
* FindDlgHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for FindDlg listview.
*
*/
BOOL FindDlgHandleNotify(
    _In_ LPNMLISTVIEW pListView
)
{
    INT      nImageIndex;
    LPWSTR   lpItemText;

    if (pListView->hdr.idFrom != ID_SEARCH_LIST)
        return FALSE;

    switch (pListView->hdr.code) {

    case LVN_ITEMCHANGED:

        if ((pListView->uNewState & LVIS_SELECTED) &&
            !(pListView->uOldState & LVIS_SELECTED))
        {

            lpItemText = supGetItemText(pListView->hdr.hwndFrom,
                pListView->iItem,
                0,
                NULL);

            if (lpItemText) {
                ListToObject(lpItemText);
                supHeapFree(lpItemText);
            }
        }

        break;

    case LVN_COLUMNCLICK:
        g_FindDlgContext.SortInverse = (~g_FindDlgContext.SortInverse) & 1;
        g_FindDlgContext.SortColumn = pListView->iSubItem;
        ListView_SortItemsEx(g_FindDlgContext.SearchList, &FindDlgCompareFunc, g_FindDlgContext.SortColumn);

        nImageIndex = ImageList_GetImageCount(g_ListViewImages);
        if (g_FindDlgContext.SortInverse)
            nImageIndex -= 2;
        else
            nImageIndex -= 1;

        supUpdateLvColumnHeaderImage(
            g_FindDlgContext.SearchList,
            g_FindDlgContext.ColumnCount,
            g_FindDlgContext.SortColumn,
            nImageIndex);

        break;

    default:
        return FALSE;
    }

    return TRUE;
}

/*
* FindDlgHandleSettingsChange
*
* Purpose:
*
* Handle global settings change.
*
*/
VOID FindDlgHandleSettingsChange(
    _In_ FINDDLG_CONTEXT* Context
)
{
    DWORD lvExStyle;

    lvExStyle = ListView_GetExtendedListViewStyle(Context->SearchList);
    if (g_WinObj.ListViewDisplayGrid)
        lvExStyle |= LVS_EX_GRIDLINES;
    else
        lvExStyle &= ~LVS_EX_GRIDLINES;

    ListView_SetExtendedListViewStyle(Context->SearchList, lvExStyle);
}

/*
* FindDlgHandlePopupMenu
*
* Purpose:
*
* Search list popup construction.
*
*/
VOID FindDlgHandlePopupMenu(
    _In_ HWND hwndDlg,
    _In_ LPPOINT lpPoint,
    _In_ PVOID lpUserParam
)
{
    HMENU hMenu;
    UINT uPos = 0;
    FINDDLG_CONTEXT* Context = (FINDDLG_CONTEXT*)lpUserParam;

    hMenu = CreatePopupMenu();
    if (hMenu) {

        if (supListViewAddCopyValueItem(hMenu,
            Context->SearchList,
            ID_OBJECT_COPY,
            uPos,
            lpPoint,
            &Context->iSelectedItem,
            &Context->iColumnHit))
        {
            TrackPopupMenu(hMenu,
                TPM_RIGHTBUTTON | TPM_LEFTALIGN,
                lpPoint->x,
                lpPoint->y,
                0,
                hwndDlg,
                NULL);
        }

        DestroyMenu(hMenu);
    }
}

/*
* FindDlgSearchWorkerThread
*
* Purpose:
*
* Background thread to perform object search.
*
*/
DWORD WINAPI FindDlgSearchWorkerThread(
    _In_ LPVOID lpParameter
)
{
    PFIND_SEARCH_PARAMS searchParams = (PFIND_SEARCH_PARAMS)lpParameter;
    HWND hwndDlg = searchParams->hwndDlg;
    PFO_LIST_ITEM flist = NULL;
    UNICODE_STRING usName, usType;
    PUNICODE_STRING pusName = NULL, pusType = NULL;

    // Set up search strings
    if (searchParams->UseName) {
        RtlInitUnicodeString(&usName, searchParams->NameString);
        pusName = &usName;
    }

    if (searchParams->UseType) {
        RtlInitUnicodeString(&usType, searchParams->TypeString);
        pusType = &usType;
    }

    // Perform search
    FindObject(ObGetPredefinedUnicodeString(OBP_ROOT), pusName, pusType, &flist);

    // Update UI from main thread
    SendMessage(hwndDlg, WM_FINDOBJECT_SEARCHCOMPLETE, (WPARAM)flist, 0);

    // Free search parameters
    supHeapFree(searchParams);
    return 0;
}

/*
* FindDlgHandleSearchComplete
*
* Purpose:
*
* Process search results from background thread.
*
*/
VOID FindDlgHandleSearchComplete(
    _In_ HWND hwndDlg,
    _In_ PFO_LIST_ITEM ResultList
)
{
    PFO_LIST_ITEM flist = ResultList;
    PFO_LIST_ITEM plist;
    ULONG cci = 0;
    WCHAR searchString[MAX_PATH + 1];

    // Return to search mode
    SetDlgItemText(hwndDlg, ID_SEARCH_FIND, TEXT("Search"));
    EnableWindow(GetDlgItem(hwndDlg, ID_SEARCH_FIND), TRUE);

    // Check if search was cancelled
    if (g_FindDlgContext.SearchCancelled) {
        g_FindDlgContext.SearchCancelled = FALSE;
        SetDlgItemText(hwndDlg, ID_SEARCH_STATUSBAR, TEXT("Search cancelled"));

        // Free the result list
        while (flist != NULL) {
            plist = flist->Prev;
            supHeapFree(flist);
            flist = plist;
        }

        if (g_FindDlgContext.SearchThread) {
            CloseHandle(g_FindDlgContext.SearchThread);
            g_FindDlgContext.SearchThread = NULL;
        }
        return;
    }

    // Begin batch processing
    supDisableRedraw(g_FindDlgContext.SearchList);

    // Process results
    while (flist != NULL) {
        FindDlgAddListItem(g_FindDlgContext.SearchList, &flist->ObjectName, &flist->ObjectType);
        plist = flist->Prev;
        supHeapFree(flist);
        flist = plist;
        cci++;
    }

    // Sort results
    ListView_SortItemsEx(g_FindDlgContext.SearchList,
        &FindDlgCompareFunc, g_FindDlgContext.SortColumn);

    // Update status
    ultostr(cci, searchString);
    _strcat(searchString, TEXT(" matching object(s)."));
    SetDlgItemText(hwndDlg, ID_SEARCH_STATUSBAR, searchString);

    // End batch processing
    supEnableRedraw(g_FindDlgContext.SearchList);

    // Clean up
    if (g_FindDlgContext.SearchThread) {
        CloseHandle(g_FindDlgContext.SearchThread);
        g_FindDlgContext.SearchThread = NULL;
    }
}

/*
* FindDlgHandleSearch
*
* Purpose:
*
* Search button click handler.
*
*/
VOID FindDlgHandleSearch(
    _In_ HWND hwndDlg
)
{
    WCHAR searchString[MAX_PATH + 1], typeName[MAX_PATH + 1];
    PFIND_SEARCH_PARAMS searchParams;

    // Cancel ongoing search if any
    if (g_FindDlgContext.SearchThread) {
        // Signal cancellation
        if (WaitForSingleObject(g_FindDlgContext.SearchThread, 0) == WAIT_TIMEOUT) {
            g_FindDlgContext.SearchCancelled = TRUE;
            SetDlgItemText(hwndDlg, ID_SEARCH_STATUSBAR, TEXT("Cancelling search..."));
            return;
        }

        CloseHandle(g_FindDlgContext.SearchThread);
        g_FindDlgContext.SearchThread = NULL;
    }

    // Prepare for new search
    g_FindDlgContext.SearchCancelled = FALSE;

    RtlSecureZeroMemory(&searchString, sizeof(searchString));
    RtlSecureZeroMemory(&typeName, sizeof(typeName));

    GetDlgItemText(hwndDlg, ID_SEARCH_NAME, (LPWSTR)&searchString, MAX_PATH);
    GetDlgItemText(hwndDlg, ID_SEARCH_TYPE, (LPWSTR)&typeName, MAX_PATH);

    // Update status and UI
    ListView_DeleteAllItems(g_FindDlgContext.SearchList);
    SetDlgItemText(hwndDlg, ID_SEARCH_STATUSBAR, TEXT("Searching..."));
    EnableWindow(GetDlgItem(hwndDlg, ID_SEARCH_FIND), FALSE);

    // Allocate search params
    searchParams = (PFIND_SEARCH_PARAMS)supHeapAlloc(sizeof(FIND_SEARCH_PARAMS));
    if (searchParams == NULL) {
        SetDlgItemText(hwndDlg, ID_SEARCH_STATUSBAR, TEXT("Memory allocation failed"));
        EnableWindow(GetDlgItem(hwndDlg, ID_SEARCH_FIND), TRUE);
        return;
    }

    searchParams->hwndDlg = hwndDlg;

    // Set up search parameters
    if (searchString[0] == 0) {
        searchParams->UseName = FALSE;
    }
    else {
        searchParams->UseName = TRUE;
        _strcpy(searchParams->NameString, searchString);
    }

    if (typeName[0] == L'*') {
        searchParams->UseType = FALSE;
    }
    else {
        searchParams->UseType = TRUE;
        _strcpy(searchParams->TypeString, typeName);
    }

    // Start search thread
    g_FindDlgContext.SearchThread = CreateThread(NULL, 0, FindDlgSearchWorkerThread, searchParams, 0, NULL);
    if (!g_FindDlgContext.SearchThread) {
        supHeapFree(searchParams);
        SetDlgItemText(hwndDlg, ID_SEARCH_STATUSBAR, TEXT("Failed to create search thread"));
        EnableWindow(GetDlgItem(hwndDlg, ID_SEARCH_FIND), TRUE);
    }
}

/*
* FindDlgOnInit
*
* Purpose:
*
* WM_INITDIALOG handler.
*
*/
VOID FindDlgOnInit(
    _In_ HWND hwndDlg
)
{
    INT iImage = ImageList_GetImageCount(g_ListViewImages) - 1;
    LVCOLUMNS_DATA columnData[] =
    {
        { L"Name", 300, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  iImage },
        { L"Type", 100, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  I_IMAGENONE }
    };

    g_FindDlgContext.DialogWindow = hwndDlg;
    g_FindDlgContext.StatusBar = GetDlgItem(hwndDlg, ID_SEARCH_STATUSBAR);
    g_FindDlgContext.iColumnHit = -1;
    g_FindDlgContext.iSelectedItem = -1;
    g_FindDlgContext.SearchThread = NULL;
    g_FindDlgContext.SearchCancelled = FALSE;

    //
    // Set dialog icon.
    //
    g_FindDlgContext.DialogIcon = (HICON)LoadImage(g_WinObj.hInstance,
        MAKEINTRESOURCE(IDI_ICON_MAIN),
        IMAGE_ICON,
        32, 32,
        0);

    if (g_FindDlgContext.DialogIcon) {
        SendMessage(hwndDlg, WM_SETICON, (WPARAM)ICON_SMALL, (LPARAM)g_FindDlgContext.DialogIcon);
        SendMessage(hwndDlg, WM_SETICON, (WPARAM)ICON_BIG, (LPARAM)g_FindDlgContext.DialogIcon);
    }

    g_FindDlgContext.SearchList = GetDlgItem(hwndDlg, ID_SEARCH_LIST);
    if (g_FindDlgContext.SearchList) {

        //
        // Set listview imagelist, style flags and theme.
        //
        supSetListViewSettings(g_FindDlgContext.SearchList,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP,
            FALSE,
            TRUE,
            g_ListViewImages,
            LVSIL_SMALL);

        //
        // And columns and remember their count.
        //
        g_FindDlgContext.ColumnCount = supAddLVColumnsFromArray(
            g_FindDlgContext.SearchList,
            columnData,
            RTL_NUMBER_OF(columnData));

    }

    FindDlgAddTypes(hwndDlg);
    supCenterWindowSpecifyParent(hwndDlg, g_hwndMain);
    FindDlgResize(hwndDlg, &g_FindDlgContext);
    SetActiveWindow(hwndDlg);
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
    if (uMsg == g_WinObj.SettingsChangeMessage) {
        FindDlgHandleSettingsChange(&g_FindDlgContext);
        return TRUE;
    }

    switch (uMsg) {

    case WM_FINDOBJECT_SEARCHCOMPLETE:
        FindDlgHandleSearchComplete(hwndDlg, (PFO_LIST_ITEM)wParam);
        return TRUE;

    case WM_NOTIFY:
        return FindDlgHandleNotify((LPNMLISTVIEW)lParam);

    case WM_GETMINMAXINFO:
        if (lParam) {
            supSetMinMaxTrackSize((PMINMAXINFO)lParam,
                FINDDLG_TRACKSIZE_MIN_X,
                FINDDLG_TRACKSIZE_MIN_Y,
                TRUE);
        }
        break;

    case WM_INITDIALOG:
        FindDlgOnInit(hwndDlg);
        break;

    case WM_SIZE:
        FindDlgResize(hwndDlg, &g_FindDlgContext);
        break;

    case WM_DESTROY:
        // Cancel any ongoing search
        if (g_FindDlgContext.SearchThread) {
            g_FindDlgContext.SearchCancelled = TRUE;
            WaitForSingleObject(g_FindDlgContext.SearchThread, 1000);
            CloseHandle(g_FindDlgContext.SearchThread);
            g_FindDlgContext.SearchThread = NULL;
        }
        PostQuitMessage(0);
        break;

    case WM_CLOSE:
        if (g_FindDlgContext.DialogIcon)
            DestroyIcon(g_FindDlgContext.DialogIcon);

        DestroyWindow(hwndDlg);
        break;

    case WM_COMMAND:

        switch (GET_WM_COMMAND_ID(wParam, lParam)) {
        case ID_OBJECT_COPY:

            supListViewCopyItemValueToClipboard(g_FindDlgContext.SearchList,
                g_FindDlgContext.iSelectedItem,
                g_FindDlgContext.iColumnHit);

            break;

        case IDCANCEL:
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            break;

        case ID_SEARCH_FIND:
            FindDlgHandleSearch(hwndDlg);
            break;

        }
        break;

    case WM_CONTEXTMENU:

        supHandleContextMenuMsgForListView(hwndDlg,
            wParam,
            lParam,
            g_FindDlgContext.SearchList,
            (pfnPopupMenuHandler)FindDlgHandlePopupMenu,
            &g_FindDlgContext);

        break;

    }

    return FALSE;
}

/*
* FindpDlgWorkerThread
*
* Purpose:
*
* Find Dialog thread.
*
*/
DWORD FindpDlgWorkerThread(
    _In_ PVOID Parameter
)
{
    BOOL bResult;
    MSG message;
    HWND hwndDlg;

    UNREFERENCED_PARAMETER(Parameter);

    hwndDlg = CreateDialogParam(g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_SEARCH),
        0,
        &FindDlgProc,
        0);

    supSetFastEvent(&FindDialogInitializedEvent);

    do {

        bResult = GetMessage(&message, NULL, 0, 0);
        if (bResult == -1)
            break;

        if (!IsDialogMessage(hwndDlg, &message)) {
            TranslateMessage(&message);
            DispatchMessage(&message);
        }

    } while (bResult != 0);

    supResetFastEvent(&FindDialogInitializedEvent);

    if (FindDialogThreadHandle) {
        NtClose(FindDialogThreadHandle);
        FindDialogThreadHandle = NULL;
    }
    return 0;
}

/*
* FindDlgCreate
*
* Purpose:
*
* Run Find Dialog.
*
*/
VOID FindDlgCreate(
    VOID
)
{
    if (!FindDialogThreadHandle) {

        RtlSecureZeroMemory(&g_FindDlgContext, sizeof(g_FindDlgContext));
        FindDialogThreadHandle = supCreateDialogWorkerThread(FindpDlgWorkerThread, NULL, 0);
        supWaitForFastEvent(&FindDialogInitializedEvent, NULL);

    }
}
