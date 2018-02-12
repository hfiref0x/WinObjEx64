/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.52
*
*  DATE:        10 Feb 2018
*
*  Program entry point and main window handler.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#define OEMRESOURCE
#include "global.h"
#include "aboutDlg.h"
#include "findDlg.h"
#include "props\propDlg.h"
#include "extras\extras.h"
#include "tests\testunit.h"

static LONG	SplitterPos = 180;
static LONG	SortColumn = 0;
HTREEITEM	SelectedTreeItem = NULL;
BOOL        bMainWndSortInverse = FALSE;
HWND        hwndToolBar = NULL, hwndSplitter = NULL, hwndStatusBar = NULL, MainWindow = NULL;

/*
* MainWindowObjectListCompareFunc
*
* Purpose:
*
* Main window listview comparer function.
*
*/
INT CALLBACK MainWindowObjectListCompareFunc(
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort
)
{
    INT    nResult = 0;
    LPWSTR lpItem1 = NULL, lpItem2 = NULL;

    lpItem1 = supGetItemText(g_hwndObjectList, (INT)lParam1, (INT)lParamSort, NULL);
    lpItem2 = supGetItemText(g_hwndObjectList, (INT)lParam2, (INT)lParamSort, NULL);

    if ((lpItem1 == NULL) && (lpItem2 == NULL)) {
        nResult = 0;
        goto Done;
    }
    if ((lpItem1 == NULL) && (lpItem2 != NULL)) {
        nResult = (bMainWndSortInverse) ? 1 : -1;
        goto Done;
    }
    if ((lpItem2 == NULL) && (lpItem1 != NULL)) {
        nResult = (bMainWndSortInverse) ? -1 : 1;
        goto Done;
    }

    if (bMainWndSortInverse)
        nResult = _strcmpi(lpItem2, lpItem1);
    else
        nResult = _strcmpi(lpItem1, lpItem2);

Done:
    if (lpItem1) supHeapFree(lpItem1);
    if (lpItem2) supHeapFree(lpItem2);

    return nResult;
}

/*
* MainWindowHandleObjectTreeProp
*
* Purpose:
*
* Object Tree properties per selected item.
*
*/
VOID MainWindowHandleObjectTreeProp(
    _In_ HWND hwnd
)
{
    TV_ITEM tvi;
    WCHAR   szBuffer[MAX_PATH + 1];

    if (g_PropWindow != NULL)
        return;

    if (SelectedTreeItem == NULL)
        return;

    szBuffer[0] = 0; //mars workaround

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    RtlSecureZeroMemory(&tvi, sizeof(TV_ITEM));

    tvi.pszText = szBuffer;
    tvi.cchTextMax = MAX_PATH;
    tvi.mask = TVIF_TEXT;
    tvi.hItem = SelectedTreeItem;
    if (TreeView_GetItem(g_hwndObjectTree, &tvi)) {
        propCreateDialog(hwnd, szBuffer, g_lpObjectNames[TYPE_DIRECTORY], NULL);
    }
}

/*
* MainWindowHandleObjectListProp
*
* Purpose:
*
* Object List properties per selected item.
*
*/
VOID MainWindowHandleObjectListProp(
    _In_ HWND hwnd
)
{
    INT     nSelected;
    LPWSTR  lpItemText, lpType, lpDesc = NULL;

    if (g_PropWindow != NULL)
        return;

    //nothing selected, go away
    if (ListView_GetSelectedCount(g_hwndObjectList) == 0) {
        return;
    }

    nSelected = ListView_GetSelectionMark(g_hwndObjectList);
    if (nSelected == -1) {
        return;
    }

    lpItemText = supGetItemText(g_hwndObjectList, nSelected, 0, NULL);
    if (lpItemText) {
        lpType = supGetItemText(g_hwndObjectList, nSelected, 1, NULL);
        if (lpType) {

            //lpDesc is not important, we can work if it NULL
            lpDesc = supGetItemText(g_hwndObjectList, nSelected, 2, NULL);

            propCreateDialog(hwnd, lpItemText, lpType, lpDesc);

            if (lpDesc) {
                supHeapFree(lpDesc);
            }
            supHeapFree(lpType);
        }
        supHeapFree(lpItemText);
    }
}

/*
* MainWindowOnRefresh
*
* Purpose:
*
* Main Window Refresh handler.
*
*/
VOID MainWindowOnRefresh(
    _In_ HWND hwnd
)
{
    LPWSTR  CurrentPath = NULL;
    SIZE_T  len;

    UNREFERENCED_PARAMETER(hwnd);

    supSetWaitCursor(TRUE);

    if (g_kdctx.hDevice != NULL) {
        ObListDestroy(&g_kdctx.ObjectList);
        if (g_kdctx.hThreadWorker) {
            WaitForSingleObject(g_kdctx.hThreadWorker, INFINITE);
            CloseHandle(g_kdctx.hThreadWorker);
            g_kdctx.hThreadWorker = NULL;
        }

        //query object list info
        g_kdctx.hThreadWorker = CreateThread(NULL, 0,
            kdQueryProc,
            &g_kdctx, 0, NULL);
    }

    supFreeSCMSnapshot();
    sapiFreeSnapshot();

    supCreateSCMSnapshot();
    sapiCreateSetupDBSnapshot();

    len = _strlen(g_WinObj.CurrentObjectPath);
    CurrentPath = supHeapAlloc((len + 1) * sizeof(WCHAR));
    if (CurrentPath)
        _strcpy(CurrentPath, g_WinObj.CurrentObjectPath);

    TreeView_DeleteAllItems(g_hwndObjectTree);
    ListObjectDirectoryTree(L"\\", NULL, NULL);
    TreeView_SelectItem(g_hwndObjectTree, TreeView_GetRoot(g_hwndObjectTree));

    if (CurrentPath) {
        ListToObject(CurrentPath);
        supHeapFree(CurrentPath);
    }

    supSetWaitCursor(FALSE);
}

/*
* MainWindowHandleWMCommand
*
* Purpose:
*
* Main window WM_COMMAND handler.
*
*/
LRESULT MainWindowHandleWMCommand(
    _In_ HWND hwnd,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    LPWSTR  lpItemText;
    HWND    hwndFocus;

    UNREFERENCED_PARAMETER(lParam);

    switch (LOWORD(wParam)) {

    case ID_FILE_RUNASADMIN:
        supRunAsAdmin();
        break;

    case ID_FILE_EXIT:
        PostQuitMessage(0);
        break;

    case ID_OBJECT_PROPERTIES:
        hwndFocus = GetFocus();
        if (hwndFocus == g_hwndObjectList) {
            MainWindowHandleObjectListProp(hwnd);
        }
        if (hwndFocus == g_hwndObjectTree) {
            MainWindowHandleObjectTreeProp(hwnd);
        }
        break;

    case ID_OBJECT_GOTOLINKTARGET:
        lpItemText = supGetItemText(g_hwndObjectList, ListView_GetSelectionMark(g_hwndObjectList), 2, NULL);
        if (lpItemText) {
            if (_strcmpi(lpItemText, L"\\??") == 0) {
                ListToObject(L"\\GLOBAL??");
            }
            else {
                ListToObject(lpItemText);
            }
            supHeapFree(lpItemText);
        }
        else {
            lpItemText = supGetItemText(g_hwndObjectList, ListView_GetSelectionMark(g_hwndObjectList), 0, NULL);
            if (lpItemText) {
                if ((_strcmpi(lpItemText, L"GLOBALROOT") == 0) &&
                    (_strcmpi(g_WinObj.CurrentObjectPath, L"\\GLOBAL??") == 0))
                {
                    ListToObject(L"\\");
                }
                supHeapFree(lpItemText);
            }
        }
        break;

    case ID_FIND_FINDOBJECT:
        FindDlgCreate(hwnd);
        break;

    case ID_VIEW_REFRESH:
        MainWindowOnRefresh(hwnd);
        break;

        //Extras -> Pipes
    case ID_EXTRAS_PIPES:
        extrasShowPipeDialog(hwnd);
        break;

        //Extras -> Mailslots
    case ID_EXTRAS_MAILSLOTS:
        extrasShowMailslotsDialog(hwnd);
        break;

        //Extras -> UserSharedData
    case ID_EXTRAS_USERSHAREDDATA:
        extrasShowUserSharedDataDialog(hwnd);
        break;

        //Extras -> Private Namespaces
    case ID_EXTRAS_PRIVATENAMESPACES:
        if (g_WinObj.osver.dwBuildNumber <= 10240) {

            //feature require driver usage
            if (g_kdctx.hDevice != NULL) {
                extrasShowPrivateNamespacesDialog(hwnd);
            }
        }
        break;

        //Extras -> KiServiceTable
    case ID_EXTRAS_SSDT:

        //feature require driver usage
#ifndef _DEBUG
        if (g_kdctx.hDevice != NULL) {
#endif
            extrasShowSSDTDialog(hwnd);
#ifndef _DEBUG
        }
#endif
        break;

        //Extras -> Drivers
    case ID_EXTRAS_DRIVERS:
        extrasShowDriversDialog(hwnd);
        break;

    case ID_HELP_ABOUT:
        DialogBoxParam(g_WinObj.hInstance, MAKEINTRESOURCE(IDD_DIALOG_ABOUT),
            hwnd, (DLGPROC)&AboutDialogProc, 0);
        break;

    case ID_HELP_HELP:
        supShowHelp();
        break;

    default:
        break;
    }
    return FALSE;
}

/*
* MainWindowTreeViewSelChanged
*
* Purpose:
*
* Tree List TVN_ITEMEXPANDED, TVN_SELCHANGED handler.
*
*/
VOID MainWindowTreeViewSelChanged(
    _In_ LPNMTREEVIEWW trhdr
)
{
    WCHAR           text[MAX_PATH + 2];
    HTREEITEM       hitem, root;
    TVITEMEX        sitem;
    POE_LIST_ITEM   list = NULL, prevlist = NULL;
    SIZE_T          p = 1; // size of empty string buffer in characters

    if (trhdr == NULL)
        return;

    if (!trhdr->itemNew.hItem)
        return;

    if (g_WinObj.CurrentObjectPath != NULL)
        supHeapFree(g_WinObj.CurrentObjectPath);

    root = TreeView_GetRoot(trhdr->hdr.hwndFrom);

    // build the path from bottom to top and counting string buffer size
    for (hitem = trhdr->itemNew.hItem; hitem != root;
        hitem = TreeView_GetParent(trhdr->hdr.hwndFrom, hitem))
    {
        RtlSecureZeroMemory(&sitem, sizeof(sitem));
        RtlSecureZeroMemory(&text, sizeof(text));
        sitem.mask = TVIF_HANDLE | TVIF_TEXT;
        sitem.hItem = hitem;
        sitem.pszText = text;
        sitem.cchTextMax = MAX_PATH;
        TreeView_GetItem(trhdr->hdr.hwndFrom, &sitem);

        p += _strlen(text) + 1; //+1 for '\'

        list = supHeapAlloc(sizeof(OE_LIST_ITEM));
        if (list) {
            list->Prev = prevlist;
            list->TreeItem = hitem;
        }
        prevlist = list;
    }

    if (list == NULL) {
        g_WinObj.CurrentObjectPath = supHeapAlloc(2 * sizeof(WCHAR));
        if (g_WinObj.CurrentObjectPath) {
            g_WinObj.CurrentObjectPath[0] = L'\\';
            g_WinObj.CurrentObjectPath[1] = 0;
        }
        return;
    }

    list = prevlist;
    g_WinObj.CurrentObjectPath = supHeapAlloc(p * sizeof(WCHAR));
    if (g_WinObj.CurrentObjectPath) {
        p = 0;
        // building the final string
        while (list != NULL) {
            RtlSecureZeroMemory(&sitem, sizeof(sitem));
            RtlSecureZeroMemory(&text, sizeof(text));
            sitem.mask = TVIF_HANDLE | TVIF_TEXT;
            sitem.hItem = list->TreeItem;
            sitem.pszText = text;
            sitem.cchTextMax = MAX_PATH;
            TreeView_GetItem(trhdr->hdr.hwndFrom, &sitem);

            g_WinObj.CurrentObjectPath[p] = L'\\';
            p++;
            _strcpy(g_WinObj.CurrentObjectPath + p, text);
            p += _strlen(text);

            prevlist = list->Prev;
            supHeapFree(list);
            list = prevlist;
        }
    }
    return;
}

/*
* MainWindowHandleWMNotify
*
* Purpose:
*
* Main window WM_NOTIFY handler.
*
*/
LRESULT MainWindowHandleWMNotify(
    _In_ HWND hwnd,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    INT             c, k;
    LPNMHDR         hdr = (LPNMHDR)lParam;
    LPTOOLTIPTEXT   lpttt;
    LPNMLISTVIEW    lvn;
    LPNMTREEVIEW    lpnmTreeView;
    LPWSTR          str;
    SIZE_T          lcp;
    LVITEM          lvitem;
    LVCOLUMN        col;
    TVHITTESTINFO   hti;
    POINT           pt;
    WCHAR           item_string[MAX_PATH + 1];

    UNREFERENCED_PARAMETER(wParam);

    if (hdr) {

        if (hdr->hwndFrom == g_hwndObjectTree) {
            switch (hdr->code) {
            case TVN_ITEMEXPANDED:
            case TVN_SELCHANGED:
                SetFocus(g_hwndObjectTree);
                supSetWaitCursor(TRUE);
                MainWindowTreeViewSelChanged((LPNMTREEVIEWW)lParam);
                SendMessage(hwndStatusBar, WM_SETTEXT, 0, (LPARAM)g_WinObj.CurrentObjectPath);

                ListObjectsInDirectory(g_WinObj.CurrentObjectPath);

                ListView_SortItemsEx(g_hwndObjectList, &MainWindowObjectListCompareFunc, SortColumn);

                supSetWaitCursor(FALSE);

                lpnmTreeView = (LPNMTREEVIEW)lParam;
                if (lpnmTreeView) {
                    SelectedTreeItem = lpnmTreeView->itemNew.hItem;
                }
                break;

            case NM_RCLICK:
                GetCursorPos(&pt);
                hti.pt = pt;
                ScreenToClient(hdr->hwndFrom, &hti.pt);
                if (TreeView_HitTest(hdr->hwndFrom, &hti) &&
                    (hti.flags & (TVHT_ONITEM | TVHT_ONITEMRIGHT))) {
                    SelectedTreeItem = hti.hItem;
                    TreeView_SelectItem(g_hwndObjectTree, SelectedTreeItem);
                    SendMessage(hwndStatusBar, WM_SETTEXT, 0, (LPARAM)g_WinObj.CurrentObjectPath);
                    supHandleTreePopupMenu(hwnd, &pt);
                }
                break;
            }
        }

        if (hdr->hwndFrom == g_hwndObjectList) {
            switch (hdr->code) {
            case NM_SETFOCUS:
                if (ListView_GetSelectionMark(g_hwndObjectList) == -1) {
                    lvitem.mask = LVIF_STATE;
                    lvitem.iItem = 0;
                    lvitem.state = LVIS_SELECTED | LVIS_FOCUSED;
                    lvitem.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
                    ListView_SetItem(g_hwndObjectList, &lvitem);
                }

                break;
            case LVN_ITEMCHANGED:
                lvn = (LPNMLISTVIEW)lParam;
                RtlSecureZeroMemory(&item_string, sizeof(item_string));
                ListView_GetItemText(g_hwndObjectList, lvn->iItem, 0, item_string, MAX_PATH);
                lcp = _strlen(g_WinObj.CurrentObjectPath);
                if (lcp) {
                    str = supHeapAlloc((lcp + sizeof(item_string) + 4) * sizeof(WCHAR));
                    if (str == NULL)
                        break;
                    _strcpy(str, g_WinObj.CurrentObjectPath);

                    if ((str[0] == '\\') && (str[1] == 0)) {
                        _strcpy(str + lcp, item_string);
                    }
                    else {
                        str[lcp] = '\\';
                        _strcpy(str + lcp + 1, item_string);
                    }
                    SendMessage(hwndStatusBar, WM_SETTEXT, 0, (LPARAM)str);
                    supHeapFree(str);
                }
                break;

                //handle sort by column
            case LVN_COLUMNCLICK:
                bMainWndSortInverse = !bMainWndSortInverse;
                SortColumn = ((NMLISTVIEW *)lParam)->iSubItem;
                ListView_SortItemsEx(g_hwndObjectList, &MainWindowObjectListCompareFunc, SortColumn);

                RtlSecureZeroMemory(&col, sizeof(col));
                col.mask = LVCF_IMAGE;
                col.iImage = -1;

                for (c = 0; c < 3; c++)
                    ListView_SetColumn(g_hwndObjectList, c, &col);

                k = ImageList_GetImageCount(g_ListViewImages);
                if (bMainWndSortInverse)
                    col.iImage = k - 2;
                else
                    col.iImage = k - 1;

                ListView_SetColumn(g_hwndObjectList, ((NMLISTVIEW *)lParam)->iSubItem, &col);

                break;

            case NM_DBLCLK:
                MainWindowHandleObjectListProp(hwnd);
                break;

            default:
                break;
            }
        }

        //handle tooltip
        if (hdr->code == TTN_GETDISPINFO) {
            lpttt = (LPTOOLTIPTEXT)lParam;

            switch (lpttt->hdr.idFrom) {

            case ID_OBJECT_PROPERTIES:
            case ID_VIEW_REFRESH:
            case ID_FIND_FINDOBJECT:
                lpttt->hinst = g_WinObj.hInstance;
                lpttt->lpszText = MAKEINTRESOURCE(lpttt->hdr.idFrom);
                lpttt->uFlags |= TTF_DI_SETITEM;
                break;

            default:
                break;

            }
        }
    }
    return FALSE;
}

/*
* MainWindowResizeHandler
*
* Purpose:
*
* Main window WM_SIZE handler.
*
*/
VOID MainWindowResizeHandler(
    _In_ LONG sPos
)
{
    RECT ToolBarRect, StatusBarRect;
    LONG posY, sizeY, sizeX;

    if (hwndToolBar != NULL) {
        SendMessage(hwndToolBar, WM_SIZE, 0, 0);
        SendMessage(hwndStatusBar, WM_SIZE, 0, 0);
        RtlSecureZeroMemory(&ToolBarRect, sizeof(ToolBarRect));
        RtlSecureZeroMemory(&StatusBarRect, sizeof(StatusBarRect));
        GetWindowRect(hwndToolBar, &ToolBarRect);
        GetWindowRect(hwndStatusBar, &StatusBarRect);

        sizeX = ToolBarRect.right - ToolBarRect.left;
        if (sPos > sizeX - SplitterMargin)
            sPos = sizeX - SplitterMargin - 1;

        sizeY = StatusBarRect.top - ToolBarRect.bottom;
        posY = ToolBarRect.bottom - ToolBarRect.top;
        sizeX = ToolBarRect.right - ToolBarRect.left - sPos - SplitterSize;

        SetWindowPos(g_hwndObjectTree, NULL, 0, posY, sPos, sizeY, 0);
        SetWindowPos(g_hwndObjectList, NULL, sPos + SplitterSize, posY, sizeX, sizeY, 0);
        SetWindowPos(hwndSplitter, NULL, sPos, posY, SplitterSize, sizeY, 0);
    }
}

/*
* MainWindowProc
*
* Purpose:
*
* Main window procedure.
*
*/
LRESULT CALLBACK MainWindowProc(
    _In_ HWND hwnd,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    INT                 mark;
    RECT                ToolBarRect, crc;
    LPDRAWITEMSTRUCT    pds;
    LPMEASUREITEMSTRUCT pms;

    switch (uMsg) {
    case WM_CONTEXTMENU:

        RtlSecureZeroMemory(&crc, sizeof(crc));

        if ((HWND)wParam == g_hwndObjectTree) {
            TreeView_GetItemRect(g_hwndObjectTree, TreeView_GetSelection(g_hwndObjectTree), &crc, TRUE);
            crc.top = crc.bottom;
            ClientToScreen(g_hwndObjectTree, (LPPOINT)&crc);
            supHandleTreePopupMenu(hwnd, (LPPOINT)&crc);
        }

        if ((HWND)wParam == g_hwndObjectList) {
            mark = ListView_GetSelectionMark(g_hwndObjectList);

            if (lParam == MAKELPARAM(-1, -1)) {
                ListView_GetItemRect(g_hwndObjectList, mark, &crc, TRUE);
                crc.top = crc.bottom;
                ClientToScreen(g_hwndObjectList, (LPPOINT)&crc);
            }
            else
                GetCursorPos((LPPOINT)&crc);

            supHandleObjectPopupMenu(hwnd, g_hwndObjectList, mark, (LPPOINT)&crc);
        }
        break;

    case WM_COMMAND:
        MainWindowHandleWMCommand(hwnd, wParam, lParam);
        break;

    case WM_NOTIFY:
        MainWindowHandleWMNotify(hwnd, wParam, lParam);
        break;

    case WM_MEASUREITEM:
        pms = (LPMEASUREITEMSTRUCT)lParam;
        if (pms && pms->CtlType == ODT_MENU) {
            pms->itemWidth = 16;
            pms->itemHeight = 16;
        }
        break;

    case WM_DRAWITEM:
        pds = (LPDRAWITEMSTRUCT)lParam;
        if (pds && pds->CtlType == ODT_MENU) {
            DrawIconEx(pds->hDC, pds->rcItem.left - 15,
                pds->rcItem.top,
                (HICON)pds->itemData,
                16, 16, 0, NULL, DI_NORMAL);
        }
        break;

    case WM_CLOSE:
        PostQuitMessage(0);
        break;

    case WM_LBUTTONDOWN:
        SetCapture(MainWindow);
        break;

    case WM_LBUTTONUP:
        ReleaseCapture();
        break;

    case WM_MOUSEMOVE:
        if ((wParam & MK_LBUTTON) != 0) {
            GetClientRect(MainWindow, &ToolBarRect);
            SplitterPos = (SHORT)LOWORD(lParam);
            if (SplitterPos < SplitterMargin)
                SplitterPos = SplitterMargin;
            if (SplitterPos > ToolBarRect.right - SplitterMargin)
                SplitterPos = ToolBarRect.right - SplitterMargin;
            SendMessage(MainWindow, WM_SIZE, 0, 0);
            UpdateWindow(MainWindow);
        }
        break;

    case WM_SIZE:
        if (!IsIconic(hwnd)) {
            MainWindowResizeHandler(SplitterPos);
        }
        break;

    case WM_GETMINMAXINFO:
        if (lParam) {
            ((PMINMAXINFO)lParam)->ptMinTrackSize.x = 400;
            ((PMINMAXINFO)lParam)->ptMinTrackSize.y = 256;
        }
        break;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

/*
* MainDlgMsgHandler
*
* Purpose:
*
* Check window message against existing dialogs.
*
*/
BOOL MainDlgMsgHandler(
    _In_ MSG msg
)
{
    UINT c;

    for (c = 0; c < WOBJ_MAX_DIALOGS; c++) {
        if ((g_WinObj.AuxDialogs[c] != NULL)) {
            if (IsDialogMessage(g_WinObj.AuxDialogs[c], &msg))
                return TRUE;
        }
    }

    if (g_SubPropWindow != NULL)
        if (IsDialogMessage(g_SubPropWindow, &msg))
            return TRUE;

    if (g_PropWindow != NULL)
        if (IsDialogMessage(g_PropWindow, &msg))
            return TRUE;

    return FALSE;
}

/*
* WinObjInitGlobals
*
* Purpose:
*
* Initialize global variables.
*
*/
BOOL WinObjInitGlobals()
{
    SIZE_T cch;
    BOOL bResult = FALSE, bCond = FALSE;

    do {
        RtlSecureZeroMemory(&g_WinObj, sizeof(g_WinObj));

        //
        // Query version info.
        //
        g_WinObj.osver.dwOSVersionInfoSize = sizeof(g_WinObj.osver);
        RtlGetVersion(&g_WinObj.osver);

        //
        // Remember hInstance.
        //
        g_WinObj.hInstance = GetModuleHandle(NULL);

        //
        // Create dedicated heap.
        //
        g_WinObj.Heap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
        if (g_WinObj.Heap == NULL)
            break;

        RtlSetHeapInformation(g_WinObj.Heap, HeapEnableTerminationOnCorruption, NULL, 0);
        RtlInitializeCriticalSection(&g_WinObj.Lock);

        //
        // Remember %TEMP% directory.
        //
        cch = ExpandEnvironmentStrings(L"%temp%", g_WinObj.szTempDirectory, MAX_PATH);
        if ((cch == 0) || (cch > MAX_PATH))
            break;

        //
        // Remember Windows directory.
        //
        if (!GetWindowsDirectory(g_WinObj.szWindowsDirectory, MAX_PATH))
            break;

        //
        // Remember System32 directory.
        //
        if (!GetSystemDirectory(g_WinObj.szSystemDirectory, MAX_PATH))
            break;

        bResult = TRUE;

    } while (bCond);

    if (bResult == FALSE) {
        if (g_WinObj.Heap)
            RtlDestroyHeap(g_WinObj.Heap);
    }

    return bResult;
}

/*
* WinObjExMain
*
* Purpose:
*
* Actual program entry point.
*
*/
void WinObjExMain()
{
    MSG                     msg1;
    WNDCLASSEX              wincls;
    BOOL                    IsFullAdmin = FALSE, IsWine = FALSE, rv = TRUE, cond = FALSE;
    ATOM                    class_atom = 0;
    INITCOMMONCONTROLSEX    icc;   
    LVCOLUMN                col;
    SHSTOCKICONINFO         sii;
    HMENU                   hMenu;
    HACCEL                  hAccTable = 0;
    WCHAR                   szWindowTitle[100];
    HANDLE                  hIcon;
    HIMAGELIST              TreeViewImages;

    if (!WinObjInitGlobals())
        return;

    // do not move anywhere
    IsFullAdmin = supUserIsFullAdmin();

    // check compatibility
    IsWine = supIsWine();
    if (IsWine != FALSE) {
        IsFullAdmin = FALSE;
    }

    supInit(IsFullAdmin, IsWine);

    // do not move anywhere
    // g_kdctx variable initialized BEFORE this.
    // if you move these lines anywhere above they will be zeroed during kdInit
    g_kdctx.IsWine = IsWine;
    g_kdctx.IsFullAdmin = IsFullAdmin;

#ifdef _DEBUG
    TestStart();
#endif

    do {
        //
        // Create main window and it components.
        //
        wincls.cbSize = sizeof(WNDCLASSEX);
        wincls.style = 0;
        wincls.lpfnWndProc = &MainWindowProc;
        wincls.cbClsExtra = 0;
        wincls.cbWndExtra = 0;
        wincls.hInstance = g_WinObj.hInstance;
        wincls.hIcon = (HICON)LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDI_ICON_MAIN), IMAGE_ICON, 0, 0, LR_SHARED);
        wincls.hCursor = (HCURSOR)LoadImage(NULL, MAKEINTRESOURCE(OCR_SIZEWE), IMAGE_CURSOR, 0, 0, LR_SHARED);
        wincls.hbrBackground = NULL;
        wincls.lpszMenuName = MAKEINTRESOURCE(IDR_MENU1);
        wincls.lpszClassName = MAINWINDOWCLASSNAME;
        wincls.hIconSm = 0;

        class_atom = RegisterClassEx(&wincls);
        if (class_atom == 0)
            break;
        
        RtlSecureZeroMemory(szWindowTitle, sizeof(szWindowTitle));
        _strcpy(szWindowTitle, PROGRAM_NAME);
        if (IsFullAdmin != FALSE) {
            _strcat(szWindowTitle, L" (Administrator)");
        }

        if (IsWine != FALSE) {
            _strcat(szWindowTitle, L" (Wine emulation)");
        }

        MainWindow = CreateWindowEx(0, MAKEINTATOM(class_atom), szWindowTitle,
            WS_VISIBLE | WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600, NULL, NULL, g_WinObj.hInstance, NULL);
        if (MainWindow == NULL)
            break;

        icc.dwSize = sizeof(icc);
        icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES | ICC_BAR_CLASSES | ICC_TAB_CLASSES;
        if (!InitCommonControlsEx(&icc))
            break;

        hwndStatusBar = CreateWindowEx(0, STATUSCLASSNAME, NULL,
            WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, MainWindow, NULL, g_WinObj.hInstance, NULL);

        g_hwndObjectTree = CreateWindowEx(WS_EX_CLIENTEDGE, WC_TREEVIEW, NULL,
            WS_VISIBLE | WS_CHILD | WS_TABSTOP | TVS_DISABLEDRAGDROP | TVS_HASBUTTONS |
            TVS_HASLINES | TVS_LINESATROOT, 0, 0, 0, 0, MainWindow, (HMENU)1002, g_WinObj.hInstance, NULL);

        if (g_hwndObjectTree == NULL)
            break;

        g_hwndObjectList = CreateWindowEx(WS_EX_CLIENTEDGE, WC_LISTVIEW, NULL,
            WS_VISIBLE | WS_CHILD | WS_TABSTOP | LVS_AUTOARRANGE | LVS_REPORT |
            LVS_SHOWSELALWAYS | LVS_SINGLESEL | LVS_SHAREIMAGELISTS, 0, 0, 0, 0,
            MainWindow, (HMENU)1003, g_WinObj.hInstance, NULL);

        if (g_hwndObjectList == NULL)
            break;

        hwndToolBar = CreateWindowEx(0, TOOLBARCLASSNAME, NULL,
            WS_VISIBLE | WS_CHILD | CCS_TOP | TBSTYLE_FLAT | TBSTYLE_TRANSPARENT |
            TBSTYLE_TOOLTIPS, 0, 0, 0, 0, MainWindow, (HMENU)1004, g_WinObj.hInstance, NULL);

        if (hwndToolBar == NULL)
            break;

        hwndSplitter = CreateWindowEx(0, WC_STATIC, NULL,
            WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, MainWindow, (HMENU)1005, g_WinObj.hInstance, NULL);

        // initialization of views
        SendMessage(MainWindow, WM_SIZE, 0, 0);
        ListView_SetExtendedListViewStyle(g_hwndObjectList,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_LABELTIP | LVS_EX_DOUBLEBUFFER);

        // set tree imagelist
        TreeViewImages = supLoadImageList(g_WinObj.hInstance, IDI_ICON_VIEW_DEFAULT, IDI_ICON_VIEW_SELECTED);
        if (TreeViewImages) {
            TreeView_SetImageList(g_hwndObjectTree, TreeViewImages, TVSIL_NORMAL);
        }

        //not enough user rights, insert run as admin menu entry and hide admin only stuff
        if ((IsFullAdmin == FALSE) && (g_kdctx.IsWine == FALSE)) {
            hMenu = GetSubMenu(GetMenu(MainWindow), 0);
            InsertMenu(hMenu, 0, MF_BYPOSITION, ID_FILE_RUNASADMIN, T_RUNASADMIN);
            InsertMenu(hMenu, 1, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
            //set menu shield icon
            RtlSecureZeroMemory(&sii, sizeof(sii));
            sii.cbSize = sizeof(sii);
            if (SHGetStockIconInfo(SIID_SHIELD, SHGSI_ICON | SHGFI_SMALLICON, &sii) == S_OK) {
                supSetMenuIcon(hMenu, ID_FILE_RUNASADMIN, (ULONG_PTR)sii.hIcon);
            }
        }

        if (g_kdctx.hDevice == NULL) {
            //require driver usage, remove
            DeleteMenu(GetSubMenu(GetMenu(MainWindow), 4), ID_EXTRAS_SSDT, MF_BYCOMMAND);
            DeleteMenu(GetSubMenu(GetMenu(MainWindow), 4), ID_EXTRAS_PRIVATENAMESPACES, MF_BYCOMMAND);
        }

        //unsupported
        if (g_WinObj.osver.dwBuildNumber > 10240) {
            DeleteMenu(GetSubMenu(GetMenu(MainWindow), 4), ID_EXTRAS_PRIVATENAMESPACES, MF_BYCOMMAND);
        }

        //wine unsupported
        if (g_kdctx.IsWine != FALSE) {
            DeleteMenu(GetSubMenu(GetMenu(MainWindow), 4), ID_EXTRAS_DRIVERS, MF_BYCOMMAND);
        }

        //load listview images
        g_ListViewImages = supLoadImageList(g_WinObj.hInstance, IDI_ICON_DEVICE, IDI_ICON_UNKNOWN);
        if (g_ListViewImages) {
            hIcon = LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDI_ICON_SORTUP), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
            if (hIcon) {
                ImageList_ReplaceIcon(g_ListViewImages, -1, hIcon);
                DestroyIcon(hIcon);
            }
            hIcon = LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDI_ICON_SORTDOWN), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
            if (hIcon) {
                ImageList_ReplaceIcon(g_ListViewImages, -1, hIcon);
                DestroyIcon(hIcon);
            }
            ListView_SetImageList(g_hwndObjectList, g_ListViewImages, LVSIL_SMALL);
        }

        //load toolbar images
        g_ToolBarMenuImages = ImageList_LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDB_BITMAP1),
            16, 7, CLR_DEFAULT, IMAGE_BITMAP, LR_CREATEDIBSECTION);

        if (g_ToolBarMenuImages) {

            supCreateToolbarButtons(hwndToolBar);

            //set menu icons
            hMenu = GetSubMenu(GetMenu(MainWindow), 1);
            if (hMenu) {
                supSetMenuIcon(hMenu, ID_VIEW_REFRESH,
                    (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 1));
            }
            hMenu = GetSubMenu(GetMenu(MainWindow), 2);
            if (hMenu && g_ListViewImages) {
                supSetMenuIcon(hMenu, ID_OBJECT_PROPERTIES,
                    (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 0));
                supSetMenuIcon(hMenu, ID_OBJECT_GOTOLINKTARGET,
                    (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ListViewImages,
                        ID_FROM_VALUE(IDI_ICON_SYMLINK)));
            }

            //set object -> find object menu image
            hMenu = GetSubMenu(GetMenu(MainWindow), 3);
            if (hMenu) {
                supSetMenuIcon(hMenu, ID_FIND_FINDOBJECT,
                    (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 2));
            }

            //set extras-mailslots/pipes menu image
            hMenu = GetSubMenu(GetMenu(MainWindow), 4);
            if (hMenu) {
                supSetMenuIcon(hMenu, ID_EXTRAS_MAILSLOTS,
                    (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 5));
                supSetMenuIcon(hMenu, ID_EXTRAS_PIPES,
                    (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 6));
            }

            //set help menu image
            hMenu = GetSubMenu(GetMenu(MainWindow), 5);
            if (hMenu) {
                supSetMenuIcon(hMenu, ID_HELP_HELP,
                    (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 3));
            }

        }

        hAccTable = LoadAccelerators(g_WinObj.hInstance, MAKEINTRESOURCE(IDR_ACCELERATOR1));

        //create ObjectList columns
        RtlSecureZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
        col.iSubItem = 1;
        col.pszText = TEXT("Name");
        col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;
        col.iOrder = 0;
        col.iImage = -1;
        if (g_ListViewImages) {
            col.iImage = ImageList_GetImageCount(g_ListViewImages) - 1;
        }
        col.cx = 300;
        ListView_InsertColumn(g_hwndObjectList, 1, &col);

        col.iSubItem = 2;
        col.pszText = TEXT("Type");
        col.iOrder = 1;
        col.iImage = -1;
        col.cx = 100;
        ListView_InsertColumn(g_hwndObjectList, 2, &col);

        col.iSubItem = 3;
        col.pszText = TEXT("Additional Information");
        col.iOrder = 2;
        col.iImage = -1;
        col.cx = 170;
        ListView_InsertColumn(g_hwndObjectList, 3, &col);

        ListObjectDirectoryTree(L"\\", NULL, NULL);

        TreeView_SelectItem(g_hwndObjectTree, TreeView_GetRoot(g_hwndObjectTree));
        SetFocus(g_hwndObjectTree);

        do {
            rv = GetMessage(&msg1, NULL, 0, 0);

            if (rv == -1)
                break;

            if (MainDlgMsgHandler(msg1))
                continue;

            if (IsDialogMessage(MainWindow, &msg1)) {
                TranslateAccelerator(MainWindow, hAccTable, &msg1);
                continue;
            }

            TranslateMessage(&msg1);
            DispatchMessage(&msg1);
        } while (rv != 0);

    } while (cond);

    if (class_atom != 0)
        UnregisterClass(MAKEINTATOM(class_atom), g_WinObj.hInstance);

    //do not move anywhere

    supShutdown();

#ifdef _DEBUG
    TestStop();
#endif

}

/*
* main
*
* Purpose:
*
* Program entry point.
*
*/
void main()
{
    __security_init_cookie();
    WinObjExMain();
    ExitProcess(0);
}
