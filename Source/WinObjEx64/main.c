/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.80
*
*  DATE:        29 June 2019
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
#include "treelist/treelist.h"
#include "props/propDlg.h"
#include "extras/extras.h"
#include "tests/testunit.h"

pswprintf_s rtl_swprintf_s;
pqsort rtl_qsort;

static LONG	SplitterPos = 180;
static LONG	SortColumn = 0;
HTREEITEM	SelectedTreeItem = NULL;
BOOL        bMainWndSortInverse = FALSE;
HWND        hwndToolBar = NULL, hwndSplitter = NULL, hwndStatusBar = NULL, MainWindow = NULL;

//
// Global UI variables.
//

ATOM g_TreeListAtom;
HWND g_hwndObjectTree;
HWND g_hwndObjectList;
HIMAGELIST g_ListViewImages;
HIMAGELIST g_ToolBarMenuImages;

WINOBJ_GLOBALS g_WinObj;

/*
* MainWindowExtrasDisableAdminFeatures
*
* Purpose:
*
* Disable menu items require admin privileges.
*
*/
VOID MainWindowExtrasDisableAdminFeatures(
    _In_ HWND hWnd
)
{
    HMENU hExtrasSubMenu = GetSubMenu(GetMenu(hWnd), 4);

    MENUITEMINFO mii;

    mii.cbSize = sizeof(mii);
    mii.fMask = MIIM_STATE;
    mii.fState = MFS_DISABLED;

    //
    // These features require driver usage.
    //
    if (g_kdctx.hDevice == NULL) {
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_SSDT, FALSE, &mii);
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_PRIVATENAMESPACES, FALSE, &mii);
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_W32PSERVICETABLE, FALSE, &mii);
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_CALLBACKS, FALSE, &mii);
    }

    //
    // This feature is not supported in Windows 10 10586.
    //
    if (g_NtBuildNumber == 10586) {
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_PRIVATENAMESPACES, FALSE, &mii);
    }

    //
    // This feature is only supported starting from Windows 10 14393 (RS1).
    //
    if (g_NtBuildNumber < 14393) {
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_W32PSERVICETABLE, FALSE, &mii);
    }

    //
    // This feature is not unsupported in Wine.
    //
    if (g_WinObj.IsWine) {
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_DRIVERS, FALSE, &mii);
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_SOFTWARELICENSECACHE, FALSE, &mii);
    }
}

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

        propCreateDialog(
            hwnd,
            szBuffer,
            OBTYPE_NAME_DIRECTORY,
            NULL,
            NULL,
            NULL);
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

            propCreateDialog(
                hwnd,
                lpItemText,
                lpType,
                lpDesc,
                NULL,
                NULL);

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

    ObCollectionDestroy(&g_kdctx.ObCollection);

    supFreeSCMSnapshot(NULL);
    sapiFreeSnapshot();

    supCreateSCMSnapshot(SERVICE_DRIVER, NULL);
    sapiCreateSetupDBSnapshot();

    len = _strlen(g_WinObj.CurrentObjectPath);
    CurrentPath = (LPWSTR)supHeapAlloc((len + 1) * sizeof(WCHAR));
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
    WORD    ControlId = LOWORD(wParam);

    UNREFERENCED_PARAMETER(lParam);

    switch (ControlId) {

    case ID_FILE_RUNASADMIN:
        if (g_kdctx.IsFullAdmin) {
            supRunAsLocalSystem(hwnd);
        }
        else {
            supRunAsAdmin();
        }
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

    case ID_EXTRAS_PIPES:
    case ID_EXTRAS_MAILSLOTS:
    case ID_EXTRAS_USERSHAREDDATA:
    case ID_EXTRAS_PRIVATENAMESPACES:       
    case ID_EXTRAS_SSDT:
    case ID_EXTRAS_W32PSERVICETABLE:
    case ID_EXTRAS_DRIVERS:
    case ID_EXTRAS_PROCESSLIST:
    case ID_EXTRAS_CALLBACKS:
    case ID_EXTRAS_SOFTWARELICENSECACHE:
        //
        // Extras -> Pipes
        //           Mailslots
        //           UserSharedData
        //           Private Namespaces
        //           KiServiceTable
        //           W32pServiceTable
        //           Drivers
        //           Process List
        //           Callbacks
        //           Software Licensing Cache
        //
        extrasShowDialogById(hwnd, ControlId);
        break;

    case ID_HELP_ABOUT:

        DialogBoxParam(
            g_WinObj.hInstance,
            MAKEINTRESOURCE(IDD_DIALOG_ABOUT),
            hwnd,
            (DLGPROC)&AboutDialogProc,
            0);

        break;

    case ID_HELP_HELP:
        supShowHelp(hwnd);
        break;

    default:
        break;
    }

    if ((ControlId >= ID_MENU_PLUGINS) && (ControlId < WINOBJEX_MAX_PLUGINS)) {
        PluginManagerProcessEntry(hwnd, ControlId);
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

        list = (POE_LIST_ITEM)supHeapAlloc(sizeof(OE_LIST_ITEM));
        if (list) {
            list->Prev = prevlist;
            list->TreeItem = hitem;
        }
        prevlist = list;
    }

    if (list == NULL) {
        g_WinObj.CurrentObjectPath = (LPWSTR)supHeapAlloc(2 * sizeof(WCHAR));
        if (g_WinObj.CurrentObjectPath) {
            g_WinObj.CurrentObjectPath[0] = L'\\';
            g_WinObj.CurrentObjectPath[1] = 0;
        }
        return;
    }

    list = prevlist;
    g_WinObj.CurrentObjectPath = (LPWSTR)supHeapAlloc(p * sizeof(WCHAR));
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
* MainWindowHandleTreePopupMenu
*
* Purpose:
*
* Object Tree popup menu builder.
*
*/
VOID MainWindowHandleTreePopupMenu(
    _In_ HWND hwnd,
    _In_ LPPOINT point
)
{
    HMENU hMenu;

    hMenu = CreatePopupMenu();
    if (hMenu) {
        InsertMenu(hMenu, 0, MF_BYCOMMAND, ID_OBJECT_PROPERTIES, T_PROPERTIES);

        supSetMenuIcon(hMenu, ID_OBJECT_PROPERTIES,
            (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 0));

        TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, point->x, point->y, 0, hwnd, NULL);
        DestroyMenu(hMenu);
    }
}

/*
* MainWindowHandleObjectPopupMenu
*
* Purpose:
*
* Object List popup menu builder.
*
*/
VOID MainWindowHandleObjectPopupMenu(
    _In_ HWND hwnd,
    _In_ HWND hwndlv,
    _In_ INT iItem,
    _In_ LPPOINT point
)
{
    HMENU hMenu;
    UINT  uEnable = MF_BYCOMMAND | MF_GRAYED;

    hMenu = CreatePopupMenu();
    if (hMenu == NULL) return;

    InsertMenu(hMenu, 0, MF_BYCOMMAND, ID_OBJECT_PROPERTIES, T_PROPERTIES);

    supSetMenuIcon(hMenu, ID_OBJECT_PROPERTIES,
        (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 0));

    if (supIsSymlink(hwndlv, iItem)) {
        InsertMenu(hMenu, 1, MF_BYCOMMAND, ID_OBJECT_GOTOLINKTARGET, T_GOTOLINKTARGET);
        supSetMenuIcon(hMenu, ID_OBJECT_GOTOLINKTARGET,
            (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ListViewImages,
                ObManagerGetImageIndexByTypeName(OBTYPE_NAME_SYMBOLIC_LINK)));
        uEnable &= ~MF_GRAYED;
    }
    EnableMenuItem(GetSubMenu(GetMenu(hwnd), 2), ID_OBJECT_GOTOLINKTARGET, uEnable);

    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, point->x, point->y, 0, hwnd, NULL);
    DestroyMenu(hMenu);
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
    INT             nImageIndex;
    LPNMHDR         hdr = (LPNMHDR)lParam;
    LPTOOLTIPTEXT   lpttt;
    LPNMLISTVIEW    lvn;
    LPNMTREEVIEW    lpnmTreeView;
    LPWSTR          str;
    SIZE_T          lcp;
    LVITEM          lvitem;
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

                supSetGotoLinkTargetToolButtonState(hwnd, 0, 0, TRUE, FALSE);

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
                    supSetGotoLinkTargetToolButtonState(hwnd, 0, 0, TRUE, FALSE);
                    MainWindowHandleTreePopupMenu(hwnd, &pt);
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
                    str = (LPWSTR)supHeapAlloc((lcp + sizeof(item_string) + 4) * sizeof(WCHAR));
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
                    supSetGotoLinkTargetToolButtonState(hwnd, g_hwndObjectList, lvn->iItem, FALSE, FALSE);
                }
                break;

                //handle sort by column
            case LVN_COLUMNCLICK:
                bMainWndSortInverse = !bMainWndSortInverse;
                SortColumn = ((NMLISTVIEW *)lParam)->iSubItem;
                ListView_SortItemsEx(g_hwndObjectList, &MainWindowObjectListCompareFunc, SortColumn);

                nImageIndex = ImageList_GetImageCount(g_ListViewImages);
                if (bMainWndSortInverse)
                    nImageIndex -= 2; //sort down/up images are always at the end of g_ListViewImages
                else
                    nImageIndex -= 1;

                supUpdateLvColumnHeaderImage(
                    g_hwndObjectList,
                    3,
                    SortColumn,
                    nImageIndex);

                break;

            case NM_DBLCLK:
                MainWindowHandleObjectListProp(hwnd);
                break;

            default:
                break;
            }
        }

        //handle tooltip
#pragma warning(push)
#pragma warning(disable: 26454)
        if (hdr->code == TTN_GETDISPINFO) {
#pragma warning(pop)
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
            MainWindowHandleTreePopupMenu(hwnd, (LPPOINT)&crc);
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

            MainWindowHandleObjectPopupMenu(hwnd, g_hwndObjectList, mark, (LPPOINT)&crc);
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
* MainWindowDlgMsgHandler
*
* Purpose:
*
* Check window message against existing dialogs.
*
*/
BOOL MainWindowDlgMsgHandler(
    _In_ MSG msg,
    _In_ HACCEL hAccTable
)
{
    UINT c;

    for (c = 0; c < wobjMaxDlgId; c++) {
        if ((g_WinObj.AuxDialogs[c] != NULL)) {
            if (IsDialogMessage(g_WinObj.AuxDialogs[c], &msg)) {
                TranslateAccelerator(g_WinObj.AuxDialogs[c], hAccTable, &msg);
                return TRUE;
            }
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
BOOL WinObjInitGlobals(
    _In_ BOOLEAN IsWine)
{
    SIZE_T cch;
    BOOL bResult = FALSE;
    LPWSTR *szArglist;
    INT nArgs = 0;


    do {
        RtlSecureZeroMemory(&g_WinObj, sizeof(g_WinObj));

        g_WinObj.IsWine = IsWine;

        //
        // Query version info.
        //
        g_WinObj.osver.dwOSVersionInfoSize = sizeof(g_WinObj.osver);
        RtlGetVersion(&g_WinObj.osver);

        g_NtBuildNumber = g_WinObj.osver.dwBuildNumber;

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

        if (IsWine == FALSE) {
            RtlSetHeapInformation(g_WinObj.Heap, HeapEnableTerminationOnCorruption, NULL, 0);
        }
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

        //
        // Check command line parameters.
        //
        szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
        if (szArglist) {
            if (nArgs > 1) {
                g_WinObj.EnableExperimentalFeatures = (_strcmpi(szArglist[1], L"-exp") == 0);
            }
            LocalFree(szArglist);
        }

        bResult = TRUE;

    } while (FALSE);

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
UINT WinObjExMain()
{
    BOOLEAN                 IsWine = FALSE;
    MSG                     msg1;
    WNDCLASSEX              wincls;
    BOOL                    IsFullAdmin = FALSE, rv = TRUE, bLocalSystem = FALSE;
    ATOM                    class_atom = 0;
    INITCOMMONCONTROLSEX    icc;
    LVCOLUMN                col;
    SHSTOCKICONINFO         sii;
    HMENU                   hMenu;
    HACCEL                  hAccTable = 0;
    WCHAR                   szWindowTitle[100];
    HICON                   hIcon;
    HANDLE                  hToken;
    HIMAGELIST              TreeViewImages;

    IsWine = supIsWine();

    if (!supInitNtdllCRT(IsWine)) {
        MessageBox(GetDesktopWindow(), TEXT("Could not initialize CRT"), NULL, MB_ICONERROR);
        return ERROR_APP_INIT_FAILURE;
    }

    //
    // wine 1.6 xenial does not suport this routine.
    //
    if (IsWine == FALSE) {
        RtlSetHeapInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0);
    }

    if (!WinObjInitGlobals(IsWine))
        return ERROR_APP_INIT_FAILURE;

    // do not move anywhere
    IsFullAdmin = supUserIsFullAdmin();

    // check compatibility
    if (IsWine != FALSE) {
        IsFullAdmin = FALSE;
    }

    supInit(IsFullAdmin);

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

        wincls.hIcon = (HICON)LoadImage(
            g_WinObj.hInstance,
            MAKEINTRESOURCE(IDI_ICON_MAIN),
            IMAGE_ICON,
            0,
            0,
            LR_SHARED);

        wincls.hCursor = (HCURSOR)LoadImage(
            NULL,
            MAKEINTRESOURCE(OCR_SIZEWE),
            IMAGE_CURSOR,
            0,
            0,
            LR_SHARED);

        wincls.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
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

        //
        // Create main window.
        //
        MainWindow = CreateWindowEx(
            0,
            MAKEINTATOM(class_atom),
            szWindowTitle,
            WS_VISIBLE | WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            800,
            600,
            NULL,
            NULL,
            g_WinObj.hInstance,
            NULL);

        if (MainWindow == NULL)
            break;

        icc.dwSize = sizeof(icc);
        icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES | ICC_BAR_CLASSES | ICC_TAB_CLASSES;
        if (!InitCommonControlsEx(&icc))
            break;

        //
        // Status Bar window.
        //
        hwndStatusBar = CreateWindowEx(
            0,
            STATUSCLASSNAME,
            NULL,
            WS_VISIBLE | WS_CHILD,
            0,
            0,
            0,
            0,
            MainWindow,
            NULL,
            g_WinObj.hInstance,
            NULL);

        //
        // TreeView window.
        //
        g_hwndObjectTree = CreateWindowEx(
            WS_EX_CLIENTEDGE,
            WC_TREEVIEW,
            NULL,
            WS_VISIBLE | WS_CHILD | WS_TABSTOP |
            TVS_DISABLEDRAGDROP | TVS_HASBUTTONS | TVS_HASLINES | TVS_LINESATROOT,
            0,
            0,
            0,
            0,
            MainWindow,
            (HMENU)1002,
            g_WinObj.hInstance,
            NULL);

        if (g_hwndObjectTree == NULL)
            break;

        //
        // ListView window.
        //
        g_hwndObjectList = CreateWindowEx(
            WS_EX_CLIENTEDGE,
            WC_LISTVIEW,
            NULL,
            WS_VISIBLE | WS_CHILD | WS_TABSTOP |
            LVS_AUTOARRANGE | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL | LVS_SHAREIMAGELISTS,
            0,
            0,
            0,
            0,
            MainWindow,
            (HMENU)1003,
            g_WinObj.hInstance,
            NULL);

        if (g_hwndObjectList == NULL)
            break;

        //
        // Toolbar window.
        //
        hwndToolBar = CreateWindowEx(
            0,
            TOOLBARCLASSNAME,
            NULL,
            WS_VISIBLE | WS_CHILD | CCS_TOP |
            TBSTYLE_FLAT | TBSTYLE_TRANSPARENT | TBSTYLE_TOOLTIPS,
            0,
            0,
            0,
            0,
            MainWindow,
            (HMENU)1004,
            g_WinObj.hInstance,
            NULL);

        if (hwndToolBar == NULL)
            break;

        //
        // Spliter window.
        //
        hwndSplitter = CreateWindowEx(
            0,
            WC_STATIC,
            NULL,
            WS_VISIBLE | WS_CHILD,
            0,
            0,
            0,
            0,
            MainWindow,
            (HMENU)1005,
            g_WinObj.hInstance,
            NULL);

        //
        // Register treelist control class.
        //
        g_TreeListAtom = InitializeTreeListControl();

        //
        // Initialization of views.
        //
        SendMessage(MainWindow, WM_SIZE, 0, 0);
        ListView_SetExtendedListViewStyle(g_hwndObjectList,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_LABELTIP | LVS_EX_DOUBLEBUFFER);

        //
        // Apply Window theme.
        //
        SetWindowTheme(g_hwndObjectList, TEXT("Explorer"), NULL);
        SetWindowTheme(g_hwndObjectTree, TEXT("Explorer"), NULL);

        // set tree imagelist
        TreeViewImages = supLoadImageList(g_WinObj.hInstance, IDI_ICON_VIEW_DEFAULT, IDI_ICON_VIEW_SELECTED);
        if (TreeViewImages) {
            TreeView_SetImageList(g_hwndObjectTree, TreeViewImages, TVSIL_NORMAL);
        }

        //
        // Insert run as admin/local system menu entry if not under Wine.
        //
        if (g_WinObj.IsWine == FALSE) {
            //
            // We are running as user, add menu item to request elevation.
            //
            if (IsFullAdmin == FALSE) {
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
            else {
                //
                // We are running with admin privileges, determine if we need to 
                // insert run as LocalSystem menu entry.
                //
                hToken = supGetCurrentProcessToken();
                if (hToken) {
                    if (NT_SUCCESS(supIsLocalSystem(hToken, &bLocalSystem))) {
                        if (bLocalSystem == FALSE) {
                            //
                            // Not LocalSystem account, insert item.
                            //
                            hMenu = GetSubMenu(GetMenu(MainWindow), 0);
                            InsertMenu(hMenu, 0, MF_BYPOSITION, ID_FILE_RUNASADMIN, T_RUNASSYSTEM);
                            InsertMenu(hMenu, 1, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
                            RtlSecureZeroMemory(&sii, sizeof(sii));
                            sii.cbSize = sizeof(sii);
                            if (SHGetStockIconInfo(SIID_DESKTOPPC, SHGSI_ICON | SHGFI_SMALLICON, &sii) == S_OK) {
                                supSetMenuIcon(hMenu, ID_FILE_RUNASADMIN, (ULONG_PTR)sii.hIcon);
                            }
                        }
                        else {
                            //
                            // LocalSystem account, update window title.
                            //
                            RtlSecureZeroMemory(szWindowTitle, sizeof(szWindowTitle));
                            _strcpy(szWindowTitle, PROGRAM_NAME);
                            _strcat(szWindowTitle, TEXT(" (LocalSystem)"));
                            SetWindowText(MainWindow, szWindowTitle);
                        }
                    }
                    NtClose(hToken);
                }
            }
        }

        //
        // Hide admin only stuff.
        //

        MainWindowExtrasDisableAdminFeatures(MainWindow);

        //
        // Load listview images for object types.
        //
        g_ListViewImages = ObManagerLoadImageList();
        if (g_ListViewImages) {
            //
            // Append two column sorting images to the end of the listview imagelist.
            //
            hIcon = (HICON)LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDI_ICON_SORTUP), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
            if (hIcon) {
                ImageList_ReplaceIcon(g_ListViewImages, -1, hIcon);
                DestroyIcon(hIcon);
            }
            hIcon = (HICON)LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDI_ICON_SORTDOWN), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
            if (hIcon) {
                ImageList_ReplaceIcon(g_ListViewImages, -1, hIcon);
                DestroyIcon(hIcon);
            }
            ListView_SetImageList(g_hwndObjectList, g_ListViewImages, LVSIL_SMALL);
        }

        //
        // Load toolbar images.
        //
        g_ToolBarMenuImages = ImageList_LoadImage(
            g_WinObj.hInstance,
            MAKEINTRESOURCE(IDB_BITMAP1),
            16,
            7,
            CLR_DEFAULT,
            IMAGE_BITMAP,
            LR_CREATEDIBSECTION);

        if (g_ToolBarMenuImages) {
            supCreateToolbarButtons(hwndToolBar);
        }

        //set menu icons
        hMenu = GetSubMenu(GetMenu(MainWindow), 1);
        if (hMenu && g_ToolBarMenuImages) {
            supSetMenuIcon(hMenu, ID_VIEW_REFRESH,
                (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 1));
        }
        hMenu = GetSubMenu(GetMenu(MainWindow), 2);
        if (hMenu && g_ListViewImages) {
            supSetMenuIcon(hMenu, ID_OBJECT_PROPERTIES,
                (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 0));
            supSetMenuIcon(hMenu, ID_OBJECT_GOTOLINKTARGET,
                (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ListViewImages,
                    ObManagerGetImageIndexByTypeName(OBTYPE_NAME_SYMBOLIC_LINK)));
        }

        //set object -> find object menu image
        hMenu = GetSubMenu(GetMenu(MainWindow), 3);
        if (hMenu && g_ToolBarMenuImages) {
            supSetMenuIcon(hMenu, ID_FIND_FINDOBJECT,
                (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 2));
        }

        //set extras -> menu images
        hMenu = GetSubMenu(GetMenu(MainWindow), 4);
        if (hMenu && g_ToolBarMenuImages) {
            // pipes & mailslots
            supSetMenuIcon(hMenu, ID_EXTRAS_MAILSLOTS,
                (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 5));
            supSetMenuIcon(hMenu, ID_EXTRAS_PIPES,
                (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 6));

            // process list menu image
            RtlSecureZeroMemory(&sii, sizeof(sii));
            sii.cbSize = sizeof(sii);
            if (SHGetStockIconInfo(SIID_APPLICATION, SHGSI_ICON | SHGFI_SMALLICON, &sii) == S_OK) {
                supSetMenuIcon(hMenu, ID_EXTRAS_PROCESSLIST, (ULONG_PTR)sii.hIcon);
            }

            // private namespaces menu image
            if (SHGetStockIconInfo(SIID_STACK, SHGSI_ICON | SHGFI_SMALLICON, &sii) == S_OK) {
                supSetMenuIcon(hMenu, ID_EXTRAS_PRIVATENAMESPACES, (ULONG_PTR)sii.hIcon);
            }
        }

        //set help menu image
        hMenu = GetSubMenu(GetMenu(MainWindow), 5);
        if (hMenu) {
            RtlSecureZeroMemory(&sii, sizeof(sii));
            sii.cbSize = sizeof(sii);
            if (SHGetStockIconInfo(SIID_HELP, SHGSI_ICON | SHGFI_SMALLICON, &sii) == S_OK) {
                supSetMenuIcon(hMenu, ID_HELP_HELP, (ULONG_PTR)sii.hIcon);
            }
        }

        hAccTable = LoadAccelerators(g_WinObj.hInstance, MAKEINTRESOURCE(IDR_ACCELERATOR1));

        PluginManagerCreate(MainWindow);

        //create ObjectList columns
        RtlSecureZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
        col.iSubItem = 1;
        col.pszText = TEXT("Name");
        col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;
        col.iOrder = 0;
        if (g_ListViewImages) {
            col.iImage = ImageList_GetImageCount(g_ListViewImages) - 1;
        }
        else {
            col.iImage = I_IMAGENONE;
        }
        col.cx = 300;
        ListView_InsertColumn(g_hwndObjectList, 1, &col);

        col.iImage = I_IMAGENONE;

        col.iSubItem = 2;
        col.pszText = TEXT("Type");
        col.iOrder = 1;
        col.cx = 100;
        ListView_InsertColumn(g_hwndObjectList, 2, &col);

        col.iSubItem = 3;
        col.pszText = TEXT("Additional Information");
        col.iOrder = 2;
        col.cx = 170;
        ListView_InsertColumn(g_hwndObjectList, 3, &col);

        ListObjectDirectoryTree(L"\\", NULL, NULL);

        TreeView_SelectItem(g_hwndObjectTree, TreeView_GetRoot(g_hwndObjectTree));
        SetFocus(g_hwndObjectTree);

        do {
            rv = GetMessage(&msg1, NULL, 0, 0);

            if (rv == -1)
                break;

            if (MainWindowDlgMsgHandler(msg1, hAccTable))
                continue;

            if (IsDialogMessage(MainWindow, &msg1)) {
                TranslateAccelerator(MainWindow, hAccTable, &msg1);
                continue;
            }

            TranslateMessage(&msg1);
            DispatchMessage(&msg1);
        } while (rv != 0);

    } while (FALSE);

    if (class_atom != 0)
        UnregisterClass(MAKEINTATOM(class_atom), g_WinObj.hInstance);

    if (g_TreeListAtom != 0)
        UnregisterClass(MAKEINTATOM(g_TreeListAtom), g_WinObj.hInstance);

    PluginManagerDestroy();

    //do not move anywhere

    supShutdown();

#ifdef _DEBUG
    TestStop();
#endif

    return ERROR_SUCCESS;
}

/*
* WinMain/main
*
* Purpose:
*
* Program entry point.
*
*/
#if !defined(__cplusplus)
#pragma comment(linker, "/ENTRY:main")
void main()
{
    __security_init_cookie();
    ExitProcess(WinObjExMain());
}
#else
#pragma comment(linker, "/ENTRY:WinMain")
int CALLBACK WinMain(
    _In_ HINSTANCE hInstance,
    _In_ HINSTANCE hPrevInstance,
    _In_ LPSTR     lpCmdLine,
    _In_ int       nCmdShow
)
{
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    ExitProcess(WinObjExMain());
}
#endif