/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.87
*
*  DATE:        28 June 2020
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
HTREEITEM	g_SelectedTreeItem = NULL;
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
    HMENU hExtrasSubMenu = GetSubMenu(GetMenu(hWnd), IDMM_EXTRAS);

    MENUITEMINFO mii;

    mii.cbSize = sizeof(mii);
    mii.fMask = MIIM_STATE;
    mii.fState = MFS_DISABLED;

    //
    // These features require driver usage.
    //
    if (g_kdctx.DeviceHandle == NULL) {
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_SSDT, FALSE, &mii);
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_PRIVATENAMESPACES, FALSE, &mii);
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_W32PSERVICETABLE, FALSE, &mii);
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_CALLBACKS, FALSE, &mii);
    }

    //
    // This feature is not supported in Windows 10 10586.
    //
    if (g_NtBuildNumber == NT_WIN10_THRESHOLD2) {
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_PRIVATENAMESPACES, FALSE, &mii);
    }

    //
    // This feature is only supported starting from Windows 10 14393 (RS1).
    //
    if (g_NtBuildNumber < NT_WIN10_REDSTONE1) {
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_W32PSERVICETABLE, FALSE, &mii);
    }

    //
    // These features are not unsupported in Wine.
    //
    if (g_WinObj.IsWine) {
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_CALLBACKS, FALSE, &mii);
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_DRIVERS, FALSE, &mii);
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_SOFTWARELICENSECACHE, FALSE, &mii);
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_SSDT, FALSE, &mii);
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_W32PSERVICETABLE, FALSE, &mii);
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
    return supListViewBaseComparer(g_hwndObjectList,
        bMainWndSortInverse,
        lParam1,
        lParam2,
        lParamSort);
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
    WCHAR szBuffer[MAX_PATH + 1];
    PROP_DIALOG_CREATE_SETTINGS propSettings;

    //
    // Only one object properties dialog at the same time allowed.
    //
    ENSURE_DIALOG_UNIQUE(g_PropWindow);

    if (g_SelectedTreeItem == NULL)
        return;

    RtlSecureZeroMemory(&tvi, sizeof(TV_ITEM));

    szBuffer[0] = 0;
    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
    tvi.pszText = szBuffer;
    tvi.cchTextMax = MAX_PATH;
    tvi.mask = TVIF_TEXT;
    tvi.hItem = g_SelectedTreeItem;
    if (TreeView_GetItem(g_hwndObjectTree, &tvi)) {

        RtlSecureZeroMemory(&propSettings, sizeof(propSettings));
        propSettings.hwndParent = hwnd;
        propSettings.lpObjectName = szBuffer;
        propSettings.lpObjectType = OBTYPE_NAME_DIRECTORY;

        propCreateDialog(&propSettings);
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

    PROP_DIALOG_CREATE_SETTINGS propSettings;

    //
    // Only one object properties dialog allowed at same time.
    //
    if (g_PropWindow != NULL)
        return;

    //
    // Query selection, leave on failure.
    //
    if (ListView_GetSelectedCount(g_hwndObjectList) == 0)
        return;

    //
    // Query selected index, leave on failure.
    //
    nSelected = ListView_GetSelectionMark(g_hwndObjectList);
    if (nSelected == -1)
        return;

    lpItemText = supGetItemText(g_hwndObjectList, nSelected, 0, NULL);
    if (lpItemText) {
        lpType = supGetItemText(g_hwndObjectList, nSelected, 1, NULL);
        if (lpType) {

            //lpDesc is not important, we can work if it NULL
            lpDesc = supGetItemText(g_hwndObjectList, nSelected, 2, NULL);

            RtlSecureZeroMemory(&propSettings, sizeof(propSettings));

            propSettings.hwndParent = hwnd;
            propSettings.lpObjectName = lpItemText;
            propSettings.lpObjectType = lpType;
            propSettings.lpDescription = lpDesc;

            propCreateDialog(&propSettings);

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
    VOID
)
{
    LPWSTR CurrentPath = NULL;
    SIZE_T len;

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
    _In_ WPARAM wParam
)
{
    LPWSTR lpItemText;
    HWND   hwndFocus;
    DWORD  lvExStyle;
    WORD   ControlId = LOWORD(wParam);

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

    case ID_FILE_VIEW_PLUGINS:
        PmViewPlugins(hwnd);
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
        lpItemText = supGetItemText(g_hwndObjectList,
            ListView_GetSelectionMark(g_hwndObjectList), 2, NULL);

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
            lpItemText = supGetItemText(g_hwndObjectList,
                ListView_GetSelectionMark(g_hwndObjectList), 0, NULL);

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
        MainWindowOnRefresh();
        break;

    case ID_VIEW_DISPLAYGRID:
        g_WinObj.ListViewDisplayGrid = !g_WinObj.ListViewDisplayGrid;
        lvExStyle = ListView_GetExtendedListViewStyle(g_hwndObjectList);
        if (g_WinObj.ListViewDisplayGrid)
            lvExStyle |= LVS_EX_GRIDLINES;
        else
            lvExStyle &= ~LVS_EX_GRIDLINES;

        ListView_SetExtendedListViewStyle(g_hwndObjectList, lvExStyle);

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

    case ID_HELP_SHOWLOG:
        LogViewerShowDialog(hwnd);
        break;

    default:
        break;
    }

    if ((ControlId >= ID_MENU_PLUGINS) && (ControlId < ID_MENU_PLUGINS_MAX)) {
        PmProcessEntry(GetFocus(), ControlId);
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
    HTREEITEM       treeItem, treeRoot;
    TVITEMEX        tvexItem;
    POE_LIST_ITEM   objectListItem = NULL, prevObjectListItem = NULL;
    SIZE_T          objectPathLength = 1; // size of empty string buffer in characters
    WCHAR           szTreeItemText[MAX_PATH + 1];

    if (trhdr == NULL)
        return;

    if (!trhdr->itemNew.hItem)
        return;

    if (g_WinObj.CurrentObjectPath != NULL)
        supHeapFree(g_WinObj.CurrentObjectPath);

    RtlSecureZeroMemory(&tvexItem, sizeof(tvexItem));

    treeRoot = TreeView_GetRoot(trhdr->hdr.hwndFrom);

    //
    // Build the path from bottom to top and counting string buffer size.
    //
    for (treeItem = trhdr->itemNew.hItem; treeItem != treeRoot;
        treeItem = TreeView_GetParent(trhdr->hdr.hwndFrom, treeItem))
    {
        RtlSecureZeroMemory(&szTreeItemText, sizeof(szTreeItemText));
        tvexItem.mask = TVIF_HANDLE | TVIF_TEXT;
        tvexItem.hItem = treeItem;
        tvexItem.pszText = szTreeItemText;
        tvexItem.cchTextMax = MAX_PATH;
        TreeView_GetItem(trhdr->hdr.hwndFrom, &tvexItem);

        objectPathLength += _strlen(szTreeItemText) + 1; //+1 for '\'

        objectListItem = (POE_LIST_ITEM)supHeapAlloc(sizeof(OE_LIST_ITEM));
        if (objectListItem) {
            objectListItem->Prev = prevObjectListItem;
            objectListItem->TreeItem = treeItem;
        }
        prevObjectListItem = objectListItem;
    }

    if (objectListItem == NULL) {
        g_WinObj.CurrentObjectPath = (LPWSTR)supHeapAlloc(2 * sizeof(WCHAR));
        if (g_WinObj.CurrentObjectPath) {
            g_WinObj.CurrentObjectPath[0] = L'\\';
            g_WinObj.CurrentObjectPath[1] = 0;
        }
        return;
    }

    objectListItem = prevObjectListItem;
    g_WinObj.CurrentObjectPath = (LPWSTR)supHeapAlloc(objectPathLength * sizeof(WCHAR));
    if (g_WinObj.CurrentObjectPath) {

        objectPathLength = 0;

        //
        // Building the final string.
        //
        while (objectListItem != NULL) {

            RtlSecureZeroMemory(&szTreeItemText, sizeof(szTreeItemText));
            tvexItem.mask = TVIF_HANDLE | TVIF_TEXT;
            tvexItem.hItem = objectListItem->TreeItem;
            tvexItem.pszText = szTreeItemText;
            tvexItem.cchTextMax = MAX_PATH;
            TreeView_GetItem(trhdr->hdr.hwndFrom, &tvexItem);

            g_WinObj.CurrentObjectPath[objectPathLength] = L'\\';
            objectPathLength++;
            _strcpy(g_WinObj.CurrentObjectPath + objectPathLength, szTreeItemText);
            objectPathLength += _strlen(szTreeItemText);

            prevObjectListItem = objectListItem->Prev;
            supHeapFree(objectListItem);
            objectListItem = prevObjectListItem;
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

        PmBuildPluginPopupMenuByObjectType(hMenu, ObjectTypeDirectory);

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
    HMENU   hMenu;
    UINT    uEnable = MF_BYCOMMAND | MF_GRAYED;
    LVITEM  lvItem;

    hMenu = CreatePopupMenu();
    if (hMenu == NULL) return;

    InsertMenu(hMenu, 0, MF_BYCOMMAND, ID_OBJECT_PROPERTIES, T_PROPERTIES);

    supSetMenuIcon(hMenu, ID_OBJECT_PROPERTIES,
        (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 0));

    if (supIsSymbolicLinkObject(hwndlv, iItem)) {

        InsertMenu(hMenu, 1, MF_BYCOMMAND, ID_OBJECT_GOTOLINKTARGET, T_GOTOLINKTARGET);

        supSetMenuIcon(hMenu, ID_OBJECT_GOTOLINKTARGET,
            (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance,
                g_ListViewImages,
                g_TypeSymbolicLink.ImageIndex));

        uEnable = MF_BYCOMMAND;
    }
    EnableMenuItem(GetSubMenu(GetMenu(hwnd), IDMM_OBJECT), ID_OBJECT_GOTOLINKTARGET, uEnable);

    lvItem.mask = LVIF_PARAM;
    lvItem.iItem = iItem;
    lvItem.iSubItem = 0;
    lvItem.lParam = 0;

    if (ListView_GetItem(hwndlv, &lvItem)) {
        PmBuildPluginPopupMenuByObjectType(
            hMenu,
            (UCHAR)lvItem.lParam);
    }

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
    WCHAR           szItemString[MAX_PATH + 1];

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
                    g_SelectedTreeItem = lpnmTreeView->itemNew.hItem;
                }
                break;

            case NM_RCLICK:
                GetCursorPos(&pt);
                hti.pt = pt;
                ScreenToClient(hdr->hwndFrom, &hti.pt);
                if (TreeView_HitTest(hdr->hwndFrom, &hti) &&
                    (hti.flags & (TVHT_ONITEM | TVHT_ONITEMRIGHT))) {
                    g_SelectedTreeItem = hti.hItem;
                    TreeView_SelectItem(g_hwndObjectTree, g_SelectedTreeItem);
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
                RtlSecureZeroMemory(&szItemString, sizeof(szItemString));
                ListView_GetItemText(g_hwndObjectList, lvn->iItem, 0, szItemString, MAX_PATH);
                lcp = _strlen(g_WinObj.CurrentObjectPath);
                if (lcp) {
                    str = (LPWSTR)supHeapAlloc((lcp + sizeof(szItemString) + 4) * sizeof(WCHAR));
                    if (str == NULL)
                        break;
                    _strcpy(str, g_WinObj.CurrentObjectPath);

                    if ((str[0] == '\\') && (str[1] == 0)) {
                        _strcpy(str + lcp, szItemString);
                    }
                    else {
                        str[lcp] = '\\';
                        _strcpy(str + lcp + 1, szItemString);
                    }
                    SendMessage(hwndStatusBar, WM_SETTEXT, 0, (LPARAM)str);
                    supHeapFree(str);
                    supSetGotoLinkTargetToolButtonState(hwnd, g_hwndObjectList, lvn->iItem, FALSE, FALSE);
                }
                break;

                //handle sort by column
            case LVN_COLUMNCLICK:
                bMainWndSortInverse = !bMainWndSortInverse;
                SortColumn = ((NMLISTVIEW*)lParam)->iSubItem;
                ListView_SortItemsEx(g_hwndObjectList, &MainWindowObjectListCompareFunc, SortColumn);

                nImageIndex = ImageList_GetImageCount(g_ListViewImages);
                if (bMainWndSortInverse)
                    nImageIndex -= 2; //sort down/up images are always at the end of g_ListViewImages
                else
                    nImageIndex -= 1;

                supUpdateLvColumnHeaderImage(
                    g_hwndObjectList,
                    MAIN_OBJLIST_COLUMN_COUNT,
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
            case ID_VIEW_DISPLAYGRID:
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

        if (GetWindowRect(hwndToolBar, &ToolBarRect) &&
            GetWindowRect(hwndStatusBar, &StatusBarRect)) {

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
    LONG                NewSplitterPos;
    RECT                ToolBarRect, crc;
    LPDRAWITEMSTRUCT    pds;
    LPMEASUREITEMSTRUCT pms;

    switch (uMsg) {
    case WM_CONTEXTMENU:

        RtlSecureZeroMemory(&crc, sizeof(crc));

        if ((HWND)wParam == g_hwndObjectTree) {

            TreeView_GetItemRect(g_hwndObjectTree,
                TreeView_GetSelection(g_hwndObjectTree), (PRECT)&crc, TRUE);

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
        MainWindowHandleWMCommand(hwnd, wParam);
        break;

    case WM_NOTIFY:
        MainWindowHandleWMNotify(hwnd, lParam);
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
            NewSplitterPos = (SHORT)LOWORD(lParam);
            if (NewSplitterPos < SplitterMargin)
                NewSplitterPos = SplitterMargin;
            if (NewSplitterPos > ToolBarRect.right - SplitterMargin)
                NewSplitterPos = ToolBarRect.right - SplitterMargin;
            if (SplitterPos != NewSplitterPos) {
                SplitterPos = NewSplitterPos;
                SendMessage(MainWindow, WM_SIZE, 0, 0);
                UpdateWindow(MainWindow);
            }
        }
        break;

    case WM_SIZE:
        if (!IsIconic(hwnd)) {
            MainWindowResizeHandler(SplitterPos);
        }
        break;

    case WM_GETMINMAXINFO:
        if (lParam) {
            ((PMINMAXINFO)lParam)->ptMinTrackSize.x = SCALE_DPI_VALUE(400, g_WinObj.CurrentDPI);
            ((PMINMAXINFO)lParam)->ptMinTrackSize.y = SCALE_DPI_VALUE(256, g_WinObj.CurrentDPI);
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
    _In_ LPMSG lpMsg,
    _In_ HACCEL hAccTable
)
{
    UINT c;

    for (c = 0; c < wobjMaxDlgId; c++) {
        if ((g_WinObj.AuxDialogs[c] != NULL)) {
            if (IsDialogMessage(g_WinObj.AuxDialogs[c], lpMsg)) {
                TranslateAccelerator(g_WinObj.AuxDialogs[c], hAccTable, lpMsg);
                return TRUE;
            }
        }
    }

    if (g_DesktopPropWindow != NULL)
        if (IsDialogMessage(g_DesktopPropWindow, lpMsg))
            return TRUE;

    if (g_PropWindow != NULL)
        if (IsDialogMessage(g_PropWindow, lpMsg))
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
INT WinObjInitGlobals(
    _In_ BOOLEAN IsWine)
{
    SIZE_T cch;
    INT Result = wobjInitSuccess;


    do {
        RtlSecureZeroMemory(&g_WinObj, sizeof(g_WinObj));

#ifdef _USE_OWN_DRIVER
        //
        // The quality of MMIO driver is outstanding, try to reduce possible impact.
        //
        g_WinObj.EnableFullMitigations = TRUE;
#else
        g_WinObj.EnableFullMitigations = FALSE;
#endif

        g_WinObj.IsWine = IsWine;

        g_WinObj.ListViewDisplayGrid = TRUE;

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
        if (g_WinObj.Heap == NULL) {
            Result = wobjInitNoHeap;
            break;
        }

        if (IsWine == FALSE) {
            RtlSetHeapInformation(g_WinObj.Heap, HeapEnableTerminationOnCorruption, NULL, 0);
        }
        RtlInitializeCriticalSection(&g_WinObj.Lock);

        //
        // Remember %TEMP% directory.
        //
        cch = ExpandEnvironmentStrings(L"%temp%", g_WinObj.szTempDirectory, MAX_PATH);
        if ((cch == 0) || (cch > MAX_PATH)) {
            Result = wobjInitNoTemp;
            break;
        }

        //
        // Remember Windows directory.
        //

        cch = GetWindowsDirectory(g_WinObj.szWindowsDirectory, MAX_PATH);
        if ((cch == 0) || (cch > MAX_PATH)) {
            Result = wobjInitNoWinDir;
            break;
        }

        //
        // Remember System32 directory.
        //
        cch = GetSystemDirectory(g_WinObj.szSystemDirectory, MAX_PATH);
        if ((cch == 0) || (cch > MAX_PATH)) {
            Result = wobjInitNoSys32Dir;
            break;
        }

        //
        // Remember program current directory.
        //
        cch = GetCurrentDirectory(MAX_PATH, g_WinObj.szProgramDirectory);
        if ((cch == 0) || (cch > MAX_PATH)) {
            Result = wobjInitNoProgDir;
            break;
        }

        Result = wobjInitSuccess;

    } while (FALSE);

    if (Result != wobjInitSuccess) {
        if (g_WinObj.Heap)
            RtlDestroyHeap(g_WinObj.Heap);
    }

    return Result;
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

    ATOM                    classAtom = 0;
    BOOL                    bIsFullAdmin = FALSE, bRet = TRUE, bLocalSystem = FALSE;

    HWND                    hDesktopWnd = GetDesktopWindow();
    HMENU                   hMenu;
    HACCEL                  hAccTable = 0;
    HICON                   hIcon;
    HANDLE                  processToken;

    MSG                     msg;
    INITCOMMONCONTROLSEX    iccx;
    WNDCLASSEX              wndClass;
    HIMAGELIST              TreeViewImages;

    WCHAR                   szWindowTitle[100];

    INT                     initResult;
    LPWSTR                  lpErrorMsg;

    logCreate();
    IsWine = supIsWine();

    if (!supInitMSVCRT()) {
        MessageBox(hDesktopWnd, T_WOBJINIT_NOCRT, NULL, MB_ICONERROR);
        return ERROR_APP_INIT_FAILURE;
    }

    //
    // Wine 1.6 xenial does not suport this routine.
    //
    if (IsWine == FALSE) {
        RtlSetHeapInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0);
    }

    initResult = WinObjInitGlobals(IsWine);

    if (initResult != wobjInitSuccess) {
        switch (initResult) {

        case wobjInitNoHeap:
            lpErrorMsg = T_WOBJINIT_NOHEAP;
            break;

        case wobjInitNoTemp:
            lpErrorMsg = T_WOBJINIT_NOTEMP;
            break;

        case wobjInitNoWinDir:
            lpErrorMsg = T_WOBJINIT_NOWINDIR;
            break;

        case wobjInitNoSys32Dir:
            lpErrorMsg = T_WOBJINIT_NOSYS32DIR;
            break;

        case wobjInitNoProgDir:
            lpErrorMsg = T_WOBJINIT_NOPROGDIR;
            break;

        default:
            lpErrorMsg = TEXT("Unknown initialization error");
            break;
        }
        MessageBox(hDesktopWnd, lpErrorMsg, NULL, MB_ICONERROR);
        return ERROR_APP_INIT_FAILURE;
    }

    //
    // !Do not move anywhere!
    //
    bIsFullAdmin = supUserIsFullAdmin();

    //
    // Drop admin related features on Wine.
    //
    if (IsWine != FALSE) {
        bIsFullAdmin = FALSE;
    }

    supInit(bIsFullAdmin);

#ifdef _DEBUG
    TestStart();
#endif

    do {
        //
        // Create main window and it components.
        //
        wndClass.cbSize = sizeof(WNDCLASSEX);
        wndClass.style = 0;
        wndClass.lpfnWndProc = &MainWindowProc;
        wndClass.cbClsExtra = 0;
        wndClass.cbWndExtra = 0;
        wndClass.hInstance = g_WinObj.hInstance;

        wndClass.hIcon = (HICON)LoadImage(
            g_WinObj.hInstance,
            MAKEINTRESOURCE(IDI_ICON_MAIN),
            IMAGE_ICON,
            0,
            0,
            LR_SHARED);

        wndClass.hCursor = (HCURSOR)LoadImage(
            NULL,
            MAKEINTRESOURCE(OCR_SIZEWE),
            IMAGE_CURSOR,
            0,
            0,
            LR_SHARED);

        wndClass.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wndClass.lpszMenuName = MAKEINTRESOURCE(IDR_MAINMENU);
        wndClass.lpszClassName = WINOBJEX64_WNDCLASS;
        wndClass.hIconSm = 0;

        classAtom = RegisterClassEx(&wndClass);
        if (classAtom == 0) {
            MessageBox(hDesktopWnd, T_WOBJINIT_NOCLASS, NULL, MB_ICONERROR);
            break;
        }

        RtlSecureZeroMemory(szWindowTitle, sizeof(szWindowTitle));
        _strcpy(szWindowTitle, PROGRAM_NAME);
        if (bIsFullAdmin != FALSE) {
            _strcat(szWindowTitle, TEXT(" (Administrator)"));
        }

        if (IsWine != FALSE) {
            _strcat(szWindowTitle, TEXT(" (Wine)"));
        }

        //
        // Create main window.
        //
        MainWindow = CreateWindowEx(
            0,
            MAKEINTATOM(classAtom),
            szWindowTitle,
            WS_VISIBLE | WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            SCALE_DPI_VALUE(800, g_WinObj.CurrentDPI),
            SCALE_DPI_VALUE(600, g_WinObj.CurrentDPI),
            NULL,
            NULL,
            g_WinObj.hInstance,
            NULL);

        if (MainWindow == NULL) {
            MessageBox(hDesktopWnd, T_WOBJINIT_NOMAINWINDOW, NULL, MB_ICONERROR);
            break;
        }

        iccx.dwSize = sizeof(iccx);
        iccx.dwICC = ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES | ICC_BAR_CLASSES | ICC_TAB_CLASSES;
        if (!InitCommonControlsEx(&iccx)) {
            MessageBox(hDesktopWnd, T_WOBJINIT_NOICCX, NULL, MB_ICONERROR);
            break;
        }

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
            (HMENU)1001,
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

        if (g_hwndObjectTree == NULL) {
            MessageBox(hDesktopWnd, T_WOBJINIT_NOTREEWND, NULL, MB_ICONERROR);
            break;
        }

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

        if (g_hwndObjectList == NULL) {
            MessageBox(hDesktopWnd, T_WOBJINIT_NOLISTWND, NULL, MB_ICONERROR);
            break;
        }

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

        if (hwndToolBar == NULL) {
            MessageBox(hDesktopWnd, T_WOBJINIT_NOTLBARWND, NULL, MB_ICONERROR);
            break;
        }

        SendMessage(hwndToolBar, TB_SETEXTENDEDSTYLE, 0, TBSTYLE_EX_DOUBLEBUFFER);

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
            LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);

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
            if (bIsFullAdmin == FALSE) {
                hMenu = GetSubMenu(GetMenu(MainWindow), IDMM_FILE);
                InsertMenu(hMenu, 0, MF_BYPOSITION, ID_FILE_RUNASADMIN, T_RUNASADMIN);
                InsertMenu(hMenu, 1, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);

                //
                // Set menu shield icon.
                //
                hIcon = supGetStockIcon(SIID_SHIELD, SHGSI_ICON | SHGFI_SMALLICON);
                if (hIcon)
                    supSetMenuIcon(hMenu, ID_FILE_RUNASADMIN, (ULONG_PTR)hIcon);

            }
            else {
                //
                // We are running with admin privileges, determine if we need to 
                // insert run as LocalSystem menu entry.
                //
                processToken = supGetCurrentProcessToken();
                if (processToken) {
                    if (NT_SUCCESS(supIsLocalSystem(processToken, &bLocalSystem))) {
                        if (bLocalSystem == FALSE) {
                            //
                            // Not LocalSystem account, insert item.
                            //
                            hMenu = GetSubMenu(GetMenu(MainWindow), IDMM_FILE);
                            InsertMenu(hMenu, 0, MF_BYPOSITION, ID_FILE_RUNASADMIN, T_RUNASSYSTEM);
                            InsertMenu(hMenu, 1, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);

                            //
                            // Set menu LocalSystem icon.
                            //
                            hIcon = supGetStockIcon(SIID_DESKTOPPC, SHGSI_ICON | SHGFI_SMALLICON);
                            if (hIcon)
                                supSetMenuIcon(hMenu, ID_FILE_RUNASADMIN, (ULONG_PTR)hIcon);

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
                    NtClose(processToken);
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
            8,
            CLR_DEFAULT,
            IMAGE_BITMAP,
            LR_CREATEDIBSECTION);

        if (g_ToolBarMenuImages) {
            supCreateToolbarButtons(hwndToolBar);
        }

        //set menu icons
        hMenu = GetSubMenu(GetMenu(MainWindow), IDMM_VIEW);
        if (hMenu && g_ToolBarMenuImages) {
            supSetMenuIcon(hMenu, ID_VIEW_REFRESH,
                (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 1));
            supSetMenuIcon(hMenu, ID_VIEW_DISPLAYGRID,
                (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 7));
        }
        hMenu = GetSubMenu(GetMenu(MainWindow), IDMM_OBJECT);
        if (hMenu && g_ListViewImages) {

            supSetMenuIcon(hMenu, ID_OBJECT_PROPERTIES,
                (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 0));

            supSetMenuIcon(hMenu, ID_OBJECT_GOTOLINKTARGET,
                (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance,
                    g_ListViewImages,
                    g_TypeSymbolicLink.ImageIndex));
        }

        //set object -> find object menu image
        hMenu = GetSubMenu(GetMenu(MainWindow), IDMM_FIND);
        if (hMenu && g_ToolBarMenuImages) {
            supSetMenuIcon(hMenu, ID_FIND_FINDOBJECT,
                (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 2));
        }

        //
        // Set extras -> menu images.
        //
        hMenu = GetSubMenu(GetMenu(MainWindow), IDMM_EXTRAS);
        if (hMenu && g_ToolBarMenuImages) {

            //
            // Pipes & mailslots images.
            //
            supSetMenuIcon(hMenu, ID_EXTRAS_MAILSLOTS,
                (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 5));
            supSetMenuIcon(hMenu, ID_EXTRAS_PIPES,
                (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 6));

            //
            // Process list menu image.
            //
            hIcon = supGetStockIcon(SIID_APPLICATION, SHGSI_ICON | SHGFI_SMALLICON);
            if (hIcon)
                supSetMenuIcon(hMenu, ID_EXTRAS_PROCESSLIST, (ULONG_PTR)hIcon);

            //
            // Private namespaces menu image.
            //
            hIcon = supGetStockIcon(SIID_STACK, SHGSI_ICON | SHGFI_SMALLICON);
            if (hIcon)
                supSetMenuIcon(hMenu, ID_EXTRAS_PRIVATENAMESPACES, (ULONG_PTR)hIcon);

        }

        //
        // Set help menu image.
        //
        hMenu = GetSubMenu(GetMenu(MainWindow), IDMM_HELP);
        if (hMenu) {

            hIcon = supGetStockIcon(SIID_HELP, SHGSI_ICON | SHGFI_SMALLICON);
            if (hIcon)
                supSetMenuIcon(hMenu, ID_HELP_HELP, (ULONG_PTR)hIcon);

        }

        hAccTable = LoadAccelerators(g_WinObj.hInstance, MAKEINTRESOURCE(IDR_ACCELERATOR1));

        PmCreate(MainWindow);

        //
        // Create ObjectList columns.
        //

        supAddListViewColumn(g_hwndObjectList, 0, 0, 0,
            g_ListViewImages ? ImageList_GetImageCount(g_ListViewImages) - 1 : I_IMAGENONE,
            LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
            TEXT("Name"), 300);

        supAddListViewColumn(g_hwndObjectList, 1, 1, 1,
            I_IMAGENONE,
            LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
            TEXT("Type"), 100);

        supAddListViewColumn(g_hwndObjectList, 2, 2, 2,
            I_IMAGENONE,
            LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
            TEXT("Additional Information"), 170);

        ListObjectDirectoryTree(L"\\", NULL, NULL);

        TreeView_SelectItem(g_hwndObjectTree, TreeView_GetRoot(g_hwndObjectTree));
        SetFocus(g_hwndObjectTree);

        do {
            bRet = GetMessage(&msg, NULL, 0, 0);

            if (bRet == -1)
                break;

            if (MainWindowDlgMsgHandler(&msg, hAccTable))
                continue;

            if (IsDialogMessage(MainWindow, &msg)) {
                TranslateAccelerator(MainWindow, hAccTable, &msg);
                continue;
            }

            TranslateMessage(&msg);
            DispatchMessage(&msg);

        } while (bRet != 0);

    } while (FALSE);

    if (classAtom != 0)
        UnregisterClass(MAKEINTATOM(classAtom), g_WinObj.hInstance);

    if (g_TreeListAtom != 0)
        UnregisterClass(MAKEINTATOM(g_TreeListAtom), g_WinObj.hInstance);

    PmDestroy();

    //do not move anywhere

    supShutdown();
    logFree();

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
    _In_opt_ HINSTANCE hPrevInstance,
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
