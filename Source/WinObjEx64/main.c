/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2022
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.94
*
*  DATE:        07 Jun 2022
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
#include "sdviewDlg.h"
#include "sysinfoDlg.h"
#include "treelist/treelist.h"
#include "props/propDlg.h"
#include "extras/extras.h"

#define MAINWND_TRACKSIZE_MIN_X 400
#define MAINWND_TRACKSIZE_MIN_Y 256

pswprintf_s rtl_swprintf_s;
pqsort rtl_qsort;

static LONG	g_SplitterPos = 180;
static LONG	g_SortColumn = 0;

HTREEITEM ObjectTreeSelectedItem;
BOOL bMainWndSortInverse = FALSE;

//
// Global UI variables.
//
WINOBJ_GLOBALS g_WinObj;

/*
* guiExtrasDisableAdminFeatures
*
* Purpose:
*
* Disable menu items require admin privileges.
*
*/
VOID guiExtrasDisableAdminFeatures(
    _In_ HWND hWnd
)
{
    HICON hIcon;
    HMENU hExtrasSubMenu = GetSubMenu(GetMenu(hWnd), IDMM_EXTRAS);

    MENUITEMINFO mii;

    mii.cbSize = sizeof(mii);
    mii.fMask = MIIM_STATE;
    mii.fState = MFS_DISABLED;

    //
    // These features are not unsupported in Wine.
    //
    if (g_WinObj.IsWine) {
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_CALLBACKS, FALSE, &mii);
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_DRIVERS, FALSE, &mii);
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_UNLOADEDDRIVERS, FALSE, &mii);
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_SOFTWARELICENSECACHE, FALSE, &mii);
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_SSDT, FALSE, &mii);
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_W32PSERVICETABLE, FALSE, &mii);
        SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_CMCONTROLVECTOR, FALSE, &mii);
        return;
    }

    //
    // Elevated launch.
    //
    if (g_kdctx.IsFullAdmin) {
        //
        // These features require driver usage.
        //
        /*if (FALSE == kdIoDriverLoaded()) {
            SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_SSDT, FALSE, &mii);
            SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_PRIVATENAMESPACES, FALSE, &mii);
            SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_CALLBACKS, FALSE, &mii);
            SetMenuItemInfo(hExtrasSubMenu, ID_EXTRAS_UNLOADEDDRIVERS, FALSE, &mii);
        }*/

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
    }
    else {
        //
        // Non elevated launch set shield icon.
        //
        hIcon = supGetStockIcon(SIID_SHIELD, SHGSI_ICON | SHGFI_SMALLICON);
        if (hIcon) {
            supSetMenuIcon(hExtrasSubMenu, ID_EXTRAS_SSDT, hIcon);
            supSetMenuIcon(hExtrasSubMenu, ID_EXTRAS_PRIVATENAMESPACES, hIcon);
            supSetMenuIcon(hExtrasSubMenu, ID_EXTRAS_CALLBACKS, hIcon);
            supSetMenuIcon(hExtrasSubMenu, ID_EXTRAS_UNLOADEDDRIVERS, hIcon);
        }

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

    if (ObjectTreeSelectedItem == NULL)
        return;

    RtlSecureZeroMemory(&tvi, sizeof(TV_ITEM));

    szBuffer[0] = 0;
    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
    tvi.pszText = szBuffer;
    tvi.cchTextMax = MAX_PATH;
    tvi.mask = TVIF_TEXT;
    tvi.hItem = ObjectTreeSelectedItem;
    if (TreeView_GetItem(g_hwndObjectTree, &tvi)) {

        RtlSecureZeroMemory(&propSettings, sizeof(propSettings));
        propSettings.hwndParent = hwnd;
        propSettings.lpObjectName = szBuffer;
        propSettings.lpObjectType = OBTYPE_NAME_DIRECTORY;

        propCreateDialog(&propSettings);
    }
}

/*
* MainWindowHandleObjectViewSD
*
* Purpose:
*
* Handler for View Security Descriptor menu.
*
*/
VOID MainWindowHandleObjectViewSD(
    _In_ HWND hwndParent,
    _In_ BOOL fList
)
{
    LVITEM lvi;
    TV_ITEM tvi;
    WOBJ_OBJECT_TYPE wobjType;
    WCHAR szBuffer[MAX_PATH + 1];

    szBuffer[0] = 0;

    if (fList) {

        RtlSecureZeroMemory(&lvi, sizeof(LVITEM));
        lvi.mask = LVIF_PARAM | LVIF_TEXT;
        lvi.iItem = ListView_GetSelectionMark(g_hwndObjectList);
        lvi.pszText = szBuffer;
        lvi.cchTextMax = MAX_PATH;

        if (!ListView_GetItem(g_hwndObjectList, &lvi))
            return;

        wobjType = (WOBJ_OBJECT_TYPE)lvi.lParam;

    }
    else {

        RtlSecureZeroMemory(&tvi, sizeof(TV_ITEM));
        tvi.pszText = szBuffer;
        tvi.cchTextMax = MAX_PATH;
        tvi.mask = TVIF_TEXT;
        tvi.hItem = ObjectTreeSelectedItem;

        if (!TreeView_GetItem(g_hwndObjectTree, &tvi))
            return;

        wobjType = ObjectTypeDirectory;
    }

    SDViewDialogCreate(hwndParent,
        g_WinObj.CurrentObjectPath,
        szBuffer,
        wobjType);

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
* MainWindowEnumWndProc
*
* Purpose:
*
* Settings update enum callback.
*
*/
BOOL CALLBACK MainWindowEnumWndProc(
    _In_ HWND hwnd,
    _In_ LPARAM lParam
)
{
    DWORD dwProcessId;
    DWORD dwCurrentProcessId = (DWORD)lParam;

    if (GetWindowThreadProcessId(hwnd, &dwProcessId)) {
        if (dwProcessId == dwCurrentProcessId)
            PostMessage(hwnd, g_WinObj.SettingsChangeMessage, 0, 0);
    }
    return TRUE;
}

/*
* MainWindowOnDisplayGridChange
*
* Purpose:
*
* Handle listview grid settings change and broadcast it to all WinObjEx64 sub dialogs.
*
*/
VOID MainWindowOnDisplayGridChange(
    VOID
)
{
    DWORD lvExStyle;
    DWORD dwProcessId = GetCurrentProcessId();
    g_WinObj.ListViewDisplayGrid = (~g_WinObj.ListViewDisplayGrid) & 1;
    lvExStyle = ListView_GetExtendedListViewStyle(g_hwndObjectList);
    if (g_WinObj.ListViewDisplayGrid)
        lvExStyle |= LVS_EX_GRIDLINES;
    else
        lvExStyle &= ~LVS_EX_GRIDLINES;

    ListView_SetExtendedListViewStyle(g_hwndObjectList, lvExStyle);

    EnumWindows((WNDENUMPROC)MainWindowEnumWndProc, (LPARAM)dwProcessId);
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
        PmViewPlugins();
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

    case ID_VIEW_SECURITYDESCRIPTOR:
        MainWindowHandleObjectViewSD(hwnd, (GetFocus() == g_hwndObjectList));
        break;

    case ID_FIND_FINDOBJECT:
        FindDlgCreate();
        break;

    case ID_VIEW_REFRESH:
        MainWindowOnRefresh();
        break;

    case ID_VIEW_DISPLAYGRID:
        MainWindowOnDisplayGridChange();
        break;

    case ID_EXTRAS_PIPES:
    case ID_EXTRAS_MAILSLOTS:
    case ID_EXTRAS_USERSHAREDDATA:
    case ID_EXTRAS_PRIVATENAMESPACES:
    case ID_EXTRAS_SSDT:
    case ID_EXTRAS_W32PSERVICETABLE:
    case ID_EXTRAS_DRIVERS:
    case ID_EXTRAS_UNLOADEDDRIVERS:
    case ID_EXTRAS_PROCESSLIST:
    case ID_EXTRAS_CALLBACKS:
    case ID_EXTRAS_SOFTWARELICENSECACHE:
    case ID_EXTRAS_CMCONTROLVECTOR:
        //
        // Extras -> Pipes
        //           Mailslots
        //           UserSharedData
        //           Private Namespaces
        //           KiServiceTable
        //           W32pServiceTable
        //           Drivers
        //           Unloaded Drivers
        //           Process List
        //           Callbacks
        //           Software Licensing Cache
        //           CmControlVector
        //
        extrasShowDialogById(ControlId);
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

    case ID_VIEW_SYSINFO:
        ShowSysInfoDialog(hwnd);
        break;

    default:
        break;
    }

    if ((ControlId >= ID_MENU_PLUGINS) && (ControlId < ID_MENU_PLUGINS_MAX)) {
        PmProcessEntry(GetFocus(), ControlId, ObjectTreeSelectedItem);
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
* MainWindowPopupMenuInsertViewSD
*
* Purpose:
*
* Add "View Security Descriptor" menu item to the popup menu.
*
*/
VOID MainWindowPopupMenuInsertViewSD(
    _In_ HMENU hMenu,
    _In_ UINT uPosition
)
{
    HICON hIcon;

    InsertMenu(hMenu, uPosition, MF_BYCOMMAND, ID_VIEW_SECURITYDESCRIPTOR, T_VIEWSD);

    hIcon = (HICON)LoadImage(g_WinObj.hInstance,
        MAKEINTRESOURCE(IDI_ICON_SECURITY),
        IMAGE_ICON,
        0,
        0,
        LR_SHARED);

    if (hIcon) {

        supSetMenuIcon(hMenu,
            ID_VIEW_SECURITYDESCRIPTOR,
            hIcon);

        DestroyIcon(hIcon);
    }
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
            ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 0));

        MainWindowPopupMenuInsertViewSD(hMenu, 1);

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
    HMENU hMenu;
    UINT  uGotoSymLinkEnable = MF_BYCOMMAND | MF_GRAYED, uPosition = 0;

    WOBJ_OBJECT_TYPE objType;

    hMenu = CreatePopupMenu();
    if (hMenu == NULL) return;

    InsertMenu(hMenu, uPosition++, MF_BYCOMMAND, ID_OBJECT_PROPERTIES, T_PROPERTIES);

    supSetMenuIcon(hMenu, ID_OBJECT_PROPERTIES,
        ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 0));

    objType = supObjectListGetObjectType(hwndlv, iItem);

    //
    // Only supOpenNamedObjectByType supported types.
    //
    switch (objType) {

        //
        // Insert "Go To Link Target"
        //
    case ObjectTypeSymbolicLink:

        InsertMenu(hMenu, uPosition++, MF_BYCOMMAND, ID_OBJECT_GOTOLINKTARGET, T_GOTOLINKTARGET);

        supSetMenuIcon(hMenu, ID_OBJECT_GOTOLINKTARGET,
            ImageList_ExtractIcon(g_WinObj.hInstance,
                g_ListViewImages,
                g_TypeSymbolicLink.ImageIndex));

        uGotoSymLinkEnable = MF_BYCOMMAND; //-V796

        //
        // Intentionally do not 'break' here.
        //

    case ObjectTypeDirectory:
    case ObjectTypeDevice:
    case ObjectTypeEvent:
    case ObjectTypeEventPair:
    case ObjectTypeIoCompletion:
    case ObjectTypeJob:
    case ObjectTypeKey:
    case ObjectTypeKeyedEvent:
    case ObjectTypeMemoryPartition:
    case ObjectTypeMutant:
    case ObjectTypePort:
    case ObjectTypeSection:
    case ObjectTypeSemaphore:
    case ObjectTypeSession:
    case ObjectTypeTimer:

        MainWindowPopupMenuInsertViewSD(hMenu, uPosition);
        break;

    default:
        break;
    }

    EnableMenuItem(GetSubMenu(GetMenu(hwnd), IDMM_OBJECT), ID_OBJECT_GOTOLINKTARGET, uGotoSymLinkEnable);

    PmBuildPluginPopupMenuByObjectType(
        hMenu,
        (UCHAR)objType);

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
                SendMessage(g_hwndStatusBar, WM_SETTEXT, 0, (LPARAM)g_WinObj.CurrentObjectPath);

                ListObjectsInDirectory(g_WinObj.CurrentObjectPath);

                ListView_SortItemsEx(g_hwndObjectList, &MainWindowObjectListCompareFunc, g_SortColumn);

                supSetGotoLinkTargetToolButtonState(hwnd, 0, 0, TRUE, FALSE);

                supSetWaitCursor(FALSE);

                lpnmTreeView = (LPNMTREEVIEW)lParam;
                if (lpnmTreeView) {
                    ObjectTreeSelectedItem = lpnmTreeView->itemNew.hItem;
                }
                break;

            case NM_RCLICK:
                GetCursorPos(&pt);
                hti.pt = pt;
                ScreenToClient(hdr->hwndFrom, &hti.pt);
                if (TreeView_HitTest(hdr->hwndFrom, &hti) &&
                    (hti.flags & (TVHT_ONITEM | TVHT_ONITEMRIGHT))) {
                    ObjectTreeSelectedItem = hti.hItem;
                    TreeView_SelectItem(g_hwndObjectTree, ObjectTreeSelectedItem);
                    SendMessage(g_hwndStatusBar, WM_SETTEXT, 0, (LPARAM)g_WinObj.CurrentObjectPath);
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
                if ((lvn->uNewState & LVIS_SELECTED) &&
                    !(lvn->uOldState & LVIS_SELECTED))
                {
                    RtlSecureZeroMemory(&szItemString, sizeof(szItemString));
                    ListView_GetItemText(g_hwndObjectList, lvn->iItem, 0, szItemString, MAX_PATH);
                    lcp = _strlen(g_WinObj.CurrentObjectPath);
                    if (lcp) {
                        str = (LPWSTR)supHeapAlloc((lcp + sizeof(szItemString) + 4) * sizeof(WCHAR));
                        if (str) {

                            _strcpy(str, g_WinObj.CurrentObjectPath);

                            if ((str[0] == L'\\') && (str[1] == 0)) {
                                _strcpy(str + lcp, szItemString);
                            }
                            else {
                                str[lcp] = L'\\';
                                _strcpy(str + lcp + 1, szItemString);
                            }
                            SendMessage(g_hwndStatusBar, WM_SETTEXT, 0, (LPARAM)str);
                            supHeapFree(str);
                        }
                        supSetGotoLinkTargetToolButtonState(hwnd, g_hwndObjectList, lvn->iItem, FALSE, FALSE);
                    }
                }
                break;

                //handle sort by column
            case LVN_COLUMNCLICK:
                bMainWndSortInverse = (~bMainWndSortInverse) & 1;
                g_SortColumn = ((NMLISTVIEW*)lParam)->iSubItem;
                ListView_SortItemsEx(g_hwndObjectList, &MainWindowObjectListCompareFunc, g_SortColumn);

                nImageIndex = ImageList_GetImageCount(g_ListViewImages);
                if (bMainWndSortInverse)
                    nImageIndex -= 2; //sort down/up images are always at the end of g_ListViewImages
                else
                    nImageIndex -= 1;

                supUpdateLvColumnHeaderImage(
                    g_hwndObjectList,
                    MAIN_OBJLIST_COLUMN_COUNT,
                    g_SortColumn,
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

    if (g_hwndToolBar != NULL) {

        SendMessage(g_hwndToolBar, WM_SIZE, 0, 0);
        SendMessage(g_hwndStatusBar, WM_SIZE, 0, 0);

        if (GetWindowRect(g_hwndToolBar, &ToolBarRect) &&
            GetWindowRect(g_hwndStatusBar, &StatusBarRect)) {

            sizeX = ToolBarRect.right - ToolBarRect.left;
            if (sPos > sizeX - SplitterMargin)
                sPos = sizeX - SplitterMargin - 1;

            sizeY = StatusBarRect.top - ToolBarRect.bottom;
            posY = ToolBarRect.bottom - ToolBarRect.top;
            sizeX = ToolBarRect.right - ToolBarRect.left - sPos - SplitterSize;

            SetWindowPos(g_hwndObjectTree, NULL, 0, posY, sPos, sizeY, 0);
            SetWindowPos(g_hwndObjectList, NULL, sPos + SplitterSize, posY, sizeX, sizeY, 0);
            SetWindowPos(g_hwndSplitter, NULL, sPos, posY, SplitterSize, sizeY, 0);
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
                TreeView_GetSelection(g_hwndObjectTree), &crc, TRUE);

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
        SetCapture(g_hwndMain);
        break;

    case WM_LBUTTONUP:
        ReleaseCapture();
        break;

    case WM_MOUSEMOVE:
        if ((wParam & MK_LBUTTON) != 0) {
            GetClientRect(g_hwndMain, &ToolBarRect);
            NewSplitterPos = (SHORT)LOWORD(lParam);
            if (NewSplitterPos < SplitterMargin)
                NewSplitterPos = SplitterMargin;
            if (NewSplitterPos > ToolBarRect.right - SplitterMargin)
                NewSplitterPos = ToolBarRect.right - SplitterMargin;
            if (g_SplitterPos != NewSplitterPos) {
                g_SplitterPos = NewSplitterPos;
                SendMessage(g_hwndMain, WM_SIZE, 0, 0);
                UpdateWindow(g_hwndMain);
            }
        }
        break;

    case WM_SIZE:
        if (!IsIconic(hwnd)) {
            MainWindowResizeHandler(g_SplitterPos);
        }
        break;

    case WM_GETMINMAXINFO:
        if (lParam) {
            supSetMinMaxTrackSize((PMINMAXINFO)lParam,
                MAINWND_TRACKSIZE_MIN_X,
                MAINWND_TRACKSIZE_MIN_Y,
                TRUE);
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
    _In_ LPMSG lpMsg
)
{
    if (g_DesktopPropWindow != NULL)       
        if (PropSheet_IsDialogMessage(g_DesktopPropWindow, lpMsg))
            return TRUE;
    
    if (g_PropWindow != NULL)
        if (PropSheet_IsDialogMessage(g_PropWindow, lpMsg))
            return TRUE;

    return FALSE;
}

/*
* guiInitGlobals
*
* Purpose:
*
* Initialize WinObjEx global variables.
*
*/
DWORD guiInitGlobals(
    _In_ BOOLEAN IsWine,
    _In_ WINOBJ_GLOBALS* Globals)
{
    SIZE_T cch;
    DWORD dwResult = INIT_ERROR_UNSPECIFIED;


    do {

        Globals->IsWine = IsWine;
        Globals->ListViewDisplayGrid = TRUE;

        //
        // Query version info.
        //
        Globals->osver.dwOSVersionInfoSize = sizeof(Globals->osver);
        RtlGetVersion(&Globals->osver);

        g_NtBuildNumber = Globals->osver.dwBuildNumber;

        //
        // Remember hInstance.
        //
        Globals->hInstance = GetModuleHandle(NULL);

        //
        // Create dedicated heap.
        //
        Globals->Heap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
        if (Globals->Heap == NULL) {
            dwResult = INIT_ERROR_NOHEAP;
            break;
        }

        if (IsWine == FALSE) {
            RtlSetHeapInformation(Globals->Heap, HeapEnableTerminationOnCorruption, NULL, 0);
        }

        //
        // Remember %TEMP% directory.
        //
        cch = ExpandEnvironmentStrings(L"%temp%", Globals->szTempDirectory, MAX_PATH);
        if ((cch == 0) || (cch > MAX_PATH)) {
            dwResult = INIT_ERROR_NOTEMP;
            break;
        }

        //
        // Remember Windows directory.
        //
        cch = GetWindowsDirectory(Globals->szWindowsDirectory, MAX_PATH);
        if ((cch == 0) || (cch > MAX_PATH)) {
            dwResult = INIT_ERROR_NOWINDIR;
            break;
        }

        //
        // Remember System32 directory.
        //
        cch = GetSystemDirectory(Globals->szSystemDirectory, MAX_PATH);
        if ((cch == 0) || (cch > MAX_PATH)) {
            dwResult = INIT_ERROR_NOSYS32DIR;
            break;
        }

        //
        // Remember program current directory.
        //
        cch = GetCurrentDirectory(MAX_PATH, Globals->szProgramDirectory);
        if ((cch == 0) || (cch > MAX_PATH)) {
            dwResult = INIT_ERROR_NOPROGDIR;
            break;
        }

        dwResult = INIT_NO_ERROR;

    } while (FALSE);

    if (dwResult != INIT_NO_ERROR) {
        if (Globals->Heap)
            RtlDestroyHeap(Globals->Heap);
    }

    return dwResult;
}

/*
* guiCreateObjectListColumns
*
* Purpose:
*
* Add object list columns.
*
*/
VOID guiCreateObjectListColumns()
{
    LVCOLUMNS_DATA columnData[] =
    {
        { TEXT("Name"), 300, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  g_ListViewImages ? ImageList_GetImageCount(g_ListViewImages) - 1 : I_IMAGENONE },
        { TEXT("Type"), 100, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  I_IMAGENONE },
        { TEXT("Additional Information"), 170, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  I_IMAGENONE }
    };

    supAddLVColumnsFromArray(g_hwndObjectList, columnData, RTL_NUMBER_OF(columnData));
}

/*
* guiUnregisterClassAtoms
*
* Purpose:
*
* Deregister main window and treelist class.
*
*/
VOID guiUnregisterClassAtoms(
    VOID
)
{
    ATOM classAtom;

    classAtom = g_WinObj.MainWindowClassAtom;
    if (classAtom != 0)
        UnregisterClass(MAKEINTATOM(classAtom), g_WinObj.hInstance);

    classAtom = g_WinObj.TreeListAtom;
    if (classAtom != 0)
        UnregisterClass(MAKEINTATOM(classAtom), g_WinObj.hInstance);
}

/*
* guiSetMainMenuImages
*
* Purpose:
*
* Load menu icons (Four-F legacy stuff).
*
*/
VOID guiSetMainMenuImages(
    VOID
)
{
    HMENU hMenu;
    HICON hIcon;
    HIMAGELIST hToolBarMenuImages = g_ToolBarMenuImages;

    //
    // Set help menu image.
    //
    hMenu = GetSubMenu(GetMenu(g_hwndMain), IDMM_HELP);
    if (hMenu) {

        hIcon = supGetStockIcon(SIID_HELP, SHGSI_ICON | SHGFI_SMALLICON);
        if (hIcon)
            supSetMenuIcon(hMenu, ID_HELP_HELP, hIcon);

    }

    if (hToolBarMenuImages == NULL)
        return;

    //set menu icons
    hMenu = GetSubMenu(GetMenu(g_hwndMain), IDMM_VIEW);
    if (hMenu) {
        supSetMenuIcon(hMenu, ID_VIEW_REFRESH,
            ImageList_ExtractIcon(g_WinObj.hInstance, hToolBarMenuImages, 1));
        supSetMenuIcon(hMenu, ID_VIEW_DISPLAYGRID,
            ImageList_ExtractIcon(g_WinObj.hInstance, hToolBarMenuImages, 7));
        hIcon = supGetStockIcon(SIID_INFO, SHGSI_ICON | SHGFI_SMALLICON);
        if (hIcon)
            supSetMenuIcon(hMenu, ID_VIEW_SYSINFO, hIcon);
    }
    hMenu = GetSubMenu(GetMenu(g_hwndMain), IDMM_OBJECT);
    if (hMenu && g_ListViewImages) {

        supSetMenuIcon(hMenu, ID_OBJECT_PROPERTIES,
            ImageList_ExtractIcon(g_WinObj.hInstance, hToolBarMenuImages, 0));

        supSetMenuIcon(hMenu, ID_OBJECT_GOTOLINKTARGET,
            ImageList_ExtractIcon(g_WinObj.hInstance,
                g_ListViewImages,
                g_TypeSymbolicLink.ImageIndex));
    }

    //set object -> find object menu image
    hMenu = GetSubMenu(GetMenu(g_hwndMain), IDMM_FIND);
    if (hMenu) {

        supSetMenuIcon(hMenu, ID_FIND_FINDOBJECT,
            ImageList_ExtractIcon(g_WinObj.hInstance, hToolBarMenuImages, 2));

    }

    //
    // Set extras -> menu images.
    //
    hMenu = GetSubMenu(GetMenu(g_hwndMain), IDMM_EXTRAS);
    if (hMenu) {

        //
        // Pipes & mailslots images.
        //
        supSetMenuIcon(hMenu, ID_EXTRAS_MAILSLOTS,
            ImageList_ExtractIcon(g_WinObj.hInstance, hToolBarMenuImages, 5));
        supSetMenuIcon(hMenu, ID_EXTRAS_PIPES,
            ImageList_ExtractIcon(g_WinObj.hInstance, hToolBarMenuImages, 6));

    }

}

/*
* guiProcessMainMessageLoop
*
* Purpose:
*
* Process messages loop for the main window and sub dialogs.
*
*/
INT guiProcessMainMessageLoop(
    _In_ HINSTANCE hInstance
)
{
    BOOL bResult;
    HACCEL acceleratorTable;
    MSG message;

    acceleratorTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDR_ACCELERATOR1));

    do {

        bResult = GetMessage(&message, NULL, 0, 0);
        if (bResult == -1)
            break;

        if (MainWindowDlgMsgHandler(&message))
            continue;

        if (IsDialogMessage(g_hwndMain, &message)) {
            TranslateAccelerator(g_hwndMain, acceleratorTable, &message);
        }
        else {
            TranslateMessage(&message);
            DispatchMessage(&message);
        }

    } while (bResult != 0);

    if (acceleratorTable)
        DestroyAcceleratorTable(acceleratorTable);

    return bResult;
}

/*
* guiInsertRunAsMainMenuEntry
*
* Purpose:
*
* Insert run as admin/local system menu entry if not under Wine.
*
*/
VOID guiInsertRunAsMainMenuEntry(
    _In_ BOOLEAN bIsFullAdmin
)
{
    BOOL bLocalSystem;
    HICON hIcon;
    HMENU hMenu;
    HANDLE processToken;
    WCHAR  szWindowTitle[100];

    if (g_WinObj.IsWine == FALSE) {
        //
        // We are running as user, add menu item to request elevation.
        //
        if (bIsFullAdmin == FALSE) {
            hMenu = GetSubMenu(GetMenu(g_hwndMain), IDMM_FILE);
            InsertMenu(hMenu, 0, MF_BYPOSITION, ID_FILE_RUNASADMIN, T_RUNASADMIN);
            InsertMenu(hMenu, 1, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);

            //
            // Set menu shield icon.
            //
            hIcon = supGetStockIcon(SIID_SHIELD, SHGSI_ICON | SHGFI_SMALLICON);
            if (hIcon)
                supSetMenuIcon(hMenu, ID_FILE_RUNASADMIN, hIcon);

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
                        hMenu = GetSubMenu(GetMenu(g_hwndMain), IDMM_FILE);
                        InsertMenu(hMenu, 0, MF_BYPOSITION, ID_FILE_RUNASADMIN, T_RUNASSYSTEM);
                        InsertMenu(hMenu, 1, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);

                        //
                        // Set menu LocalSystem icon.
                        //
                        hIcon = supGetStockIcon(SIID_DESKTOPPC, SHGSI_ICON | SHGFI_SMALLICON);
                        if (hIcon)
                            supSetMenuIcon(hMenu, ID_FILE_RUNASADMIN, hIcon);

                    }
                    else {
                        //
                        // LocalSystem account, update window title.
                        //
                        RtlSecureZeroMemory(szWindowTitle, sizeof(szWindowTitle));
                        _strcpy(szWindowTitle, PROGRAM_NAME);
                        _strcat(szWindowTitle, TEXT(" (LocalSystem)"));
                        SetWindowText(g_hwndMain, szWindowTitle);
                    }
                }
                NtClose(processToken);
            }
        }
    }
}

/*
* guiCreateMainWindowAndComponents
*
* Purpose:
*
* Register new window class and create main window, listview, treelist, statusbar etc.
*
*/
DWORD guiCreateMainWindowAndComponents(
    _In_ BOOLEAN bIsFullAdmin,
    _In_ WINOBJ_GLOBALS* Globals
)
{
    ATOM classAtom;
    DWORD dwResult = INIT_NO_ERROR;
    HICON hIcon;
    HWND hwndMain, hwndObjectList, hwndObjectTree, hwndToolBar;
    HIMAGELIST treeViewImages;
    INITCOMMONCONTROLSEX iccx;
    WNDCLASSEX wndClass;
    HINSTANCE hInstance = Globals->hInstance;
    WCHAR szWindowTitle[100];

    do {

        iccx.dwSize = sizeof(iccx);
        iccx.dwICC = ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES | ICC_BAR_CLASSES | ICC_TAB_CLASSES | ICC_LINK_CLASS;
        if (!InitCommonControlsEx(&iccx)) {
            dwResult = INIT_ERROR_NOICCX;
            break;
        }

        wndClass.cbSize = sizeof(WNDCLASSEX);
        wndClass.style = 0;
        wndClass.lpfnWndProc = &MainWindowProc;
        wndClass.cbClsExtra = 0;
        wndClass.cbWndExtra = 0;
        wndClass.hInstance = hInstance;

        wndClass.hIcon = (HICON)LoadImage(
            hInstance,
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
            dwResult = INIT_ERROR_NOCLASS;
            break;
        }

        Globals->MainWindowClassAtom = classAtom;

        RtlSecureZeroMemory(szWindowTitle, sizeof(szWindowTitle));
        _strcpy(szWindowTitle, PROGRAM_NAME);
        if (bIsFullAdmin != FALSE) {
            _strcat(szWindowTitle, TEXT(" (Administrator)"));
        }

        if (Globals->IsWine != FALSE) {
            _strcat(szWindowTitle, TEXT(" (Wine)"));
        }

        //
        // Create main window.
        //
        hwndMain = CreateWindowEx(
            0,
            MAKEINTATOM(classAtom),
            szWindowTitle,
            WS_VISIBLE | WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            SCALE_DPI_VALUE(800, Globals->CurrentDPI),
            SCALE_DPI_VALUE(600, Globals->CurrentDPI),
            NULL,
            NULL,
            hInstance,
            NULL);

        if (hwndMain == NULL) {
            dwResult = INIT_ERROR_NOMAINWND;
            break;
        }

        Globals->MainWindow = hwndMain;
        Globals->SettingsChangeMessage = RegisterWindowMessage(T_MSG_SETTINGS_CHANGE);

        //
        // Status Bar window.
        //
        Globals->MainWindowStatusBar = CreateWindowEx(
            0,
            STATUSCLASSNAME,
            NULL,
            WS_VISIBLE | WS_CHILD,
            0,
            0,
            0,
            0,
            hwndMain,
            (HMENU)1001,
            hInstance,
            NULL);

        //
        // TreeView window.
        //
        hwndObjectTree = CreateWindowEx(
            WS_EX_CLIENTEDGE,
            WC_TREEVIEW,
            NULL,
            WS_VISIBLE | WS_CHILD | WS_TABSTOP |
            TVS_DISABLEDRAGDROP | TVS_HASBUTTONS | TVS_HASLINES | TVS_LINESATROOT,
            0,
            0,
            0,
            0,
            hwndMain,
            (HMENU)1002,
            hInstance,
            NULL);

        if (hwndObjectTree == NULL) {
            dwResult = INIT_ERROR_NOTREEWND;
            break;
        }

        Globals->ObjectTreeView = hwndObjectTree;

        //
        // ListView window.
        //
        hwndObjectList = CreateWindowEx(
            WS_EX_CLIENTEDGE,
            WC_LISTVIEW,
            NULL,
            WS_VISIBLE | WS_CHILD | WS_TABSTOP |
            LVS_AUTOARRANGE | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL | LVS_SHAREIMAGELISTS,
            0,
            0,
            0,
            0,
            hwndMain,
            (HMENU)1003,
            hInstance,
            NULL);

        if (hwndObjectList == NULL) {
            dwResult = INIT_ERROR_NOLISTWND;
            break;
        }

        Globals->ObjectListView = hwndObjectList;

        //
        // Set treeview imagelist.
        //
        treeViewImages = supLoadImageList(hInstance,
            IDI_ICON_VIEW_DEFAULT,
            IDI_ICON_VIEW_SELECTED);

        if (treeViewImages) {
            TreeView_SetImageList(hwndObjectTree, treeViewImages, TVSIL_NORMAL);
        }

        //
        // Load listview images for object types.
        //
        Globals->ListViewImages = ObManagerLoadImageList();
        if (Globals->ListViewImages) {
            //
            // Append two column sorting images to the end of the listview imagelist.
            //
            hIcon = (HICON)LoadImage(hInstance, MAKEINTRESOURCE(IDI_ICON_SORTUP), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
            if (hIcon) {
                ImageList_ReplaceIcon(Globals->ListViewImages, -1, hIcon);
                DestroyIcon(hIcon);
            }
            hIcon = (HICON)LoadImage(hInstance, MAKEINTRESOURCE(IDI_ICON_SORTDOWN), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
            if (hIcon) {
                ImageList_ReplaceIcon(Globals->ListViewImages, -1, hIcon);
                DestroyIcon(hIcon);
            }
            ListView_SetImageList(hwndObjectList, Globals->ListViewImages, LVSIL_SMALL);
        }

        ListView_SetExtendedListViewStyle(hwndObjectList,
            LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);

        //
        // Apply Window theme.
        //
        SetWindowTheme(hwndObjectList, TEXT("Explorer"), NULL);
        SetWindowTheme(hwndObjectTree, TEXT("Explorer"), NULL);

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
            hwndMain,
            (HMENU)1004,
            hInstance,
            NULL);

        if (hwndToolBar == NULL) {
            dwResult = INIT_ERROR_NOTLBARWND;
            break;
        }

        Globals->MainWindowToolBar = hwndToolBar;

        SendMessage(hwndToolBar, TB_SETEXTENDEDSTYLE, 0, TBSTYLE_EX_DOUBLEBUFFER);

        //
        // Load toolbar images.
        //
        Globals->ToolBarMenuImages = ImageList_LoadImage(
            hInstance,
            MAKEINTRESOURCE(IDB_BITMAP1),
            16,
            8,
            CLR_DEFAULT,
            IMAGE_BITMAP,
            LR_CREATEDIBSECTION);

        if (Globals->ToolBarMenuImages) {
            supCreateToolbarButtons(hwndToolBar, Globals->ToolBarMenuImages);
        }

        //
        // Spliter window.
        //
        Globals->MainWindowSplitter = CreateWindowEx(
            0,
            WC_STATIC,
            NULL,
            WS_VISIBLE | WS_CHILD,
            0,
            0,
            0,
            0,
            hwndMain,
            (HMENU)1005,
            hInstance,
            NULL);

        if (Globals->MainWindowSplitter == NULL)
            dwResult = INIT_ERROR_NOSPLITTERWND;

    } while (FALSE);

    return dwResult;
}

/*
* InitMSVCRT
*
* Purpose:
*
* Initialize MS CRT routines from ntdll (either msvcrt).
*
*/
BOOL InitMSVCRT(
    VOID
)
{
    HMODULE DllHandle;

    DllHandle = GetModuleHandle(TEXT("ntdll.dll"));

    if (DllHandle) {
        rtl_swprintf_s = (pswprintf_s)GetProcAddress(DllHandle, "swprintf_s");
        rtl_qsort = (pqsort)GetProcAddress(DllHandle, "qsort");
    }

    if (rtl_swprintf_s == NULL ||
        rtl_qsort == NULL)
    {
        DllHandle = GetModuleHandle(TEXT("msvcrt.dll"));
        if (DllHandle == NULL)
            DllHandle = LoadLibraryEx(TEXT("msvcrt.dll"), NULL, 0);

        if (DllHandle) {
            rtl_swprintf_s = (pswprintf_s)GetProcAddress(DllHandle, "swprintf_s");
            rtl_qsort = (pqsort)GetProcAddress(DllHandle, "qsort");
        }
    }

    return ((rtl_swprintf_s != NULL) && (rtl_qsort != NULL));
}

/*
* ShowInitError
*
* Purpose:
*
* Display initialization error depending on it type.
*
*/
VOID ShowInitError(
    _In_ DWORD ErrorType
)
{
    WCHAR szErrorBuffer[MAX_PATH * 2];
    LPWSTR lpError;

    //
    // CRT not initialized, no fancy swprinfs for you.
    //
    if (ErrorType == INIT_ERROR_NOCRT) {

        MessageBox(GetDesktopWindow(),
            (LPCWSTR)T_WOBJINIT_NOCRT,
            (LPCWSTR)PROGRAM_NAME,
            MB_ICONWARNING | MB_OK);

        return;
    }

    switch (ErrorType) {

    case INIT_ERROR_NOHEAP:
        lpError = L"Heap not allocated";
        break;

    case INIT_ERROR_NOTEMP:
        lpError = L"%temp% not resolved";
        break;

    case INIT_ERROR_NOWINDIR:
        lpError = L"Windows directory not resolved";
        break;

    case INIT_ERROR_NOSYS32DIR:
        lpError = L"System32 directory not resolved";
        break;

    case INIT_ERROR_NOPROGDIR:
        lpError = L"Program directory not resolved";
        break;

    case INIT_ERROR_NOCLASS:
        lpError = L"Main window class not registered";
        break;

    case INIT_ERROR_NOMAINWND:
        lpError = L"Main window not created";
        break;

    case INIT_ERROR_NOICCX:
        lpError = L"Common Controls Library";
        break;

    case INIT_ERROR_NOLISTWND:
        lpError = L"Main list window not created";
        break;

    case INIT_ERROR_NOTREEWND:
        lpError = L"Main tree window not created";
        break;

    case INIT_ERROR_NOTLBARWND:
        lpError = L"Main toolbar window not created";
        break;

    case INIT_ERROR_NOSPLITTERWND:
        lpError = L"Main splitter window not created";
        break;

    default:
        lpError = L"Unknown initialization error";
        break;
    }

    RtlStringCchPrintfSecure(szErrorBuffer,
        MAX_PATH * 2,
        TEXT("WinObjEx64 failed to initialize: %ws, abort"),
        lpError);

    MessageBox(GetDesktopWindow(),
        (LPWSTR)szErrorBuffer,
        (LPCWSTR)PROGRAM_NAME,
        MB_ICONWARNING | MB_OK);

}

/*
* WinObjExMain
*
* Purpose:
*
* Initialize subsystems, create windows and process message loop.
*
*/
UINT WinObjExMain()
{
    BOOLEAN bIsWine = FALSE, bIsFullAdmin = FALSE;
    UINT result = ERROR_SUCCESS;
    DWORD initResult;

    logCreate();

    bIsFullAdmin = ntsupUserIsFullAdmin();
    bIsWine = (is_wine() == 1);
    if (bIsWine) bIsFullAdmin = FALSE; // On Wine drop admin related features as they require driver.

    if (!InitMSVCRT()) {
        ShowInitError(INIT_ERROR_NOCRT);
        return ERROR_APP_INIT_FAILURE;
    }

    //
    // Wine 1.6 xenial does not support this routine.
    //
    if (bIsWine == FALSE) {
        RtlSetHeapInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0);
    }

    RtlSecureZeroMemory(&g_WinObj, sizeof(g_WinObj));
    initResult = guiInitGlobals(bIsWine, &g_WinObj);
    if (initResult != INIT_NO_ERROR) {
        ShowInitError(initResult);
        return ERROR_APP_INIT_FAILURE;
    }

    supInit(bIsFullAdmin);

    BeginTests();

    initResult = guiCreateMainWindowAndComponents(bIsFullAdmin, &g_WinObj);
    if (initResult != INIT_NO_ERROR) {
        ShowInitError(initResult);
        result = ERROR_APP_INIT_FAILURE;
    }
    else {

        SendMessage(g_hwndMain, WM_SIZE, 0, 0);

        g_WinObj.TreeListAtom = InitializeTreeListControl(); // Register treelist control class.

        guiInsertRunAsMainMenuEntry(bIsFullAdmin);

        guiExtrasDisableAdminFeatures(g_hwndMain); // Hide admin only stuff.

        guiSetMainMenuImages();

        PmCreate(g_hwndMain); // Plugin manager initialization

        guiCreateObjectListColumns();

        ListObjectDirectoryTree(KM_OBJECTS_ROOT_DIRECTORY, NULL, NULL);

        TreeView_SelectItem(g_hwndObjectTree, TreeView_GetRoot(g_hwndObjectTree));
        SetFocus(g_hwndObjectTree);

        result = guiProcessMainMessageLoop(g_WinObj.hInstance);
    }

    guiUnregisterClassAtoms();

    PmDestroy(); // Destroy plugin manager.

    //
    // Do not move anywhere.
    //
    supShutdown();
    logFree();

    EndTests();

    return result;
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
