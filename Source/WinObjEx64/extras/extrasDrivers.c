/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2020
*
*  TITLE:       EXTRASDRIVERS.C
*
*  VERSION:     1.87
*
*  DATE:        27 June 2020
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "extras.h"

EXTRASCONTEXT DrvDlgContext;
BOOLEAN g_DrvDlgShimsEnabled = FALSE;

#define ID_DRVLIST_DUMP     40001
#define ID_DRVLIST_SAVE     40002
#define ID_DRVLIST_PROP     ID_OBJECT_PROPERTIES
#define ID_DRVLIST_REFRESH  ID_VIEW_REFRESH

#define DRVLIST_FILENAME_COLUMN_INDEX 4


/*
* DrvUpdateStatusBar
*
* Purpose:
*
* Update status bar information.
*
*/
VOID DrvUpdateStatusBar(
    _In_ INT iItem)
{
    WCHAR szBuffer[MAX_PATH + 1];

    _strcpy(szBuffer, TEXT("Total: "));
    ultostr(ListView_GetItemCount(DrvDlgContext.ListView), _strend(szBuffer));
    supStatusBarSetText(DrvDlgContext.StatusBar, 0, (LPWSTR)&szBuffer);

    if (iItem >= 0) {

        supGetItemText2(
            DrvDlgContext.ListView,
            iItem,
            1,
            szBuffer,
            MAX_PATH);

        supStatusBarSetText(DrvDlgContext.StatusBar, 1, (LPWSTR)&szBuffer);
    }
}

/*
* DrvHandlePopupMenu
*
* Purpose:
*
* Table list popup construction.
*
*/
VOID DrvHandlePopupMenu(
    _In_ HWND hwndDlg
)
{
    POINT pt1;
    HMENU hMenu;
    UINT iPos = 0;

    if (GetCursorPos(&pt1)) {
        hMenu = CreatePopupMenu();
        if (hMenu) {
            InsertMenu(hMenu, iPos++, MF_BYCOMMAND, ID_DRVLIST_PROP, T_PROPERTIES);
            InsertMenu(hMenu, iPos++, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
            if (kdConnectDriver()) {
                InsertMenu(hMenu, iPos++, MF_BYCOMMAND, ID_DRVLIST_DUMP, T_DUMPDRIVER);
            }
            InsertMenu(hMenu, iPos++, MF_BYCOMMAND, ID_JUMPTOFILE, T_JUMPTOFILE);
            InsertMenu(hMenu, iPos++, MF_BYCOMMAND, ID_DRVLIST_SAVE, T_EXPORTTOFILE);
            InsertMenu(hMenu, iPos++, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
            InsertMenu(hMenu, iPos++, MF_BYCOMMAND, ID_DRVLIST_REFRESH, T_VIEW_REFRESH);
            TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, pt1.x, pt1.y, 0, hwndDlg, NULL);
            DestroyMenu(hMenu);
        }
    }
}

/*
* DrvListViewProperties
*
* Purpose:
*
* View selected driver file properties.
*
*/
VOID DrvListViewProperties(
    VOID)
{
    LPWSTR  lpItem;
    INT     mark;
    WCHAR   szBuffer[MAX_PATH + 1];

    mark = ListView_GetSelectionMark(DrvDlgContext.ListView);
    if (mark >= 0) {

        lpItem = supGetItemText(DrvDlgContext.ListView, mark,
            DRVLIST_FILENAME_COLUMN_INDEX, NULL);

        if (lpItem) {
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            if (supGetWin32FileName(lpItem, szBuffer, MAX_PATH))
                supShowProperties(DrvDlgContext.hwndDlg, szBuffer);
            supHeapFree(lpItem);
        }
    }
}

/*
* DrvDumpDriver
*
* Purpose:
*
* Read driver from memory and write to disk, ignore read errors
*
*/
VOID DrvDumpDriver(
    VOID
)
{
    BOOL      bSuccess = FALSE;
    INT       iPos;
    ULONG     ImageSize;
    SIZE_T    sz;
    LPWSTR    lpDriverName = NULL;
    PVOID     DumpedDrv = NULL;
    ULONG_PTR ImageBase = 0;
    WCHAR     szBuffer[MAX_PATH * 2], szDriverDumpInfo[MAX_TEXT_CONVERSION_ULONG64 + 1];

    do {
        //
        // Remember selected index.
        //
        iPos = ListView_GetNextItem(DrvDlgContext.ListView, -1, LVNI_SELECTED);
        if (iPos < 0)
            break;

        //
        // Query selected driver name.
        //
        sz = 0;
        lpDriverName = supGetItemText(DrvDlgContext.ListView, iPos, 1, &sz);
        if (lpDriverName == NULL)
            break;

        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        _strncpy(szBuffer, MAX_PATH, lpDriverName, sz / sizeof(WCHAR));

        //
        // Run Save As Dialog.
        //
        if (!supSaveDialogExecute(DrvDlgContext.hwndDlg, szBuffer, TEXT("All files\0*.*\0\0")))
            break;

        //
        // Query driver address from listview.
        //
        RtlSecureZeroMemory(szDriverDumpInfo, sizeof(szDriverDumpInfo));
        supGetItemText2(
            DrvDlgContext.ListView,
            iPos,
            2,
            szDriverDumpInfo,
            MAX_TEXT_CONVERSION_ULONG64);

        ImageBase = hextou64(&szDriverDumpInfo[2]);
        if (ImageBase < g_kdctx.SystemRangeStart)
            break;

        //
        // Query driver size from listview.
        //
        RtlSecureZeroMemory(szDriverDumpInfo, sizeof(szDriverDumpInfo));
        supGetItemText2(
            DrvDlgContext.ListView,
            iPos,
            3,
            szDriverDumpInfo,
            MAX_TEXT_CONVERSION_ULONG64);

        ImageSize = strtoul(szDriverDumpInfo);
        if (ImageSize == 0)
            break;

        //
        // Allocate buffer for dump and read kernel memory.
        //
        DumpedDrv = supVirtualAlloc((SIZE_T)ImageSize);
        if (DumpedDrv) {

            supSetWaitCursor(TRUE);

            //
            // Ignore read errors during dump.
            //
            bSuccess = kdReadSystemMemory(ImageBase, DumpedDrv, ImageSize);
            supSetWaitCursor(FALSE);

            if (supWriteBufferToFile(szBuffer, DumpedDrv, ImageSize, FALSE, FALSE) == ImageSize)
                _strcpy(szBuffer, TEXT("Driver saved to disk"));
            else
                _strcpy(szBuffer, TEXT("Driver save to disk error"));

            //
            // Free allocated buffer.
            //
            supVirtualFree(DumpedDrv);

            _strcat(szBuffer, TEXT(", kernel memory read was "));
            if (bSuccess)
                _strcat(szBuffer, TEXT("successful"));
            else
                _strcat(szBuffer, TEXT("partially successful"));

            supStatusBarSetText(DrvDlgContext.StatusBar, 1, (LPWSTR)&szBuffer);
        }

    } while (FALSE);

    if (lpDriverName) supHeapFree(lpDriverName);
}

/*
* DrvDlgCompareFunc
*
* Purpose:
*
* Drivers Dialog listview comparer function.
*
*/
INT CALLBACK DrvDlgCompareFunc(
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort
)
{
    INT nResult = 0;

    switch (lParamSort) {
    case 0: //Load Order
    case 3: //Size
        return supGetMaxOfTwoULongFromString(
            DrvDlgContext.ListView,
            lParam1,
            lParam2,
            lParamSort,
            DrvDlgContext.bInverseSort);

    case 2: //Address
        return supGetMaxOfTwoU64FromHex(
            DrvDlgContext.ListView,
            lParam1,
            lParam2,
            lParamSort,
            DrvDlgContext.bInverseSort);

    case 1: //Name
    case 4: //Module
    case 5: //Shimmed
        return supGetMaxCompareTwoFixedStrings(
            DrvDlgContext.ListView,
            lParam1,
            lParam2,
            lParamSort,
            DrvDlgContext.bInverseSort);
    }

    return nResult;
}

/*
* DrvListDrivers
*
* Purpose:
*
* Drivers query and list routine.
*
*/
VOID DrvListDrivers(
    _In_ BOOL bRefresh
)
{
    INT    lvItemIndex, iImage;
    ULONG  i;
    LVITEM lvitem;
    WCHAR  szBuffer[MAX_PATH + 1];

    RTL_PROCESS_MODULES* pModulesList = NULL;
    PRTL_PROCESS_MODULE_INFORMATION pModule;

    if (bRefresh) {
        ListView_DeleteAllItems(DrvDlgContext.ListView);
        kdQueryKernelShims(&g_kdctx, TRUE);
    }

    do {
        pModulesList = (PRTL_PROCESS_MODULES)supGetSystemInfo(SystemModuleInformation, NULL);
        if (pModulesList == NULL)
            break;

        iImage = ObManagerGetImageIndexByTypeIndex(ObjectTypeDriver);

        for (i = 0; i < pModulesList->NumberOfModules; i++) {

            pModule = &pModulesList->Modules[i];

            if ((ULONG_PTR)pModule->ImageBase < g_kdctx.SystemRangeStart)
                continue;

            RtlSecureZeroMemory(&lvitem, sizeof(lvitem));

            //LoadOrder
            szBuffer[0] = 0;
            ultostr(pModule->LoadOrderIndex, szBuffer);

            lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
            lvitem.iItem = MAXINT;
            lvitem.iImage = iImage;
            lvitem.pszText = szBuffer;
            lvItemIndex = ListView_InsertItem(DrvDlgContext.ListView, &lvitem);

            //Name
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

            MultiByteToWideChar(
                CP_ACP, 0,
                (LPCSTR)&pModule->FullPathName[pModule->OffsetToFileName],
                -1,
                szBuffer,
                MAX_PATH);

            lvitem.mask = LVIF_TEXT;
            lvitem.iSubItem = 1;
            lvitem.pszText = szBuffer;
            lvitem.iItem = lvItemIndex;
            ListView_SetItem(DrvDlgContext.ListView, &lvitem);

            //Address
            szBuffer[0] = L'0';
            szBuffer[1] = L'x';
            szBuffer[2] = 0;
            u64tohex((ULONG_PTR)pModule->ImageBase, &szBuffer[2]);
            lvitem.iSubItem = 2;
            ListView_SetItem(DrvDlgContext.ListView, &lvitem);

            //Size
            szBuffer[0] = 0;
            ultostr(pModule->ImageSize, szBuffer);
            lvitem.iSubItem = 3;
            ListView_SetItem(DrvDlgContext.ListView, &lvitem);

            //FullName
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

            MultiByteToWideChar(
                CP_ACP,
                0,
                (LPCSTR)&pModule->FullPathName,
                -1,
                szBuffer,
                MAX_PATH);

            lvitem.iSubItem = 4;
            ListView_SetItem(DrvDlgContext.ListView, &lvitem);

            //Shimmed
            if (g_DrvDlgShimsEnabled) {

                szBuffer[0] = 0;

                if (supIsDriverShimmed(pModule->ImageBase)) {
                    _strcpy(szBuffer, TEXT("Yes"));
                }

                lvitem.iSubItem = 5;
                ListView_SetItem(DrvDlgContext.ListView, &lvitem);

            }
        }

        DrvUpdateStatusBar(-1);

    } while (FALSE);

    if (pModulesList) supHeapFree(pModulesList);

    ListView_SortItemsEx(DrvDlgContext.ListView, &DrvDlgCompareFunc, DrvDlgContext.lvColumnToSort);
}

/*
* DriversHandleNotify
*
* Purpose:
*
* Common WM_NOTIFY processing for Driver list dialogs.
*
*/
BOOL CALLBACK DriversHandleNotify(
    _In_ LPNMLISTVIEW nhdr,
    _In_ EXTRASCONTEXT* Context,
    _In_opt_ PVOID CustomParameter
)
{
    BOOL    bHandled = TRUE;

    UNREFERENCED_PARAMETER(CustomParameter);

    if ((nhdr == NULL) || (Context == NULL))
        return FALSE;

    if (nhdr->hdr.idFrom != ID_EXTRASLIST)
        return FALSE;

    switch (nhdr->hdr.code) {
    case NM_DBLCLK:
        DrvListViewProperties();
        break;
    case NM_CLICK:       
    case LVN_ITEMCHANGED:
        DrvUpdateStatusBar(nhdr->iItem);
        break;
    default:
        bHandled = FALSE;
        break;
    }

    return bHandled;
}

/*
* DriversDialogProc
*
* Purpose:
*
* Drivers Dialog window procedure.
*
*/
INT_PTR CALLBACK DriversDialogProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam
)
{
    LPNMLISTVIEW nhdr = (LPNMLISTVIEW)lParam;

    switch (uMsg) {

    case WM_INITDIALOG:
        supCenterWindow(hwndDlg);
        break;

    case WM_GETMINMAXINFO:
        if (lParam) {
            ((PMINMAXINFO)lParam)->ptMinTrackSize.x = 640;
            ((PMINMAXINFO)lParam)->ptMinTrackSize.y = 480;
        }
        break;

    case WM_NOTIFY:

        return (INT_PTR)extrasDlgHandleNotify(nhdr,
            &DrvDlgContext,
            &DrvDlgCompareFunc,
            DriversHandleNotify,
            NULL);

    case WM_SIZE:
        extrasSimpleListResize(hwndDlg);
        break;

    case WM_CLOSE:
        DestroyWindow(hwndDlg);
        g_WinObj.AuxDialogs[wobjDriversDlgId] = NULL;
        supDestroyShimmedDriversList(&g_kdctx.KseEngineDump.ShimmedDriversDumpListHead);
        break;

    case WM_COMMAND:

        switch (GET_WM_COMMAND_ID(wParam, lParam)) {
        case IDCANCEL:
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            break;
        case ID_DRVLIST_DUMP:
            DrvDumpDriver();
            break;
        case ID_JUMPTOFILE:
            supJumpToFileListView(DrvDlgContext.ListView, 4);
            break;
        case ID_DRVLIST_SAVE:

            if (supListViewExportToFile(
                TEXT("Drivers.csv"),
                hwndDlg,
                DrvDlgContext.ListView))
            {
                supStatusBarSetText(DrvDlgContext.StatusBar, 1, T_LIST_EXPORT_SUCCESS);
            }
            break;

        case ID_DRVLIST_PROP:
            DrvListViewProperties();
            break;
        case ID_DRVLIST_REFRESH:
            DrvListDrivers(TRUE);
            break;
        default:
            break;
        }
        break;

    case WM_CONTEXTMENU:
        DrvHandlePopupMenu(hwndDlg);
        break;

    default:
        return FALSE;
    }

    return TRUE;
}

/*
* extrasCreateDriversDialog
*
* Purpose:
*
* Create and initialize Drivers Dialog.
*
*/
VOID extrasCreateDriversDialog(
    _In_ HWND hwndParent
)
{
    INT SbParts[] = { 100, -1 };

    //
    // Allow only one dialog.
    //
    ENSURE_DIALOG_UNIQUE_WITH_RESTORE(g_WinObj.AuxDialogs[wobjDriversDlgId]);

    RtlSecureZeroMemory(&DrvDlgContext, sizeof(DrvDlgContext));
    DrvDlgContext.hwndDlg = CreateDialogParam(g_WinObj.hInstance, MAKEINTRESOURCE(IDD_DIALOG_EXTRASLIST),
        hwndParent, &DriversDialogProc, 0);

    if (DrvDlgContext.hwndDlg == NULL)
        return;

    g_WinObj.AuxDialogs[wobjDriversDlgId] = DrvDlgContext.hwndDlg;

    SetWindowText(DrvDlgContext.hwndDlg, TEXT("Drivers"));

    DrvDlgContext.StatusBar = GetDlgItem(DrvDlgContext.hwndDlg, ID_EXTRASLIST_STATUSBAR);
    SendMessage(DrvDlgContext.StatusBar, SB_SETPARTS, 2, (LPARAM)&SbParts);

    extrasSetDlgIcon(DrvDlgContext.hwndDlg);

    DrvDlgContext.ListView = GetDlgItem(DrvDlgContext.hwndDlg, ID_EXTRASLIST);
    if (DrvDlgContext.ListView) {

        //
        // Set listview imagelist, style flags and theme.
        //
        ListView_SetImageList(DrvDlgContext.ListView, g_ListViewImages, LVSIL_SMALL);
        ListView_SetExtendedListViewStyle(DrvDlgContext.ListView,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

        SetWindowTheme(DrvDlgContext.ListView, TEXT("Explorer"), NULL);

        //
        // Add listview columns.
        //

        supAddListViewColumn(DrvDlgContext.ListView, 0, 0, 0,
            ImageList_GetImageCount(g_ListViewImages) - 1,
            LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
            TEXT("LoadOrder"), 100);

        supAddListViewColumn(DrvDlgContext.ListView, 1, 1, 1,
            I_IMAGENONE,
            LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
            TEXT("Name"), 150);

        supAddListViewColumn(DrvDlgContext.ListView, 2, 2, 2,
            I_IMAGENONE,
            LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
            TEXT("Address"), 130);

        supAddListViewColumn(DrvDlgContext.ListView, 3, 3, 3,
            I_IMAGENONE,
            LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
            TEXT("Size"), 80);

        supAddListViewColumn(DrvDlgContext.ListView, 4, 4, 4,
            I_IMAGENONE,
            LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
            TEXT("Image Path"), 280);

        //
        // Remember columns count.
        //
        DrvDlgContext.lvColumnCount = DRVLIST_COLUMN_COUNT;

        //
        // Add "Shimmed" column on supported Windows version.
        //
        if (g_NtBuildNumber >= NT_WIN10_THRESHOLD1) {

            if (kdQueryKernelShims(&g_kdctx, FALSE)) {

                supAddListViewColumn(DrvDlgContext.ListView, 5, 5, 5,
                    I_IMAGENONE,
                    LVCFMT_CENTER | LVCFMT_BITMAP_ON_RIGHT,
                    TEXT("Shimmed"), 100);

                g_DrvDlgShimsEnabled = TRUE;
                DrvDlgContext.lvColumnCount = DRVLIST_COLUMN_COUNT + 1;
            }
        }

        DrvListDrivers(FALSE);
        SendMessage(DrvDlgContext.hwndDlg, WM_SIZE, 0, 0);
        SetFocus(DrvDlgContext.ListView);
    }
}
