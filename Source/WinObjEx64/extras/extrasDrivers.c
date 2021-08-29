/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2021
*
*  TITLE:       EXTRASDRIVERS.C
*
*  VERSION:     1.91
*
*  DATE:        10 Aug 2021
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "extras.h"
#include "extrasDrivers.h"

BOOLEAN g_DrvDlgShimsEnabled = FALSE;

#define ID_DRVLIST_DUMP     40001
#define ID_DRVLIST_SAVE     40002
#define ID_DRVLIST_PROP     ID_OBJECT_PROPERTIES
#define ID_DRVLIST_REFRESH  ID_VIEW_REFRESH

#define COLUMN_DRVLIST_LOAD_ORDER               0
#define COLUMN_DRVLIST_DRIVER_NAME              1
#define COLUMN_DRVLIST_DRIVER_ADDRESS           2
#define COLUMN_DRVLIST_SIZE                     3
#define COLUMN_DRVLIST_MODULE_NAME              4
#define COLUMN_DRVLIST_SHIMMED                  5

#define COLUMN_DRVLIST_UNLOADED_DRIVER_NAME     0
#define COLUMN_DRVLIST_UNLOADED_START_ADDRESS   1
#define COLUMN_DRVLIST_UNLOADED_END_ADDRESS     2
#define COLUMN_DRVLIST_UNLOADED_CURRENT_TIME    3


#define DRVLISTDLG_TRACKSIZE_MIN_X 640
#define DRVLISTDLG_TRACKSIZE_MIN_Y 480

EXTRASCONTEXT g_DriversDlgContext[DDM_Max];

/*
* DrvUpdateStatusBar
*
* Purpose:
*
* Update status bar information.
*
*/
VOID DrvUpdateStatusBar(
    _In_ EXTRASCONTEXT* Context,
    _In_ INT iItem)
{
    INT iSubItem;
    WCHAR szBuffer[MAX_PATH + 1];

    _strcpy(szBuffer, TEXT("Total: "));
    ultostr(ListView_GetItemCount(Context->ListView), _strend(szBuffer));
    supStatusBarSetText(Context->StatusBar, 0, (LPWSTR)&szBuffer);

    if (iItem >= 0) {

        if (Context->DialogMode == DDM_Normal)
            iSubItem = COLUMN_DRVLIST_DRIVER_NAME;
        else
            iSubItem = COLUMN_DRVLIST_UNLOADED_DRIVER_NAME;

        supGetItemText2(
            Context->ListView,
            iItem,
            iSubItem,
            szBuffer,
            MAX_PATH);

        supStatusBarSetText(Context->StatusBar, 1, (LPWSTR)&szBuffer);
    }
    else {
        supStatusBarSetText(Context->StatusBar, 1, (LPWSTR)T_EmptyString);
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
    _In_ HWND hwndDlg,
    _In_ LPPOINT lpPoint,
    _In_ PVOID lpUserParam
)
{
    HMENU hMenu;
    UINT uPos = 0;
    EXTRASCONTEXT* Context = (EXTRASCONTEXT*)lpUserParam;

    hMenu = CreatePopupMenu();
    if (hMenu) {

        if (supListViewAddCopyValueItem(hMenu,
            Context->ListView,
            ID_OBJECT_COPY,
            uPos,
            lpPoint,
            &Context->lvItemHit,
            &Context->lvColumnHit))
        {
            InsertMenu(hMenu, ++uPos, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
        }

        if (Context->DialogMode == DDM_Normal) {

            InsertMenu(hMenu, ++uPos, MF_BYCOMMAND, ID_DRVLIST_PROP, T_PROPERTIES);
            InsertMenu(hMenu, ++uPos, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
            if (kdConnectDriver()) {
                InsertMenu(hMenu, ++uPos, MF_BYCOMMAND, ID_DRVLIST_DUMP, T_DUMPDRIVER);
            }
            InsertMenu(hMenu, ++uPos, MF_BYCOMMAND, ID_JUMPTOFILE, T_JUMPTOFILE);

        }

        InsertMenu(hMenu, ++uPos, MF_BYCOMMAND, ID_DRVLIST_SAVE, T_EXPORTTOFILE);
        InsertMenu(hMenu, ++uPos, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
        InsertMenu(hMenu, ++uPos, MF_BYCOMMAND, ID_DRVLIST_REFRESH, T_VIEW_REFRESH);

        TrackPopupMenu(hMenu,
            TPM_RIGHTBUTTON | TPM_LEFTALIGN,
            lpPoint->x,
            lpPoint->y,
            0,
            hwndDlg,
            NULL);

        DestroyMenu(hMenu);
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
    _In_ EXTRASCONTEXT* Context
)
{
    LPWSTR  lpItem;
    INT     mark;
    WCHAR   szBuffer[MAX_PATH + 1];

    mark = ListView_GetSelectionMark(Context->ListView);
    if (mark >= 0) {

        lpItem = supGetItemText(Context->ListView, mark,
            COLUMN_DRVLIST_MODULE_NAME, NULL);

        if (lpItem) {
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            if (supGetWin32FileName(lpItem, szBuffer, MAX_PATH))
                supShowProperties(Context->hwndDlg, szBuffer);
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
    _In_ EXTRASCONTEXT* Context
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
        iPos = ListView_GetNextItem(Context->ListView, -1, LVNI_SELECTED);
        if (iPos < 0)
            break;

        //
        // Query selected driver name.
        //
        sz = 0;
        lpDriverName = supGetItemText(Context->ListView, iPos, 1, &sz);
        if (lpDriverName == NULL)
            break;

        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        _strncpy(szBuffer, MAX_PATH, lpDriverName, sz / sizeof(WCHAR));

        //
        // Run Save As Dialog.
        //
        if (!supSaveDialogExecute(Context->hwndDlg, szBuffer, TEXT("All files\0*.*\0\0")))
            break;

        //
        // Query driver address from listview.
        //
        RtlSecureZeroMemory(szDriverDumpInfo, sizeof(szDriverDumpInfo));
        supGetItemText2(
            Context->ListView,
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
            Context->ListView,
            iPos,
            3,
            szDriverDumpInfo,
            MAX_TEXT_CONVERSION_ULONG64);

        ImageSize = _strtoul(szDriverDumpInfo);
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

            supStatusBarSetText(Context->StatusBar, 1, (LPWSTR)&szBuffer);
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
    EXTRASCONTEXT* pDlgContext = (EXTRASCONTEXT*)lParamSort;

    if (pDlgContext == NULL)
        return 0;

    if (pDlgContext->DialogMode == DDM_Normal) {

        switch (pDlgContext->lvColumnToSort) {
        case COLUMN_DRVLIST_LOAD_ORDER: //Load Order
        case COLUMN_DRVLIST_SIZE: //Size
            return supGetMaxOfTwoULongFromString(
                pDlgContext->ListView,
                lParam1,
                lParam2,
                pDlgContext->lvColumnToSort,
                pDlgContext->bInverseSort);

        case COLUMN_DRVLIST_DRIVER_ADDRESS: //Address
            return supGetMaxOfTwoU64FromHex(
                pDlgContext->ListView,
                lParam1,
                lParam2,
                pDlgContext->lvColumnToSort,
                pDlgContext->bInverseSort);

        case COLUMN_DRVLIST_DRIVER_NAME: //Name
        case COLUMN_DRVLIST_MODULE_NAME: //Module
        case COLUMN_DRVLIST_SHIMMED: //Shimmed
            return supGetMaxCompareTwoFixedStrings(
                pDlgContext->ListView,
                lParam1,
                lParam2,
                pDlgContext->lvColumnToSort,
                pDlgContext->bInverseSort);
        }

    }
    else {

        switch (pDlgContext->lvColumnToSort) {
        case COLUMN_DRVLIST_UNLOADED_DRIVER_NAME: //Name
        case COLUMN_DRVLIST_UNLOADED_CURRENT_TIME: //CurrentTime
            return supGetMaxCompareTwoFixedStrings(
                pDlgContext->ListView,
                lParam1,
                lParam2,
                pDlgContext->lvColumnToSort,
                pDlgContext->bInverseSort);

        case COLUMN_DRVLIST_UNLOADED_START_ADDRESS: //StartAddress
        case COLUMN_DRVLIST_UNLOADED_END_ADDRESS: //EndAddress
            return supGetMaxOfTwoU64FromHex(
                pDlgContext->ListView,
                lParam1,
                lParam2,
                pDlgContext->lvColumnToSort,
                pDlgContext->bInverseSort);

        }
    }

    return 0;
}

/*
* DrvListUnloadedDrivers
*
* Purpose:
*
* Unloaded drivers query and list routine.
*
*/
VOID DrvListUnloadedDrivers(
    _In_ EXTRASCONTEXT* Context,
    _In_ BOOLEAN bRefresh
)
{
    BOOLEAN bValidName;
    ULONG   i;
    LPWSTR  lpName;
    HWND    hwndList = Context->ListView;
    INT     lvItemIndex, iImage;

    LVITEM lvitem;
    WCHAR  szBuffer[100];

    PUNLOADED_DRIVERS pvDrivers = NULL;

    if (bRefresh) {
        ListView_DeleteAllItems(hwndList);
    }

    if (!kdQueryMmUnloadedDrivers(&g_kdctx,
        (PVOID*)&pvDrivers))
    {
        _strcpy(szBuffer, TEXT("Could not resolve MmUnloadedDrivers"));
        supStatusBarSetText(Context->StatusBar, 1, (LPWSTR)&szBuffer);
        return;
    }

    iImage = ObManagerGetImageIndexByTypeIndex(ObjectTypeDriver);

    supListViewEnableRedraw(hwndList, FALSE);

    for (i = 0; i < MI_UNLOADED_DRIVERS; i++) {

        if (pvDrivers[i].StartAddress &&
            pvDrivers[i].EndAddress)
        {
            bValidName = NT_SUCCESS(ObIsValidUnicodeString(&pvDrivers[i].Name));

            if (!bValidName)
                lpName = T_Unknown;
            else
                lpName = pvDrivers[i].Name.Buffer;

            RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
            lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
            lvitem.iItem = MAXINT;
            lvitem.iImage = iImage;
            lvitem.pszText = lpName;

            lvItemIndex = ListView_InsertItem(hwndList, &lvitem);

            lvitem.pszText = szBuffer;

            //StartAddress
            szBuffer[0] = L'0';
            szBuffer[1] = L'x';
            szBuffer[2] = 0;
            u64tohex((ULONG_PTR)pvDrivers[i].StartAddress, &szBuffer[2]);
            lvitem.iSubItem = 1;
            lvitem.iItem = lvItemIndex;
            ListView_SetItem(hwndList, &lvitem);

            //EndAddress
            szBuffer[0] = L'0';
            szBuffer[1] = L'x';
            szBuffer[2] = 0;
            u64tohex((ULONG_PTR)pvDrivers[i].EndAddress, &szBuffer[2]);
            lvitem.iSubItem = 2;
            ListView_SetItem(hwndList, &lvitem);

            //CurrentTime
            szBuffer[0] = 0;
            supPrintTimeConverted(&pvDrivers[i].CurrentTime, szBuffer, RTL_NUMBER_OF(szBuffer));
            lvitem.iSubItem = 3;
            ListView_SetItem(hwndList, &lvitem);

            if (bValidName) RtlFreeUnicodeString(&pvDrivers[i].Name);

        }

    }

    DrvUpdateStatusBar(Context, -1);

    supHeapFree(pvDrivers);

    ListView_SortItemsEx(hwndList,
        &DrvDlgCompareFunc,
        (LPARAM)Context);

    supListViewEnableRedraw(hwndList, TRUE);
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
    _In_ EXTRASCONTEXT* Context,
    _In_ BOOLEAN bRefresh
)
{
    INT    lvItemIndex, iImage;
    ULONG  i;

    PCHAR  lpDriverName;
    HWND   hwndList = Context->ListView;

    LVITEM lvitem;
    WCHAR  szBuffer[MAX_PATH + 1];

    RTL_PROCESS_MODULES* pModulesList = NULL;
    PRTL_PROCESS_MODULE_INFORMATION pModule;

    if (bRefresh) {
        ListView_DeleteAllItems(hwndList);
        kdQueryKernelShims(&g_kdctx, TRUE);
    }

    pModulesList = (PRTL_PROCESS_MODULES)supGetLoadedModulesList(NULL);
    if (pModulesList == NULL)
        return;

    iImage = ObManagerGetImageIndexByTypeIndex(ObjectTypeDriver);

    supListViewEnableRedraw(hwndList, FALSE);

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
        lvItemIndex = ListView_InsertItem(hwndList, &lvitem);

        //Name
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

        //
        // Handle malformed result.
        //
        if (pModule->OffsetToFileName > RTL_NUMBER_OF(pModule->FullPathName)) {
            _strcpy(szBuffer, T_Unknown);
        }
        else {
            lpDriverName = (PCHAR)&pModule->FullPathName[pModule->OffsetToFileName];
            if (*lpDriverName == 0)
            {
                _strcpy(szBuffer, T_Unknown);
            }
            else {
                MultiByteToWideChar(
                    CP_ACP, 0,
                    (LPCSTR)lpDriverName,
                    -1,
                    szBuffer,
                    MAX_PATH);

            }
        }
        
        lvitem.mask = LVIF_TEXT;
        lvitem.iSubItem = 1;
        lvitem.pszText = szBuffer;
        lvitem.iItem = lvItemIndex;
        ListView_SetItem(hwndList, &lvitem);

        //Address
        szBuffer[0] = L'0';
        szBuffer[1] = L'x';
        szBuffer[2] = 0;
        u64tohex((ULONG_PTR)pModule->ImageBase, &szBuffer[2]);
        lvitem.iSubItem = 2;
        ListView_SetItem(hwndList, &lvitem);

        //Size
        szBuffer[0] = 0;
        ultostr(pModule->ImageSize, szBuffer);
        lvitem.iSubItem = 3;
        ListView_SetItem(hwndList, &lvitem);

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
        ListView_SetItem(hwndList, &lvitem);

        //Shimmed
        if (g_DrvDlgShimsEnabled) {

            szBuffer[0] = 0;

            if (supIsDriverShimmed(
                &g_kdctx.Data->KseEngineDump,
                pModule->ImageBase)) 
            {
                _strcpy(szBuffer, TEXT("Yes"));
            }

            lvitem.iSubItem = 5;
            ListView_SetItem(hwndList, &lvitem);

        }
    }

    supHeapFree(pModulesList);
    DrvUpdateStatusBar(Context, -1);

    ListView_SortItemsEx(hwndList,
        &DrvDlgCompareFunc,
        (LPARAM)Context);

    supListViewEnableRedraw(hwndList, TRUE);

}

/*
* DriversHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for Driver list dialogs.
*
*/
BOOL CALLBACK DriversHandleNotify(
    _In_ LPNMLISTVIEW NMListView,
    _In_ EXTRASCONTEXT* Context
)
{
    BOOL bHandled = TRUE;
    INT nImageIndex;


    if (NMListView->hdr.idFrom != ID_EXTRASLIST)
        return FALSE;

    switch (NMListView->hdr.code) {

    case LVN_COLUMNCLICK:

        Context->bInverseSort = !Context->bInverseSort;
        Context->lvColumnToSort = NMListView->iSubItem;

        ListView_SortItemsEx(Context->ListView,
            DrvDlgCompareFunc,
            Context);

        nImageIndex = ImageList_GetImageCount(g_ListViewImages);
        if (Context->bInverseSort)
            nImageIndex -= 2; //sort down/up images are always at the end of g_ListViewImages
        else
            nImageIndex -= 1;

        supUpdateLvColumnHeaderImage(
            Context->ListView,
            Context->lvColumnCount,
            Context->lvColumnToSort,
            nImageIndex);

        break;

    case NM_DBLCLK:
        DrvListViewProperties(Context);
        break;

    case NM_CLICK:
        DrvUpdateStatusBar(Context, NMListView->iItem);
        break;

    case LVN_ITEMCHANGED:

        if ((NMListView->uNewState & LVIS_SELECTED) &&
            !(NMListView->uOldState & LVIS_SELECTED))
        {
            DrvUpdateStatusBar(Context, NMListView->iItem);
        }

        break;
    default:
        bHandled = FALSE;
        break;
    }

    return bHandled;
}

/*
* DriversHandleWMCommand
*
* Purpose:
*
* WM_COMMAND handler.
*
*/
VOID DriversHandleWMCommand(
    _In_ HWND hwndDlg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    EXTRASCONTEXT* pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
    LPWSTR lpFileName;

    UNREFERENCED_PARAMETER(lParam);

    switch (GET_WM_COMMAND_ID(wParam, lParam)) {
    case ID_OBJECT_COPY:

        if (pDlgContext) {

            supListViewCopyItemValueToClipboard(pDlgContext->ListView,
                pDlgContext->lvItemHit,
                pDlgContext->lvColumnHit);

        }

        break;

    case IDCANCEL:
        SendMessage(hwndDlg, WM_CLOSE, 0, 0);
        break;

    case ID_DRVLIST_DUMP:
        DrvDumpDriver(pDlgContext);
        break;

    case ID_JUMPTOFILE:
        if (pDlgContext) {
            supJumpToFileListView(pDlgContext->ListView, COLUMN_DRVLIST_MODULE_NAME);
        }
        break;

    case ID_DRVLIST_SAVE:

        if (pDlgContext) {

            if (pDlgContext->DialogMode == DDM_Normal)
                lpFileName = TEXT("Drivers.csv");
            else
                lpFileName = TEXT("UnloadedDrivers.txt");

            if (supListViewExportToFile(
                lpFileName,
                hwndDlg,
                pDlgContext->ListView))
            {
                supStatusBarSetText(pDlgContext->StatusBar, 1, T_LIST_EXPORT_SUCCESS);
            }
        }
        break;

    case ID_DRVLIST_PROP:
        if (pDlgContext) {
            DrvListViewProperties(pDlgContext);
        }
        break;

    case ID_DRVLIST_REFRESH:
        if (pDlgContext) {

            if (pDlgContext->DialogMode == DDM_Normal) {

                DrvListDrivers(pDlgContext, TRUE);

            }
            else {

                DrvListUnloadedDrivers(pDlgContext, TRUE);

            }
        }
        break;

    default:
        break;
    }
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
    INT dlgIndex;
    EXTRASCONTEXT* pDlgContext;

    if (uMsg == g_WinObj.SettingsChangeMessage) {
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            extrasHandleSettingsChange(pDlgContext);
            return TRUE;
        }
    }

    switch (uMsg) {

    case WM_INITDIALOG:
        SetProp(hwndDlg, T_DLGCONTEXT, (HANDLE)lParam);
        supCenterWindow(hwndDlg);
        break;

    case WM_GETMINMAXINFO:
        if (lParam) {
            supSetMinMaxTrackSize((PMINMAXINFO)lParam,
                DRVLISTDLG_TRACKSIZE_MIN_X,
                DRVLISTDLG_TRACKSIZE_MIN_Y,
                TRUE);
        }
        break;

    case WM_NOTIFY:

        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            return (INT_PTR)DriversHandleNotify(
                (LPNMLISTVIEW)lParam,
                pDlgContext);
        }
        break;

    case WM_SIZE:
        extrasSimpleListResize(hwndDlg);
        break;

    case WM_CLOSE:
        pDlgContext = (EXTRASCONTEXT*)RemoveProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            extrasRemoveDlgIcon(pDlgContext);

            dlgIndex = 0;

            if (pDlgContext->DialogMode == DDM_Normal)
                dlgIndex = wobjDriversDlgId;
            else if (pDlgContext->DialogMode == DDM_Unloaded)
                dlgIndex = wobjUnloadedDriversDlgId;

            if ((dlgIndex == wobjDriversDlgId) ||
                (dlgIndex == wobjUnloadedDriversDlgId))
            {
                g_WinObj.AuxDialogs[dlgIndex] = NULL;
            }

            if (pDlgContext->DialogMode == DDM_Normal) {
                kdDestroyShimmedDriversList(&g_kdctx.Data->KseEngineDump);
            }

            RtlSecureZeroMemory(pDlgContext, sizeof(EXTRASCONTEXT));

        }
        return DestroyWindow(hwndDlg);

    case WM_COMMAND:

        DriversHandleWMCommand(hwndDlg, wParam, lParam);
        break;

    case WM_CONTEXTMENU:

        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            supHandleContextMenuMsgForListView(hwndDlg,
                wParam,
                lParam,
                pDlgContext->ListView,
                (pfnPopupMenuHandler)DrvHandlePopupMenu,
                pDlgContext);
        }
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
    _In_ HWND hwndParent,
    _In_ DRIVERS_DLG_MODE dialogMode
)
{
    INT dlgIndex;
    INT SbParts[] = { 100, -1 };
    INT iImage = ImageList_GetImageCount(g_ListViewImages) - 1, iColumn;

    ULONG columnsCount;
    HWND hwndDlg;
    EXTRASCONTEXT* pDlgContext;
    LPWSTR lpCaption;
    LVCOLUMNS_DATA* pvColumnsData;

    LVCOLUMNS_DATA columnDataDrvList[] =
    {
        { L"LoadOrder", 100, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT, iImage },
        { L"Name", 150, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT, I_IMAGENONE },
        { L"Address", 130, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT, I_IMAGENONE },
        { L"Size", 80, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT, I_IMAGENONE },
        { L"Image Path", 280, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT, I_IMAGENONE }
    };

    LVCOLUMNS_DATA columnsDataUnloadedDrvList[] = {
        { L"Name", 150, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT, iImage },
        { L"StartAddress", 140, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT, I_IMAGENONE },
        { L"EndAddress", 140, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT, I_IMAGENONE },
        { L"CurrentTime", 140, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT, I_IMAGENONE }
    };

    switch (dialogMode) {
    case DDM_Normal:
        dlgIndex = wobjDriversDlgId;
        lpCaption = TEXT("Drivers");
        pvColumnsData = columnDataDrvList;
        columnsCount = RTL_NUMBER_OF(columnDataDrvList);
        break;
    case DDM_Unloaded:
        dlgIndex = wobjUnloadedDriversDlgId;
        lpCaption = TEXT("Unloaded Drivers");
        pvColumnsData = columnsDataUnloadedDrvList;
        columnsCount = RTL_NUMBER_OF(columnsDataUnloadedDrvList);
        break;
    default:
        return;

    }

    //
    // Allow only one dialog per mode.
    //
    ENSURE_DIALOG_UNIQUE_WITH_RESTORE(g_WinObj.AuxDialogs[dlgIndex]);

    RtlSecureZeroMemory(&g_DriversDlgContext[dialogMode], sizeof(EXTRASCONTEXT));

    pDlgContext = &g_DriversDlgContext[dialogMode];
    pDlgContext->DialogMode = dialogMode;
    pDlgContext->lvColumnHit = -1;
    pDlgContext->lvItemHit = -1;

    hwndDlg = CreateDialogParam(g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_EXTRASLIST),
        hwndParent,
        &DriversDialogProc,
        (LPARAM)pDlgContext);

    if (hwndDlg == NULL) {
        //
        // Do not free context, it's local.
        //
        return;
    }

    pDlgContext->hwndDlg = hwndDlg;
    g_WinObj.AuxDialogs[dlgIndex] = hwndDlg;

    SetWindowText(hwndDlg, lpCaption);

    pDlgContext->StatusBar = GetDlgItem(hwndDlg, ID_EXTRASLIST_STATUSBAR);
    SendMessage(pDlgContext->StatusBar, SB_SETPARTS, 2, (LPARAM)&SbParts);

    extrasSetDlgIcon(pDlgContext);

    pDlgContext->ListView = GetDlgItem(hwndDlg, ID_EXTRASLIST);
    if (pDlgContext->ListView) {

        pDlgContext->lvColumnHit = -1;
        pDlgContext->lvItemHit = -1;

        //
        // Set listview imagelist, style flags and theme.
        //
        supSetListViewSettings(pDlgContext->ListView,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP,
            FALSE,
            TRUE,
            g_ListViewImages,
            LVSIL_SMALL);

        //
        // And columns and remember their count.
        //
        iColumn = supAddLVColumnsFromArray(
            pDlgContext->ListView,
            pvColumnsData,
            columnsCount);

        pDlgContext->lvColumnCount = iColumn;

        if (dialogMode == DDM_Normal) {

            //
            // Add "Shimmed" column on supported Windows version.
            //
            if (g_NtBuildNumber >= NT_WIN10_THRESHOLD1) {

                if (kdQueryKernelShims(&g_kdctx, FALSE)) {

                    supAddListViewColumn(pDlgContext->ListView,
                        iColumn,
                        iColumn,
                        iColumn,
                        I_IMAGENONE,
                        LVCFMT_CENTER | LVCFMT_BITMAP_ON_RIGHT,
                        TEXT("Shimmed"), 100);

                    g_DrvDlgShimsEnabled = TRUE;
                    pDlgContext->lvColumnCount += 1;
                }
            }

            DrvListDrivers(pDlgContext, FALSE);

        }
        else {

            DrvListUnloadedDrivers(pDlgContext, FALSE);

        }

        SendMessage(hwndDlg, WM_SIZE, 0, 0);
        SetFocus(pDlgContext->ListView);
    }
}
