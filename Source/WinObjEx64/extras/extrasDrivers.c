/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2022
*
*  TITLE:       EXTRASDRIVERS.C
*
*  VERSION:     1.94
*
*  DATE:        04 Jun 2022
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

BOOLEAN DrvDlgShimsEnabled = FALSE;

#define ID_DRVLIST_DUMP     40001
#define ID_DRVLIST_SAVE     40002
#define ID_DRVLIST_PROP     ID_OBJECT_PROPERTIES
#define ID_DRVLIST_REFRESH  ID_VIEW_REFRESH

#define ID_CALC_HASH_MD5            6000
#define ID_CALC_HASH_SHA1           6001
#define ID_CALC_HASH_SHA256         6002
#define ID_CALC_HASH_SHA384         6003
#define ID_CALC_HASH_SHA512         6004
#define ID_CALC_HASH_PAGE_SHA1      6005
#define ID_CALC_HASH_PAGE_SHA256    6006

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

static EXTRASCONTEXT DrvDlgContext[DrvModeMax];
static HANDLE DrvDlgThreadHandles[DrvModeMax] = { NULL, NULL };
static FAST_EVENT DrvDlgInitializedEvents[DrvModeMax] = { FAST_EVENT_INIT, FAST_EVENT_INIT };
static ULONG g_cDrvShimmed = 0;

LPCWSTR CryptAlgoIdRef[] = {
    BCRYPT_MD5_ALGORITHM,
    BCRYPT_SHA1_ALGORITHM,
    BCRYPT_SHA256_ALGORITHM,
    BCRYPT_SHA384_ALGORITHM,
    BCRYPT_SHA512_ALGORITHM
};

/*
* DrvListCopyHash
*
* Purpose:
*
* Copy hash menu handler.
*
*/
VOID DrvListCopyHash(
    _In_ EXTRASCONTEXT* Context,
    _In_ UINT MenuId
)
{
    INT         mark;
    NTSTATUS    ntStatus;
    LPWSTR      lpItem, lpszHash = NULL;
    WCHAR       szBuffer[MAX_PATH + 1];

    FILE_VIEW_INFO fvi;

    if (ListView_GetSelectedCount(Context->ListView) == 0)
        return;

    mark = ListView_GetSelectionMark(Context->ListView);
    if (mark < 0)
        return;

    lpItem = supGetItemText(Context->ListView, mark,
        COLUMN_DRVLIST_MODULE_NAME, NULL);

    if (lpItem == NULL)
        return;

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    if (supGetWin32FileName(lpItem, szBuffer, MAX_PATH)) {

        RtlSecureZeroMemory(&fvi, sizeof(fvi));

        fvi.FileName = szBuffer;

        ntStatus = HashLoadFile(&fvi, FALSE);
        if (NT_SUCCESS(ntStatus)) {

            if (MenuId >= ID_CALC_HASH_PAGE_SHA1 && MenuId <= ID_CALC_HASH_PAGE_SHA256) {

                lpszHash = ComputeHashForFile(&fvi,
                    (MenuId == ID_CALC_HASH_PAGE_SHA1) ? BCRYPT_SHA1_ALGORITHM : BCRYPT_SHA256_ALGORITHM,
                    PAGE_SIZE,
                    g_WinObj.Heap,
                    TRUE);

            }
            else if (MenuId >= ID_CALC_HASH_MD5 && MenuId <= ID_CALC_HASH_SHA512) {

                lpszHash = ComputeHashForFile(&fvi,
                    CryptAlgoIdRef[MenuId - ID_CALC_HASH_MD5],
                    PAGE_SIZE,
                    g_WinObj.Heap,
                    FALSE);
            }

            HashUnloadFile(&fvi);
        }
        else {
            supShowNtStatus(Context->hwndDlg, TEXT("Error loading file, NTSTATUS: "), ntStatus);
        }
    }

    supHeapFree(lpItem);

    if (lpszHash) {
        supClipboardCopy(lpszHash, _strlen(lpszHash) * sizeof(WCHAR));
        supHeapFree(lpszHash);
    }

}

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
    INT sbParts[] = { 100, -1 };
    WCHAR szBuffer[MAX_PATH];

    _strcpy(szBuffer, TEXT("Total: "));
    ultostr(ListView_GetItemCount(Context->ListView), _strend(szBuffer));

    //
    // Add "shimmed" drivers count for normal dialog mode.
    //
    if (Context->DialogMode == DrvModeNormal) {
        if (g_cDrvShimmed) {
            _strcat(szBuffer, TEXT(", Shimmed: "));
            ultostr(g_cDrvShimmed, _strend(szBuffer));
            sbParts[0] = 240;
        }
    }

    SendMessage(Context->StatusBar, SB_SETPARTS, 2, (LPARAM)&sbParts);
    supStatusBarSetText(Context->StatusBar, 0, (LPWSTR)&szBuffer);

    if (iItem >= 0) {

        if (Context->DialogMode == DrvModeNormal)
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
    UINT uPos = 0, i;
    EXTRASCONTEXT* Context = (EXTRASCONTEXT*)lpUserParam;
    WCHAR szMenuText[MAX_PATH + 1];

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

        if (Context->DialogMode == DrvModeNormal) {

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

        if (Context->DialogMode == DrvModeNormal) {
            //
            // Hashes.
            //
            InsertMenu(hMenu, ++uPos, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
            for (i = ID_CALC_HASH_MD5; i < ID_CALC_HASH_PAGE_SHA1; i++) {
                RtlStringCchPrintfSecure(szMenuText,
                    MAX_PATH,
                    TEXT("Copy Authenticode %ws hash"),
                    CryptAlgoIdRef[i - ID_CALC_HASH_MD5]);
                InsertMenu(hMenu, ++uPos, MF_BYCOMMAND, i, szMenuText);
            }

            InsertMenu(hMenu, ++uPos, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);

            RtlStringCchPrintfSecure(szMenuText,
                MAX_PATH,
                TEXT("Copy %ws page hash"),
                BCRYPT_SHA1_ALGORITHM);

            InsertMenu(hMenu, ++uPos, MF_BYCOMMAND, ID_CALC_HASH_PAGE_SHA1, szMenuText);

            RtlStringCchPrintfSecure(szMenuText,
                MAX_PATH,
                TEXT("Copy %ws page hash"),
                BCRYPT_SHA256_ALGORITHM);

            InsertMenu(hMenu, ++uPos, MF_BYCOMMAND, ID_CALC_HASH_PAGE_SHA256, szMenuText);

        }

        //
        // Track.
        //
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

    if (ListView_GetSelectedCount(Context->ListView)) {
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
            COLUMN_DRVLIST_DRIVER_ADDRESS,
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
            COLUMN_DRVLIST_SIZE,
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

    if (pDlgContext->DialogMode == DrvModeNormal) {

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
* DrvListCbEnumerateUnloadedDrivers
*
* Purpose:
*
* Unloaded drivers enumeration callback.
*
*/
BOOL DrvListCbEnumerateUnloadedDrivers(
    _In_ PUNLOADED_DRIVERS Entry,
    _In_ EXTRASCONTEXT* Context
)
{
    INT     lvItemIndex;
    LPWSTR  lpName;
    HWND    hwndList;
    LVITEM  lvitem;
    WCHAR   szBuffer[100];

    hwndList = Context->ListView;

    if (Entry->StartAddress && Entry->EndAddress) {

        if (!NT_SUCCESS(ObIsValidUnicodeString(&Entry->Name)))
            lpName = T_Unknown;
        else
            lpName = Entry->Name.Buffer;

        RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
        lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
        lvitem.iItem = MAXINT;
        lvitem.iImage = g_TypeDriver.ImageIndex;
        lvitem.pszText = lpName;

        lvItemIndex = ListView_InsertItem(hwndList, &lvitem);

        lvitem.pszText = szBuffer;

        //StartAddress
        szBuffer[0] = L'0';
        szBuffer[1] = L'x';
        szBuffer[2] = 0;
        u64tohex((ULONG_PTR)Entry->StartAddress, &szBuffer[2]);
        lvitem.iSubItem = 1;
        lvitem.iItem = lvItemIndex;
        ListView_SetItem(hwndList, &lvitem);

        //EndAddress
        szBuffer[0] = L'0';
        szBuffer[1] = L'x';
        szBuffer[2] = 0;
        u64tohex((ULONG_PTR)Entry->EndAddress, &szBuffer[2]);
        lvitem.iSubItem = 2;
        ListView_SetItem(hwndList, &lvitem);

        //CurrentTime
        szBuffer[0] = 0;
        supPrintTimeConverted(&Entry->CurrentTime, szBuffer, RTL_NUMBER_OF(szBuffer));
        lvitem.iSubItem = 3;
        ListView_SetItem(hwndList, &lvitem);

    }

    return FALSE;
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
    HWND    hwndList = Context->ListView;
    WCHAR  szBuffer[100];

    if (bRefresh) {
        ListView_DeleteAllItems(hwndList);
    }

    supListViewEnableRedraw(hwndList, FALSE);

    if (!kdEnumerateMmUnloadedDrivers(
        (PENUMERATE_UNLOADED_DRIVERS_CALLBACK)DrvListCbEnumerateUnloadedDrivers,
        (PVOID)Context))
    {
        _strcpy(szBuffer, TEXT("Could not resolve MmUnloadedDrivers"));
        supStatusBarSetText(Context->StatusBar, 1, (LPWSTR)&szBuffer);
        return;
    }

    DrvUpdateStatusBar(Context, -1);

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
    INT    lvItemIndex;
    ULONG  i;

    PCHAR  lpDriverName;
    HWND   hwndList = Context->ListView;

    LVITEM lvitem;
    WCHAR  szBuffer[MAX_PATH + 1];

    RTL_PROCESS_MODULES* pModulesList = NULL;
    PRTL_PROCESS_MODULE_INFORMATION pModule;

    g_cDrvShimmed = 0;

    if (bRefresh) {
        ListView_DeleteAllItems(hwndList);
        kdQueryKernelShims(&g_kdctx, TRUE);
    }

    pModulesList = (PRTL_PROCESS_MODULES)supGetLoadedModulesList(NULL);
    if (pModulesList == NULL)
        return;

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
        lvitem.iImage = g_TypeDriver.ImageIndex;
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
        if (DrvDlgShimsEnabled) {

            szBuffer[0] = 0;

            if (supIsDriverShimmed(
                &g_kdctx.Data->KseEngineDump,
                pModule->ImageBase))
            {
                g_cDrvShimmed += 1;
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
* DrvDlgHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for Driver list dialogs.
*
*/
BOOL CALLBACK DrvDlgHandleNotify(
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

        Context->bInverseSort = (~Context->bInverseSort) & 1;
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
* DrvDlgHandleWMCommand
*
* Purpose:
*
* WM_COMMAND handler.
*
*/
VOID DrvDlgHandleWMCommand(
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

            if (pDlgContext->DialogMode == DrvModeNormal)
                lpFileName = TEXT("Drivers.csv");
            else
                lpFileName = TEXT("UnloadedDrivers.csv");

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

            if (pDlgContext->DialogMode == DrvModeNormal) {

                DrvListDrivers(pDlgContext, TRUE);

            }
            else {

                DrvListUnloadedDrivers(pDlgContext, TRUE);

            }
        }
        break;

    case ID_CALC_HASH_MD5:
    case ID_CALC_HASH_SHA1:
    case ID_CALC_HASH_SHA256:
    case ID_CALC_HASH_SHA384:
    case ID_CALC_HASH_SHA512:
    case ID_CALC_HASH_PAGE_SHA1:
    case ID_CALC_HASH_PAGE_SHA256:
        DrvListCopyHash(pDlgContext, LOWORD(wParam));
        break;

    }
}

/*
* DrvDlgOnInit
*
* Purpose:
*
* Drivers Dialog WM_INITDIALOG handler.
*
*/
VOID DrvDlgOnInit(
    _In_ HWND hwndDlg,
    _In_ LPARAM lParam
)
{
    INT iImage = ImageList_GetImageCount(g_ListViewImages) - 1, iColumn;
    EXTRASCONTEXT* pDlgContext = (EXTRASCONTEXT*)lParam;

    LVCOLUMNS_DATA* pvColumnsData;
    ULONG columnsCount;
    LPWSTR lpCaption;

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

    SetProp(hwndDlg, T_DLGCONTEXT, (HANDLE)lParam);
    supCenterWindowSpecifyParent(hwndDlg, g_WinObj.MainWindow);

    pDlgContext->hwndDlg = hwndDlg;
    pDlgContext->lvColumnHit = -1;
    pDlgContext->lvItemHit = -1;

    switch (pDlgContext->DialogMode) {
    case DrvModeUnloaded:
        lpCaption = TEXT("Unloaded Drivers");
        pvColumnsData = columnsDataUnloadedDrvList;
        columnsCount = RTL_NUMBER_OF(columnsDataUnloadedDrvList);
        break;
    default:
        lpCaption = TEXT("Drivers");
        pvColumnsData = columnDataDrvList;
        columnsCount = RTL_NUMBER_OF(columnDataDrvList);
        break;
    }

    SetWindowText(hwndDlg, lpCaption);

    pDlgContext->StatusBar = GetDlgItem(hwndDlg, ID_EXTRASLIST_STATUSBAR);

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

        if (pDlgContext->DialogMode == DrvModeNormal) {

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

                    DrvDlgShimsEnabled = TRUE;
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

/*
* DrvDlgProc
*
* Purpose:
*
* Drivers Dialog window procedure.
*
*/
INT_PTR CALLBACK DrvDlgProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
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
        DrvDlgOnInit(hwndDlg, lParam);
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
            DrvDlgHandleNotify(
                (LPNMLISTVIEW)lParam,
                pDlgContext);
        }
        break;

    case WM_SIZE:
        extrasSimpleListResize(hwndDlg);
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    case WM_CLOSE:
        pDlgContext = (EXTRASCONTEXT*)RemoveProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            extrasRemoveDlgIcon(pDlgContext);

            if (pDlgContext->DialogMode == DrvModeNormal) {
                kdDestroyShimmedDriversList(&g_kdctx.Data->KseEngineDump);
            }

        }
        DestroyWindow(hwndDlg);
        break;

    case WM_COMMAND:

        DrvDlgHandleWMCommand(hwndDlg, wParam, lParam);
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
    }

    return FALSE;
}

/*
* extrasDrvDlgWorkerThread
*
* Purpose:
*
* Drivers Dialog worker thread.
*
*/
DWORD extrasDrvDlgWorkerThread(
    _In_ PVOID Parameter
)
{
    HWND hwndDlg;
    BOOL bResult;
    MSG message;
    HACCEL acceleratorTable;
    HANDLE workerThread;
    FAST_EVENT fastEvent;
    EXTRASCONTEXT* pDlgContext = (EXTRASCONTEXT*)Parameter;

    hwndDlg = CreateDialogParam(g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_EXTRASLIST),
        0,
        &DrvDlgProc,
        (LPARAM)pDlgContext);

    acceleratorTable = LoadAccelerators(g_WinObj.hInstance, MAKEINTRESOURCE(IDR_ACCELERATOR1));

    fastEvent = DrvDlgInitializedEvents[pDlgContext->DialogMode];

    supSetFastEvent(&fastEvent);

    do {

        bResult = GetMessage(&message, NULL, 0, 0);
        if (bResult == -1)
            break;

        if (IsDialogMessage(hwndDlg, &message)) {
            TranslateAccelerator(hwndDlg, acceleratorTable, &message);
        }
        else {
            TranslateMessage(&message);
            DispatchMessage(&message);
        }

    } while (bResult != 0);

    supResetFastEvent(&fastEvent);

    if (acceleratorTable)
        DestroyAcceleratorTable(acceleratorTable);

    workerThread = DrvDlgThreadHandles[pDlgContext->DialogMode];
    if (workerThread) {
        NtClose(workerThread);
        DrvDlgThreadHandles[pDlgContext->DialogMode] = NULL;
    }

    return 0;
}

/*
* extrasCreateDriversDialog
*
* Purpose:
*
* Run Drivers Dialog worker thread.
*
*/
VOID extrasCreateDriversDialog(
    _In_ DRIVERS_DLG_MODE Mode
)
{
    if (Mode < 0 || Mode >= DrvModeMax)
        return;

    if (!DrvDlgThreadHandles[Mode]) {

        RtlSecureZeroMemory(&DrvDlgContext[Mode], sizeof(EXTRASCONTEXT));
        DrvDlgContext[Mode].DialogMode = Mode;
        DrvDlgThreadHandles[Mode] = supCreateDialogWorkerThread(extrasDrvDlgWorkerThread, (PVOID)&DrvDlgContext[Mode], 0);
        supWaitForFastEvent(&DrvDlgInitializedEvents[Mode], NULL);

    }
}
