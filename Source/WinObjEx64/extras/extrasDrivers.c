/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2018
*
*  TITLE:       EXTRASDRIVERS.C
*
*  VERSION:     1.52
*
*  DATE:        08 Jan 2018
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "extras.h"

EXTRASCONTEXT DlgContext;

/*
* DrvHandlePopupMenu
*
* Purpose:
*
* Table list popup construction
*
*/
VOID DrvHandlePopupMenu(
    _In_ HWND hwndDlg
)
{
    POINT pt1;
    HMENU hMenu;

    if (g_kdctx.hDevice == NULL)
        return;

    if (GetCursorPos(&pt1)) {
        hMenu = CreatePopupMenu();
        if (hMenu) {
            InsertMenu(hMenu, 0, MF_BYCOMMAND, ID_OBJECT_COPY, T_DUMPDRIVER);
            TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, pt1.x, pt1.y, 0, hwndDlg, NULL);
            DestroyMenu(hMenu);
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
    BOOL      bCond = FALSE, bSuccess = FALSE;
    USHORT    AddressPrefix;
    INT       iPos;
    ULONG     ImageSize;
    SIZE_T    sz, cbItem;
    LPWSTR    lpDriverName = NULL, lpszValue = NULL;
    PVOID     DumpedDrv = NULL;
    ULONG_PTR ImageBase = 0;
    WCHAR     szBuffer[MAX_PATH * 2];

    do {
        //
        // Remember selected index.
        //
        iPos = ListView_GetNextItem(DlgContext.ListView, -1, LVNI_SELECTED);
        if (iPos < 0)
            break;

        //
        // Query selected driver name.
        //
        sz = 0;
        lpDriverName = supGetItemText(DlgContext.ListView, iPos, 1, &sz);
        if (lpDriverName == NULL)
            break;

        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        _strncpy(szBuffer, MAX_PATH, lpDriverName, sz / sizeof(WCHAR));

        //
        // Run Save As Dialog.
        //
        if (!supSaveDialogExecute(DlgContext.hwndDlg, szBuffer, TEXT("All files\0*.*\0\0")))
            break;

        //
        // Query driver address from listview.
        //
        cbItem = 0;
        lpszValue = supGetItemText(DlgContext.ListView, iPos, 2, &cbItem);
        if (lpszValue == NULL)
            break;

        if ((cbItem / sizeof(WCHAR)) != MAX_ADDRESS_TEXT_LENGTH64)
            break;

        AddressPrefix = supIsAddressPrefix(lpszValue, cbItem);
        if (AddressPrefix == 2) {
            ImageBase = hextou64(&lpszValue[AddressPrefix]);
            if (ImageBase < g_kdctx.SystemRangeStart)
                break;
        }
        else
            break;

        supHeapFree(lpszValue);

        //
        // Query driver size from listview.
        //
        lpszValue = supGetItemText(DlgContext.ListView, iPos, 3, NULL);
        if (lpszValue == NULL)
            break;

        ImageSize = strtoul(lpszValue);
        if (ImageSize == 0)
            break;

        supHeapFree(lpszValue);
        lpszValue = NULL;

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

            MessageBox(DlgContext.hwndDlg, szBuffer, PROGRAM_NAME, MB_ICONINFORMATION);
        }

    } while (bCond);

    if (lpDriverName) supHeapFree(lpDriverName);
    if (lpszValue) supHeapFree(lpszValue);
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
    VOID
)
{
    BOOL   bCond = FALSE;
    INT    index;
    ULONG i;
    LVITEM lvitem;
    WCHAR  szBuffer[MAX_PATH + 1];

    RTL_PROCESS_MODULES            *pModulesList = NULL;
    PRTL_PROCESS_MODULE_INFORMATION pModule;

    do {
        pModulesList = supGetSystemInfo(SystemModuleInformation);
        if (pModulesList == NULL)
            break;

        for (i = 0; i < pModulesList->NumberOfModules; i++) {

            pModule = &pModulesList->Modules[i];

            if ((ULONG_PTR)pModule->ImageBase < g_kdctx.SystemRangeStart)
                continue;

            RtlSecureZeroMemory(&lvitem, sizeof(lvitem));

            //LoadOrder
            lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
            lvitem.iItem = MAXINT;
            lvitem.iImage = TYPE_DRIVER; //imagelist id
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            ultostr(pModule->LoadOrderIndex, szBuffer);
            lvitem.pszText = szBuffer;
            index = ListView_InsertItem(DlgContext.ListView, &lvitem);

            //Name
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            MultiByteToWideChar(CP_ACP, 0,
                (LPCSTR)&pModule->FullPathName[pModule->OffsetToFileName],
                -1, szBuffer, MAX_PATH);

            lvitem.mask = LVIF_TEXT;
            lvitem.iSubItem++;
            lvitem.pszText = szBuffer;
            lvitem.iItem = index;
            ListView_SetItem(DlgContext.ListView, &lvitem);

            //Address
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            szBuffer[0] = L'0';
            szBuffer[1] = L'x';
            u64tohex((ULONG_PTR)pModule->ImageBase, &szBuffer[2]);
            lvitem.iSubItem++;
            ListView_SetItem(DlgContext.ListView, &lvitem);

            //Size
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            ultostr(pModule->ImageSize, szBuffer);
            lvitem.iSubItem++;
            ListView_SetItem(DlgContext.ListView, &lvitem);

            //FullName
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            MultiByteToWideChar(CP_ACP, 0,
                (LPCSTR)&pModule->FullPathName,
                -1, szBuffer, MAX_PATH);
            lvitem.iSubItem++;
            ListView_SetItem(DlgContext.ListView, &lvitem);
        }

    } while (bCond);

    if (pModulesList) supHeapFree(pModulesList);
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
    LPWSTR    lpItem1 = NULL, lpItem2 = NULL;
    INT       nResult = 0;
    ULONG     id1, id2;
    ULONG_PTR ad1, ad2;

    SIZE_T cbItem1 = 0, cbItem2 = 0;

    USHORT AddressPrefix;

    lpItem1 = supGetItemText(
        DlgContext.ListView, 
        (INT)lParam1, 
        (INT)lParamSort, 
        &cbItem1);

    lpItem2 = supGetItemText(
        DlgContext.ListView, 
        (INT)lParam2, 
        (INT)lParamSort, 
        &cbItem2);

    if ((lpItem1 == NULL) && 
        (lpItem2 == NULL))
    {
        return 0;
    }

    if ((lpItem1 == NULL) && (lpItem2 != NULL)) {
        nResult = (DlgContext.bInverseSort) ? 1 : -1;
        goto Done;
    }
    if ((lpItem2 == NULL) && (lpItem1 != NULL)) {
        nResult = (DlgContext.bInverseSort) ? -1 : 1;
        goto Done;
    }  

    switch (lParamSort) {

    case 0: //sort Load Order
    case 3: //sort Size
        id1 = strtoul(lpItem1);
        id2 = strtoul(lpItem2);

        if (DlgContext.bInverseSort)
            nResult = id1 < id2;
        else
            nResult = id1 > id2;

        break;
   
    case 2:  //sort Address

        if ((cbItem1 / sizeof(WCHAR) != MAX_ADDRESS_TEXT_LENGTH64) &&
            (cbItem2 / sizeof(WCHAR) != MAX_ADDRESS_TEXT_LENGTH64))
        {
            nResult = 0;
            break;
        }

        ad1 = 0;
        ad2 = 0;

        if (lpItem1) {
            AddressPrefix = supIsAddressPrefix(lpItem1, cbItem1);
            if (AddressPrefix == 2)
                ad1 = hextou64(&lpItem1[AddressPrefix]);
        }

        if (lpItem2) {
            AddressPrefix = supIsAddressPrefix(lpItem2, cbItem2);
            if (AddressPrefix == 2)
                ad2 = hextou64(&lpItem2[AddressPrefix]);
        }

        if (DlgContext.bInverseSort)
            nResult = ad1 < ad2;
        else
            nResult = ad1 > ad2;

        break;

    case 1:  //sort Name
    case 4:  //sort Module
    default:
        if (DlgContext.bInverseSort)
            nResult = _strcmpi(lpItem2, lpItem1);
        else
            nResult = _strcmpi(lpItem1, lpItem2);
        break;
    }

Done:
    if (lpItem1) supHeapFree(lpItem1);
    if (lpItem2) supHeapFree(lpItem2);

    return nResult;
}

/*
* DriversHandleNotify
*
* Purpose:
*
* Common WM_NOTIFY processing for Driver list dialogs.
*
*/
VOID CALLBACK DriversHandleNotify(
    _In_ LPNMLISTVIEW nhdr,
    _In_ EXTRASCONTEXT *Context,
    _In_opt_ PVOID CustomParameter
)
{
    LPWSTR  lpItem;
    INT     mark;
    WCHAR   szBuffer[MAX_PATH + 1];

    UNREFERENCED_PARAMETER(CustomParameter);

    if ((nhdr == NULL) || (Context == NULL))
        return;

    if (nhdr->hdr.idFrom != ID_EXTRASLIST)
        return;

    if (nhdr->hdr.code == NM_DBLCLK) {
        mark = ListView_GetSelectionMark(Context->ListView);
        if (mark >= 0) {
            lpItem = supGetItemText(Context->ListView, mark, 4, NULL);
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
        extrasDlgHandleNotify(nhdr, &DlgContext, &DrvDlgCompareFunc, DriversHandleNotify, NULL);
        break;

    case WM_SIZE:
        extrasSimpleListResize(hwndDlg, DlgContext.SizeGrip);
        break;

    case WM_CLOSE:
        if (DlgContext.SizeGrip) DestroyWindow(DlgContext.SizeGrip);
        DestroyWindow(hwndDlg);
        g_WinObj.AuxDialogs[WOBJ_DRVDLG_IDX] = NULL;
        return TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDCANCEL) {
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            return TRUE;
        }
        if (LOWORD(wParam) == ID_OBJECT_COPY) {
            DrvDumpDriver();
            return TRUE;
        }
        break;

    case WM_CONTEXTMENU:
        DrvHandlePopupMenu(hwndDlg);
        break;
    }

    return FALSE;
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
    LVCOLUMN col;

    //allow only one dialog
    if (g_WinObj.AuxDialogs[WOBJ_DRVDLG_IDX]) {
        if (IsIconic(g_WinObj.AuxDialogs[WOBJ_DRVDLG_IDX]))
            ShowWindow(g_WinObj.AuxDialogs[WOBJ_DRVDLG_IDX], SW_RESTORE);
        else
            SetActiveWindow(g_WinObj.AuxDialogs[WOBJ_DRVDLG_IDX]);
        return;
    }

    RtlSecureZeroMemory(&DlgContext, sizeof(DlgContext));
    DlgContext.hwndDlg = CreateDialogParam(g_WinObj.hInstance, MAKEINTRESOURCE(IDD_DIALOG_EXTRASLIST),
        hwndParent, &DriversDialogProc, 0);

    if (DlgContext.hwndDlg == NULL) {
        return;
    }

    g_WinObj.AuxDialogs[WOBJ_DRVDLG_IDX] = DlgContext.hwndDlg;

    SetWindowText(DlgContext.hwndDlg, TEXT("Drivers"));

    DlgContext.SizeGrip = supCreateSzGripWindow(DlgContext.hwndDlg);

    extrasSetDlgIcon(DlgContext.hwndDlg);

    DlgContext.ListView = GetDlgItem(DlgContext.hwndDlg, ID_EXTRASLIST);
    if (DlgContext.ListView) {

        ListView_SetImageList(DlgContext.ListView, g_ListViewImages, LVSIL_SMALL);
        ListView_SetExtendedListViewStyle(DlgContext.ListView,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

        RtlSecureZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
        col.iSubItem++;
        col.pszText = TEXT("#");
        col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;
        col.iImage = ImageList_GetImageCount(g_ListViewImages) - 1;
        col.cx = 60;
        ListView_InsertColumn(DlgContext.ListView, col.iSubItem, &col);

        col.iSubItem++;
        col.pszText = TEXT("Name");
        col.iImage = -1;
        col.iOrder++;
        col.cx = 160;
        ListView_InsertColumn(DlgContext.ListView, col.iSubItem, &col);

        col.iSubItem++;
        col.pszText = TEXT("Address");
        col.iOrder++;
        col.cx = 130;
        ListView_InsertColumn(DlgContext.ListView, col.iSubItem, &col);

        col.iSubItem++;
        col.pszText = TEXT("Size");
        col.iOrder++;
        col.cx = 80;
        ListView_InsertColumn(DlgContext.ListView, col.iSubItem, &col);

        col.iSubItem++;
        col.pszText = TEXT("Image Path");
        col.iOrder++;
        col.cx = 280;
        ListView_InsertColumn(DlgContext.ListView, col.iSubItem, &col);

        //remember col count
        DlgContext.lvColumnCount = col.iSubItem;

        DrvListDrivers();
        SendMessage(DlgContext.hwndDlg, WM_SIZE, 0, 0);

        ListView_SortItemsEx(DlgContext.ListView, &DrvDlgCompareFunc, 0);
    }
}
