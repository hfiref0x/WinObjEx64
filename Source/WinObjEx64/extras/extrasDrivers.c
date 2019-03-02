/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2019
*
*  TITLE:       EXTRASDRIVERS.C
*
*  VERSION:     1.72
*
*  DATE:        10 Feb 2019
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

            MessageBox(DrvDlgContext.hwndDlg, szBuffer, PROGRAM_NAME, MB_ICONINFORMATION);
        }

    } while (bCond);

    if (lpDriverName) supHeapFree(lpDriverName);
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
    INT    index, iImage;
    ULONG i;
    LVITEM lvitem;
    WCHAR  szBuffer[MAX_PATH + 1];

    RTL_PROCESS_MODULES            *pModulesList = NULL;
    PRTL_PROCESS_MODULE_INFORMATION pModule;

    do {
        pModulesList = (PRTL_PROCESS_MODULES)supGetSystemInfo(SystemModuleInformation);
        if (pModulesList == NULL)
            break;

        iImage = ObManagerGetImageIndexByTypeIndex(ObjectTypeDriver);

        for (i = 0; i < pModulesList->NumberOfModules; i++) {

            pModule = &pModulesList->Modules[i];

            if ((ULONG_PTR)pModule->ImageBase < g_kdctx.SystemRangeStart)
                continue;

            RtlSecureZeroMemory(&lvitem, sizeof(lvitem));

            //LoadOrder
            lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
            lvitem.iItem = MAXINT;
            lvitem.iImage = iImage;
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            ultostr(pModule->LoadOrderIndex, szBuffer);
            lvitem.pszText = szBuffer;
            index = ListView_InsertItem(DrvDlgContext.ListView, &lvitem);

            //Name
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

            MultiByteToWideChar(
                CP_ACP, 0,
                (LPCSTR)&pModule->FullPathName[pModule->OffsetToFileName],
                -1,
                szBuffer,
                MAX_PATH);

            lvitem.mask = LVIF_TEXT;
            lvitem.iSubItem++;
            lvitem.pszText = szBuffer;
            lvitem.iItem = index;
            ListView_SetItem(DrvDlgContext.ListView, &lvitem);

            //Address
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            szBuffer[0] = L'0';
            szBuffer[1] = L'x';
            u64tohex((ULONG_PTR)pModule->ImageBase, &szBuffer[2]);
            lvitem.iSubItem++;
            ListView_SetItem(DrvDlgContext.ListView, &lvitem);

            //Size
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            ultostr(pModule->ImageSize, szBuffer);
            lvitem.iSubItem++;
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

            lvitem.iSubItem++;
            ListView_SetItem(DrvDlgContext.ListView, &lvitem);
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
        extrasDlgHandleNotify(nhdr, &DrvDlgContext, &DrvDlgCompareFunc, DriversHandleNotify, NULL);
        break;

    case WM_SIZE:
        extrasSimpleListResize(hwndDlg, DrvDlgContext.SizeGrip);
        break;

    case WM_CLOSE:
        if (DrvDlgContext.SizeGrip) DestroyWindow(DrvDlgContext.SizeGrip);
        DestroyWindow(hwndDlg);
        g_WinObj.AuxDialogs[wobjDriversDlgId] = NULL;
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
    if (g_WinObj.AuxDialogs[wobjDriversDlgId]) {
        if (IsIconic(g_WinObj.AuxDialogs[wobjDriversDlgId]))
            ShowWindow(g_WinObj.AuxDialogs[wobjDriversDlgId], SW_RESTORE);
        else
            SetActiveWindow(g_WinObj.AuxDialogs[wobjDriversDlgId]);
        return;
    }

    RtlSecureZeroMemory(&DrvDlgContext, sizeof(DrvDlgContext));
    DrvDlgContext.hwndDlg = CreateDialogParam(g_WinObj.hInstance, MAKEINTRESOURCE(IDD_DIALOG_EXTRASLIST),
        hwndParent, &DriversDialogProc, 0);

    if (DrvDlgContext.hwndDlg == NULL) {
        return;
    }

    g_WinObj.AuxDialogs[wobjDriversDlgId] = DrvDlgContext.hwndDlg;

    SetWindowText(DrvDlgContext.hwndDlg, TEXT("Drivers"));

    DrvDlgContext.SizeGrip = supCreateSzGripWindow(DrvDlgContext.hwndDlg);

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

        RtlSecureZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
        col.iSubItem++;
        col.pszText = TEXT("#");
        col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;
        col.iImage = ImageList_GetImageCount(g_ListViewImages) - 1;
        col.cx = 60;
        ListView_InsertColumn(DrvDlgContext.ListView, col.iSubItem, &col);

        col.iImage = I_IMAGENONE;

        col.iSubItem++;
        col.pszText = TEXT("Name");
        col.iOrder++;
        col.cx = 160;
        ListView_InsertColumn(DrvDlgContext.ListView, col.iSubItem, &col);

        col.iSubItem++;
        col.pszText = TEXT("Address");
        col.iOrder++;
        col.cx = 130;
        ListView_InsertColumn(DrvDlgContext.ListView, col.iSubItem, &col);

        col.iSubItem++;
        col.pszText = TEXT("Size");
        col.iOrder++;
        col.cx = 80;
        ListView_InsertColumn(DrvDlgContext.ListView, col.iSubItem, &col);

        col.iSubItem++;
        col.pszText = TEXT("Image Path");
        col.iOrder++;
        col.cx = 280;
        ListView_InsertColumn(DrvDlgContext.ListView, col.iSubItem, &col);

        //remember col count
        DrvDlgContext.lvColumnCount = col.iSubItem;

        DrvListDrivers();
        SendMessage(DrvDlgContext.hwndDlg, WM_SIZE, 0, 0);

        ListView_SortItemsEx(DrvDlgContext.ListView, &DrvDlgCompareFunc, 0);
    }
}
