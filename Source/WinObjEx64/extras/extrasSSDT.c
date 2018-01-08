/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       EXTRASSSDT.C
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
#include "extrasSSDT.h"

EXTRASCONTEXT DlgContext;
PSERVICETABLEENTRY g_SdtTable = NULL;
ULONG g_cSdtTable = 0;

/*
* SdtDlgCompareFunc
*
* Purpose:
*
* KiServiceTable Dialog listview comparer function.
*
*/
INT CALLBACK SdtDlgCompareFunc(
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort
)
{
    INT       nResult = 0;
    LPWSTR    lpItem1 = NULL, lpItem2 = NULL;
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

    case 0: //sort Index
        id1 = strtoul(lpItem1);
        id2 = strtoul(lpItem2);

        if (DlgContext.bInverseSort)
            nResult = id1 < id2;
        else
            nResult = id1 > id2;

        break;

    case 2: //sort Address

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

    case 1://sort Name, Module
    case 3:
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
* SdtHandlePopupMenu
*
* Purpose:
*
* Table list popup construction
*
*/
VOID SdtHandlePopupMenu(
    _In_ HWND hwndDlg
)
{
    POINT pt1;
    HMENU hMenu;

    if (GetCursorPos(&pt1) == FALSE)
        return;

    hMenu = CreatePopupMenu();
    if (hMenu) {
        InsertMenu(hMenu, 0, MF_BYCOMMAND, ID_OBJECT_COPY, T_SAVETOFILE);
        TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, pt1.x, pt1.y, 0, hwndDlg, NULL);
        DestroyMenu(hMenu);
    }
}

WCHAR output[0x2000];

/*
* SdtSaveListToFile
*
* Purpose:
*
* Dump table to the selected file
*
*/
VOID SdtSaveListToFile(
    _In_ HWND hwndDlg
)
{
    WCHAR   ch;
    INT	    row, subitem, numitems, BufferSize = 0;
    SIZE_T  sz, k;
    LPWSTR  pItem = NULL;
    HCURSOR hSaveCursor, hHourGlass;
    WCHAR   szTempBuffer[MAX_PATH + 1];

    RtlSecureZeroMemory(szTempBuffer, sizeof(szTempBuffer));

    _strcpy(szTempBuffer, TEXT("list.txt"));
    if (supSaveDialogExecute(hwndDlg, (LPWSTR)&szTempBuffer, TEXT("Text files\0*.txt\0\0"))) {

        hHourGlass = LoadCursor(NULL, IDC_WAIT);

        ch = (WCHAR)0xFEFF;
        supWriteBufferToFile(szTempBuffer, &ch, sizeof(WCHAR), FALSE, FALSE);

        SetCapture(hwndDlg);
        hSaveCursor = SetCursor(hHourGlass);

        numitems = ListView_GetItemCount(DlgContext.ListView);
        for (row = 0; row < numitems; row++) {

            output[0] = 0;
            for (subitem = 0; subitem < DlgContext.lvColumnCount; subitem++) {

                sz = 0;
                pItem = supGetItemText(DlgContext.ListView, row, subitem, &sz);
                if (pItem) {
                    _strcat(output, pItem);
                    supHeapFree(pItem);
                }
                if (subitem == 1) {
                    for (k = 54; k > sz / sizeof(WCHAR); k--) {
                        _strcat(output, TEXT(" "));
                    }
                }
                else {
                    _strcat(output, TEXT("\t"));
                }
            }
            _strcat(output, L"\r\n");
            BufferSize = (INT)_strlen(output);
            supWriteBufferToFile(szTempBuffer, output, BufferSize * sizeof(WCHAR), FALSE, TRUE);
        }

        SetCursor(hSaveCursor);
        ReleaseCapture();
    }
}

/*
* SdtDialogProc
*
* Purpose:
*
* KiServiceTable Dialog window procedure.
*
*/
INT_PTR CALLBACK SdtDialogProc(
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
        extrasDlgHandleNotify(nhdr, &DlgContext, &SdtDlgCompareFunc, NULL, NULL);
        break;

    case WM_SIZE:
        extrasSimpleListResize(hwndDlg, DlgContext.SizeGrip);
        break;

    case WM_CLOSE:
        if (DlgContext.SizeGrip) DestroyWindow(DlgContext.SizeGrip);
        DestroyWindow(hwndDlg);
        g_WinObj.AuxDialogs[WOBJ_SSDTDLG_IDX] = NULL;
        return TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDCANCEL) {
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            return TRUE;
        }
        if (LOWORD(wParam) == ID_OBJECT_COPY) {
            SdtSaveListToFile(hwndDlg);
            return TRUE;
        }
        break;

    case WM_CONTEXTMENU:
        SdtHandlePopupMenu(hwndDlg);
        break;
    }

    return FALSE;
}

/*
* SdtListTable
*
* Purpose:
*
* KiServiceTable query and list routine.
*
*/
VOID SdtListTable(
    VOID
)
{
    BOOL                    cond = FALSE;
    PUTable                 TableDump = NULL;
    PRTL_PROCESS_MODULES    pModules = NULL;
    PVOID                   Module = NULL;
    PIMAGE_EXPORT_DIRECTORY pexp = NULL;
    PIMAGE_NT_HEADERS       NtHeaders = NULL;
    DWORD                   ETableVA;
    PDWORD                  names, functions;
    PWORD                   ordinals;
    LVITEM                  lvitem;
    WCHAR                   szBuffer[MAX_PATH + 1];

    char *name;
    void *addr;
    ULONG number, i;
    INT index;

    __try {

        do {
            pModules = (PRTL_PROCESS_MODULES)supGetSystemInfo(SystemModuleInformation);
            if (pModules == NULL)
                break;

            //if table empty, dump and prepare table
            if (g_SdtTable == NULL) {

                if (g_WinObj.hNtdllModule == NULL) {
                    Module = GetModuleHandle(TEXT("ntdll.dll"));
                }
                else {
                    Module = g_WinObj.hNtdllModule;
                }

                if (Module == NULL)
                    break;

                g_SdtTable = (PSERVICETABLEENTRY)supHeapAlloc(sizeof(SERVICETABLEENTRY) * g_kdctx.KiServiceLimit);
                if (g_SdtTable == NULL)
                    break;

                if (!supDumpSyscallTableConverted(&g_kdctx, &TableDump))
                    break;

                NtHeaders = RtlImageNtHeader(Module);
                if (NtHeaders == NULL)
                    break;

                ETableVA = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                pexp = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)Module + ETableVA);
                names = (PDWORD)((PBYTE)Module + pexp->AddressOfNames),
                    functions = (PDWORD)((PBYTE)Module + pexp->AddressOfFunctions);
                ordinals = (PWORD)((PBYTE)Module + pexp->AddressOfNameOrdinals);

                //walk for Nt stubs
                g_cSdtTable = 0;
                for (i = 0; i < pexp->NumberOfNames; i++) {

                    name = ((CHAR *)Module + names[i]);
                    addr = (PVOID *)((CHAR *)Module + functions[ordinals[i]]);

                    if (*(USHORT*)name == 'tN') {

                        number = *(ULONG*)((UCHAR*)addr + 4);

                        if (number < g_kdctx.KiServiceLimit) {
                            MultiByteToWideChar(CP_ACP, 0, name, (INT)_strlen_a(name),
                                g_SdtTable[g_cSdtTable].Name, MAX_PATH);

                            g_SdtTable[g_cSdtTable].ServiceId = number;
                            g_SdtTable[g_cSdtTable].Address = TableDump[number];
                            TableDump[number] = 0;
                            g_cSdtTable++;
                        }

                    }//tN
                }//for

                //
                // Temporary workaround for NtQuerySystemTime.
                // (not implemented in user mode as syscall only as query to shared data, still exist in SSDT)
                //  
                //  This will produce incorrect result if more like that services will be added.
                //
                for (i = 0; i < g_kdctx.KiServiceLimit; i++) {
                    if (TableDump[i] != 0) {
                        g_SdtTable[g_cSdtTable].ServiceId = i;
                        g_SdtTable[g_cSdtTable].Address = TableDump[i];
                        _strcpy(g_SdtTable[g_cSdtTable].Name, L"NtQuerySystemTime");
                        g_cSdtTable++;
                        break;
                    }
                }
                
                supHeapFree(TableDump);
                TableDump = NULL;
            }

            //list table
            for (i = 0; i < g_cSdtTable; i++) {

                //ServiceId
                RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
                lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
                lvitem.iSubItem = 0;
                lvitem.iItem = MAXINT;
                lvitem.iImage = TYPE_DEVICE; //imagelist id
                RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
                ultostr(g_SdtTable[i].ServiceId, szBuffer);
                lvitem.pszText = szBuffer;
                index = ListView_InsertItem(DlgContext.ListView, &lvitem);

                //Name
                lvitem.mask = LVIF_TEXT;
                lvitem.iSubItem = 1;
                lvitem.pszText = (LPWSTR)g_SdtTable[i].Name;
                lvitem.iItem = index;
                ListView_SetItem(DlgContext.ListView, &lvitem);

                //Address
                lvitem.iSubItem = 2;
                RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
                szBuffer[0] = L'0';
                szBuffer[1] = L'x';
                u64tohex(g_SdtTable[i].Address, &szBuffer[2]);
                lvitem.pszText = szBuffer;
                lvitem.iItem = index;
                ListView_SetItem(DlgContext.ListView, &lvitem);

                //Module
                lvitem.iSubItem = 3;
                RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

                number = supFindModuleEntryByAddress(pModules, (PVOID)g_SdtTable[i].Address);
                if (number == (ULONG)-1) {
                    _strcpy(szBuffer, TEXT("Unknown Module"));
                }
                else {

                    MultiByteToWideChar(CP_ACP, 0,
                        (LPCSTR)&pModules->Modules[number].FullPathName,
                        (INT)_strlen_a((char*)pModules->Modules[number].FullPathName),
                        szBuffer,
                        MAX_PATH);
                }

                lvitem.pszText = szBuffer;
                lvitem.iItem = index;
                ListView_SetItem(DlgContext.ListView, &lvitem);
            }

        } while (cond);

        if (pModules) {
            supHeapFree(pModules);
        }

        if (TableDump) {
            supHeapFree(TableDump);
        }
    }
    __except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
        return;
    }
}

/*
* extrasCreateSSDTDialog
*
* Purpose:
*
* Create and initialize KiServiceTable Dialog.
*
*/
VOID extrasCreateSSDTDialog(
    _In_ HWND hwndParent
)
{
    LVCOLUMN  col;

    //allow only one dialog
    if (g_WinObj.AuxDialogs[WOBJ_SSDTDLG_IDX]) {
        if (IsIconic(g_WinObj.AuxDialogs[WOBJ_SSDTDLG_IDX]))
            ShowWindow(g_WinObj.AuxDialogs[WOBJ_SSDTDLG_IDX], SW_RESTORE);
        else
            SetActiveWindow(g_WinObj.AuxDialogs[WOBJ_SSDTDLG_IDX]);
        return;
    }

    RtlSecureZeroMemory(&DlgContext, sizeof(DlgContext));
    DlgContext.hwndDlg = CreateDialogParam(g_WinObj.hInstance, MAKEINTRESOURCE(IDD_DIALOG_EXTRASLIST),
        hwndParent, &SdtDialogProc, 0);

    if (DlgContext.hwndDlg == NULL) {
        return;
    }

    g_WinObj.AuxDialogs[WOBJ_SSDTDLG_IDX] = DlgContext.hwndDlg;

    DlgContext.SizeGrip = supCreateSzGripWindow(DlgContext.hwndDlg);

    SetWindowText(DlgContext.hwndDlg, TEXT("System Service Table"));

    extrasSetDlgIcon(DlgContext.hwndDlg);

    DlgContext.ListView = GetDlgItem(DlgContext.hwndDlg, ID_EXTRASLIST);
    if (DlgContext.ListView) {

        ListView_SetImageList(DlgContext.ListView, g_ListViewImages, LVSIL_SMALL);
        ListView_SetExtendedListViewStyle(DlgContext.ListView,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

        //columns
        RtlSecureZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
        col.iSubItem++;
        col.pszText = TEXT("Id");
        col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;
        col.iImage = ImageList_GetImageCount(g_ListViewImages) - 1;
        col.cx = 80;
        ListView_InsertColumn(DlgContext.ListView, col.iSubItem, &col);

        col.iSubItem++;
        col.pszText = TEXT("Service Name");
        col.iOrder++;
        col.iImage = -1;
        col.cx = 200;
        ListView_InsertColumn(DlgContext.ListView, col.iSubItem, &col);

        col.iSubItem++;
        col.pszText = TEXT("Address");
        col.iOrder++;
        col.cx = 130;
        ListView_InsertColumn(DlgContext.ListView, col.iSubItem, &col);

        col.iSubItem++;
        col.pszText = TEXT("Module");
        col.iOrder++;
        col.cx = 200;
        ListView_InsertColumn(DlgContext.ListView, col.iSubItem, &col);

        //remember columns count
        DlgContext.lvColumnCount = col.iSubItem;

        SdtListTable();
        SendMessage(DlgContext.hwndDlg, WM_SIZE, 0, 0);

        ListView_SortItemsEx(DlgContext.ListView, &SdtDlgCompareFunc, 0);
    }
}
