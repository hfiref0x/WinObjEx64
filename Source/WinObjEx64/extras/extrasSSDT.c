/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       EXTRASSSDT.C
*
*  VERSION:     1.70
*
*  DATE:        30 Nov 2018
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "hde\hde64.h"
#include "extras.h"
#include "extrasSSDT.h"

PSERVICETABLEENTRY g_pSDT = NULL;
ULONG g_SDTLimit = 0;

PSERVICETABLEENTRY g_pSDTShadow = NULL;
ULONG g_SDTShadowLimit = 0;

EXTRASCONTEXT SSTDlgContext[SST_Max];

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
    _In_ LPARAM lParamSort //pointer to EXTRASCALLBACK
)
{
    INT       nResult = 0;

    EXTRASCONTEXT *pDlgContext;
    EXTRASCALLBACK *CallbackParam = (EXTRASCALLBACK*)lParamSort;

    if (CallbackParam == NULL)
        return 0;

    pDlgContext = &SSTDlgContext[CallbackParam->Value];

    switch (pDlgContext->lvColumnToSort) {
    case 0: //index
        return supGetMaxOfTwoULongFromString(
            pDlgContext->ListView,
            lParam1,
            lParam2,
            pDlgContext->lvColumnToSort,
            pDlgContext->bInverseSort);
    case 2: //address (hex)
        return supGetMaxOfTwoU64FromHex(
            pDlgContext->ListView,
            lParam1,
            lParam2,
            pDlgContext->lvColumnToSort,
            pDlgContext->bInverseSort);
    case 1: //string (fixed size)
    case 3: //string (fixed size)
        return supGetMaxCompareTwoFixedStrings(
            pDlgContext->ListView,
            lParam1,
            lParam2,
            pDlgContext->lvColumnToSort,
            pDlgContext->bInverseSort);
    }

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
    _In_ HWND hwndDlg,
    _In_ EXTRASCONTEXT *pDlgContext
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

        numitems = ListView_GetItemCount(pDlgContext->ListView);
        for (row = 0; row < numitems; row++) {

            output[0] = 0;
            for (subitem = 0; subitem < pDlgContext->lvColumnCount; subitem++) {

                sz = 0;
                pItem = supGetItemText(pDlgContext->ListView, row, subitem, &sz);
                if (pItem) {
                    _strcat(output, pItem);
                    supHeapFree(pItem);
                }
                if (subitem == 1) {
                    for (k = 100; k > sz / sizeof(WCHAR); k--) {
                        _strcat(output, TEXT(" "));
                    }
                }
                else {
                    _strcat(output, TEXT("\t"));
                }
            }
            _strcat(output, L"\r\n");
            BufferSize = (INT)_strlen(output);
            supWriteBufferToFile(szTempBuffer, output, (SIZE_T)(BufferSize * sizeof(WCHAR)), FALSE, TRUE);
        }

        SetCursor(hSaveCursor);
        ReleaseCapture();
    }
}

/*
* SdtDlgHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for dialog listview.
*
*/
VOID SdtDlgHandleNotify(
    _In_ LPARAM lParam,
    _In_ EXTRASCONTEXT *pDlgContext
)
{
    LPNMHDR  nhdr = (LPNMHDR)lParam;
    INT      nImageIndex;

    EXTRASCALLBACK CallbackParam;

    if (nhdr == NULL)
        return;

    if (nhdr->hwndFrom != pDlgContext->ListView)
        return;

    switch (nhdr->code) {

    case LVN_COLUMNCLICK:
        pDlgContext->bInverseSort = !pDlgContext->bInverseSort;
        pDlgContext->lvColumnToSort = ((NMLISTVIEW *)lParam)->iSubItem;
        CallbackParam.lParam = (LPARAM)pDlgContext->lvColumnToSort;
        CallbackParam.Value = pDlgContext->DialogMode;
        ListView_SortItemsEx(pDlgContext->ListView, &SdtDlgCompareFunc, (LPARAM)&CallbackParam);

        nImageIndex = ImageList_GetImageCount(g_ListViewImages);
        if (pDlgContext->bInverseSort)
            nImageIndex -= 2;
        else
            nImageIndex -= 1;

        supUpdateLvColumnHeaderImage(
            pDlgContext->ListView,
            pDlgContext->lvColumnCount,
            pDlgContext->lvColumnToSort,
            nImageIndex);

        break;

    default:
        break;
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
    INT dlgIndex;
    EXTRASCONTEXT *pDlgContext;

    switch (uMsg) {

    case WM_INITDIALOG:
        SetProp(hwndDlg, T_DLGCONTEXT, (HANDLE)lParam);
        supCenterWindow(hwndDlg);
        break;

    case WM_GETMINMAXINFO:
        if (lParam) {
            ((PMINMAXINFO)lParam)->ptMinTrackSize.x = 640;
            ((PMINMAXINFO)lParam)->ptMinTrackSize.y = 480;
        }
        break;

    case WM_NOTIFY:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            SdtDlgHandleNotify(lParam, pDlgContext);
        }
        break;

    case WM_SIZE:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            extrasSimpleListResize(hwndDlg, pDlgContext->SizeGrip);
        }
        break;

    case WM_CLOSE:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            if (pDlgContext->SizeGrip) DestroyWindow(pDlgContext->SizeGrip);

            dlgIndex = 0;

            if (pDlgContext->DialogMode == SST_Ntos)
                dlgIndex = wobjKSSTDlgId;
            else if (pDlgContext->DialogMode == SST_Win32k)
                dlgIndex = wobjW32SSTDlgId;

            if ((dlgIndex == wobjKSSTDlgId)
                || (dlgIndex == wobjW32SSTDlgId))
            {
                g_WinObj.AuxDialogs[dlgIndex] = NULL;
            }
            RtlSecureZeroMemory(pDlgContext, sizeof(EXTRASCONTEXT));
        }
        return DestroyWindow(hwndDlg);

    case WM_COMMAND:
        if (LOWORD(wParam) == IDCANCEL) {
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            return TRUE;
        }
        if (LOWORD(wParam) == ID_OBJECT_COPY) {
            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
            if (pDlgContext) {
                SdtSaveListToFile(hwndDlg, pDlgContext);
            }
            return TRUE;
        }
        break;

    case WM_DESTROY:
        RemoveProp(hwndDlg, T_DLGCONTEXT);
        break;

    case WM_CONTEXTMENU:
        SdtHandlePopupMenu(hwndDlg);
        break;
    }

    return FALSE;
}

/*
* SdtOutputTable
*
* Purpose:
*
* Output dumped and converted syscall table to listview.
*
*/
VOID SdtOutputTable(
    _In_ HWND hwndDlg,
    _In_ PRTL_PROCESS_MODULES Modules,
    _In_ PSERVICETABLEENTRY Table,
    _In_ ULONG Count
)
{
    INT index, number;
    ULONG i;
    EXTRASCONTEXT *Context = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);

    LVITEM lvitem;
    WCHAR szBuffer[MAX_PATH + 1];

    szBuffer[0] = 0;

    switch (Context->DialogMode) {
    case SST_Ntos:
        _strcpy(szBuffer, TEXT("KiServiceTable 0x"));
        u64tohex(g_kdctx.KiServiceTableAddress, _strend(szBuffer));
        _strcat(szBuffer, TEXT(" / KiServiceLimit 0x"));
        ultohex(g_kdctx.KiServiceLimit, _strend(szBuffer));
        _strcat(szBuffer, TEXT(" ("));
        ultostr(g_kdctx.KiServiceLimit, _strend(szBuffer));
        _strcat(szBuffer, TEXT(")"));
        break;
    case SST_Win32k:
        _strcpy(szBuffer, TEXT("W32pServiceTable 0x"));
        u64tohex(g_kdctx.W32pServiceTableAddress, _strend(szBuffer));
        _strcat(szBuffer, TEXT(" / W32pServiceLimit 0x"));
        ultohex(g_kdctx.W32pServiceLimit, _strend(szBuffer));
        _strcat(szBuffer, TEXT(" ("));
        ultostr(g_kdctx.W32pServiceLimit, _strend(szBuffer));
        _strcat(szBuffer, TEXT(")"));
        break;
    default:
        break;
    }
    SetWindowText(hwndDlg, szBuffer);

    //list table
    for (i = 0; i < Count; i++) {

        //ServiceId
        RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
        lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
        lvitem.iSubItem = 0;
        lvitem.iItem = MAXINT;
        lvitem.iImage = ObjectTypeDevice; //imagelist id
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        ultostr(Table[i].ServiceId, szBuffer);
        lvitem.pszText = szBuffer;
        index = ListView_InsertItem(Context->ListView, &lvitem);

        //Name
        lvitem.mask = LVIF_TEXT;
        lvitem.iSubItem = 1;
        lvitem.pszText = (LPWSTR)Table[i].Name;
        lvitem.iItem = index;
        ListView_SetItem(Context->ListView, &lvitem);

        //Address
        lvitem.iSubItem = 2;
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        szBuffer[0] = L'0';
        szBuffer[1] = L'x';
        u64tohex(Table[i].Address, &szBuffer[2]);
        lvitem.pszText = szBuffer;
        lvitem.iItem = index;
        ListView_SetItem(Context->ListView, &lvitem);

        //Module
        lvitem.iSubItem = 3;
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

        number = supFindModuleEntryByAddress(Modules, (PVOID)Table[i].Address);
        if (number == (ULONG)-1) {
            _strcpy(szBuffer, TEXT("Unknown Module"));
        }
        else {

            MultiByteToWideChar(
                CP_ACP,
                0,
                (LPCSTR)&Modules->Modules[number].FullPathName,
                (INT)_strlen_a((char*)Modules->Modules[number].FullPathName),
                szBuffer,
                MAX_PATH);
        }

        lvitem.pszText = szBuffer;
        lvitem.iItem = index;
        ListView_SetItem(Context->ListView, &lvitem);
    }
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
    _In_ HWND hwndDlg
)
{
    ULONG                   EntrySize = 0;
    SIZE_T                  memIO;
    PUTable                 TableDump = NULL;
    PRTL_PROCESS_MODULES    pModules = NULL;
    PBYTE                   Module = NULL;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PDWORD                  names, functions;
    PWORD                   ordinals;

    char *name;
    void *addr;
    ULONG number, i;

#ifndef _DEBUG
    HWND hwndBanner;

    hwndBanner = supDisplayLoadBanner(hwndDlg,
        TEXT("Loading service table dump, please wait"));
#endif

    __try {

        if ((g_kdctx.KiServiceTableAddress == 0) ||
            (g_kdctx.KiServiceLimit == 0))
        {
            if (!kdFindKiServiceTables(
                (ULONG_PTR)g_kdctx.NtOsImageMap,
                (ULONG_PTR)g_kdctx.NtOsBase,
                &g_kdctx.KiServiceTableAddress,
                &g_kdctx.KiServiceLimit,
                NULL,
                NULL))
            {
                __leave;
            }
        }

        pModules = (PRTL_PROCESS_MODULES)supGetSystemInfo(SystemModuleInformation);
        if (pModules == NULL)
            __leave;

        //if table empty, dump and prepare table
        if (g_pSDT == NULL) {

            Module = (PBYTE)GetModuleHandle(TEXT("ntdll.dll"));

            if (Module == NULL)
                __leave;

            memIO = sizeof(SERVICETABLEENTRY) * g_kdctx.KiServiceLimit;
            g_pSDT = (PSERVICETABLEENTRY)supHeapAlloc(memIO);
            if (g_pSDT == NULL)
                __leave;

            if (!supDumpSyscallTableConverted(
                g_kdctx.KiServiceTableAddress,
                g_kdctx.KiServiceLimit,
                &TableDump))
            {
                supHeapFree(g_pSDT);
                g_pSDT = NULL;
                __leave;
            }

            ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(
                Module,
                TRUE,
                IMAGE_DIRECTORY_ENTRY_EXPORT,
                &EntrySize);

            if (ExportDirectory == NULL) {
                supHeapFree(g_pSDT);
                g_pSDT = NULL;
                __leave;
            }

            names = (PDWORD)((PBYTE)Module + ExportDirectory->AddressOfNames);
            functions = (PDWORD)((PBYTE)Module + ExportDirectory->AddressOfFunctions);
            ordinals = (PWORD)((PBYTE)Module + ExportDirectory->AddressOfNameOrdinals);

            //
            // Walk for Nt stubs.
            //
            g_SDTLimit = 0;
            for (i = 0; i < ExportDirectory->NumberOfNames; i++) {

                name = ((CHAR *)Module + names[i]);
                addr = (PVOID *)((CHAR *)Module + functions[ordinals[i]]);

                if (*(USHORT*)name == 'tN') {

                    number = *(ULONG*)((UCHAR*)addr + 4);

                    if (number < g_kdctx.KiServiceLimit) {

                        MultiByteToWideChar(
                            CP_ACP,
                            0,
                            name,
                            (INT)_strlen_a(name),
                            g_pSDT[g_SDTLimit].Name,
                            MAX_PATH);

                        g_pSDT[g_SDTLimit].ServiceId = number;
                        g_pSDT[g_SDTLimit].Address = TableDump[number];
                        TableDump[number] = 0;
                        g_SDTLimit += 1;
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
                    g_pSDT[g_SDTLimit].ServiceId = i;
                    g_pSDT[g_SDTLimit].Address = TableDump[i];
                    _strcpy(g_pSDT[g_SDTLimit].Name, L"NtQuerySystemTime");
                    g_SDTLimit += 1;
                    break;
                }
            }

            supHeapFree(TableDump);
            TableDump = NULL;
        }

        SdtOutputTable(
            hwndDlg,
            pModules,
            g_pSDT,
            g_SDTLimit);

    }
    __finally {

#ifndef _DEBUG
        SendMessage(hwndBanner, WM_CLOSE, 0, 0);
#endif

        if (pModules) {
            supHeapFree(pModules);
        }

        if (TableDump) {
            supHeapFree(TableDump);
        }
    }
}


/*
*
*  W32pServiceTable query related structures and definitions.
*
*/

typedef struct _LOAD_MODULE_ENTRY {
    HMODULE hModule;
    struct _LOAD_MODULE_ENTRY *Next;
} LOAD_MODULE_ENTRY, *PLOAD_MODULE_ENTRY;

typedef struct _WIN32_SHADOWTABLE {
    ULONG Index;
    CHAR Name[256];
    ULONG_PTR KernelStubAddress;
    ULONG_PTR KernelStubTargetAddress;
    struct _WIN32_SHADOWTABLE *NextService;
} WIN32_SHADOWTABLE, *PWIN32_SHADOWTABLE;

typedef enum _RESOLVE_POINTER_TYPE {
    ForwarderString = 0,
    FunctionCode = 1
} RESOLVE_POINTER_TYPE;

typedef struct _RESOLVE_INFO {
    RESOLVE_POINTER_TYPE ResultType;
    union {
        LPCSTR ForwarderName;
        LPVOID Function;
    };
} RESOLVE_INFO, *PRESOLVE_INFO;

/*
* NtRawGetProcAddress
*
* Purpose:
*
* Custom GPA.
*
*/
NTSTATUS NtRawGetProcAddress(
    _In_ LPVOID Module,
    _In_ LPCSTR ProcName,
    _In_ PRESOLVE_INFO Pointer
)
{
    PIMAGE_NT_HEADERS           NtHeaders;
    PIMAGE_EXPORT_DIRECTORY     exp;
    PDWORD                      fntable, nametable;
    PWORD                       ordtable;
    ULONG                       mid, high, low;
    ULONG_PTR                   fnptr, exprva, expsize;
    int                         r;

    NtHeaders = RtlImageNtHeader(Module);
    if (NtHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
        return STATUS_OBJECT_NAME_NOT_FOUND;

    exprva = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    expsize = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    exp = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)Module + exprva);
    fntable = (PDWORD)((ULONG_PTR)Module + exp->AddressOfFunctions);

    if ((ULONG_PTR)ProcName < 0x10000) {
        // ProcName is ordinal
        if (
            ((ULONG_PTR)ProcName < (ULONG_PTR)exp->Base) ||
            ((ULONG_PTR)ProcName >= (ULONG_PTR)exp->Base + exp->NumberOfFunctions))
            return STATUS_OBJECT_NAME_NOT_FOUND;

        fnptr = fntable[(ULONG_PTR)ProcName - exp->Base];

    }
    else {
        // ProcName is ANSI string
        nametable = (PDWORD)((ULONG_PTR)Module + exp->AddressOfNames);
        ordtable = (PWORD)((ULONG_PTR)Module + exp->AddressOfNameOrdinals);

        if (exp->NumberOfNames == 0)
            return STATUS_OBJECT_NAME_NOT_FOUND;

        low = 0;
        high = exp->NumberOfNames;

        do {
            mid = low + (high - low) / 2;
            r = _strcmp_a(ProcName, (LPCSTR)((ULONG_PTR)Module + nametable[mid]));

            if (r > 0)
            {
                low = mid + 1;
            }
            else
            {
                if (r < 0)
                    high = mid;
                else
                    break;
            }
        } while (low < high);

        if (r == 0)
            fnptr = fntable[ordtable[mid]];
        else
            return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    if ((fnptr >= exprva) && (fnptr < exprva + expsize))
        Pointer->ResultType = ForwarderString;
    else
        Pointer->ResultType = FunctionCode;

    Pointer->Function = (LPVOID)((ULONG_PTR)Module + fnptr);
    return STATUS_SUCCESS;
}

/*
* NtRawEnumExports
*
* Purpose:
*
* Enumerate module exports to the table.
*
*/
_Success_(return != 0)
ULONG NtRawEnumExports(
    _In_ HANDLE HeapHandle,
    _In_ LPVOID Module,
    _Out_ PWIN32_SHADOWTABLE* Table
)
{
    PIMAGE_NT_HEADERS           NtHeaders;
    PIMAGE_EXPORT_DIRECTORY		exp;
    PDWORD						FnPtrTable, NameTable;
    PWORD						NameOrdTable;
    ULONG_PTR					fnptr, exprva, expsize;
    ULONG						c, n, result;
    PWIN32_SHADOWTABLE			NewEntry;

    NtHeaders = RtlImageNtHeader(Module);
    if (NtHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
        return 0;

    exprva = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exprva == 0)
        return 0;

    expsize = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    exp = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)Module + exprva);
    FnPtrTable = (PDWORD)((ULONG_PTR)Module + exp->AddressOfFunctions);
    NameTable = (PDWORD)((ULONG_PTR)Module + exp->AddressOfNames);
    NameOrdTable = (PWORD)((ULONG_PTR)Module + exp->AddressOfNameOrdinals);

    result = 0;

    for (c = 0; c < exp->NumberOfFunctions; ++c)
    {
        fnptr = (ULONG_PTR)Module + FnPtrTable[c];
        if (*(PDWORD)fnptr != 0xb8d18b4c)
            continue;

        NewEntry = (PWIN32_SHADOWTABLE)RtlAllocateHeap(HeapHandle,
            HEAP_ZERO_MEMORY, sizeof(WIN32_SHADOWTABLE));

        if (NewEntry == NULL)
            break;

        NewEntry->Index = *(PDWORD)(fnptr + 4);

        for (n = 0; n < exp->NumberOfNames; ++n)
        {
            if (NameOrdTable[n] == c)
            {
                _strncpy_a(&NewEntry->Name[0],
                    sizeof(NewEntry->Name),
                    (LPCSTR)((ULONG_PTR)Module + NameTable[n]),
                    sizeof(NewEntry->Name));

                break;
            }
        }

        ++result;

        *Table = NewEntry;
        Table = &NewEntry->NextService;
    }

    return result;
}

/*
* IATEntryToImport
*
* Purpose:
*
* Resolve function name.
*
*/
_Success_(return != NULL)
LPCSTR IATEntryToImport(
    _In_ LPVOID Module,
    _In_ LPVOID IATEntry,
    _Out_ LPCSTR *ImportModuleName
)
{
    PIMAGE_NT_HEADERS           NtHeaders;
    PIMAGE_IMPORT_DESCRIPTOR    impd;
    ULONG_PTR                   *rname, imprva;
    LPVOID                      *raddr;

    if (ImportModuleName == NULL)
        return NULL;

    NtHeaders = RtlImageNtHeader(Module);
    if (NtHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT)
        return NULL;

    imprva = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (imprva == 0)
        return NULL;

    impd = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)Module + imprva);

    while (impd->Name != 0) {
        raddr = (LPVOID *)((ULONG_PTR)Module + impd->FirstThunk);
        if (impd->OriginalFirstThunk == 0)
            rname = (ULONG_PTR *)raddr;
        else
            rname = (ULONG_PTR *)((ULONG_PTR)Module + impd->OriginalFirstThunk);

        while (*rname != 0) {
            if (IATEntry == raddr)
            {
                if (((*rname) & IMAGE_ORDINAL_FLAG) == 0)
                {
                    *ImportModuleName = (LPCSTR)((ULONG_PTR)Module + impd->Name);
                    return (LPCSTR)&((PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)Module + *rname))->Name;
                }
            }

            ++rname;
            ++raddr;
        }
        ++impd;
    }

    return NULL;
}

/*
* SdtListTableShadow
*
* Purpose:
*
* W32pServiceTable query and list routine.
*
* Note: This code only for Windows 10 RS1+
*
*/
VOID SdtListTableShadow(
    _In_ HWND hwndDlg
)
{
    ULONG       w32u_limit, w32k_limit, c;
    LONG32      jmpaddr;
    HMODULE     w32u = NULL, w32k = NULL, impdll, forwdll;
    PBYTE       fptr;
    PULONG      pServiceLimit, pServiceTable;
    LPCSTR	    ModuleName, FunctionName, ForwarderDot, ForwarderFunctionName;
    HANDLE      EnumerationHeap = NULL;
    ULONG_PTR   win32kBase = 0;

    PWIN32_SHADOWTABLE  table, itable;
    RESOLVE_INFO        rfn;

    PRTL_PROCESS_MODULE_INFORMATION Module, ForwardModule;
    PRTL_PROCESS_MODULES            pModules = NULL;

    LOAD_MODULE_ENTRY               LoadedModulesHead;
    PLOAD_MODULE_ENTRY              ModuleEntry = NULL, PreviousEntry = NULL;

    hde64s hs;

    WCHAR szBuffer[MAX_PATH * 2];
    CHAR szForwarderModuleName[MAX_PATH];

#ifndef _DEBUG
    HWND hwndBanner;

    hwndBanner = supDisplayLoadBanner(hwndDlg,
        TEXT("Loading service table dump, please wait"));
#endif

    LoadedModulesHead.Next = NULL;
    LoadedModulesHead.hModule = NULL;

    __try {

        //
        // Query modules list.
        //
        pModules = (PRTL_PROCESS_MODULES)supGetSystemInfo(SystemModuleInformation);
        if (pModules == NULL) {
            MessageBox(hwndDlg, TEXT("Could not allocate memory for Modules list"), NULL, MB_ICONERROR);
            __leave;
        }

        //
        // Check if table already built.
        //
        if (g_pSDTShadow == NULL) {

            //
            // Find win32k loaded image base.
            //
            Module = (PRTL_PROCESS_MODULE_INFORMATION)supFindModuleEntryByName(pModules,
                "win32k.sys");

            if (Module == NULL) {
                MessageBox(hwndDlg, TEXT("Could not find win32k module"), NULL, MB_ICONERROR);
                __leave;
            }

            win32kBase = (ULONG_PTR)Module->ImageBase;

            //
            // Prepare dedicated heap for exports enumeration.
            //
            EnumerationHeap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
            if (EnumerationHeap == NULL) {
                MessageBox(hwndDlg, TEXT("Could not allocate memory"), NULL, MB_ICONERROR);
                __leave;
            }

            //
            // Load win32u and dump exports, in KnownDlls.
            //
            w32u = LoadLibraryEx(TEXT("win32u.dll"), NULL, 0);
            if (w32u == NULL) {
                MessageBox(hwndDlg, TEXT("Could not load win32u.dll"), NULL, MB_ICONERROR);
                __leave;
            }

            w32u_limit = NtRawEnumExports(EnumerationHeap, w32u, &table);

            //
            // Load win32k.
            //
            _strcpy(szBuffer, g_WinObj.szSystemDirectory);
            _strcat(szBuffer, TEXT("\\win32k.sys"));
            w32k = LoadLibraryEx(szBuffer, NULL, DONT_RESOLVE_DLL_REFERENCES);
            if (w32k == NULL) {
                MessageBox(hwndDlg, TEXT("Could not load win32k.sys"), NULL, MB_ICONERROR);
                __leave;
            }

            //
            // Query win32k!W32pServiceLimit.
            //
            pServiceLimit = (PULONG)GetProcAddress(w32k, "W32pServiceLimit");
            if (pServiceLimit == NULL) {
                MessageBox(hwndDlg, TEXT("W32pServiceLimit not found in win32k module"), NULL, MB_ICONERROR);
                __leave;
            }

            w32k_limit = *pServiceLimit;
            if (w32k_limit != w32u_limit) {
                MessageBox(hwndDlg, TEXT("Not all services found in win32u"), NULL, MB_ICONERROR);
                __leave;
            }

            //
            // Query win32k!W32pServiceTable.
            //
            if (!NT_SUCCESS(NtRawGetProcAddress(w32k, "W32pServiceTable", &rfn))) {
                MessageBox(hwndDlg, TEXT("W32pServiceTable not found in win32k module"), NULL, MB_ICONERROR);
                __leave;
            }

            //
            // Set global variables.
            //
            g_kdctx.W32pServiceLimit = w32k_limit;
            g_kdctx.W32pServiceTableAddress = win32kBase + (ULONG_PTR)rfn.Function - (ULONG_PTR)w32k;

            //
            // Insert SystemRoot\System32\Drivers to the loader directories search list.
            //
            _strcpy(szBuffer, g_WinObj.szSystemDirectory);
            _strcat(szBuffer, TEXT("\\drivers"));
            SetDllDirectory(szBuffer);

            //
            // Build table.
            //
            pServiceTable = (PULONG)rfn.Function;

            for (c = 0; c < w32k_limit; ++c) {

                itable = table;
                while (itable != 0) {

                    if (itable->Index == c + 0x1000) {

                        itable->KernelStubAddress = pServiceTable[c];
                        fptr = (PBYTE)w32k + itable->KernelStubAddress;
                        itable->KernelStubAddress += win32kBase;

                        hde64_disasm((void*)fptr, &hs);
                        if (hs.flags & F_ERROR) {
                            OutputDebugString(TEXT("SdtListTableShadow, HDE Error\r\n"));
                            break;
                        }

                        while (fptr) {

                            jmpaddr = *(PLONG32)(fptr + (hs.len - 4)); // retrieve the offset
                            fptr = fptr + hs.len + jmpaddr; // hs.len -> length of jmp instruction

                            FunctionName = IATEntryToImport(w32k, fptr, &ModuleName);
                            if (FunctionName == NULL) {
                                OutputDebugString(TEXT("SdtListTableShadow, could not resolve function name\r\n"));
                                break;
                            }

                            impdll = LoadLibraryExA(ModuleName, NULL, DONT_RESOLVE_DLL_REFERENCES);
                            if (impdll == NULL) {
                                OutputDebugString(TEXT("SdtListTableShadow, could not load import dll\r\n"));
                                break;
                            }

                            //
                            // Rememeber loaded module to the internal list.
                            //
                            ModuleEntry = (PLOAD_MODULE_ENTRY)RtlAllocateHeap(EnumerationHeap,
                                HEAP_ZERO_MEMORY,
                                sizeof(LOAD_MODULE_ENTRY));

                            if (ModuleEntry) {
                                ModuleEntry->Next = LoadedModulesHead.Next;
                                ModuleEntry->hModule = impdll;
                                LoadedModulesHead.Next = ModuleEntry;
                            }

                            if (!NT_SUCCESS(NtRawGetProcAddress(impdll, FunctionName, &rfn))) {
                                OutputDebugString(TEXT("SdtListTableShadow, could not resolve function address\r\n"));
                                break;
                            }

                            if (rfn.ResultType == ForwarderString) {

                                ForwarderDot = _strchr_a(rfn.ForwarderName, '.');
                                ForwarderFunctionName = ForwarderDot + 1;

                                //
                                // Build forwarder module name.
                                //
                                RtlSecureZeroMemory(szForwarderModuleName, sizeof(szForwarderModuleName));
                                _strncpy_a(szForwarderModuleName, sizeof(szForwarderModuleName),
                                    rfn.ForwarderName, ForwarderDot - &rfn.ForwarderName[0]);

                                _strcat_a(szForwarderModuleName, ".SYS");

                                ForwardModule = (PRTL_PROCESS_MODULE_INFORMATION)supFindModuleEntryByName(pModules,
                                    szForwarderModuleName);

                                if (ForwardModule) {

                                    if (ForwarderFunctionName) {

                                        forwdll = LoadLibraryExA(szForwarderModuleName, NULL, DONT_RESOLVE_DLL_REFERENCES);
                                        if (forwdll) {

                                            //
                                            // Remember loaded module to the internal list.
                                            //
                                            ModuleEntry = (PLOAD_MODULE_ENTRY)RtlAllocateHeap(EnumerationHeap,
                                                HEAP_ZERO_MEMORY,
                                                sizeof(LOAD_MODULE_ENTRY));

                                            if (ModuleEntry) {
                                                ModuleEntry->Next = LoadedModulesHead.Next;
                                                ModuleEntry->hModule = forwdll;
                                                LoadedModulesHead.Next = ModuleEntry;
                                            }

                                            if (NT_SUCCESS(NtRawGetProcAddress(forwdll, ForwarderFunctionName, &rfn))) {

                                                //
                                                // Calculate routine kernel mode address.
                                                //
                                                itable->KernelStubTargetAddress =
                                                    (ULONG_PTR)ForwardModule->ImageBase + ((ULONG_PTR)rfn.Function - (ULONG_PTR)forwdll);
                                            }

                                        }
                                        else {
                                            OutputDebugString(TEXT("SdtListTableShadow, could not load forwarded module\r\n"));
                                        }

                                    } // if (ForwarderFunctionName)

                                }//if (ForwardModule)

                            }
                            else {
                                //
                                // Calculate routine kernel mode address.
                                //
                                Module = (PRTL_PROCESS_MODULE_INFORMATION)supFindModuleEntryByName(pModules, ModuleName);
                                if (Module) {
                                    itable->KernelStubTargetAddress =
                                        (ULONG_PTR)Module->ImageBase + ((ULONG_PTR)rfn.Function - (ULONG_PTR)impdll);
                                }
                            }
                            break;
                        }
                    }
                    itable = itable->NextService;
                }
            }

            //
            // Output table.
            //
            g_pSDTShadow = (PSERVICETABLEENTRY)supHeapAlloc(sizeof(SERVICETABLEENTRY) * w32k_limit);
            if (g_pSDTShadow) {

                //
                // Convert table to output format.
                //
                g_SDTShadowLimit = 0;
                itable = table;
                while (itable != 0) {

                    //
                    // Service Id.
                    //
                    g_pSDTShadow[g_SDTShadowLimit].ServiceId = itable->Index;

                    //
                    // Routine real address.
                    //
                    if (itable->KernelStubTargetAddress) {
                        //
                        // Output stub target address.
                        //
                        g_pSDTShadow[g_SDTShadowLimit].Address = itable->KernelStubTargetAddress;

                    } else {
                        //
                        // Query failed, output stub address.
                        //
                        g_pSDTShadow[g_SDTShadowLimit].Address = itable->KernelStubAddress;

                    }

                    //
                    // Remember service name.
                    //
                    MultiByteToWideChar(
                        CP_ACP,
                        0,
                        itable->Name,
                        (INT)_strlen_a(itable->Name),
                        g_pSDTShadow[g_SDTShadowLimit].Name,
                        MAX_PATH);

                    g_SDTShadowLimit += 1;

                    itable = itable->NextService;
                }

            }

        } // if (g_pSDTShadow == NULL)


        //
        // Output shadow table if available.
        //
        if (g_pSDTShadow) {

            SdtOutputTable(
                hwndDlg,
                pModules,
                g_pSDTShadow,
                g_SDTShadowLimit);

        }

    }
    __finally {
        //
        // Restore default search order.
        //
        SetDllDirectory(NULL);

        //
        // Unload all loaded modules.
        //
        for (PreviousEntry = &LoadedModulesHead, ModuleEntry = LoadedModulesHead.Next;
            ModuleEntry != NULL;
            PreviousEntry = ModuleEntry, ModuleEntry = ModuleEntry->Next)
        {
            FreeLibrary(ModuleEntry->hModule);
        }

        if (pModules) supHeapFree(pModules);
        if (EnumerationHeap) RtlDestroyHeap(EnumerationHeap);
        if (w32u) FreeLibrary(w32u);
        if (w32k) FreeLibrary(w32k);

#ifndef _DEBUG
        SendMessage(hwndBanner, WM_CLOSE, 0, 0);
#endif
    }
}

/*
* extrasCreateSSDTDialog
*
* Purpose:
*
* Create and initialize SSDT Dialog.
*
*/
VOID extrasCreateSSDTDialog(
    _In_ HWND hwndParent,
    _In_ SSDT_DLG_MODE Mode
)
{
    INT         dlgIndex;
    HWND        hwndDlg;
    LVCOLUMN    col;

    EXTRASCONTEXT  *pDlgContext;

    EXTRASCALLBACK CallbackParam;

    switch (Mode) {
    case SST_Ntos:
        dlgIndex = wobjKSSTDlgId;
        break;
    case SST_Win32k:
        dlgIndex = wobjW32SSTDlgId;
        break;
    default:
        return;

    }

    //allow only one dialog
    if (g_WinObj.AuxDialogs[dlgIndex]) {
        if (IsIconic(g_WinObj.AuxDialogs[dlgIndex]))
            ShowWindow(g_WinObj.AuxDialogs[dlgIndex], SW_RESTORE);
        else
            SetActiveWindow(g_WinObj.AuxDialogs[dlgIndex]);
        return;
    }

    RtlSecureZeroMemory(&SSTDlgContext[Mode], sizeof(EXTRASCONTEXT));

    pDlgContext = &SSTDlgContext[Mode];
    pDlgContext->DialogMode = Mode;

    hwndDlg = CreateDialogParam(
        g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_EXTRASLIST),
        hwndParent,
        &SdtDialogProc,
        (LPARAM)pDlgContext);

    if (hwndDlg == NULL) {
        return;
    }

    pDlgContext->hwndDlg = hwndDlg;
    g_WinObj.AuxDialogs[dlgIndex] = hwndDlg;
    pDlgContext->SizeGrip = supCreateSzGripWindow(hwndDlg);

    extrasSetDlgIcon(hwndDlg);

    pDlgContext->ListView = GetDlgItem(hwndDlg, ID_EXTRASLIST);
    if (pDlgContext->ListView) {

        //
        // Set listview imagelist, style flags and theme.
        //
        ListView_SetImageList(
            pDlgContext->ListView,
            g_ListViewImages,
            LVSIL_SMALL);

        ListView_SetExtendedListViewStyle(
            pDlgContext->ListView,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

        SetWindowTheme(pDlgContext->ListView, TEXT("Explorer"), NULL);

        //columns
        RtlSecureZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
        col.iSubItem++;
        col.pszText = TEXT("Id");
        col.cx = 80;
        col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;
        col.iImage = ImageList_GetImageCount(g_ListViewImages) - 1;
        ListView_InsertColumn(pDlgContext->ListView, col.iSubItem, &col);

        col.iImage = I_IMAGENONE;

        col.iSubItem++;
        col.pszText = TEXT("Service Name");
        col.iOrder++;
        col.cx = 220;
        ListView_InsertColumn(pDlgContext->ListView, col.iSubItem, &col);

        col.iSubItem++;
        col.pszText = TEXT("Address");
        col.iOrder++;
        col.cx = 130;
        ListView_InsertColumn(pDlgContext->ListView, col.iSubItem, &col);

        col.iSubItem++;
        col.pszText = TEXT("Module");
        col.iOrder++;
        col.cx = 220;
        ListView_InsertColumn(pDlgContext->ListView, col.iSubItem, &col);

        //remember column count
        pDlgContext->lvColumnCount = col.iSubItem;

        switch (Mode) {

        case SST_Ntos:
            SdtListTable(hwndDlg);
            break;
        case SST_Win32k:
            SdtListTableShadow(hwndDlg);
            break;

        default:
            break;
        }

        SendMessage(hwndDlg, WM_SIZE, 0, 0);
        CallbackParam.lParam = 0;
        CallbackParam.Value = Mode;
        ListView_SortItemsEx(pDlgContext->ListView, &SdtDlgCompareFunc, (LPARAM)&CallbackParam);
        SetFocus(pDlgContext->ListView);
    }
}
