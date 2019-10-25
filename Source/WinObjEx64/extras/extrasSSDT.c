/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       EXTRASSSDT.C
*
*  VERSION:     1.81
*
*  DATE:        18 Oct 2019
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "hde/hde64.h"
#include "extras.h"
#include "extrasSSDT.h"
#include "ntos/ntldr.h"

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
* KiServiceTable/W32pServiceTable Dialog listview comparer function.
*
*/
INT CALLBACK SdtDlgCompareFunc(
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort //pointer to EXTRASCALLBACK
)
{
    INT nResult = 0;

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
    LPNMHDR nhdr = (LPNMHDR)lParam;
    INT     nImageIndex, mark;
    LPWSTR  lpItem;

    EXTRASCALLBACK CallbackParam;
    WCHAR szBuffer[MAX_PATH + 1];

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

    case NM_DBLCLK:
        mark = ListView_GetSelectionMark(pDlgContext->ListView);
        if (mark >= 0) {
            lpItem = supGetItemText(pDlgContext->ListView, mark, 3, NULL);
            if (lpItem) {
                RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
                if (supGetWin32FileName(lpItem, szBuffer, MAX_PATH))
                    supShowProperties(pDlgContext->hwndDlg, szBuffer);
                supHeapFree(lpItem);
            }
        }
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
            extrasSimpleListResize(hwndDlg);
        }
        break;

    case WM_CLOSE:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {

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
    ULONG i, iImage;
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

    SetWindowText(Context->StatusBar, szBuffer);

    iImage = ObManagerGetImageIndexByTypeIndex(ObjectTypeDevice);

    //list table
    for (i = 0; i < Count; i++) {

        //ServiceId
        RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
        lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
        lvitem.iSubItem = 0;
        lvitem.iItem = MAXINT;
        lvitem.iImage = iImage; //imagelist id
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

        pModules = (PRTL_PROCESS_MODULES)supGetSystemInfo(SystemModuleInformation, NULL);
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

//
// Win32kApiSetTable adapter patterns
//
BYTE Win32kApiSetAdapterPattern1[] = {
   0x4C, 0x8B, 0x15
};
BYTE Win32kApiSetAdapterPattern2[] = {
   0x48, 0x8B, 0x05
};

#define W32K_API_SET_ADAPTERS_COUNT 2

W32K_API_SET_ADAPTER_PATTERN W32kApiSetAdapters[W32K_API_SET_ADAPTERS_COUNT] = {
    { sizeof(Win32kApiSetAdapterPattern1), Win32kApiSetAdapterPattern1 },
    { sizeof(Win32kApiSetAdapterPattern2), Win32kApiSetAdapterPattern2 }
};

/*
* ApiSetExtractReferenceFromAdapter
*
* Purpose:
*
* Extract apiset reference from adapter code.
*
*/
ULONG_PTR ApiSetExtractReferenceFromAdapter(
    _In_ PBYTE ptrFunction
)
{
    BOOL       bFound;
    PBYTE      ptrCode = ptrFunction;
    ULONG      Index = 0, i;
    ULONG_PTR  Reference = 0;
    LONG       Rel = 0;
    hde64s     hs;

    ULONG      PatternSize;
    PVOID      PatternData;

    __try {

        do {
            hde64_disasm((void*)(ptrCode + Index), &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == 7) {

                bFound = FALSE;

                for (i = 0; i < W32K_API_SET_ADAPTERS_COUNT; i++) {

                    PatternSize = W32kApiSetAdapters[i].Size;
                    PatternData = W32kApiSetAdapters[i].Data;

                    if (PatternSize == RtlCompareMemory(&ptrCode[Index],
                        PatternData,
                        PatternSize))
                    {
                        Rel = *(PLONG)(ptrCode + Index + (hs.len - 4));
                        bFound = TRUE;
                        break;
                    }

                }

                if (bFound)
                    break;
            }

            Index += hs.len;

        } while (Index < 32);

        if (Rel == 0)
            return 0;

        Reference = (ULONG_PTR)ptrCode + Index + hs.len + Rel;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }

    return Reference;
}

/*
* ApiSetResolveWin32kTableEntry
*
* Purpose:
*
* Find entry in Win32kApiSetTable.
*
* Function return TRUE on success and sets ResolvedEntry parameter.
*
*/
BOOLEAN ApiSetResolveWin32kTableEntry(
    _In_ ULONG_PTR ApiSetTable,
    _In_ PBYTE MappedImageBase,
    _In_ ULONG_PTR LookupEntry,
    _Out_ PW32K_API_SET_TABLE_ENTRY *ResolvedEntry
)
{
    BOOLEAN bResult = FALSE;
    PW32K_API_SET_TABLE_ENTRY Entry = (PW32K_API_SET_TABLE_ENTRY)ApiSetTable;
    ULONG EntriesCount;
    ULONG_PTR EntryValue;
    PULONG_PTR ArrayPtr;

    UNREFERENCED_PARAMETER(MappedImageBase);

    *ResolvedEntry = NULL;

    //
    // Lookup entry in table.
    //
    __try {
        while (Entry->Host) {
            EntriesCount = Entry->Host->HostEntriesCount;
            ArrayPtr = (PULONG_PTR)Entry->HostEntriesArray;
            //
            // Search inside table host entry array.
            //
            while (EntriesCount) {

                EntryValue = (ULONG_PTR)ArrayPtr;
                ArrayPtr++;
                EntriesCount--;

                if (EntryValue == LookupEntry) {
                    *ResolvedEntry = Entry;
                    bResult = TRUE;
                    break;
                }

            }
            Entry = (PW32K_API_SET_TABLE_ENTRY)RtlOffsetToPointer(Entry, sizeof(W32K_API_SET_TABLE_ENTRY));
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        //
        // Should never be here. Only in case if table structure changed or ApiSetTable address points to invalid data.
        //
        DbgPrint("Win32kApiSet list exception %lx\r\n", GetExceptionCode());
        return FALSE;
    }

    return bResult;
}

/*
* ApiSetLoadResolvedModule
*
* Purpose:
*
* Final apiset resolving and loading actual file.
*
* Function return NTSTATUS value and sets ResolvedEntry parameter.
*
*/
NTSTATUS ApiSetLoadResolvedModule(
    _In_ PVOID ApiSetMap,
    _In_ PUNICODE_STRING ApiSetToResolve,
    _Out_ PANSI_STRING ConvertedModuleName,
    _Out_ HMODULE *DllModule
)
{
    BOOL            ResolvedResult;
    NTSTATUS        Status;
    UNICODE_STRING  usResolvedModule;

    ResolvedResult = FALSE;
    RtlInitEmptyUnicodeString(&usResolvedModule, NULL, 0);

    //
    // Resolve ApiSet.
    //
    Status = NtLdrApiSetResolveLibrary(ApiSetMap,
        ApiSetToResolve,
        NULL,
        &ResolvedResult,
        &usResolvedModule);

    if (NT_SUCCESS(Status)) {

        if (ResolvedResult) {
            //
            // ApiSet resolved, load result library.
            //
            *DllModule = LoadLibraryEx(usResolvedModule.Buffer, NULL, DONT_RESOLVE_DLL_REFERENCES);

            //
            // Convert resolved name back to ANSI for module query.
            //
            RtlUnicodeStringToAnsiString(ConvertedModuleName,
                &usResolvedModule,
                TRUE);

            RtlFreeUnicodeString(&usResolvedModule);
            Status = STATUS_SUCCESS;
        }
    }
    else {
        //
        // Change status code for dbg output.
        //
        if (Status == STATUS_UNSUCCESSFUL)
            Status = STATUS_APISET_NOT_PRESENT;
    }

    return Status;
}

/*
* SdtResolveServiceEntryModule
*
* Purpose:
*
* Find a module for shadow table entry by parsing apisets(if present) and/or forwarders (if present).
*
* Function return NTSTATUS value and sets ResolvedModule, ResolvedModuleName, FunctionName parameters.
*
*/
_Success_(return == STATUS_SUCCESS)
NTSTATUS SdtResolveServiceEntryModule(
    _In_ PBYTE FunctionPtr,
    _In_ HMODULE MappedWin32k,
    _In_opt_ PVOID ApiSetMap,
    _In_ ULONG_PTR Win32kApiSetTable,
    _In_ PWIN32_SHADOWTABLE ShadowTableEntry,
    _Out_ HMODULE *ResolvedModule,
    _Out_ PANSI_STRING ResolvedModuleName,
    _Out_ LPCSTR *FunctionName
)
{
    BOOLEAN         NeedApiSetResolve = (g_NtBuildNumber > 18885);
    BOOLEAN         Win32kApiSetTableExpected = (g_NtBuildNumber > 18935);

    NTSTATUS        resultStatus = STATUS_UNSUCCESSFUL, resolveStatus;

    HMODULE         DllModule = NULL;

    LONG32          JmpAddress;
    ULONG_PTR       ApiSetReference;

    LPCSTR	        ModuleName;
    UNICODE_STRING  usApiSetEntry, usModuleName;

    hde64s hs;

    PW32K_API_SET_TABLE_ENTRY Win32kApiSetEntry;


    *ResolvedModule = NULL;

    hde64_disasm((void*)FunctionPtr, &hs);
    if (hs.flags & F_ERROR) {
        return STATUS_INTERNAL_ERROR;
    }

    do {

        //
        // See if this is new Win32kApiSetTable adapter.
        //
        if (Win32kApiSetTableExpected) {

            ApiSetReference = ApiSetExtractReferenceFromAdapter(FunctionPtr);
            if (ApiSetReference) {

                if (!ApiSetResolveWin32kTableEntry(Win32kApiSetTable,
                    (PBYTE)MappedWin32k,
                    ApiSetReference,
                    &Win32kApiSetEntry))
                {
                    return STATUS_APISET_NOT_PRESENT;
                }

                RtlInitUnicodeString(&usApiSetEntry, Win32kApiSetEntry->Host->HostName);
                resolveStatus = ApiSetLoadResolvedModule(ApiSetMap, &usApiSetEntry, ResolvedModuleName, &DllModule);
                if (NT_SUCCESS(resolveStatus)) {
                    if (DllModule) {
                        *ResolvedModule = DllModule;
                        *FunctionName = ShadowTableEntry->Name;
                        return STATUS_SUCCESS;
                    }
                    else {
                        return STATUS_DRIVER_UNABLE_TO_LOAD;
                    }
                }
                else {
                    return resolveStatus;
                }

            }
            else {
                resultStatus = STATUS_APISET_NOT_HOSTED;
            }
        }

        JmpAddress = *(PLONG32)(FunctionPtr + (hs.len - 4)); // retrieve the offset
        FunctionPtr = FunctionPtr + hs.len + JmpAddress; // hs.len -> length of jmp instruction

        *FunctionName = NtRawIATEntryToImport(MappedWin32k, FunctionPtr, &ModuleName);
        if (*FunctionName == NULL) {
            resultStatus = STATUS_PROCEDURE_NOT_FOUND;
            break;
        }

        //
        // Convert module name to UNICODE.
        //
        if (RtlCreateUnicodeStringFromAsciiz(&usModuleName, (PSTR)ModuleName)) {

            //
            // Check whatever ApiSet resolving required.
            //
            if (NeedApiSetResolve) {

                resolveStatus = ApiSetLoadResolvedModule(ApiSetMap,
                    &usModuleName,
                    ResolvedModuleName, &DllModule);

                if (!NT_SUCCESS(resolveStatus)) {
                    RtlFreeUnicodeString(&usModuleName);
                    return resolveStatus;
                }

            }
            else {
                //
                // No ApiSet resolve required, load as usual.
                //
                DllModule = LoadLibraryEx(usModuleName.Buffer, NULL, DONT_RESOLVE_DLL_REFERENCES);
                RtlUnicodeStringToAnsiString(ResolvedModuleName, &usModuleName, TRUE);
            }

            RtlFreeUnicodeString(&usModuleName);

            *ResolvedModule = DllModule;
            resultStatus = (DllModule != NULL) ? STATUS_SUCCESS : STATUS_DRIVER_UNABLE_TO_LOAD;
        }


    } while (FALSE);

    return resultStatus;
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
    BOOLEAN     NeedApiSetResolve = (g_NtBuildNumber > 18885);
    BOOLEAN     Win32kApiSetTableExpected = (g_NtBuildNumber > 18935);
    NTSTATUS    Status;
    ULONG       w32u_limit, w32k_limit, c;
    HMODULE     w32u = NULL, w32k = NULL, DllModule, forwdll;
    PBYTE       fptr;
    PULONG      pServiceLimit, pServiceTable;
    LPCSTR	    ModuleName, FunctionName, ForwarderDot, ForwarderFunctionName;
    HANDLE      EnumerationHeap = NULL;
    ULONG_PTR   win32kBase = 0;

    PWIN32_SHADOWTABLE  table, itable;
    RESOLVE_INFO        rfn;

    ULONG_PTR   Win32kApiSetTable = 0;

    PVOID                           ApiSetMap = NULL;
    ULONG                           ApiSetSchemaVersion = 0;

    PRTL_PROCESS_MODULE_INFORMATION Module, ForwardModule;
    PRTL_PROCESS_MODULES            pModules = NULL;

    LOAD_MODULE_ENTRY               LoadedModulesHead;
    PLOAD_MODULE_ENTRY              ModuleEntry = NULL, PreviousEntry = NULL;

    ANSI_STRING ResolvedModuleName;

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
        pModules = (PRTL_PROCESS_MODULES)supGetSystemInfo(SystemModuleInformation, NULL);
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

            w32u_limit = NtRawEnumW32kExports(EnumerationHeap, w32u, &table);

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

            if (Win32kApiSetTableExpected) {
                //
                // Locate Win32kApiSetTable variable. Failure will result in unresolved apiset adapters.
                //
                Win32kApiSetTable = kdQueryWin32kApiSetTable(w32k);
                if (Win32kApiSetTable == 0) {
                    MessageBox(hwndDlg, 
                        TEXT("Win32kApiSetTable was not found, win32k adapters targets will not be determinated."), 
                        NULL, 
                        MB_ICONINFORMATION);
                }
            }

            //
            // Query win32k!W32pServiceLimit.
            //
            pServiceLimit = (PULONG)GetProcAddress(w32k, "W32pServiceLimit");
            if (pServiceLimit == NULL) {
                MessageBox(hwndDlg, TEXT("W32pServiceLimit not found in win32k module"), NULL, MB_ICONERROR);
                __leave;
            }

            //
            // Check whatever win32u is compatible with win32k data.
            //
            w32k_limit = *pServiceLimit;
            if (w32k_limit != w32u_limit) {
                MessageBox(hwndDlg, TEXT("Not all services found in win32u"), NULL, MB_ICONERROR);
                __leave;
            }

            //
            // Query win32k!W32pServiceTable.
            //
            RtlSecureZeroMemory(&rfn, sizeof(RESOLVE_INFO));
            if (!NT_SUCCESS(NtRawGetProcAddress(w32k, "W32pServiceTable", &rfn))) {
                MessageBox(hwndDlg, TEXT("W32pServiceTable not found in win32k module"), NULL, MB_ICONERROR);
                __leave;
            }

            //
            // Query ApiSetMap
            //
            if (NeedApiSetResolve) {

                if (!NtLdrApiSetLoadFromPeb(&ApiSetSchemaVersion, (PVOID*)&ApiSetMap)) {
                    MessageBox(hwndDlg, TEXT("ApiSetSchema map not found"), NULL, MB_ICONERROR);
                    __leave;
                }

                //
                // Windows 10+ uses modern ApiSetSchema version, everything else not supported.
                //
                if (ApiSetSchemaVersion != 6) {
                    MessageBox(hwndDlg, TEXT("ApiSetSchema version is unknown"), NULL, MB_ICONERROR);
                    __leave;
                }
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

                        DllModule = NULL;
                        RtlSecureZeroMemory(&ResolvedModuleName, sizeof(ResolvedModuleName));

                        Status = SdtResolveServiceEntryModule(fptr,
                            w32k,
                            ApiSetMap,
                            Win32kApiSetTable,
                            itable,
                            &DllModule,
                            &ResolvedModuleName,
                            &FunctionName);

                        if (!NT_SUCCESS(Status)) {

                            //
                            // Most of this errors are not critical and ok.
                            //

                            switch (Status) {

                            case STATUS_INTERNAL_ERROR:
                                DbgPrint("SdtListTableShadow, HDE Error\r\n");
                                break;

                            case STATUS_APISET_NOT_HOSTED:
                                //
                                // Corresponding apiset not found.
                                //
                                DbgPrint("SdtListTableShadow not an apiset adapter for %s\r\n",
                                    itable->Name);
                                break;

                            case STATUS_APISET_NOT_PRESENT:
                                //
                                // ApiSet extension present but empty.
                                // 
                                DbgPrint("SdtListTableShadow, extension contains a host for a non-existent apiset %s\r\n",
                                    itable->Name);
                                break;

                            case STATUS_PROCEDURE_NOT_FOUND:
                                //
                                // Not a critical issue. This mean we cannot pass this service next to forwarder lookup code.
                                //
                                DbgPrint("SdtListTableShadow, could not resolve function name in module for service id %lu, service name %s\r\n",
                                    itable->Index,
                                    itable->Name);
                                break;

                            case STATUS_DRIVER_UNABLE_TO_LOAD:
                                DbgPrint("SdtListTableShadow, could not load import dll %s\r\n", ResolvedModuleName.Buffer);
                                break;

                            default:
                                break;
                            }

                            break;
                        }

                        if (DllModule == NULL) {
                            break;
                        }

                        ModuleName = ResolvedModuleName.Buffer;

                        //
                        // Rememeber loaded module to the internal list.
                        //
                        ModuleEntry = (PLOAD_MODULE_ENTRY)RtlAllocateHeap(EnumerationHeap,
                            HEAP_ZERO_MEMORY,
                            sizeof(LOAD_MODULE_ENTRY));

                        if (ModuleEntry) {
                            ModuleEntry->Next = LoadedModulesHead.Next;
                            ModuleEntry->hModule = DllModule;
                            LoadedModulesHead.Next = ModuleEntry;
                        }

                        if (!NT_SUCCESS(NtRawGetProcAddress(DllModule, FunctionName, &rfn))) {
                            DbgPrint("SdtListTableShadow: Could not resolve function %s address\r\n", FunctionName);
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
                                    (ULONG_PTR)Module->ImageBase + ((ULONG_PTR)rfn.Function - (ULONG_PTR)DllModule);
                            }

                            RtlFreeAnsiString(&ResolvedModuleName);

                        }
                        //break;
                    //}
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

                    }
                    else {
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

    WCHAR szText[100];


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
    pDlgContext->StatusBar = GetDlgItem(hwndDlg, ID_EXTRASLIST_STATUSBAR);

    _strcpy(szText, TEXT("Viewing "));
    if (Mode == SST_Ntos)
        _strcat(szText, TEXT("ntoskrnl service table"));
    else
        _strcat(szText, TEXT("win32k service table"));

    SetWindowText(hwndDlg, szText);

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
