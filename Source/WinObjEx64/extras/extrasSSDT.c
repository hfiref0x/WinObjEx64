/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       EXTRASSSDT.C
*
*  VERSION:     1.84
*
*  DATE:        28 Feb 2020
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

SDT_TABLE KiServiceTable;
SDT_TABLE W32pServiceTable;

EXTRASCONTEXT SSTDlgContext[SST_Max];

VOID SdtListCreate(
    _In_ HWND hwndDlg,
    _In_ BOOL fRescan,
    _In_ EXTRASCONTEXT* pDlgContext);

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

    EXTRASCONTEXT* pDlgContext;
    EXTRASCALLBACK* CallbackParam = (EXTRASCALLBACK*)lParamSort;

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
* Table list popup construction.
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
        InsertMenu(hMenu, 1, MF_BYCOMMAND, ID_VIEW_REFRESH, T_RESCAN);
        TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, pt1.x, pt1.y, 0, hwndDlg, NULL);
        DestroyMenu(hMenu);
    }
}

/*
* SdtFreeGlobals
*
* Purpose:
*
* Release memory allocated for SDT table globals.
*
*/
VOID SdtFreeGlobals()
{
    if (KiServiceTable.Allocated) {
        supHeapFree(KiServiceTable.Table);
        KiServiceTable.Allocated = FALSE;
    }
    if (W32pServiceTable.Allocated) {
        supHeapFree(W32pServiceTable.Table);
        W32pServiceTable.Allocated = FALSE;
    }
}

/*
* SdtSaveListToFile
*
* Purpose:
*
* Dump table to the selected file.
*
*/
VOID SdtSaveListToFile(
    _In_ HWND hwndDlg,
    _In_ EXTRASCONTEXT* pDlgContext
)
{
    WCHAR   ch;
    INT	    row, subitem, numitems;
    SIZE_T  sz, k, BufferSize = 0;
    LPWSTR  pItem = NULL, pText = NULL;
    HCURSOR hSaveCursor, hHourGlass;
    WCHAR   szTempBuffer[MAX_PATH + 1];

    RtlSecureZeroMemory(szTempBuffer, sizeof(szTempBuffer));

    _strcpy(szTempBuffer, TEXT("List.txt"));
    if (supSaveDialogExecute(hwndDlg, (LPWSTR)&szTempBuffer, TEXT("Text files\0*.txt\0\0"))) {

        pText = (LPWSTR)supHeapAlloc(0x2000);
        if (pText == NULL) return;

        hHourGlass = LoadCursor(NULL, IDC_WAIT);

        ch = (WCHAR)0xFEFF;
        supWriteBufferToFile(szTempBuffer, &ch, sizeof(WCHAR), FALSE, FALSE);

        SetCapture(hwndDlg);
        hSaveCursor = SetCursor(hHourGlass);

        numitems = ListView_GetItemCount(pDlgContext->ListView);
        for (row = 0; row < numitems; row++) {

            pText[0] = 0;
            for (subitem = 0; subitem < pDlgContext->lvColumnCount; subitem++) {

                sz = 0;
                pItem = supGetItemText(pDlgContext->ListView, row, subitem, &sz);
                if (pItem) {
                    _strcat(pText, pItem);
                    supHeapFree(pItem);
                }
                if (subitem == 1) {
                    for (k = 100; k > sz / sizeof(WCHAR); k--) {
                        _strcat(pText, TEXT(" "));
                    }
                }
                else {
                    _strcat(pText, TEXT("\t"));
                }
            }
            _strcat(pText, L"\r\n");
            BufferSize = _strlen(pText) * sizeof(WCHAR);
            supWriteBufferToFile(szTempBuffer, pText, BufferSize, FALSE, TRUE);
        }

        SetCursor(hSaveCursor);
        ReleaseCapture();
        supHeapFree(pText);
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
    _In_ EXTRASCONTEXT* pDlgContext
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
        pDlgContext->lvColumnToSort = ((NMLISTVIEW*)lParam)->iSubItem;
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
    EXTRASCONTEXT* pDlgContext;

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

        switch (LOWORD(wParam)) {

        case IDCANCEL:
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            return TRUE;

        case ID_OBJECT_COPY:
            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
            if (pDlgContext) {
                SdtSaveListToFile(hwndDlg, pDlgContext);
            }
            return TRUE;

        case ID_VIEW_REFRESH:
            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
            if (pDlgContext) {
                SdtListCreate(hwndDlg, TRUE, pDlgContext);
            }
            break;
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
* SdtListOutputTable
*
* Purpose:
*
* Output dumped and converted syscall table to listview.
*
*/
VOID SdtListOutputTable(
    _In_ HWND hwndDlg,
    _In_ PRTL_PROCESS_MODULES Modules,
    _In_ PSDT_TABLE SdtTableEntry
)
{
    INT lvIndex, moduleIndex;
    ULONG i, iImage;
    EXTRASCONTEXT* Context = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);

    LVITEM lvItem;
    WCHAR szBuffer[MAX_PATH + 1];

    LPWSTR lpBaseName, lpBaseLimit;

    if (Context->DialogMode == SST_Ntos) {
        lpBaseName = KSW_KiServiceTable;
        lpBaseLimit = KSW_KiServiceLimit;
    }
    else if (Context->DialogMode == SST_Win32k) {
        lpBaseName = KSW_W32pServiceTable;
        lpBaseLimit = KSW_W32pServiceLimit;
    }
    else
        return;

    RtlStringCchPrintfSecure(szBuffer,
        MAX_PATH,
        TEXT("%ws 0x%p / %ws %lu (0x%lX)"),
        lpBaseName,
        (PVOID)SdtTableEntry->Base,
        lpBaseLimit,
        SdtTableEntry->Limit,
        SdtTableEntry->Limit);

    SetWindowText(Context->StatusBar, szBuffer);

    iImage = ObManagerGetImageIndexByTypeIndex(ObjectTypeDevice);

    ListView_DeleteAllItems(Context->ListView);

    //list table
    for (i = 0; i < SdtTableEntry->Limit; i++) {

        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        ultostr(SdtTableEntry->Table[i].ServiceId, szBuffer);

        //ServiceId
        RtlSecureZeroMemory(&lvItem, sizeof(lvItem));
        lvItem.mask = LVIF_TEXT | LVIF_IMAGE;
        lvItem.iItem = MAXINT;
        lvItem.iImage = iImage; //imagelist id
        lvItem.pszText = szBuffer;
        lvIndex = ListView_InsertItem(Context->ListView, &lvItem);

        //Name
        lvItem.mask = LVIF_TEXT;
        lvItem.iSubItem = 1;
        lvItem.pszText = (LPWSTR)SdtTableEntry->Table[i].Name;
        lvItem.iItem = lvIndex;
        ListView_SetItem(Context->ListView, &lvItem);

        //Address
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        szBuffer[0] = L'0';
        szBuffer[1] = L'x';
        u64tohex(SdtTableEntry->Table[i].Address, &szBuffer[2]);

        lvItem.iSubItem = 2;
        lvItem.pszText = szBuffer;
        ListView_SetItem(Context->ListView, &lvItem);

        //Module
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

        moduleIndex = supFindModuleEntryByAddress(Modules, (PVOID)SdtTableEntry->Table[i].Address);
        if (moduleIndex == (ULONG)-1) {
            _strcpy(szBuffer, TEXT("Unknown Module"));
        }
        else {

            MultiByteToWideChar(
                CP_ACP,
                0,
                (LPCSTR)&Modules->Modules[moduleIndex].FullPathName,
                (INT)_strlen_a((char*)Modules->Modules[moduleIndex].FullPathName),
                szBuffer,
                MAX_PATH);
        }

        lvItem.iSubItem = 3;
        lvItem.pszText = szBuffer;
        ListView_SetItem(Context->ListView, &lvItem);
    }
}

/*
* SdtListCreateTable
*
* Purpose:
*
* KiServiceTable dump routine.
*
*/
BOOL SdtListCreateTable(
    _In_ BOOLEAN bForceUnknown
)
{
    BOOL                    bResult = FALSE;
    ULONG                   EntrySize = 0;
    SIZE_T                  memIO;
    PUTable                 TableDump = NULL;
    PBYTE                   Module = NULL;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PDWORD                  ExportNames, ExportFunctions;
    PWORD                   NameOrdinals;

    PSERVICETABLEENTRY      ServiceEntry;

    CHAR* ServiceName;
    PVOID ServicePtr;
    ULONG ServiceId, i;

    __try {

        if ((g_kdctx.KeServiceDescriptorTable.Base == 0) ||
            (g_kdctx.KeServiceDescriptorTable.Limit == 0))
        {
            if (!kdFindKiServiceTable(
                (ULONG_PTR)g_kdctx.NtOsImageMap,
                (ULONG_PTR)g_kdctx.NtOsBase,
                &g_kdctx.KeServiceDescriptorTable))
            {
                __leave;
            }
        }

        //
        // If table empty, dump and prepare table
        //
        if (KiServiceTable.Allocated == FALSE) {

            Module = (PBYTE)GetModuleHandle(TEXT("ntdll.dll"));

            if (Module == NULL)
                __leave;

            ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(
                Module,
                TRUE,
                IMAGE_DIRECTORY_ENTRY_EXPORT,
                &EntrySize);

            if (ExportDirectory == NULL) {
                __leave;
            }

            ExportNames = (PDWORD)((PBYTE)Module + ExportDirectory->AddressOfNames);
            ExportFunctions = (PDWORD)((PBYTE)Module + ExportDirectory->AddressOfFunctions);
            NameOrdinals = (PWORD)((PBYTE)Module + ExportDirectory->AddressOfNameOrdinals);

            memIO = sizeof(SERVICETABLEENTRY) * g_kdctx.KeServiceDescriptorTable.Limit;

            KiServiceTable.Table = (PSERVICETABLEENTRY)supHeapAlloc(memIO);
            if (KiServiceTable.Table == NULL)
                __leave;

            KiServiceTable.Allocated = TRUE;

            if (!supDumpSyscallTableConverted(
                g_kdctx.KeServiceDescriptorTable.Base,
                g_kdctx.KeServiceDescriptorTable.Limit,
                &TableDump))
            {
                supHeapFree(KiServiceTable.Table);
                KiServiceTable.Allocated = FALSE;
                __leave;
            }

            KiServiceTable.Base = g_kdctx.KeServiceDescriptorTable.Base;

            //
            // Walk for Nt stubs.
            //
            KiServiceTable.Limit = 0;
            for (i = 0; i < ExportDirectory->NumberOfNames; i++) {

                ServiceName = ((CHAR*)Module + ExportNames[i]);
                ServicePtr = (PVOID*)((CHAR*)Module + ExportFunctions[NameOrdinals[i]]);

                if (*(USHORT*)ServiceName == 'tN') {

                    ServiceId = *(ULONG*)((UCHAR*)ServicePtr + 4);

                    if (ServiceId < g_kdctx.KeServiceDescriptorTable.Limit) {

                        MultiByteToWideChar(
                            CP_ACP,
                            0,
                            ServiceName,
                            (INT)_strlen_a(ServiceName),
                            KiServiceTable.Table[KiServiceTable.Limit].Name,
                            MAX_PATH);

                        ServiceEntry = &KiServiceTable.Table[KiServiceTable.Limit];
                        ServiceEntry->ServiceId = ServiceId;
                        ServiceEntry->Address = TableDump[ServiceId];
                        TableDump[ServiceId] = 0;
                        KiServiceTable.Limit += 1;
                    }

                }//tN
            }//for

            //
            // Temporary workaround for NtQuerySystemTime.
            // (not implemented in user mode as syscall only as query to shared data, still exist in SSDT)
            //  
            //  This will produce incorrect result if more like that services will be added.
            //
            if (bForceUnknown) {
                for (i = 0; i < g_kdctx.KeServiceDescriptorTable.Limit; i++) {
                    if (TableDump[i] != 0) {
                        ServiceEntry = &KiServiceTable.Table[KiServiceTable.Limit];
                        ServiceEntry->ServiceId = i;
                        ServiceEntry->Address = TableDump[i];
                        _strcpy(ServiceEntry->Name, TEXT("NtQuerySystemTime"));
                        KiServiceTable.Limit += 1;
                        break;
                    }
                }
            }

            supHeapFree(TableDump);
            TableDump = NULL;
        }

        bResult = TRUE;

    }
    __finally {

        if (TableDump) {
            supHeapFree(TableDump);
        }
    }

    return bResult;
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
    _In_ ULONG_PTR LookupEntry,
    _Out_ PW32K_API_SET_TABLE_ENTRY* ResolvedEntry
)
{
    BOOLEAN bResult = FALSE;
    PW32K_API_SET_TABLE_ENTRY Entry = (PW32K_API_SET_TABLE_ENTRY)ApiSetTable;
    ULONG EntriesCount;
    ULONG_PTR EntryValue;
    PULONG_PTR ArrayPtr;

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
_Success_(return == STATUS_SUCCESS)
NTSTATUS ApiSetLoadResolvedModule(
    _In_ PVOID ApiSetMap,
    _In_ PUNICODE_STRING ApiSetToResolve,
    _Inout_ PANSI_STRING ConvertedModuleName,
    _Out_ HMODULE * DllModule
)
{
    BOOL            ResolvedResult;
    NTSTATUS        Status;
    UNICODE_STRING  usResolvedModule;

    if (DllModule == NULL)
        return STATUS_INVALID_PARAMETER_2;
    if (ConvertedModuleName == NULL)
        return STATUS_INVALID_PARAMETER_3;

    *DllModule = NULL;

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
    _Out_ HMODULE * ResolvedModule,
    _Inout_ PANSI_STRING ResolvedModuleName,
    _Out_ LPCSTR * FunctionName
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
        if (Win32kApiSetTableExpected && ApiSetMap) {

            ApiSetReference = ApiSetExtractReferenceFromAdapter(FunctionPtr);
            if (ApiSetReference) {

                if (!ApiSetResolveWin32kTableEntry(
                    Win32kApiSetTable,
                    ApiSetReference,
                    &Win32kApiSetEntry))
                {
                    return STATUS_APISET_NOT_PRESENT;
                }

                RtlInitUnicodeString(&usApiSetEntry, Win32kApiSetEntry->Host->HostName);

                resolveStatus = ApiSetLoadResolvedModule(
                    ApiSetMap,
                    &usApiSetEntry,
                    ResolvedModuleName,
                    &DllModule);

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

                if (ApiSetMap) {
                    resolveStatus = ApiSetLoadResolvedModule(
                        ApiSetMap,
                        &usModuleName,
                        ResolvedModuleName,
                        &DllModule);
                }
                else {
                    resolveStatus = STATUS_INVALID_PARAMETER_3;
                }

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
* SdtListCreateTableShadow
*
* Purpose:
*
* W32pServiceTable create table routine.
*
* Note: This code only for Windows 10 RS1+
*
*/
BOOL SdtListCreateTableShadow(
    _In_ PRTL_PROCESS_MODULES pModules,
    _Out_ PULONG Status
)
{
    BOOLEAN     NeedApiSetResolve = (g_NtBuildNumber > 18885);
    BOOLEAN     Win32kApiSetTableExpected = (g_NtBuildNumber > 18935);
    NTSTATUS    ntStatus;
    BOOL        bResult = FALSE;
    ULONG       w32u_limit, w32k_limit, c;
    HMODULE     w32u = NULL, w32k = NULL, DllModule, forwdll;
    PBYTE       fptr;
    PULONG      pServiceLimit, pServiceTable;
    LPCSTR	    ModuleName, FunctionName, ForwarderDot, ForwarderFunctionName;
    HANDLE      EnumerationHeap = NULL;
    ULONG_PTR   Win32kBase = 0, kernelWin32kBase = 0;

    PSERVICETABLEENTRY  ServiceEntry;
    PWIN32_SHADOWTABLE  table, itable;
    RESOLVE_INFO        rfn;

    ULONG_PTR                       Win32kApiSetTable = 0;

    PVOID                           ApiSetMap = NULL;
    ULONG                           ApiSetSchemaVersion = 0;

    PRTL_PROCESS_MODULE_INFORMATION Module, ForwardModule;

    LOAD_MODULE_ENTRY               LoadedModulesHead;
    PLOAD_MODULE_ENTRY              ModuleEntry = NULL, PreviousEntry = NULL;

    ANSI_STRING                     ResolvedModuleName;

    WCHAR szBuffer[MAX_PATH * 2];
    CHAR szForwarderModuleName[MAX_PATH];

    LoadedModulesHead.Next = NULL;
    LoadedModulesHead.hModule = NULL;

    *Status = STATUS_SUCCESS;

    __try {


        //
        // Check if table already built.
        //
        if (W32pServiceTable.Allocated == FALSE) {

            //
            // Find win32k loaded image base.
            //
            Module = (PRTL_PROCESS_MODULE_INFORMATION)supFindModuleEntryByName(
                pModules,
                "win32k.sys");

            if (Module == NULL) {
                *Status = ErrShadowWin32kNotFound;
                __leave;
            }

            Win32kBase = (ULONG_PTR)Module->ImageBase;

            //
            // Prepare dedicated heap for exports enumeration.
            //
            EnumerationHeap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
            if (EnumerationHeap == NULL) {
                *Status = ErrShadowMemAllocFail;
                __leave;
            }

            //
            // Load win32u and dump exports, in KnownDlls.
            //
            w32u = LoadLibraryEx(TEXT("win32u.dll"), NULL, 0);
            if (w32u == NULL) {
                *Status = ErrShadowWin32uLoadFail;
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
                *Status = ErrShadowWin32kLoadFail;
                __leave;
            }

            if (Win32kApiSetTableExpected) {
                //
                // Locate Win32kApiSetTable variable. Failure will result in unresolved apiset adapters.
                //
                Win32kApiSetTable = kdQueryWin32kApiSetTable(w32k);
                if (Win32kApiSetTable == 0) {
                    *Status = ErrShadowApiSetNotFound;
                }
            }

            //
            // Query win32k!W32pServiceLimit.
            //
            pServiceLimit = (PULONG)GetProcAddress(w32k, KSA_W32pServiceLimit);
            if (pServiceLimit == NULL) {
                *Status = ErrShadowW32pServiceLimitNotFound;
                __leave;
            }

            //
            // Check whatever win32u is compatible with win32k data.
            //
            w32k_limit = *pServiceLimit;
            if (w32k_limit != w32u_limit) {
                *Status = ErrShadowWin32uMismatch;
                __leave;
            }

            //
            // Query win32k!W32pServiceTable.
            //
            RtlSecureZeroMemory(&rfn, sizeof(RESOLVE_INFO));
            if (!NT_SUCCESS(NtRawGetProcAddress(w32k, KSA_W32pServiceTable, &rfn))) {
                *Status = ErrShadowW32pServiceTableNotFound;
                __leave;
            }

            //
            // Query ApiSetMap
            //
            if (NeedApiSetResolve) {

                if (!NtLdrApiSetLoadFromPeb(&ApiSetSchemaVersion, (PVOID*)&ApiSetMap)) {
                    *Status = ErrShadowApiSetSchemaMapNotFound;
                    __leave;
                }

                //
                // Windows 10+ uses modern ApiSetSchema version, everything else not supported.
                //
                if (ApiSetSchemaVersion != 6) {
                    *Status = ErrShadowApiSetSchemaVerUnknown;
                    __leave;
                }
            }

            //
            // Set global variables.
            //
            kernelWin32kBase = Win32kBase + (ULONG_PTR)rfn.Function - (ULONG_PTR)w32k;

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
                        itable->KernelStubAddress += Win32kBase;

                        DllModule = NULL;
                        RtlSecureZeroMemory(&ResolvedModuleName, sizeof(ResolvedModuleName));

                        ntStatus = SdtResolveServiceEntryModule(fptr,
                            w32k,
                            ApiSetMap,
                            Win32kApiSetTable,
                            itable,
                            &DllModule,
                            &ResolvedModuleName,
                            &FunctionName);

                        if (!NT_SUCCESS(ntStatus)) {

                            //
                            // Most of this errors are not critical and ok.
                            //

                            switch (ntStatus) {

                            case STATUS_INTERNAL_ERROR:
                                DbgPrint("SdtListCreateTableShadow, HDE Error\r\n");
                                break;

                            case STATUS_APISET_NOT_HOSTED:
                                //
                                // Corresponding apiset not found.
                                //
                                DbgPrint("SdtListCreateTableShadow not an apiset adapter for %s\r\n",
                                    itable->Name);
                                break;

                            case STATUS_APISET_NOT_PRESENT:
                                //
                                // ApiSet extension present but empty.
                                // 
                                DbgPrint("SdtListCreateTableShadow, extension contains a host for a non-existent apiset %s\r\n",
                                    itable->Name);
                                break;

                            case STATUS_PROCEDURE_NOT_FOUND:
                                //
                                // Not a critical issue. This mean we cannot pass this service next to forwarder lookup code.
                                //
                                DbgPrint("SdtListCreateTableShadow, could not resolve function name in module for service id %lu, service name %s\r\n",
                                    itable->Index,
                                    itable->Name);
                                break;

                            case STATUS_DRIVER_UNABLE_TO_LOAD:
                                DbgPrint("SdtListCreateTableShadow, could not load import dll %s\r\n", ResolvedModuleName.Buffer);
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
                            DbgPrint("SdtListCreateTableShadow: Could not resolve function %s address\r\n", FunctionName);
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
                                        OutputDebugString(TEXT("SdtListCreateTableShadow, could not load forwarded module\r\n"));
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
            W32pServiceTable.Table = (PSERVICETABLEENTRY)supHeapAlloc(sizeof(SERVICETABLEENTRY) * w32k_limit);
            if (W32pServiceTable.Table) {

                W32pServiceTable.Allocated = TRUE;
                W32pServiceTable.Base = kernelWin32kBase;

                //
                // Convert table to output format.
                //
                W32pServiceTable.Limit = 0;
                itable = table;
                while (itable != 0) {

                    //
                    // Service Id.
                    //
                    ServiceEntry = &W32pServiceTable.Table[W32pServiceTable.Limit];

                    ServiceEntry->ServiceId = itable->Index;

                    //
                    // Routine real address.
                    //
                    if (itable->KernelStubTargetAddress) {
                        //
                        // Output stub target address.
                        //
                        ServiceEntry->Address = itable->KernelStubTargetAddress;

                    }
                    else {
                        //
                        // Query failed, output stub address.
                        //
                        ServiceEntry->Address = itable->KernelStubAddress;

                    }

                    //
                    // Remember service name.
                    //
                    MultiByteToWideChar(
                        CP_ACP,
                        0,
                        itable->Name,
                        (INT)_strlen_a(itable->Name),
                        ServiceEntry->Name,
                        MAX_PATH);

                    W32pServiceTable.Limit += 1;

                    itable = itable->NextService;
                }

            }

        } // if (W32pServiceTable.Allocated == FALSE)

        bResult = W32pServiceTable.Allocated;

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
        if (EnumerationHeap) RtlDestroyHeap(EnumerationHeap);
        if (w32u) FreeLibrary(w32u);
        if (w32k) FreeLibrary(w32k);

    }

    return bResult;
}

/*
* SdtListCreate
*
* Purpose:
*
* (Re)Create service table list.
*
*/
VOID SdtListCreate(
    _In_ HWND hwndDlg,
    _In_ BOOL fRescan,
    _In_ EXTRASCONTEXT * pDlgContext
)
{
    BOOL bSuccess = FALSE;
    ULONG returnStatus;
    EXTRASCALLBACK CallbackParam;
    PRTL_PROCESS_MODULES pModules = NULL;
    LPWSTR lpErrorMsg = TEXT("Unknown error");

#ifndef _DEBUG
    HWND hwndBanner;

    hwndBanner = supDisplayLoadBanner(hwndDlg,
        TEXT("Loading service table dump, please wait"));
#endif

    __try {

        pModules = (PRTL_PROCESS_MODULES)supGetSystemInfo(SystemModuleInformation, NULL);
        if (pModules == NULL) {
            MessageBox(hwndDlg, TEXT("Could not allocate memory for kernel modules list"), NULL, MB_ICONERROR);
            __leave;
        }

        if (pDlgContext->DialogMode == SST_Ntos) {

            if (fRescan) {
                if (KiServiceTable.Allocated) {
                    KiServiceTable.Allocated = FALSE;
                    supHeapFree(KiServiceTable.Table);
                    KiServiceTable.Limit = 0;
                }
            }

            bSuccess = SdtListCreateTable(TRUE);
            if (bSuccess) {
                SdtListOutputTable(hwndDlg, pModules, &KiServiceTable);
            }

        }
        else if (pDlgContext->DialogMode == SST_Win32k) {

            if (fRescan) {
                if (W32pServiceTable.Allocated) {
                    W32pServiceTable.Allocated = FALSE;
                    supHeapFree(W32pServiceTable.Table);
                    W32pServiceTable.Limit = 0;
                }
            }

            bSuccess = SdtListCreateTableShadow(pModules, &returnStatus);
            if (bSuccess) {

                if (returnStatus == ErrShadowApiSetNotFound)
                    MessageBox(hwndDlg, T_ERRSHADOW_APISETTABLE_NOT_FOUND, PROGRAM_NAME, MB_ICONINFORMATION);

                SdtListOutputTable(hwndDlg, pModules, &W32pServiceTable);
            }
            else {

#ifndef _DEBUG
                SendMessage(hwndBanner, WM_CLOSE, 0, 0);
#endif

                switch (returnStatus) {

                case ErrShadowWin32kNotFound:
                    lpErrorMsg = T_ERRSHADOW_WIN32K_NOT_FOUND;
                    break;

                case ErrShadowMemAllocFail:
                    lpErrorMsg = T_ERRSHADOW_MEMORY_NOT_ALLOCATED;
                    break;

                case ErrShadowWin32uLoadFail:
                    lpErrorMsg = T_ERRSHADOW_WIN32U_LOAD_FAILED;
                    break;

                case ErrShadowWin32kLoadFail:
                    lpErrorMsg = T_ERRSHADOW_WIN32K_LOAD_FAILED;
                    break;

                case ErrShadowW32pServiceLimitNotFound:
                    lpErrorMsg = T_ERRSHADOW_WIN32KLIMIT_NOT_FOUND;
                    break;

                case ErrShadowWin32uMismatch:
                    lpErrorMsg = T_ERRSHADOW_WIN32U_MISMATCH;
                    break;

                case ErrShadowW32pServiceTableNotFound:
                    lpErrorMsg = T_ERRSHADOW_TABLE_NOT_FOUND;
                    break;

                case ErrShadowApiSetSchemaMapNotFound:
                    lpErrorMsg = T_ERRSHADOW_APISETMAP_NOT_FOUND;
                    break;

                case ErrShadowApiSetSchemaVerUnknown:
                    lpErrorMsg = T_ERRSHADOW_APISET_VER_UNKNOWN;
                    break;

                default:
                    break;
                }

                MessageBox(hwndDlg, lpErrorMsg, NULL, MB_ICONERROR);
            }
        }

    }
    __finally {

        if (pModules)
            supHeapFree(pModules);

#ifndef _DEBUG
        SendMessage(hwndBanner, WM_CLOSE, 0, 0);
#endif

    }

    if (bSuccess) {
        CallbackParam.lParam = 0;
        CallbackParam.Value = pDlgContext->DialogMode;
        ListView_SortItemsEx(pDlgContext->ListView, &SdtDlgCompareFunc, (LPARAM)&CallbackParam);
        SetFocus(pDlgContext->ListView);
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

    EXTRASCONTEXT* pDlgContext;

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

    //
    // Allow only one dialog.
    //
    ENSURE_DIALOG_UNIQUE_WITH_RESTORE(g_WinObj.AuxDialogs[dlgIndex]);

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

        //
        // Insert columns.
        //

        supAddListViewColumn(pDlgContext->ListView, 0, 0, 0,
            ImageList_GetImageCount(g_ListViewImages) - 1,
            LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
            TEXT("Id"), 80);

        supAddListViewColumn(pDlgContext->ListView, 1, 1, 1,
            I_IMAGENONE,
            LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
            TEXT("Service Name"), 220);

        supAddListViewColumn(pDlgContext->ListView, 2, 2, 2,
            I_IMAGENONE,
            LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
            TEXT("Address"), 130);

        supAddListViewColumn(pDlgContext->ListView, 3, 3, 3,
            I_IMAGENONE,
            LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
            TEXT("Module"), 220);

        //
        // Remember column count.
        //
        pDlgContext->lvColumnCount = SSDTLIST_COLUMN_COUNT;

        SendMessage(hwndDlg, WM_SIZE, 0, 0);

        SdtListCreate(pDlgContext->hwndDlg, FALSE, pDlgContext);
    }
}
