/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2023
*
*  TITLE:       EXTRASSSDT.C
*
*  VERSION:     2.03
*
*  DATE:        21 Jul 2023
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
#include "ntos/ntldr.h"
#include "ksymbols.h"

typedef struct _SERVICETABLEENTRY {
    ULONG ServiceId;
    ULONG_PTR Address;
    WCHAR Name[MAX_PATH + 1];
} SERVICETABLEENTRY, * PSERVICETABLEENTRY;

typedef struct _SDT_TABLE {
    BOOL Allocated;
    ULONG Limit;
    ULONG_PTR Base;
    PSERVICETABLEENTRY Table;
} SDT_TABLE, * PSDT_TABLE;

//
// UI part
//
#define ID_SDTLIST_SAVE 40002

#define SDTDLG_TRACKSIZE_MIN_X 640
#define SDTDLG_TRACKSIZE_MIN_Y 480

#define COLUMN_SDTLIST_INDEX    0
#define COLUMN_SDTLIST_NAME     1
#define COLUMN_SDTLIST_ADDRESS  2
#define COLUMN_SDTLIST_MODULE   3

//
// Globals
//
#define INVALID_SERVICE_ENTRY_ID 0xFFFFFFFF
#define WIN32K_START_INDEX 0x1000

SDT_TABLE KiServiceTable;
SDT_TABLE W32pServiceTable;
SYMCONTEXT* W32SymContext;

//
// Win32kApiSetTable signatures
//

//
// Win32kApiSetTable adapter patterns
//
BYTE Win32kApiSetAdapterPattern1[] = {
   0x4C, 0x8B, 0x15
};
BYTE Win32kApiSetAdapterPattern2[] = {
   0x48, 0x8B, 0x05
};
BYTE Win32kApiSetAdapterPattern3[] = {
   0x4C, 0x8B, 0x1D // mov r11, value
};

W32K_API_SET_LOOKUP_PATTERN W32kApiSetAdapters[] = {
    { sizeof(Win32kApiSetAdapterPattern1), Win32kApiSetAdapterPattern1 },
    { sizeof(Win32kApiSetAdapterPattern2), Win32kApiSetAdapterPattern2 },
    { sizeof(Win32kApiSetAdapterPattern3), Win32kApiSetAdapterPattern3 }
};

static EXTRASCONTEXT SSTDlgContext[SST_Max];
static HANDLE SdtDlgThreadHandles[SST_Max] = { NULL, NULL };
static FAST_EVENT SdtDlgInitializedEvents[SST_Max] = { FAST_EVENT_INIT, FAST_EVENT_INIT };

/*
* SdtLoadWin32kImage
*
* Purpose:
*
* Load win32k image and symbols for it if available.
*
*/
HMODULE SdtLoadWin32kImage(
    _In_opt_ SYMCONTEXT *SymContext
)
{
    HMODULE hModule;
    WCHAR szBuffer[MAX_PATH * 2];
#ifdef _DEBUG
    _strcpy(szBuffer, L"C:\\windows\\system32");
#else
    _strcpy(szBuffer, g_WinObj.szSystemDirectory);
#endif
    _strcat(szBuffer, TEXT("\\win32k.sys"));
    hModule = LoadLibraryEx(szBuffer, NULL, DONT_RESOLVE_DLL_REFERENCES);
    
    if (hModule) {

        if (SymContext) {
            kdLoadSymbolsForNtImage(SymContext,
                szBuffer,
                hModule, 
                0);

        }

    }

    return hModule;
}

typedef struct _SDT_SEARCH_CONTEXT {
    PBYTE Result;
} SDT_SEARCH_CONTEXT, * PSDT_SEARCH_CONTEXT;

BOOL CALLBACK SearchPatternCallback(
    _In_ PBYTE Buffer,
    _In_ ULONG PatternSize,
    _In_ PVOID CallbackContext
)
{
    UNREFERENCED_PARAMETER(PatternSize);

    PSDT_SEARCH_CONTEXT context = (PSDT_SEARCH_CONTEXT)CallbackContext;
    context->Result = Buffer;

    return TRUE;
}

/*
* SdtFindInitializeWin32kCall
*
* Purpose:
*
* Locate prologue of win32k!InitializeWin32kCall.
*                    win32k!CreateWin32kApiSetTable
*
*/
PBYTE SdtFindInitializeWin32kCall(
    _In_ PVOID SectionBase,
    _In_ ULONG SectionSize
)
{
    PBYTE result = NULL;
    PATTERN_SEARCH_PARAMS params;
    SDT_SEARCH_CONTEXT scontext;

    BYTE pbPattern[] = { 
        0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C, 0x24, 0x18, 0x48, 0x89, 0x7C, 0x24, 0x20 };
    BYTE pbMask[] = { 
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x00, 0x11, 0x11, 0x11, 0x11, 0x00, 0x11, 0x11 };

    //
    // As of >23H2, there is not enough data to do a proper mask.
    // Win32ApiSetTable are now can be configured per session by win32ksgd.sys, it saves pointers to them in gSessionGlobalSlots structure.
    //
    BYTE pbPatternW11_NEXT[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x41, 0x55, 0x41, 0x56 };
    BYTE pbMask_NEXT[] = {
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x00, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };

    scontext.Result = NULL;
    params.Buffer = (PBYTE)SectionBase;
    params.BufferSize = SectionSize;
    params.Callback = SearchPatternCallback;
    params.CallbackContext = &scontext;

    if (g_NtBuildNumber > NT_WIN11_22H2) {
        params.Pattern = pbPatternW11_NEXT;
        params.PatternSize = sizeof(pbPatternW11_NEXT);
        params.Mask = pbMask_NEXT;
    }
    else {
        params.Pattern = pbPattern;
        params.PatternSize = sizeof(pbPattern);
        params.Mask = pbMask;
    }

    if (supFindPatternEx(&params))
        result = scontext.Result;

    return result;
}

/*
* SdtQueryWin32kApiSetTable
*
* Purpose:
*
* Locate address of win32k!Win32kApiSetTable structure.
*
*/
ULONG_PTR SdtQueryWin32kApiSetTable(
    _In_ HMODULE hModule,
    _In_ PVOID ImageBase,
    _In_ ULONG_PTR ImageSize
)
{
    PBYTE       ptrCode = (PBYTE)hModule;

    PVOID       SectionBase;
    ULONG       SectionSize = 0, Index;

    ULONG_PTR   tableAddress = 0, instructionLength = 0;
    LONG        relativeValue = 0;
    hde64s      hs;

    if (kdIsSymAvailable(W32SymContext)) {

        if (kdGetAddressFromSymbolEx(W32SymContext,
            KVAR_Win32kApiSetTable,
            ImageBase,
            ImageSize,
            &tableAddress))
        {
            tableAddress = tableAddress - (ULONG_PTR)ImageBase + (ULONG_PTR)hModule;
        }
    }

    if (tableAddress == 0) {

        //
        // Locate .text image section as required variable is always in .text.
        //
        SectionBase = supLookupImageSectionByName(TEXT_SECTION,
            TEXT_SECTION_LEGNTH,
            (PVOID)hModule,
            &SectionSize);

        if (SectionBase == 0 || SectionSize == 0)
            return 0;

        //
        // Locate InitializeWin32Call body.
        //
        ptrCode = SdtFindInitializeWin32kCall(SectionBase,
            SectionSize);

        if (ptrCode == NULL) {
            return 0;
        }

        Index = 0;
        instructionLength = 0;

        do {

            hde64_disasm((void*)(ptrCode + Index), &hs);
            if (hs.flags & F_ERROR)
                break;

            // lea reg, Win32kApiSetTable
            if ((hs.len == 7) &&
                (hs.flags & F_PREFIX_REX) &&
                (hs.flags & F_DISP32) &&
                (hs.flags & F_MODRM) &&
                (hs.opcode == 0x8D))
            {
                relativeValue = (LONG)hs.disp.disp32;
                instructionLength = hs.len;
                break;
            }

            Index += hs.len;

        } while (Index < 256);


        if (relativeValue == 0 || instructionLength == 0)
            return 0;

        tableAddress = (ULONG_PTR)ptrCode + Index + instructionLength + relativeValue;

    }

    return tableAddress;
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
    INT lvIndex;
    ULONG i, iImage, moduleIndex = 0;
    EXTRASCONTEXT* Context = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);

    LVITEM lvItem;
    WCHAR szBuffer[MAX_PATH + 1];

    LPWSTR lpBaseName, lpBaseLimit;

    if (Context->DialogMode == SST_Ntos) {
        lpBaseName = L"KiServiceTable";
        lpBaseLimit = L"KiServiceLimit";
    }
    else if (Context->DialogMode == SST_Win32k) {
        lpBaseName = L"W32pServiceTable";
        lpBaseLimit = L"W32pServiceLimit";
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

    supStatusBarSetText(Context->StatusBar, 0, (LPWSTR)&szBuffer);

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

        if (ntsupFindModuleEntryByAddress(
            Modules,
            (PVOID)SdtTableEntry->Table[i].Address,
            &moduleIndex))
        {
            MultiByteToWideChar(
                CP_ACP,
                0,
                (LPCSTR)&Modules->Modules[moduleIndex].FullPathName,
                (INT)_strlen_a((char*)Modules->Modules[moduleIndex].FullPathName),
                szBuffer,
                MAX_PATH);
        }
        else {
            _strcpy(szBuffer, TEXT("Unknown Module"));
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
    VOID
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
    CHAR* FunctionAddress;
    ULONG ServiceId, i, j;

    __try {

        if ((g_kdctx.Data->KeServiceDescriptorTable.Base == 0) ||
            (g_kdctx.Data->KeServiceDescriptorTable.Limit == 0))
        {
            if (!kdFindKiServiceTable(
                (ULONG_PTR)g_kdctx.NtOsImageMap,
                (ULONG_PTR)g_kdctx.NtOsBase,
                &g_kdctx.Data->KeServiceDescriptorTable))
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

            memIO = sizeof(SERVICETABLEENTRY) * ExportDirectory->NumberOfNames;

            KiServiceTable.Table = (PSERVICETABLEENTRY)supHeapAlloc(memIO);
            if (KiServiceTable.Table == NULL)
                __leave;

            KiServiceTable.Allocated = TRUE;

            if (!supDumpSyscallTableConverted(
                g_kdctx.Data->KeServiceDescriptorTable.Base,
                g_kdctx.Data->KeServiceDescriptorTable.Limit,
                &TableDump))
            {
                supHeapFree(KiServiceTable.Table);
                KiServiceTable.Allocated = FALSE;
                __leave;
            }

            KiServiceTable.Base = g_kdctx.Data->KeServiceDescriptorTable.Base;

            //
            // Walk for syscall stubs.
            //
            KiServiceTable.Limit = 0;
            for (i = 0; i < ExportDirectory->NumberOfNames; i++) {

                ServiceName = ((CHAR*)Module + ExportNames[i]);

                //
                // Use Zw alias to skip various Nt trash like NtdllDialogWndProc/NtGetTickCount.
                //

                if (*(USHORT*)ServiceName == 'wZ') {

                    MultiByteToWideChar(
                        CP_ACP,
                        0,
                        ServiceName,
                        (INT)_strlen_a(ServiceName),
                        KiServiceTable.Table[KiServiceTable.Limit].Name,
                        MAX_PATH);

                    //dirty hack
                    KiServiceTable.Table[KiServiceTable.Limit].Name[0] = L'N';
                    KiServiceTable.Table[KiServiceTable.Limit].Name[1] = L't';

                    FunctionAddress = (CHAR*)((CHAR*)Module + ExportFunctions[NameOrdinals[i]]);
                    ServiceEntry = &KiServiceTable.Table[KiServiceTable.Limit];

                    if (*(UCHAR*)((UCHAR*)FunctionAddress + 3) == 0xB8) {
                        ServiceId = *(ULONG*)((UCHAR*)FunctionAddress + 4);
                        if (ServiceId < g_kdctx.Data->KeServiceDescriptorTable.Limit) {
                            ServiceEntry->ServiceId = ServiceId;
                            ServiceEntry->Address = TableDump[ServiceId];
                            TableDump[ServiceId] = 0;
                        }
                        else {
                            kdDebugPrint(">>1 %s %lu\r\n", ServiceName, KiServiceTable.Limit);
                            ServiceEntry->ServiceId = INVALID_SERVICE_ENTRY_ID;
                        }
                    }
                    else {
                        kdDebugPrint(">>2 %s %lu\r\n", ServiceName, KiServiceTable.Limit);
                        ServiceEntry->ServiceId = INVALID_SERVICE_ENTRY_ID;
                    }

                    KiServiceTable.Limit += 1;

                }//wZ
            }//for

            for (i = 0; i < KiServiceTable.Limit; i++) {
                ServiceEntry = &KiServiceTable.Table[i];
                if (ServiceEntry->ServiceId == INVALID_SERVICE_ENTRY_ID) {
                    for (j = 0; j < g_kdctx.Data->KeServiceDescriptorTable.Limit; j++) {
                        if (TableDump[j] != 0) {
                            ServiceEntry->ServiceId = j;
                            ServiceEntry->Address = TableDump[j];
                            TableDump[j] = 0;
                            break;
                        }
                    }
                }
            }

            supHeapFree(TableDump);
            TableDump = NULL;
        }

        bResult = TRUE;

    }
    __finally {

        if (AbnormalTermination())
            supReportAbnormalTermination(__FUNCTIONW__);

        if (TableDump) {
            supHeapFree(TableDump);
        }
    }

    return bResult;
}

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
    LONG       Rel = 0;
    hde64s     hs;

    ULONG      PatternSize;
    PVOID      PatternData;

    do {
        hde64_disasm((void*)(ptrCode + Index), &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == 7) {

            bFound = FALSE;

            for (i = 0; i < RTL_NUMBER_OF(W32kApiSetAdapters); i++) {

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


    return (ULONG_PTR)ptrCode + Index + hs.len + Rel;
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
* ApiSetResolveWin32kTableEntry
*
* Purpose:
*
* Find entry in Win32kApiSetTable.
*
* Function return STATUS_SUCCESS on success and sets ResolvedEntry parameter.
*
*/
NTSTATUS ApiSetResolveWin32kTableEntry(
    _In_ ULONG_PTR ApiSetTable,
    _In_ ULONG_PTR LookupEntry,
    _In_ ULONG EntrySize,
    _Out_ PVOID* ResolvedEntry
)
{
    NTSTATUS resolveStatus = STATUS_APISET_NOT_PRESENT;
    PW32K_API_SET_TABLE_ENTRY pvTableEntry = (PW32K_API_SET_TABLE_ENTRY)ApiSetTable;
    ULONG cEntries;
    ULONG_PTR entryValue;
    PULONG_PTR pvHostEntries;

    *ResolvedEntry = NULL;

    //
    // Lookup entry in table.
    //
    __try {

        while (pvTableEntry->Host) {

            cEntries = pvTableEntry->Host->HostEntriesCount;
            pvHostEntries = (PULONG_PTR)pvTableEntry->HostEntriesArray;

            //
            // Search inside table host entry array.
            //
            do {

                entryValue = (ULONG_PTR)pvHostEntries;
                pvHostEntries++;

                if (entryValue == LookupEntry) {
                    *ResolvedEntry = (PVOID)pvTableEntry;
                    resolveStatus = STATUS_SUCCESS;
                    break;
                }

            } while (--cEntries);

            pvTableEntry = (PW32K_API_SET_TABLE_ENTRY)RtlOffsetToPointer(pvTableEntry, EntrySize);
        }
    }
    __except (WOBJ_EXCEPTION_FILTER_LOG) {
        //
        // Should never be here. Only in case if table structure changed or ApiSetTable address points to invalid data.
        //
        return STATUS_ACCESS_VIOLATION;
    }

    return resolveStatus;
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

    ULONG           ApiSetTableEntrySize;

    NTSTATUS        resultStatus = STATUS_UNSUCCESSFUL, resolveStatus;

    HMODULE         DllModule = NULL;

    LONG32          JmpAddress;
    ULONG_PTR       ApiSetReference;

    LPCSTR	        ModuleName;
    PWCHAR          HostName;

    W32K_API_SET_TABLE_ENTRY *pvApiSetEntry = NULL;

    UNICODE_STRING  usApiSetEntry, usModuleName;
    hde64s hs;


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

                if (g_NtBuildNumber >= NT_WINSRV_21H1)
                    ApiSetTableEntrySize = sizeof(W32K_API_SET_TABLE_ENTRY_V2);
                else
                    ApiSetTableEntrySize = sizeof(W32K_API_SET_TABLE_ENTRY);

                resolveStatus = ApiSetResolveWin32kTableEntry(
                    Win32kApiSetTable,
                    ApiSetReference,
                    ApiSetTableEntrySize,
                    (PVOID*)&pvApiSetEntry);

                if (!NT_SUCCESS(resolveStatus))
                    return resolveStatus;

                //
                // Host is on the same offset for both V1/V2 versions.
                //
                HostName = pvApiSetEntry->Host->HostName;

                RtlInitUnicodeString(&usApiSetEntry, HostName);

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
                        return STATUS_DLL_NOT_FOUND;
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
            resultStatus = (DllModule != NULL) ? STATUS_SUCCESS : STATUS_DLL_NOT_FOUND;
        }


    } while (FALSE);

    return resultStatus;
}

/*
* SdtListReportEvent
*
* Purpose:
*
* Add entry to WinObjEx64 runtime log accessible through main menu.
*
*/
VOID SdtListReportEvent(
    _In_ WOBJ_ENTRY_TYPE EventType,
    _In_ LPCWSTR FunctionName,
    _In_ LPCWSTR ErrorString
)
{
    WCHAR szBuffer[1024];

    RtlStringCchPrintfSecure(szBuffer,
        RTL_NUMBER_OF(szBuffer),
        TEXT("%ws, %ws"),
        FunctionName,
        ErrorString);

    logAdd(EventType, szBuffer);
}

/*
* SdtListReportFunctionResolveError
*
* Purpose:
*
* Report function name resolve error.
*
*/
VOID SdtListReportFunctionResolveError(
    _In_ LPCSTR FunctionName
)
{
    WCHAR szErrorBuffer[512];

    RtlSecureZeroMemory(szErrorBuffer, sizeof(szErrorBuffer));

    _strcpy(szErrorBuffer, TEXT("could not resolve function "));
    MultiByteToWideChar(CP_ACP, 0, FunctionName, -1, _strend(szErrorBuffer), MAX_PATH);
    _strcat(szErrorBuffer, TEXT(" address"));
    SdtListReportEvent(EntryTypeError, __FUNCTIONW__, szErrorBuffer);
}

/*
* SdtListReportResolveModuleError
*
* Purpose:
*
* Report module resolve error.
*
*/
VOID SdtListReportResolveModuleError(
    _In_ NTSTATUS Status,
    _In_ PWIN32_SHADOWTABLE Table,
    _In_ PSTRING ResolvedModuleName,
    _In_ LPCWSTR ErrorSource
)
{
    WCHAR szErrorBuffer[512];

    RtlSecureZeroMemory(szErrorBuffer, sizeof(szErrorBuffer));

    //
    // Most of this errors are not critical and ok.
    //

    switch (Status) {

    case STATUS_INTERNAL_ERROR:
        _strcpy(szErrorBuffer, TEXT("HDE Error"));
        break;

    case STATUS_APISET_NOT_HOSTED:
        //
        // Corresponding apiset not found.
        //
        _strcpy(szErrorBuffer, TEXT("not an apiset adapter for "));
        MultiByteToWideChar(CP_ACP, 0, Table->Name, -1, _strend(szErrorBuffer), MAX_PATH);
        break;

    case STATUS_APISET_NOT_PRESENT:
        //
        // ApiSet extension present but empty.
        // 
        _strcpy(szErrorBuffer, TEXT("extension contains a host for a non-existent apiset "));
        MultiByteToWideChar(CP_ACP, 0, Table->Name, -1, _strend(szErrorBuffer), MAX_PATH);
        break;

    case STATUS_PROCEDURE_NOT_FOUND:
        //
        // Not a critical issue. This mean we cannot pass this service next to forwarder lookup code.
        //
        _strcpy(szErrorBuffer, TEXT("could not resolve function name in module for service id "));
        ultostr(Table->Index, _strend(szErrorBuffer));
        _strcat(szErrorBuffer, TEXT(", service name "));
        MultiByteToWideChar(CP_ACP, 0, Table->Name, -1, _strend(szErrorBuffer), MAX_PATH);
        break;

    case STATUS_DLL_NOT_FOUND:

        _strcpy(szErrorBuffer, TEXT("could not load import dll "));

        MultiByteToWideChar(CP_ACP,
            0,
            ResolvedModuleName->Buffer,
            ResolvedModuleName->Length,
            _strend(szErrorBuffer),
            MAX_PATH);

        break;

    default:
        //
        // Unexpected error code.
        //
        _strcpy(szErrorBuffer, TEXT("unexpected error 0x"));
        ultohex(Status, _strend(szErrorBuffer));
        break;
    }

    SdtListReportEvent(EntryTypeError, ErrorSource, szErrorBuffer);
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

    PVOID                           pvApiSetMap = NULL;
    ULONG                           schemaVersion = 0;

    PRTL_PROCESS_MODULE_INFORMATION w32Module, subModule, ForwardModule;

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
            w32Module = (PRTL_PROCESS_MODULE_INFORMATION)ntsupFindModuleEntryByName(
                pModules,
                "win32k.sys");

            if (w32Module == NULL) {
                *Status = ErrShadowWin32kNotFound;
                __leave;
            }

            Win32kBase = (ULONG_PTR)w32Module->ImageBase;

            //
            // Prepare dedicated heap for exports enumeration.
            //
            EnumerationHeap = supCreateHeap(HEAP_GROWABLE, TRUE);
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

            W32SymContext = SymParserCreate();
            w32k = SdtLoadWin32kImage(W32SymContext);
            if (w32k == NULL) {
                *Status = ErrShadowWin32kLoadFail;
                __leave;
            }

            if (Win32kApiSetTableExpected) {
                //
                // Locate Win32kApiSetTable variable. Failure will result in unresolved apiset adapters.
                //
                Win32kApiSetTable = SdtQueryWin32kApiSetTable(w32k,
                    w32Module->ImageBase,
                    w32Module->ImageSize);

                if (Win32kApiSetTable == 0) {
                    *Status = ErrShadowApiSetNotFound;
                }
            }

            //
            // Query win32k!W32pServiceLimit.
            //
            pServiceLimit = (PULONG)GetProcAddress(w32k, "W32pServiceLimit");
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
            if (!NT_SUCCESS(NtRawGetProcAddress(w32k, "W32pServiceTable", &rfn))) {
                *Status = ErrShadowW32pServiceTableNotFound;
                __leave;
            }

            //
            // Query ApiSetMap
            //
            if (NeedApiSetResolve) {

                if (!NtLdrApiSetLoadFromPeb(&schemaVersion, (PVOID*)&pvApiSetMap)) {
                    *Status = ErrShadowApiSetSchemaMapNotFound;
                    __leave;
                }

                //
                // Windows 10+ uses modern ApiSetSchema version, everything else not supported.
                //
                if (schemaVersion != API_SET_SCHEMA_VERSION_V6) {
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

                    if (itable->Index == c + WIN32K_START_INDEX) {

                        itable->KernelStubAddress = pServiceTable[c];
                        fptr = (PBYTE)w32k + itable->KernelStubAddress;
                        itable->KernelStubAddress += Win32kBase;

                        //
                        // Resolve module name for table entry and load this module to the memory.
                        //

                        DllModule = NULL;
                        RtlSecureZeroMemory(&ResolvedModuleName, sizeof(ResolvedModuleName));
                        ntStatus = SdtResolveServiceEntryModule(fptr,
                            w32k,
                            pvApiSetMap,
                            Win32kApiSetTable,
                            itable,
                            &DllModule,
                            &ResolvedModuleName,
                            &FunctionName);

                        if (!NT_SUCCESS(ntStatus)) {

                            SdtListReportResolveModuleError(ntStatus,
                                itable,
                                &ResolvedModuleName,
                                __FUNCTIONW__);

                            break;
                        }

                        ModuleName = ResolvedModuleName.Buffer;

                        //
                        // Remember loaded module to the internal list.
                        //
                        ModuleEntry = (PLOAD_MODULE_ENTRY)supHeapAllocEx(EnumerationHeap,
                            sizeof(LOAD_MODULE_ENTRY));

                        if (ModuleEntry) {
                            ModuleEntry->Next = LoadedModulesHead.Next;
                            ModuleEntry->hModule = DllModule;
                            LoadedModulesHead.Next = ModuleEntry;
                        }

                        //
                        // Check function forwarding.
                        //
                        if (!NT_SUCCESS(NtRawGetProcAddress(DllModule, FunctionName, &rfn))) {
                            //
                            // Log error.
                            //
                            SdtListReportFunctionResolveError(FunctionName);
                            break;
                        }

                        //
                        // Function is forward, resolve again.
                        //
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

                            ForwardModule = (PRTL_PROCESS_MODULE_INFORMATION)ntsupFindModuleEntryByName(pModules,
                                szForwarderModuleName);

                            if (ForwardModule) {

                                if (ForwarderFunctionName) {

                                    forwdll = LoadLibraryExA(szForwarderModuleName, NULL, DONT_RESOLVE_DLL_REFERENCES);
                                    if (forwdll) {

                                        //
                                        // Remember loaded module to the internal list.
                                        //
                                        ModuleEntry = (PLOAD_MODULE_ENTRY)supHeapAllocEx(EnumerationHeap,
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
                                        //
                                        // Log error.
                                        //
                                        SdtListReportEvent(EntryTypeError, __FUNCTIONW__, TEXT("could not load forwarded module"));
                                    }

                                } // if (ForwarderFunctionName)

                            }//if (ForwardModule)

                        }
                        else {
                            //
                            // Calculate routine kernel mode address.
                            //
                            subModule = (PRTL_PROCESS_MODULE_INFORMATION)ntsupFindModuleEntryByName(pModules, ModuleName);
                            if (subModule) {
                                itable->KernelStubTargetAddress =
                                    (ULONG_PTR)subModule->ImageBase + ((ULONG_PTR)rfn.Function - (ULONG_PTR)DllModule);
                            }

                            RtlFreeAnsiString(&ResolvedModuleName);

                        }

                    } // if (itable->Index == c + WIN32K_START_INDEX)

                    itable = itable->NextService;

                } //while (itable != 0);
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

        if (AbnormalTermination())
            supReportAbnormalTermination(__FUNCTIONW__);

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
        if (EnumerationHeap) supDestroyHeap(EnumerationHeap);
        if (w32u) FreeLibrary(w32u);
        if (w32k) FreeLibrary(w32k);

        if (W32SymContext) {
            W32SymContext->Parser.UnloadModule(W32SymContext);
            SymParserDestroy(W32SymContext);
            W32SymContext = NULL;
        }

    }

    return bResult;
}

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
    case COLUMN_SDTLIST_INDEX: //index
        return supGetMaxOfTwoULongFromString(
            pDlgContext->ListView,
            lParam1,
            lParam2,
            pDlgContext->lvColumnToSort,
            pDlgContext->bInverseSort);
    case COLUMN_SDTLIST_ADDRESS: //address (hex)
        return supGetMaxOfTwoU64FromHex(
            pDlgContext->ListView,
            lParam1,
            lParam2,
            pDlgContext->lvColumnToSort,
            pDlgContext->bInverseSort);
    case COLUMN_SDTLIST_NAME: //string (fixed size)
    case COLUMN_SDTLIST_MODULE: //string (fixed size)
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
    LPWSTR lpStatusMsg;

    __try {

        supStatusBarSetText(pDlgContext->StatusBar, 1, TEXT("Initializing table view"));

        pModules = (PRTL_PROCESS_MODULES)supGetLoadedModulesList(NULL);
        if (pModules == NULL) {

            supStatusBarSetText(pDlgContext->StatusBar, 1,
                TEXT("Could not allocate memory for kernel modules list!"));

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

            bSuccess = SdtListCreateTable();
            if (bSuccess) {
                SdtListOutputTable(hwndDlg, pModules, &KiServiceTable);
            }
            else {
                supStatusBarSetText(pDlgContext->StatusBar, 1, TEXT("Error dumping table"));
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

                if (returnStatus == ErrShadowApiSetNotFound) {
                    supStatusBarSetText(pDlgContext->StatusBar, 1,
                        T_ERRSHADOW_APISETTABLE_NOT_FOUND);
                }

                SdtListOutputTable(hwndDlg, pModules, &W32pServiceTable);
            }
            else {

                switch (returnStatus) {

                case ErrShadowWin32kNotFound:
                    lpStatusMsg = T_ERRSHADOW_WIN32K_NOT_FOUND;
                    break;

                case ErrShadowMemAllocFail:
                    lpStatusMsg = T_ERRSHADOW_MEMORY_NOT_ALLOCATED;
                    break;

                case ErrShadowWin32uLoadFail:
                    lpStatusMsg = T_ERRSHADOW_WIN32U_LOAD_FAILED;
                    break;

                case ErrShadowWin32kLoadFail:
                    lpStatusMsg = T_ERRSHADOW_WIN32K_LOAD_FAILED;
                    break;

                case ErrShadowW32pServiceLimitNotFound:
                    lpStatusMsg = T_ERRSHADOW_WIN32KLIMIT_NOT_FOUND;
                    break;

                case ErrShadowWin32uMismatch:
                    lpStatusMsg = T_ERRSHADOW_WIN32U_MISMATCH;
                    break;

                case ErrShadowW32pServiceTableNotFound:
                    lpStatusMsg = T_ERRSHADOW_TABLE_NOT_FOUND;
                    break;

                case ErrShadowApiSetSchemaMapNotFound:
                    lpStatusMsg = T_ERRSHADOW_APISETMAP_NOT_FOUND;
                    break;

                case ErrShadowApiSetSchemaVerUnknown:
                    lpStatusMsg = T_ERRSHADOW_APISET_VER_UNKNOWN;
                    break;

                default:
                    lpStatusMsg = TEXT("Unknown error");
                    break;
                }

                supStatusBarSetText(pDlgContext->StatusBar, 1, lpStatusMsg);
            }
        }

    }
    __finally {

        if (AbnormalTermination())
            supReportAbnormalTermination(__FUNCTIONW__);

        if (pModules)
            supHeapFree(pModules);

    }

    if (bSuccess) {
        supStatusBarSetText(pDlgContext->StatusBar, 1, TEXT("Table read - OK"));
        CallbackParam.lParam = 0;
        CallbackParam.Value = pDlgContext->DialogMode;
        ListView_SortItemsEx(pDlgContext->ListView, &SdtDlgCompareFunc, (LPARAM)&CallbackParam);
        SetFocus(pDlgContext->ListView);
    }
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

        InsertMenu(hMenu, uPos++, MF_BYCOMMAND, ID_JUMPTOFILE, T_JUMPTOFILE);
        InsertMenu(hMenu, uPos++, MF_BYCOMMAND, ID_SDTLIST_SAVE, T_EXPORTTOFILE);
        InsertMenu(hMenu, uPos++, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
        InsertMenu(hMenu, uPos++, MF_BYCOMMAND, ID_VIEW_REFRESH, T_VIEW_REFRESH);

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
* SdtFreeGlobals
*
* Purpose:
*
* Release memory allocated for SDT table globals.
*
*/
BOOL CALLBACK SdtFreeGlobals(
    _In_opt_ PVOID Context
)
{
    UNREFERENCED_PARAMETER(Context);

    if (KiServiceTable.Allocated) {
        supHeapFree(KiServiceTable.Table);
        KiServiceTable.Allocated = FALSE;
    }
    if (W32pServiceTable.Allocated) {
        supHeapFree(W32pServiceTable.Table);
        W32pServiceTable.Allocated = FALSE;
    }

    return TRUE;
}

/*
* SdtDlgHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for dialog listview.
*
*/
BOOL SdtDlgHandleNotify(
    _In_ HWND hwndDlg,
    _In_ LPARAM lParam
)
{
    INT nImageIndex, iSelectionMark;
    LPNMLISTVIEW pListView = (LPNMLISTVIEW)lParam;
    LPWSTR lpItem, lpWin32Name;
    HWND hwndListView;

    EXTRASCONTEXT* pDlgContext;

    EXTRASCALLBACK CallbackParam;

    if (pListView == NULL)
        return FALSE;

    if (pListView->hdr.idFrom != ID_EXTRASLIST)
        return FALSE;

    hwndListView = pListView->hdr.hwndFrom;

    switch (pListView->hdr.code) {

    case LVN_COLUMNCLICK:

        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {

            pDlgContext->bInverseSort = (~pDlgContext->bInverseSort) & 1;
            pDlgContext->lvColumnToSort = pListView->iSubItem;
            CallbackParam.lParam = (LPARAM)pDlgContext->lvColumnToSort;
            CallbackParam.Value = pDlgContext->DialogMode;
            ListView_SortItemsEx(hwndListView, &SdtDlgCompareFunc, (LPARAM)&CallbackParam);

            nImageIndex = ImageList_GetImageCount(g_ListViewImages);
            if (pDlgContext->bInverseSort)
                nImageIndex -= 2;
            else
                nImageIndex -= 1;

            supUpdateLvColumnHeaderImage(
                hwndListView,
                pDlgContext->lvColumnCount,
                pDlgContext->lvColumnToSort,
                nImageIndex);
        }
        break;

    case NM_DBLCLK:

        iSelectionMark = ListView_GetSelectionMark(hwndListView);
        if (iSelectionMark >= 0) {
            lpItem = supGetItemText(hwndListView, iSelectionMark, 3, NULL);
            if (lpItem) {
                lpWin32Name = supGetWin32FileName(lpItem);
                if (lpWin32Name) {
                    supShowProperties(hwndDlg, lpWin32Name);
                    supHeapFree(lpWin32Name);
                }
                supHeapFree(lpItem);
            }
        }
        break;

    default:
        return FALSE;
    }

    return TRUE;
}

/*
* SdtDlgOnInit
*
* Purpose:
*
* KiServiceTable Dialog WM_INITDIALOG handler.
*
*/
VOID SdtDlgOnInit(
    _In_ HWND hwndDlg,
    _In_ LPARAM lParam
)
{
    INT iImage = ImageList_GetImageCount(g_ListViewImages) - 1;
    EXTRASCONTEXT* pDlgContext = (EXTRASCONTEXT*)lParam;

    INT SbParts[] = { 400, -1 };
    WCHAR szText[100];

    LVCOLUMNS_DATA columnData[] =
    {
        { L"Id", 80, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  iImage },
        { L"Service Name", 280, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  I_IMAGENONE },
        { L"Address", 130, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  I_IMAGENONE },
        { L"Module", 220, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  I_IMAGENONE }
    };

    SetProp(hwndDlg, T_DLGCONTEXT, (HANDLE)lParam);
    supCenterWindowSpecifyParent(hwndDlg, g_hwndMain);

    pDlgContext->lvColumnHit = -1;
    pDlgContext->lvItemHit = -1;

    pDlgContext->hwndDlg = hwndDlg;
    pDlgContext->StatusBar = GetDlgItem(hwndDlg, ID_EXTRASLIST_STATUSBAR);
    SendMessage(pDlgContext->StatusBar, SB_SETPARTS, 2, (LPARAM)&SbParts);

    _strcpy(szText, TEXT("Viewing "));
    if (pDlgContext->DialogMode == SST_Ntos)
        _strcat(szText, TEXT("ntoskrnl service table"));
    else
        _strcat(szText, TEXT("win32k service table"));

    SetWindowText(hwndDlg, szText);

    extrasSetDlgIcon(pDlgContext);

    pDlgContext->ListView = GetDlgItem(hwndDlg, ID_EXTRASLIST);
    if (pDlgContext->ListView) {

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
        pDlgContext->lvColumnCount = supAddLVColumnsFromArray(
            pDlgContext->ListView,
            columnData,
            RTL_NUMBER_OF(columnData));

        SendMessage(hwndDlg, WM_SIZE, 0, 0);

        supListViewEnableRedraw(pDlgContext->ListView, FALSE);
        SdtListCreate(pDlgContext->hwndDlg, FALSE, pDlgContext);
        supListViewEnableRedraw(pDlgContext->ListView, TRUE);
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
        }
        return TRUE;
    }

    switch (uMsg) {

    case WM_INITDIALOG:
        SdtDlgOnInit(hwndDlg, lParam);
        break;

    case WM_GETMINMAXINFO:
        if (lParam) {
            supSetMinMaxTrackSize((PMINMAXINFO)lParam,
                SDTDLG_TRACKSIZE_MIN_X,
                SDTDLG_TRACKSIZE_MIN_Y,
                TRUE);
        }
        break;

    case WM_NOTIFY:
        return SdtDlgHandleNotify(hwndDlg, lParam);

    case WM_SIZE:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            extrasSimpleListResize(hwndDlg);
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    case WM_CLOSE:
        pDlgContext = (EXTRASCONTEXT*)RemoveProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            extrasRemoveDlgIcon(pDlgContext);
        }
        DestroyWindow(hwndDlg);
        break;

    case WM_COMMAND:

        switch (GET_WM_COMMAND_ID(wParam, lParam)) {

        case IDCANCEL:
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            break;

        case ID_SDTLIST_SAVE:
            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
            if (pDlgContext) {

                if (supListViewExportToFile(
                    TEXT("Table.csv"),
                    hwndDlg,
                    pDlgContext->ListView))
                {
                    supStatusBarSetText(pDlgContext->StatusBar, 1, T_LIST_EXPORT_SUCCESS);
                }

            }
            break;

        case ID_VIEW_REFRESH:
            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
            if (pDlgContext) {
                supListViewEnableRedraw(pDlgContext->ListView, FALSE);
                SdtListCreate(hwndDlg, TRUE, pDlgContext);
                supListViewEnableRedraw(pDlgContext->ListView, TRUE);
            }
            break;

        case ID_JUMPTOFILE:
            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
            if (pDlgContext) {
                supJumpToFileListView(pDlgContext->ListView, 3);
            }
            break;

        case ID_OBJECT_COPY:
            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
            if (pDlgContext) {
                supListViewCopyItemValueToClipboard(pDlgContext->ListView,
                    pDlgContext->lvItemHit,
                    pDlgContext->lvColumnHit);
            }
            break;

        }

        break;

    case WM_CONTEXTMENU:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {

            supHandleContextMenuMsgForListView(hwndDlg,
                wParam,
                lParam,
                pDlgContext->ListView,
                (pfnPopupMenuHandler)SdtHandlePopupMenu,
                (PVOID)pDlgContext);

        }
        break;
    }

    return FALSE;
}

/*
* extrasSSDTDialogWorkerThread
*
* Purpose:
*
* SSDT Dialog worker thread.
*
*/
DWORD extrasSSDTDialogWorkerThread(
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

    hwndDlg = CreateDialogParam(
        g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_EXTRASLIST),
        0,
        &SdtDialogProc,
        (LPARAM)pDlgContext);

    supAddShutdownCallback(&SdtFreeGlobals, NULL);

    acceleratorTable = LoadAccelerators(g_WinObj.hInstance, MAKEINTRESOURCE(IDR_ACCELERATOR1));

    fastEvent = SdtDlgInitializedEvents[pDlgContext->DialogMode];

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

    workerThread = SdtDlgThreadHandles[pDlgContext->DialogMode];
    if (workerThread) {
        NtClose(workerThread);
        SdtDlgThreadHandles[pDlgContext->DialogMode] = NULL;
    }

    return 0;
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
    _In_ SSDT_DLG_MODE Mode
)
{
    if (Mode < 0 || Mode >= SST_Max)
        return;

    if (!SdtDlgThreadHandles[Mode]) {

        RtlSecureZeroMemory(&SSTDlgContext[Mode], sizeof(EXTRASCONTEXT));
        SSTDlgContext[Mode].DialogMode = Mode;
        SdtDlgThreadHandles[Mode] = supCreateDialogWorkerThread(extrasSSDTDialogWorkerThread, (PVOID)&SSTDlgContext[Mode], 0);
        supWaitForFastEvent(&SdtDlgInitializedEvents[Mode], NULL);

    }
}
