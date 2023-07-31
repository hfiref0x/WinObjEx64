/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2023
*
*  TITLE:       EXTRASSSDT.C
*
*  VERSION:     2.03
*
*  DATE:        28 Jul 2023
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
#include "sup/w32k.h"

static EXTRASCONTEXT SSTDlgContext[SST_Max];
static HANDLE SdtDlgThreadHandles[SST_Max] = { NULL, NULL };
static FAST_EVENT SdtDlgInitializedEvents[SST_Max] = { FAST_EVENT_INIT, FAST_EVENT_INIT };

typedef struct _SDT_TABLE_ENTRY {
    ULONG ServiceId;
    ULONG_PTR Address;
    WCHAR Name[MAX_PATH + 1];
} SDT_TABLE_ENTRY, * PSDT_TABLE_ENTRY;

typedef struct _SDT_TABLE {
    BOOL Allocated;
    ULONG Limit;
    ULONG_PTR Base;
    PSDT_TABLE_ENTRY Table;
} SDT_TABLE, * PSDT_TABLE;

static SDT_CONTEXT g_SDTCtx = { 0 };

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
    BOOL bResult = FALSE;
    ULONG EntrySize = 0;
    SIZE_T memIO;
    PUTable TableDump = NULL;
    PBYTE Module = NULL;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PDWORD ExportNames, ExportFunctions;
    PWORD NameOrdinals;

    PSDT_TABLE_ENTRY ServiceEntry;

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

            memIO = sizeof(SDT_TABLE_ENTRY) * ExportDirectory->NumberOfNames;

            KiServiceTable.Table = (PSDT_TABLE_ENTRY)supHeapAlloc(memIO);
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
* SdtListErrorProcedureNotFound
*
* Purpose:
*
* Report function name resolve error.
*
*/
VOID SdtListErrorProcedureNotFound(
    _In_ LPCSTR FunctionName,
    _In_ PCUNICODE_STRING ModuleName
)
{
    PWCHAR pszErrorMsg;
    WCHAR szFunctionName[MAX_PATH];
    SIZE_T sz;

    sz = MAX_PATH +
        (_strlen_a(FunctionName) * sizeof(WCHAR)) +
        ModuleName->MaximumLength;

    pszErrorMsg = (PWCHAR)supHeapAlloc(sz);
    if (pszErrorMsg) {

        szFunctionName[0] = 0;
        MultiByteToWideChar(CP_ACP, 0, FunctionName, -1, szFunctionName, MAX_PATH);

        RtlStringCchPrintfSecure(pszErrorMsg, sz / sizeof(WCHAR),
            L"the entry point for %ws was not found in module %wZ",
            szFunctionName,
            ModuleName);

        SdtListReportEvent(EntryTypeError, __FUNCTIONW__, pszErrorMsg);

        supHeapFree(pszErrorMsg);
    }
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
    _In_ PRAW_SYSCALL_ENTRY Table,
    _In_ PUNICODE_STRING ResolvedModuleName,
    _In_ LPCWSTR ErrorSource
)
{
    WCHAR szErrorBuffer[512];

    szErrorBuffer[0] = 0;

    //
    // Most of this errors are not critical and ok.
    //

    switch (Status) {

    case STATUS_INTERNAL_ERROR:
        _strcpy(szErrorBuffer, TEXT("Internal error"));
        break;

    case STATUS_APISET_NOT_HOSTED:
        //
        // Corresponding apiset not found.
        //
        _strcpy(szErrorBuffer, TEXT("not an ApiSet adapter for "));
        MultiByteToWideChar(CP_ACP, 0, Table->Name, -1, _strend(szErrorBuffer), MAX_PATH);
        break;

    case STATUS_APISET_NOT_PRESENT:
        //
        // ApiSet extension present but empty.
        // 
        _strcpy(szErrorBuffer, TEXT("ApiSet host is empty for "));
        MultiByteToWideChar(CP_ACP, 0, Table->Name, -1, _strend(szErrorBuffer), MAX_PATH);
        break;

    case STATUS_PROCEDURE_NOT_FOUND:
        //
        // Not a critical issue. This mean we cannot pass this service next to forwarder lookup code.
        //
        _strcpy(szErrorBuffer, TEXT("could not resolve function name in module for "));
        MultiByteToWideChar(CP_ACP, 0, Table->Name, -1, _strend(szErrorBuffer), MAX_PATH);
        _strcat(szErrorBuffer, TEXT(", service id "));
        ultostr(Table->Index, _strend(szErrorBuffer));
        break;

    case STATUS_DLL_NOT_FOUND:

        RtlStringCchPrintfSecure(szErrorBuffer, 
            RTL_NUMBER_OF(szErrorBuffer),
            L"could not load import dll %wZ",
            ResolvedModuleName);

        break;

    case STATUS_ILLEGAL_FUNCTION:

        MultiByteToWideChar(CP_ACP, 0, Table->Name, -1, szErrorBuffer, MAX_PATH);
        _strcpy(szErrorBuffer, TEXT(" code does not look like a import thunk"));
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
* SdtpSetDllDirectory
*
* Purpose:
*
* Insert/Remove SystemRoot\System32\Drivers to the loader directories search list.
*
*/
VOID SdtpSetDllDirectory(
    _In_ BOOLEAN bSet
)
{
    WCHAR szBuffer[MAX_PATH * 2];
    PWCHAR lpDirectory = NULL;

    if (bSet) {
        _strcpy(szBuffer, g_WinObj.szSystemDirectory);
        _strcat(szBuffer, TEXT("\\drivers"));
        lpDirectory = (PWCHAR)&szBuffer;
    } 

    SetDllDirectory(lpDirectory);
}

/*
* SdtListCreateTableShadow
*
* Purpose:
*
* W32pServiceTable table parsing routine.
* Does optional function resolving to actual handlers.
*
* Note: This code only for Windows 10 RS1+
*
*/
BOOL SdtListCreateTableShadow(
    _In_ PRTL_PROCESS_MODULES pModules,
    _Out_ PULONG Status
)
{
    BOOL bResult = FALSE;
    ULONG i, ulInitStatus;
    NTSTATUS ntStatus;
    HMODULE forwardDll;
    LPCSTR lpFunctionName = NULL, lpForwarderDot, lpForwarderFunctionName;
    PBYTE functionPtr;
    PSDT_TABLE_ENTRY ServiceEntry;
    PRAW_SYSCALL_ENTRY tableEntry;
    RESOLVE_INFO resolveInfo;

    PRTL_PROCESS_MODULE_INFORMATION subModule, forwardModule;
    SDT_MODULE_ENTRY loadedModulesHead, sdtModule;
    UNICODE_STRING forwardModuleName;
    SDT_FUNCTION_NAME sdtFn;
    CHAR szForwarderModuleName[MAX_PATH];

    *Status = STATUS_SUCCESS;
    RtlSecureZeroMemory(&sdtModule, sizeof(SDT_MODULE_ENTRY));
    RtlSecureZeroMemory(&loadedModulesHead, sizeof(SDT_MODULE_ENTRY));

    __try {

        //
        // Check if table already built.
        //
        if (W32pServiceTable.Allocated == FALSE) {

            ulInitStatus = SdtWin32kInitializeOnce(pModules, &g_SDTCtx);
            if (ulInitStatus != 0) {
                *Status = ulInitStatus;

                if (ulInitStatus != ErrShadowApiSetNotFound)
                    __leave;
            }

            SdtpSetDllDirectory(TRUE);

            //
            // Build table.
            //
            for (i = 0; i < g_SDTCtx.KernelLimit; ++i) {

                tableEntry = g_SDTCtx.UserTable;
                while (tableEntry != 0) {

                    if (tableEntry->Index == i + WIN32K_START_INDEX) {

                        lpFunctionName = tableEntry->Name;

                        tableEntry->KernelStubAddress = g_SDTCtx.W32pServiceTableUserBase[i];
                        functionPtr = (PBYTE)g_SDTCtx.KernelModule + tableEntry->KernelStubAddress;
                        tableEntry->KernelStubAddress += g_SDTCtx.KernelBaseAddress;

                        sdtFn.ServiceName = tableEntry->Name;
                        sdtFn.ExportName = NULL;
                        sdtFn.ExportOrdinal = 0;

                        //
                        // Resolve module name for table entry and load this module to the memory.
                        //
                        if (g_SDTCtx.ApiSetSessionAware) {

                            ntStatus = SdtResolveServiceEntryModuleSessionAware(
                                &g_SDTCtx,
                                functionPtr,
                                pModules,
                                &sdtFn,
                                &loadedModulesHead,
                                &sdtModule);

                        }
                        else {

                            ntStatus = SdtResolveServiceEntryModule(
                                &g_SDTCtx,
                                functionPtr,
                                &loadedModulesHead,
                                &sdtModule);

                        }

                        if (!NT_SUCCESS(ntStatus)) {

                            SdtListReportResolveModuleError(ntStatus,
                                tableEntry,
                                &sdtModule.Name,
                                __FUNCTIONW__);

                            break;
                        }

                        //
                        // Check function forwarding.
                        //
                        RtlSecureZeroMemory(&resolveInfo, sizeof(resolveInfo));

                        if (sdtFn.ExportName)
                            lpFunctionName = sdtFn.ExportName;
                        else if (sdtFn.ExportOrdinal)
                            lpFunctionName = MAKEINTRESOURCEA(sdtFn.ExportOrdinal);

                        if (!NT_SUCCESS(NtRawGetProcAddress(sdtModule.ImageBase, lpFunctionName, &resolveInfo))) {                         
                            SdtListErrorProcedureNotFound(lpFunctionName, &sdtModule.Name);
                            break;
                        }

                        //
                        // Function is forward, resolve again.
                        //
                        if (resolveInfo.ResultType == ForwarderString) {

                            lpForwarderDot = _strchr_a(resolveInfo.ForwarderName, '.');
                            lpForwarderFunctionName = lpForwarderDot + 1;
                            if (lpForwarderFunctionName) {

                                //
                                // Build forwarder module name.
                                //
                                RtlSecureZeroMemory(szForwarderModuleName, sizeof(szForwarderModuleName));
                                _strncpy_a(szForwarderModuleName, sizeof(szForwarderModuleName),
                                    resolveInfo.ForwarderName, lpForwarderDot - &resolveInfo.ForwarderName[0]);

                                _strcat_a(szForwarderModuleName, ".SYS");

                                forwardModule = (PRTL_PROCESS_MODULE_INFORMATION)ntsupFindModuleEntryByName(pModules,
                                    szForwarderModuleName);

                                if (forwardModule) {

                                    if (RtlCreateUnicodeStringFromAsciiz(&forwardModuleName, szForwarderModuleName)) {

                                        if (NT_SUCCESS(SdtLoadAndRememberModule(&loadedModulesHead, &forwardModuleName, &sdtModule, TRUE))) {

                                            forwardDll = sdtModule.ImageBase;

                                            if (NT_SUCCESS(NtRawGetProcAddress(forwardDll, lpForwarderFunctionName, &resolveInfo))) {

                                                //
                                                // Calculate routine kernel mode address.
                                                //
                                                tableEntry->KernelStubTargetAddress =
                                                    (ULONG_PTR)forwardModule->ImageBase + ((ULONG_PTR)resolveInfo.Function - (ULONG_PTR)forwardDll);
                                            }

                                        }
                                        else {
                                            RtlFreeUnicodeString(&forwardModuleName);

                                            //
                                            // Log error.
                                            //
                                            SdtListReportEvent(EntryTypeError, __FUNCTIONW__, TEXT("could not load forwarded module"));
                                        }

                                    }

                                }

                            }

                        }
                        else {
                            //
                            // Calculate routine kernel mode address.
                            //                           
                            subModule = (PRTL_PROCESS_MODULE_INFORMATION)ntsupFindModuleEntryByName_U(pModules, sdtModule.Name.Buffer);
                            if (subModule) {
                                tableEntry->KernelStubTargetAddress =
                                    (ULONG_PTR)subModule->ImageBase + ((ULONG_PTR)resolveInfo.Function - (ULONG_PTR)sdtModule.ImageBase);
                            }

                        }

                    } // if (itable->Index == c + WIN32K_START_INDEX)

                    tableEntry = tableEntry->NextEntry;

                } //while (itable != 0);
            }

            //
            // Output table.
            //
            W32pServiceTable.Table = (PSDT_TABLE_ENTRY)supHeapAlloc(sizeof(SDT_TABLE_ENTRY) * g_SDTCtx.KernelLimit);
            if (W32pServiceTable.Table) {

                W32pServiceTable.Allocated = TRUE;
                W32pServiceTable.Base = g_SDTCtx.W32pServiceTableKernelBase;

                //
                // Convert table to output format.
                //
                W32pServiceTable.Limit = 0;
                tableEntry = g_SDTCtx.UserTable;
                while (tableEntry != 0) {

                    //
                    // Service Id.
                    //
                    ServiceEntry = &W32pServiceTable.Table[W32pServiceTable.Limit];

                    ServiceEntry->ServiceId = tableEntry->Index;

                    //
                    // Routine real address.
                    //
                    if (tableEntry->KernelStubTargetAddress) {
                        //
                        // Output stub target address.
                        //
                        ServiceEntry->Address = tableEntry->KernelStubTargetAddress;

                    }
                    else {
                        //
                        // Query failed, output stub address.
                        //
                        ServiceEntry->Address = tableEntry->KernelStubAddress;

                    }

                    //
                    // Remember service name.
                    //
                    MultiByteToWideChar(
                        CP_ACP,
                        0,
                        tableEntry->Name,
                        (INT)_strlen_a(tableEntry->Name),
                        ServiceEntry->Name,
                        MAX_PATH);

                    W32pServiceTable.Limit += 1;

                    tableEntry = tableEntry->NextEntry;
                }

            }

        }
        else {
            //
            // Table already allocated.
            //
            *Status = 0;
        }

        bResult = W32pServiceTable.Allocated;

    }
    __finally {

        if (AbnormalTermination())
            supReportAbnormalTermination(__FUNCTIONW__);

        //
        // Unload all loaded modules.
        //
        SdtUnloadRememberedModules(&loadedModulesHead);
        SdtpSetDllDirectory(FALSE);
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
    _In_ EXTRASCONTEXT* pDlgContext
)
{
    BOOL bSuccess = FALSE;
    ULONG returnStatus;
    EXTRASCALLBACK CallbackParam;
    PRTL_PROCESS_MODULES pModules = NULL;
    LPWSTR lpModule;
    WCHAR szText[MAX_PATH];

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
                        TEXT("Win32kApiSet not found"));
                }

                SdtListOutputTable(hwndDlg, pModules, &W32pServiceTable);
            }
            else {

                switch (returnStatus) {

                case ErrShadowWin32kNotFound:
                case ErrShadowWin32ksgdNotFound:

                    RtlStringCchPrintfSecure(szText,
                        RTL_NUMBER_OF(szText),
                        TEXT("Could not find %ws module"),
                        (returnStatus == ErrShadowWin32kNotFound) ? WIN32K_FILENAME : WIN32KSGD_FILENAME);

                    break;

                case ErrShadowMemAllocFail:

                    _strcpy(szText, TEXT("Could not create heap for table"));
                    break;

                case ErrShadowWin32uLoadFail:
                case ErrShadowWin32kLoadFail:
                case ErrShadowWin32ksgdLoadFail:

                    switch (returnStatus) {
                    case ErrShadowWin32kLoadFail:
                        lpModule = WIN32K_FILENAME;
                        break;
                    case ErrShadowWin32ksgdLoadFail:
                        lpModule = WIN32KSGD_FILENAME;
                        break;
                    default:
                    case ErrShadowWin32uLoadFail:
                        lpModule = WIN32U_FILENAME;
                        break;
                    }

                    RtlStringCchPrintfSecure(szText,
                        RTL_NUMBER_OF(szText),
                        TEXT("Could not load %ws module"),
                        lpModule);
                    break;

                case ErrShadowW32pServiceLimitNotFound:
                    _strcpy(szText, TEXT("W32pServiceLimit was not found in win32k module"));
                    break;

                case ErrShadowWin32uMismatch:
                    _strcpy(szText, TEXT("Not all services found in win32u"));
                    break;

                case ErrShadowW32pServiceTableNotFound:
                    _strcpy(szText, TEXT("W32pServiceTable was not found in win32k module"));
                    break;

                case ErrShadowApiSetSchemaVerUnknown:
                    _strcpy(szText, TEXT("ApiSetSchema version is unknown"));
                    break;

                case ErrShadowWin32ksgdGlobalsNotFound:
                    _strcpy(szText, TEXT("Could not find win32ksgd.sys globals variable"));
                    break;

                case ErrShadowWin32ksgdOffsetNotFound:
                    _strcpy(szText, TEXT("Could not find win32ksgd.sys Win32kApiSetTable offset"));
                    break;

                default:
                    _strcpy(szText, TEXT("Unknown error"));
                    break;
                }

                supStatusBarSetText(pDlgContext->StatusBar, 1, szText);
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
        supStatusBarSetText(pDlgContext->StatusBar, 1, TEXT("Table read OK"));
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

    if (pDlgContext->DialogMode == SST_Win32k)
        SdtWin32kUninitialize(&g_SDTCtx);

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
