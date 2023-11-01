/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       W32K.C
*
*  VERSION:     2.04
*
*  DATE:        21 Oct 2023
*
*  Win32k syscall table actual handlers resolving routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "ntos/ntldr.h"
#include "hde/hde64.h"
#include "ksymbols.h"
#include "sup/w32k.h"

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

typedef struct _SDT_SEARCH_CONTEXT {
    PBYTE Result;
} SDT_SEARCH_CONTEXT, * PSDT_SEARCH_CONTEXT;

BOOL CALLBACK ApiSetSearchPatternCallback(
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
* ApiSetFindWin32kApiSetTableRef
*
* Purpose:
*
* Locate prologue of win32k!InitializeWin32kCall.
*
*/
PBYTE ApiSetFindWin32kApiSetTableRef(
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

    scontext.Result = NULL;
    params.Buffer = (PBYTE)SectionBase;
    params.BufferSize = SectionSize;
    params.Callback = ApiSetSearchPatternCallback;
    params.CallbackContext = &scontext;

    params.Pattern = pbPattern;
    params.PatternSize = sizeof(pbPattern);
    params.Mask = pbMask;

    if (supFindPatternEx(&params))
        result = scontext.Result;

    return result;
}

/*
* SdtpQueryWin32kApiSetTable
*
* Purpose:
*
* Locate address of win32k!Win32kApiSetTable structure.
*
*/
ULONG_PTR SdtpQueryWin32kApiSetTable(
    _In_ HMODULE hModule,
    _In_ PVOID ImageBase,
    _In_ ULONG_PTR ImageSize,
    _In_opt_ SYMCONTEXT* SymContext
)
{
    LONG relativeValue = 0;
    ULONG SectionSize = 0, Index;
    PBYTE ptrCode = (PBYTE)hModule;
    PVOID SectionBase;
    ULONG_PTR tableAddress = 0, instructionLength = 0;
    hde64s hs;

    if (SymContext) {

        if (kdGetAddressFromSymbolEx(SymContext,
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
        // Locate Win32kApiSetTable ref routine.
        //
        ptrCode = ApiSetFindWin32kApiSetTableRef(SectionBase,
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
* SdtpQuerySGDGetWin32kApiSetTableOffset
*
* Purpose:
*
* Locate offset for Win32kApiSetTable.
*
*/
ULONG SdtpQuerySGDGetWin32kApiSetTableOffset(
    _In_ HMODULE hModule
)
{
    ULONG Index;
    PBYTE ptrCode;
    hde64s hs;

    ptrCode = (PBYTE)GetProcAddress(hModule, "SGDGetWin32kApiSetTable");
    if (ptrCode == NULL) {
        return 0;
    }

    Index = 0;

    do {

        hde64_disasm((void*)(ptrCode + Index), &hs);
        if (hs.flags & F_ERROR)
            break;

        // mov rax, [rax+offset]
        if ((hs.len == 7) &&
            (hs.flags & F_PREFIX_REX) &&
            (hs.flags & F_DISP32) &&
            (hs.flags & F_MODRM) &&
            (hs.opcode == 0x8B))
        {
            return hs.disp.disp32;
        }

        Index += hs.len;

    } while (Index < 32);

    return 0;
}

/*
* SdtpQueryWin32kSessionGlobalSlots
*
* Purpose:
*
* Locate address of win32ksgd!gSessionGlobalSlots table.
*
*/
ULONG_PTR SdtpQueryWin32kSessionGlobalSlots(
    _In_ HMODULE hModule,
    _In_ PVOID ImageBase,
    _In_ ULONG_PTR ImageSize,
    _In_opt_ SYMCONTEXT* SymContext
)
{
    LONG relativeValue = 0;
    ULONG Index;
    PBYTE ptrCode;
    ULONG_PTR tableAddress = 0, instructionLength = 0;
    hde64s hs;

#ifndef _DEBUG
    if (SymContext) {

        kdGetAddressFromSymbolEx(SymContext,
            KVAR_gSessionGlobalSlots,
            ImageBase,
            ImageSize,
            &tableAddress);
    }
#else
    UNREFERENCED_PARAMETER(SymContext);
    UNREFERENCED_PARAMETER(ImageSize);
#endif

    if (tableAddress == 0) {

        ptrCode = (PBYTE)GetProcAddress(hModule, "SGDGetUserSessionState");

        if (ptrCode == NULL) {
            return 0;
        }

        Index = 0;
        instructionLength = 0;

        do {

            hde64_disasm((void*)(ptrCode + Index), &hs);
            if (hs.flags & F_ERROR)
                break;

            // mov reg, gSessionGlobalSlots
            if ((hs.len == 7) &&
                (hs.flags & F_PREFIX_REX) &&
                (hs.flags & F_DISP32) &&
                (hs.flags & F_MODRM) &&
                (hs.opcode == 0x8B))
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
        tableAddress = (ULONG_PTR)ImageBase + tableAddress - (ULONG_PTR)hModule;

    }

    return tableAddress;
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
    BOOL bFound;
    PBYTE ptrCode = ptrFunction;
    ULONG Index = 0, i;
    LONG Rel = 0;
    hde64s hs;

    ULONG PatternSize;
    PVOID PatternData;

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
* ApiSetResolveAndLoadModule
*
* Purpose:
*
* Final apiset resolving and loading actual file.
*
* Function return NTSTATUS value and sets ModuleEntry parameter.
*
*/
NTSTATUS ApiSetResolveAndLoadModule(
    _In_ PVOID ApiSetMap,
    _In_ PCUNICODE_STRING ApiSetToResolve,
    _In_ PSDT_MODULE_ENTRY ModulesHead,
    _Inout_ PSDT_MODULE_ENTRY ModuleEntry
)
{
    NTSTATUS ntStatus;
    UNICODE_STRING usResolvedModule;

    RtlInitEmptyUnicodeString(&usResolvedModule, NULL, 0);

    //
    // Resolve ApiSet.
    //
    ntStatus = NtRawApiSetResolveLibrary(ApiSetMap,
        ApiSetToResolve,
        NULL,
        &usResolvedModule);

    if (NT_SUCCESS(ntStatus)) {
        ntStatus = SdtLoadAndRememberModule(ModulesHead, &usResolvedModule, ModuleEntry, TRUE);

        if (!NT_SUCCESS(ntStatus))
            RtlFreeUnicodeString(&usResolvedModule);
    }

    return ntStatus;
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
* SdtMapModuleFromImportThunkWithResolve
*
* Purpose:
*
* Map module from disk (if it wasn't already mapped), resolve it name through ApiSet if required.
*
*/
NTSTATUS SdtMapModuleFromImportThunkWithResolve(
    _In_ LPCSTR lpModuleName,
    _In_ PSDT_MODULE_ENTRY ModulesHead,
    _Inout_ PSDT_MODULE_ENTRY ModuleEntry
)
{
    BOOLEAN bNeedApiSetResolve = (g_NtBuildNumber > 18885);
    NTSTATUS ntStatus = STATUS_DLL_NOT_FOUND;
    PVOID pvApiSetMap = NtCurrentPeb()->ApiSetMap;
    UNICODE_STRING usModuleName;

    //
    // Convert module name to UNICODE.
    //
    if (RtlCreateUnicodeStringFromAsciiz(&usModuleName, (PSTR)lpModuleName)) {

        //
        // Check whatever ApiSet resolving required.
        //
        if (bNeedApiSetResolve && pvApiSetMap) {

            ntStatus = ApiSetResolveAndLoadModule(
                pvApiSetMap,
                &usModuleName,
                ModulesHead,
                ModuleEntry);

        }
        else {
            //
            // No ApiSet resolve required, load as usual.
            //
            ntStatus = SdtLoadAndRememberModule(ModulesHead, &usModuleName, ModuleEntry, TRUE);
        }

        if (!NT_SUCCESS(ntStatus))
            RtlFreeUnicodeString(&usModuleName);

    }

    return ntStatus;
}

/*
* SdtResolveFunctionNameFromModuleExport
*
* Purpose:
*
* Resolve routine name (or ordinal) from module export.
*
*/
NTSTATUS SdtResolveFunctionNameFromModuleExport(
    _In_ HMODULE ModuleBase,
    _In_ ULONG_PTR LoadedModuleBase,
    _In_ ULONG_PTR KernelPointer,
    _Out_ LPCSTR* FunctionName,
    _Out_ PUSHORT Ordinal
)
{
    ULONG i, j, ordinalNumber = 0;
    PDWORD funcTable, nameTableBase;
    PUSHORT nameOrdinalTableBase;
    PIMAGE_EXPORT_DIRECTORY pExportDirectory;
    ULONG_PTR fnPtr;
    LPCSTR lpName = NULL;
    ULONG exportSize, exportRva;

    *FunctionName = NULL;
    *Ordinal = 0;
    __try {
        pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(ModuleBase,
            TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &exportSize);

        if (pExportDirectory) {

            nameOrdinalTableBase = (PUSHORT)RtlOffsetToPointer(ModuleBase, pExportDirectory->AddressOfNameOrdinals);
            funcTable = (PDWORD)RtlOffsetToPointer(ModuleBase, pExportDirectory->AddressOfFunctions);
            nameTableBase = (PDWORD)RtlOffsetToPointer(ModuleBase, pExportDirectory->AddressOfNames);
            fnPtr = KernelPointer - LoadedModuleBase;

            for (i = 0; i < pExportDirectory->NumberOfFunctions; i++) {

                ordinalNumber = pExportDirectory->Base + i;
                exportRva = funcTable[i];

                if (exportRva == fnPtr) {

                    for (j = 0; j < pExportDirectory->NumberOfNames; j++) {
                        if (nameOrdinalTableBase[j] == i) {
                            lpName = (LPCSTR)RtlOffsetToPointer(ModuleBase, nameTableBase[j]);
                            *FunctionName = lpName;
                            break;
                        }
                    }

                    *Ordinal = (USHORT)ordinalNumber;
                    return STATUS_SUCCESS;
                }

            }

        }
    }
    __except (WOBJ_EXCEPTION_FILTER_LOG) {
        return GetExceptionCode();
    }

    return STATUS_OBJECT_NAME_NOT_FOUND;
}

/*
* SdtResolveModuleFromImportThunk
*
* Purpose:
*
* Find a module for shadow table entry in win32k imports.
*
* Function return NTSTATUS value and sets ModuleEntry parameter.
*
*/
NTSTATUS SdtResolveModuleFromImportThunk(
    _In_ PSDT_CONTEXT Context,
    _In_ PBYTE FunctionPtr,
    _In_ PSDT_MODULE_ENTRY ModulesHead,
    _Inout_ PSDT_MODULE_ENTRY ModuleEntry
)
{
    LPCSTR pszDllName;
    ULONG importSize;
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor, pIID;
    PIMAGE_IMPORT_BY_NAME pImageImportByName;
    PIMAGE_THUNK_DATA pOrigFirstThunk, pFirstThunk, pFuncThunk;

    hde64s hs;
    LONG32 rel;

    __try {
        hde64_disasm(FunctionPtr, &hs);
        if (hs.flags & F_ERROR)
            return STATUS_INTERNAL_ERROR;

        if (!(hs.flags & F_DISP32))
            return STATUS_ILLEGAL_FUNCTION;

        rel = hs.disp.disp32;
        pFuncThunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)FunctionPtr + hs.len + rel);

        pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)RtlImageDirectoryEntryToData(
            Context->KernelModule,
            TRUE,
            IMAGE_DIRECTORY_ENTRY_IMPORT,
            &importSize);

        for (pIID = pImportDescriptor; pIID->Name != 0; pIID++) {

            pOrigFirstThunk = (PIMAGE_THUNK_DATA)RtlOffsetToPointer(Context->KernelModule, pIID->OriginalFirstThunk);
            pFirstThunk = (PIMAGE_THUNK_DATA)RtlOffsetToPointer(Context->KernelModule, pIID->FirstThunk);

            for (; pOrigFirstThunk->u1.AddressOfData; ++pOrigFirstThunk, ++pFirstThunk) {
                pImageImportByName = (PIMAGE_IMPORT_BY_NAME)RtlOffsetToPointer(Context->KernelModule,
                    pOrigFirstThunk->u1.AddressOfData);

                if (pFirstThunk == pFuncThunk) {
                    pszDllName = (LPCSTR)RtlOffsetToPointer(Context->KernelModule, pIID->Name);

                    return SdtMapModuleFromImportThunkWithResolve(
                        pszDllName,
                        ModulesHead,
                        ModuleEntry);

                }
            }
        }
    }
    __except (WOBJ_EXCEPTION_FILTER_LOG) {
        return GetExceptionCode();
    }

    return STATUS_UNSUCCESSFUL;
}

/*
* SdtResolveServiceEntryModule
*
* Purpose:
*
* Find a module for shadow table entry by parsing apisets(if present) and/or forwarders (if present).
*
* Function return NTSTATUS value and sets ModuleEntry parameter.
*
*/
NTSTATUS SdtResolveServiceEntryModule(
    _In_ PSDT_CONTEXT Context,
    _In_ PBYTE FunctionPtr,
    _In_ PSDT_MODULE_ENTRY ModulesHead,
    _Inout_ PSDT_MODULE_ENTRY ModuleEntry
)
{
    BOOLEAN bWin32kApiSetTableExpected = (g_NtBuildNumber > 18935);
    ULONG entrySize;
    NTSTATUS ntStatus = STATUS_DLL_NOT_FOUND;
    ULONG_PTR entryReference;
    PVOID pvApiSetMap = NtCurrentPeb()->ApiSetMap;
    W32K_API_SET_TABLE_ENTRY* pvApiSetEntry = NULL;
    UNICODE_STRING usApiSetEntry;

    //
    // See if this is new Win32kApiSetTable adapter.
    //
    if (bWin32kApiSetTableExpected && pvApiSetMap) {

        entryReference = ApiSetExtractReferenceFromAdapter(FunctionPtr);
        if (entryReference) {

            if (g_NtBuildNumber >= NT_WINSRV_21H1)
                entrySize = sizeof(W32K_API_SET_TABLE_ENTRY_V2);
            else
                entrySize = sizeof(W32K_API_SET_TABLE_ENTRY);

            ntStatus = ApiSetResolveWin32kTableEntry(
                Context->Win32kApiSetTable,
                entryReference,
                entrySize,
                (PVOID*)&pvApiSetEntry);

            if (!NT_SUCCESS(ntStatus))
                return ntStatus;

            //
            // Host is on the same offset for both V1/V2 versions.
            //
            RtlInitUnicodeString(&usApiSetEntry, pvApiSetEntry->Host->HostName);

            return ApiSetResolveAndLoadModule(
                pvApiSetMap,
                &usApiSetEntry,
                ModulesHead,
                ModuleEntry);

        }
    }

    //
    // Reference not found, search import.
    //

    return SdtResolveModuleFromImportThunk(Context,
        FunctionPtr,
        ModulesHead,
        ModuleEntry);
}

/*
* SdtResolveServiceEntryModuleSessionAware
*
* Purpose:
*
* Find a module for shadow table entry.
*
* Function return NTSTATUS value and sets ModuleEntry parameter.
*
*/
NTSTATUS SdtResolveServiceEntryModuleSessionAware(
    _In_ PSDT_CONTEXT Context,
    _In_ PBYTE FunctionPtr,
    _In_ PRTL_PROCESS_MODULES Modules,
    _Inout_ PSDT_FUNCTION_NAME ServiceName,
    _In_ PSDT_MODULE_ENTRY ModulesHead,
    _Inout_ PSDT_MODULE_ENTRY ModuleEntry
)
{
    BOOL bFound = FALSE;
    NTSTATUS resultStatus = STATUS_UNSUCCESSFUL;
    PCHAR pStr;
    PBYTE ptrCode = FunctionPtr;
    ULONG hostOffset = 0, hostEntryOffset = 0;
    ULONG_PTR i, slotAddress, hostAddress, hostEntry, tableAddress, routineAddress;
    PRTL_PROCESS_MODULE_INFORMATION pModule;
    UNICODE_STRING usModuleName;
    hde64s hs;

    ULONG offsets[2];
    ULONG c = 0;

    do {

        //
        // Extract offsets.
        // 
        i = 0;

        do {

            hde64_disasm(RtlOffsetToPointer(ptrCode, i), &hs);
            if (hs.flags & F_ERROR) {
                resultStatus = STATUS_INTERNAL_ERROR;
                break;
            }

            //
            // Find SGDGetWin32kApiSetTable call.
            //
            if ((hs.len == 7) &&
                (hs.flags & F_PREFIX_REX) &&
                (hs.flags & F_MODRM) &&
                (hs.opcode == 0xff))
            {
                ptrCode = (PBYTE)RtlOffsetToPointer(ptrCode, i + hs.len);
                bFound = TRUE;
                break;
            }

            i += hs.len;

        } while (i < 64);

        if (bFound == FALSE) {
            resultStatus = STATUS_INTERNAL_ERROR;
            break;
        }

        i = 0;

        offsets[0] = 0;
        offsets[1] = 0;

        do {
            hde64_disasm(RtlOffsetToPointer(ptrCode, i), &hs);
            if (hs.flags & F_ERROR) {
                resultStatus = STATUS_INTERNAL_ERROR;
                break;
            }

            if ((hs.flags & F_PREFIX_REX) &&
                (hs.flags & F_MODRM) &&
                (hs.opcode == 0x8B))
            {
                //
                // Capture offset
                //
                if (hs.flags & F_DISP8)
                    offsets[c] = hs.disp.disp8;
                else if (hs.flags & F_DISP16)
                    offsets[c] = hs.disp.disp16;
                else if (hs.flags & F_DISP32)
                    offsets[c] = hs.disp.disp32;
                else
                    offsets[c] = 0;

                c += 1;
                if (c > 1)
                    break;
            }

            i += hs.len;

        } while (i < 32);

        hostOffset = offsets[0];
        hostEntryOffset = offsets[1];

        //
        // If offsets not found try extraction from win32k import.
        //
        if (hostOffset == 0) {

            resultStatus = SdtResolveModuleFromImportThunk(
                Context,
                FunctionPtr,
                ModulesHead,
                ModuleEntry);

        }
        else {

            resultStatus = STATUS_PROCEDURE_NOT_FOUND;

            //
            // Read slot.
            //
            slotAddress = (ULONG_PTR)RtlOffsetToPointer(Context->SgdGlobals.gSessionGlobalSlots,
                (Context->SessionId - 1) * sizeof(ULONG_PTR));

            if (!kdReadSystemMemory(slotAddress, &tableAddress, sizeof(ULONG_PTR)))
                break;

            //
            // Read table base.
            //
            tableAddress = tableAddress + Context->Win32kApiSetTableOffset;
            if (!kdReadSystemMemory(tableAddress, &hostAddress, sizeof(ULONG_PTR)))
                break;

            //
            // Read host base.
            //
            hostAddress += hostOffset;
            if (!kdReadSystemMemory(hostAddress, &hostEntry, sizeof(ULONG_PTR)))
                break;

            if (hostEntry == 0) {
                resultStatus = STATUS_APISET_NOT_HOSTED;
                break;
            }

            //
            // Read host entry.
            //
            routineAddress = hostEntry + hostEntryOffset;
            if (!kdReadSystemMemory(routineAddress, &routineAddress, sizeof(ULONG_PTR)))
                break;

            if (routineAddress == 0) {
                resultStatus = STATUS_APISET_NOT_PRESENT;
                break;
            }

            pModule = (PRTL_PROCESS_MODULE_INFORMATION)ntsupGetModuleEntryByAddress(Modules, (PVOID)routineAddress);
            if (pModule) {

                pStr = (PCHAR)&pModule->FullPathName[pModule->OffsetToFileName];

                if (RtlCreateUnicodeStringFromAsciiz(&usModuleName, pStr)) {
                    resultStatus = SdtLoadAndRememberModule(ModulesHead, &usModuleName, ModuleEntry, TRUE);
                    if (NT_SUCCESS(resultStatus)) {

                        resultStatus = SdtResolveFunctionNameFromModuleExport(ModuleEntry->ImageBase,
                            (ULONG_PTR)pModule->ImageBase,
                            routineAddress,
                            &ServiceName->ExportName,
                            &ServiceName->ExportOrdinal);

                    }
                    else {
                        RtlFreeUnicodeString(&usModuleName);
                    }
                }
                else {
                    resultStatus = STATUS_INTERNAL_ERROR;
                }
            }
            else {
                resultStatus = STATUS_INTERNAL_ERROR;
            }

        }

    } while (FALSE);

    return resultStatus;
}

/*
* SdtWin32kInitializeOnce
*
* Purpose:
*
* Initialize service table lookup variables and data.
*
*/
ULONG SdtWin32kInitializeOnce(
    _In_ PRTL_PROCESS_MODULES pModules,
    _Inout_ PSDT_CONTEXT Context
)
{
    BOOLEAN bNeedApiSetResolve = (g_NtBuildNumber > 18885);
    BOOLEAN bWin32kApiSetTableExpected = (g_NtBuildNumber > 18935);
    ULONG ulResult = 0, schemaVersion;
    ULONG_PTR varAddress;
    PULONG pKernelLimit;
    PRTL_PROCESS_MODULE_INFORMATION pModule;
    HANDLE heapHandle;
    HMODULE hModule;
    SYMCONTEXT* symContext = NULL;
    RESOLVE_INFO resolveInfo;
    WCHAR szModuleFileName[MAX_PATH * 2];

    do {

        if (Context->Initialized)
            return 0;

        Context->ApiSetSessionAware = (g_NtBuildNumber > NT_WIN11_23H2);

        //
        // Find win32k loaded image base and size.
        //
        pModule = (PRTL_PROCESS_MODULE_INFORMATION)ntsupFindModuleEntryByName_U(
            pModules,
            WIN32K_FILENAME);

        if (pModule == NULL) {
            ulResult = ErrShadowWin32kNotFound;
            break;
        }

        Context->KernelBaseAddress = (ULONG_PTR)pModule->ImageBase;
        Context->KernelImageSize = pModule->ImageSize;

        //
        // Query win32u for exports dump.
        //
        hModule = GetModuleHandle(WIN32U_FILENAME);
        if (hModule == NULL) {
            ulResult = ErrShadowWin32uLoadFail;
            break;
        }

        Context->UserModule = hModule;

        //
        // Prepare dedicated heap for exports enumeration.
        //
        heapHandle = supCreateHeap(HEAP_GROWABLE, TRUE);
        if (heapHandle == NULL) {
            ulResult = ErrShadowMemAllocFail;
            break;
        }

        Context->ExportsEnumHeap = heapHandle;

        //
        // Dump syscall exports.
        //
        Context->UserLimit = NtRawEnumSyscallExports(
            heapHandle,
            hModule,
            &Context->UserTable);

        //
        // Load win32k image and load symbols if possible.
        //
        RtlStringCchPrintfSecure(szModuleFileName,
            RTL_NUMBER_OF(szModuleFileName),
            L"%ws\\%ws",
            g_WinObj.szSystemDirectory, WIN32K_FILENAME);

        hModule = LoadLibraryEx(szModuleFileName, NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (hModule == NULL) {
            ulResult = ErrShadowWin32kLoadFail;
            break;
        }
        Context->KernelModule = hModule;

        //
        // Check whatever win32u is compatible with win32k data, compare number of services.
        //
        pKernelLimit = (PULONG)GetProcAddress(hModule, "W32pServiceLimit");
        if (pKernelLimit == NULL) {
            ulResult = ErrShadowW32pServiceLimitNotFound;
            break;
        }
        if (*pKernelLimit != Context->UserLimit) {
            ulResult = ErrShadowWin32uMismatch;
            break;
        }
        Context->KernelLimit = *pKernelLimit;

        //
        // Query win32k!W32pServiceTable, calculate it kernel address.
        //
        RtlSecureZeroMemory(&resolveInfo, sizeof(RESOLVE_INFO));
        if (!NT_SUCCESS(NtRawGetProcAddress(Context->KernelModule, "W32pServiceTable", &resolveInfo))) {
            ulResult = ErrShadowW32pServiceTableNotFound;
            break;
        }

        Context->W32pServiceTableUserBase = (PULONG)resolveInfo.Function;

        Context->W32pServiceTableKernelBase =
            Context->KernelBaseAddress + (ULONG_PTR)resolveInfo.Function - (ULONG_PTR)Context->KernelModule;

        //
        // Find Win32kApiSetTable where needed.
        //
        if (bWin32kApiSetTableExpected) {

            logAdd(EntryTypeInformation, TEXT("Win32kApiSetTable parsing expected"));

            //
            // Query ApiSetMap
            //
            if (bNeedApiSetResolve) {

                schemaVersion = *(ULONG*)NtCurrentPeb()->ApiSetMap;

                //
                // Windows 10+ uses modern ApiSetSchema version, everything else not supported.
                //
                if (schemaVersion != API_SET_SCHEMA_VERSION_V6) {
                    ulResult = ErrShadowApiSetSchemaVerUnknown;
                    break;
                }
            }

            //
            // Create symbol parser context, failure insignificant.
            //
            symContext = SymParserCreate();

            //
            // Load symbols for win32k.sys
            //
            if (symContext)
                kdLoadSymbolsForNtImage(symContext, szModuleFileName, hModule, 0);

            //
            // This is win11 next layout.
            //
            if (Context->ApiSetSessionAware) {

                logAdd(EntryTypeInformation, TEXT("Session aware ApiSet parsing expected"));

                //
                // Load win32ksgd.sys
                //
                RtlStringCchPrintfSecure(szModuleFileName,
                    RTL_NUMBER_OF(szModuleFileName),
                    L"%ws\\%ws",
                    g_WinObj.szSystemDirectory, WIN32KSGD_FILENAME);

                hModule = LoadLibraryEx(szModuleFileName, NULL, DONT_RESOLVE_DLL_REFERENCES);
                if (hModule == NULL) {
                    ulResult = ErrShadowWin32ksgdLoadFail;
                    break;
                }

                Context->SgdModule = hModule;
                if (symContext)
                    kdLoadSymbolsForNtImage(symContext, szModuleFileName, hModule, 0);

                pModule = (PRTL_PROCESS_MODULE_INFORMATION)ntsupFindModuleEntryByName_U(
                    pModules,
                    WIN32KSGD_FILENAME);

                if (pModule == NULL) {
                    ulResult = ErrShadowWin32kNotFound;
                    break;
                }

                Context->SgdBaseAddress = (ULONG_PTR)pModule->ImageBase;
                Context->SgdImageSize = pModule->ImageSize;
                varAddress = SdtpQueryWin32kSessionGlobalSlots(hModule,
                    pModule->ImageBase,
                    pModule->ImageSize,
                    symContext);

                if (varAddress == 0) {
                    ulResult = ErrShadowWin32ksgdGlobalsNotFound;
                    break;
                }

                Context->Win32kApiSetTableOffset = SdtpQuerySGDGetWin32kApiSetTableOffset(Context->SgdModule);
                if (Context->Win32kApiSetTableOffset == 0) {
                    ulResult = ErrShadowWin32ksgdOffsetNotFound;
                    break;
                }

                if (!kdReadSystemMemory(varAddress, &Context->SgdGlobals, sizeof(SGD_GLOBALS))) {
                    ulResult = ErrShadowWin32ksgdGlobalsNotFound;
                    break;
                }
                Context->SessionId = NtCurrentPeb()->SessionId;

            }
            else {
                //
                // This is old win32k layout.
                // Locate Win32kApiSetTable variable. Failure will result in unresolved apiset adapters.
                //
                Context->Win32kApiSetTable = SdtpQueryWin32kApiSetTable(Context->KernelModule,
                    (PVOID)Context->KernelBaseAddress,
                    Context->KernelImageSize,
                    symContext);

                //
                // This is non critical error.
                //
                if (Context->Win32kApiSetTable == 0) {
                    ulResult = ErrShadowApiSetNotFound;
                }

                if (symContext) {
                    symContext->Parser.UnloadModule(symContext);
                    symContext = NULL;
                }
            }
        }

    } while (FALSE);

    //
    // Cleanup.
    //
    if (symContext) {
        symContext->Parser.UnloadModule(symContext);
        SymParserDestroy(symContext);
    }

    if (ulResult == 0) {

        Context->Initialized = TRUE;

    }
    else {

        if (ulResult != ErrShadowApiSetNotFound) {

            if (Context->SgdModule)
                FreeLibrary(Context->SgdModule);

            if (Context->KernelModule)
                FreeLibrary(Context->KernelModule);

            if (Context->ExportsEnumHeap)
                supDestroyHeap(Context->ExportsEnumHeap);

            Context->SgdModule = NULL;
            Context->KernelModule = NULL;
            Context->ExportsEnumHeap = NULL;
        }

    }

    return ulResult;
}

/*
* SdtWin32kUninitialize
*
* Purpose:
*
* Cleanup Win32k query context.
*
*/
VOID SdtWin32kUninitialize(
    _In_ PSDT_CONTEXT Context)
{
    if (Context->KernelModule)
        FreeLibrary(Context->KernelModule);

    if (Context->SgdModule)
        FreeLibrary(Context->SgdModule);

    if (Context->ExportsEnumHeap)
        supDestroyHeap(Context->ExportsEnumHeap);

    RtlSecureZeroMemory(Context, sizeof(SDT_CONTEXT));
}

/*
* SdtLoadAndRememberModule
*
* Purpose:
*
* Remember loaded module to the internal list.
*
*/
NTSTATUS SdtLoadAndRememberModule(
    _In_ PSDT_MODULE_ENTRY Head,
    _In_ PUNICODE_STRING ModuleName,
    _Inout_ PSDT_MODULE_ENTRY Entry,
    _In_ BOOL ModuleNameAllocated
)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    HMODULE dllModule;
    PSDT_MODULE_ENTRY nextEntry, mEntry;
    ULONG hashValue;
    ULONG dllChars = IMAGE_FILE_EXECUTABLE_IMAGE; //DONT_RESOLVE_DLL_REFERENCES

    RtlHashUnicodeString(ModuleName, TRUE, HASH_STRING_ALGORITHM_X65599, &hashValue);

    nextEntry = Head->Next;
    while (nextEntry != NULL) {

        mEntry = nextEntry;
        if (mEntry->Hash == hashValue) {
            *Entry = *mEntry;

            //
            // Free duplicate and return success.
            //
            if (ModuleNameAllocated)
                RtlFreeUnicodeString(ModuleName);

            return STATUS_SUCCESS;
        }

        nextEntry = nextEntry->Next;
    }

    mEntry = (PSDT_MODULE_ENTRY)supHeapAlloc(sizeof(SDT_MODULE_ENTRY));

    if (mEntry) {
        ntStatus = LdrLoadDll(NULL, &dllChars, ModuleName, (PVOID*)&dllModule);
        if (NT_SUCCESS(ntStatus)) {
            mEntry->Next = Head->Next;
            mEntry->Hash = hashValue;
            mEntry->ImageBase = dllModule;

            if (ModuleNameAllocated) {
                //
                // Module name memory already allocated.
                //
                mEntry->Name = *ModuleName;
            }
            else {
                //
                // Module name is local, duplicate.
                //
                supDuplicateUnicodeString(NtCurrentPeb()->ProcessHeap, &mEntry->Name, ModuleName);
            }

            Head->Next = mEntry;
            *Entry = *mEntry;
        }
        else {
#ifdef _DEBUG
            DbgBreakPoint();
#endif
            supHeapFree(mEntry);
            mEntry = NULL;
        }
    }

    return ntStatus;
}

/*
* SdtUnloadRememberedModules
*
* Purpose:
*
* Unload all remembered modules.
*
*/
VOID SdtUnloadRememberedModules(
    _In_ PSDT_MODULE_ENTRY Head
)
{
    PSDT_MODULE_ENTRY nextEntry, mEntry;

    nextEntry = Head->Next;
    while (nextEntry != NULL) {
        mEntry = nextEntry;
        nextEntry = nextEntry->Next;
        LdrUnloadDll((PVOID)mEntry->ImageBase);
        RtlFreeUnicodeString(&mEntry->Name);
        supHeapFree(mEntry);
    }

}
