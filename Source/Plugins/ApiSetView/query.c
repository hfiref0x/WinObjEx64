/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2021
*
*  TITLE:       QUERY.C
*
*  VERSION:     1.11
*
*  DATE:        11 June 2021
*
*  Query and output ApiSet specific data.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

typedef VOID(CALLBACK* pfnApiSetQueryMap)(
    _In_ PVOID ApiSetMap,
    _In_ HTREEITEM RootItem,
    _In_opt_ LPCWSTR FilterByName);

#define APISET_QUERY_ROUTINE(n) VOID n(   \
    _In_ PVOID ApiSetMap,                 \
    _In_ HTREEITEM RootItem,              \
    _In_opt_ LPCWSTR FilterByName)

VALUE_DESC g_ApiSetEntryFlags[] = {
    { API_SET_SCHEMA_ENTRY_FLAGS_SEALED, L"Sealed" },
    { API_SET_SCHEMA_ENTRY_FLAGS_EXTENSION, L"Extension" }
};

/*
* DiplayErrorText
*
* Purpose:
*
* In debug build send string to debugger else show message box.
*
*/
VOID DiplayErrorText(
    _In_ LPWSTR ErrorMsg)
{
#ifdef _DEBUG
    OutputDebugString(ErrorMsg);
#else
    MessageBox(g_ctx.MainWindow, ErrorMsg, NULL, MB_ICONERROR);
#endif
}

/*
* TreeListAddItem
*
* Purpose:
*
* Insert new treelist item.
*
*/
HTREEITEM TreeListAddItem(
    _In_ HWND TreeList,
    _In_opt_ HTREEITEM hParent,
    _In_ UINT mask,
    _In_ UINT state,
    _In_ UINT stateMask,
    _In_opt_ LPWSTR pszText,
    _In_opt_ PVOID subitems
)
{
    TVINSERTSTRUCT tvitem;
    PTL_SUBITEMS si = (PTL_SUBITEMS)subitems;

    RtlSecureZeroMemory(&tvitem, sizeof(tvitem));
    tvitem.hParent = hParent;
    tvitem.item.mask = mask;
    tvitem.item.state = state;
    tvitem.item.stateMask = stateMask;
    tvitem.item.pszText = pszText;
    tvitem.hInsertAfter = TVI_LAST;
    return TreeList_InsertTreeItem(TreeList, &tvitem, si);
}

/*
* GetApiSetEntryName
*
* Purpose:
*
* Return apiset entry name, use HeapFree to release allocated memory.
*
*/
LPWSTR GetApiSetEntryName(
    _In_ PBYTE Namespace,
    _In_ ULONG NameOffset,
    _In_ ULONG NameLength
)
{
    PWSTR lpEntryName, lpStr;

    if (NameLength == 0)
        return NULL;

    lpEntryName = HeapAlloc(
        g_ctx.PluginHeap,
        HEAP_ZERO_MEMORY,
        NameLength + sizeof(WCHAR));

    if (lpEntryName) {

        lpStr = lpEntryName;

        //
        // Copy namespace entry name.
        //
        RtlCopyMemory(
            lpStr,
            (PWSTR)RtlOffsetToPointer(Namespace, NameOffset),
            NameLength);

        //
        // Add terminating null.
        //
        lpStr += (NameLength / sizeof(WCHAR));
        *lpStr = 0;

    }

    return lpEntryName;
}

/*
* OutNamespaceEntry
*
* Purpose:
*
* Namespace entry formatted output routine.
*
*/
HTREEITEM OutNamespaceEntry(
    _In_ HTREEITEM RootItem,
    _In_ LPWSTR EntryName,
    _In_opt_ ULONG Flags
)
{
    ULONG i, flagsValue;
    LPTSTR lpText = NULL;
    HTREEITEM h_tviRootItem;

    TL_SUBITEMS_FIXED tlSubItems;

    WCHAR szBuffer[20];

    RtlSecureZeroMemory(&tlSubItems, sizeof(tlSubItems));

    flagsValue = Flags;
    
    //
    // Output first flag from combination.
    //
    if (flagsValue) {
        for (i = 0; i < RTL_NUMBER_OF(g_ApiSetEntryFlags); i++) {
            if (flagsValue & g_ApiSetEntryFlags[i].Value) {
                lpText = (LPTSTR)g_ApiSetEntryFlags[i].Desc;
                flagsValue &= ~g_ApiSetEntryFlags[i].Value;
                break;
            }
        }

        //
        // Unrecognized flags combination.
        //
        if (lpText == NULL) {
            szBuffer[0] = 0;
            ultostr(flagsValue, szBuffer);
            lpText = szBuffer;
            flagsValue = 0;
        }

    }

    if (lpText == NULL) lpText = T_EmptyString;

    tlSubItems.Text[0] = lpText;
    tlSubItems.Text[1] = T_EmptyString;
    tlSubItems.Count = 2;

    h_tviRootItem = TreeListAddItem(
        g_ctx.TreeList,
        RootItem,
        TVIF_TEXT | TVIF_STATE,
        (UINT)0,
        (UINT)0,
        EntryName,
        &tlSubItems);

    //
    // List rest of the flags.
    //
    if (h_tviRootItem && flagsValue) {
        for (i = 0; i < RTL_NUMBER_OF(g_ApiSetEntryFlags); i++) {
            if (flagsValue & g_ApiSetEntryFlags[i].Value) {

                flagsValue &= ~g_ApiSetEntryFlags[i].Value;
                tlSubItems.Text[0] = (LPTSTR)g_ApiSetEntryFlags[i].Desc;
                tlSubItems.Text[1] = T_EmptyString;
                tlSubItems.Count = 2;

                TreeListAddItem(
                    g_ctx.TreeList,
                    h_tviRootItem,
                    TVIF_TEXT | TVIF_STATE,
                    (UINT)0,
                    (UINT)0,
                    T_EmptyString,
                    &tlSubItems);

            }
        }

        //
        // Unrecognized flags.
        //
        if (flagsValue) {

            szBuffer[0] = 0;
            ultostr(flagsValue, szBuffer);
            tlSubItems.Text[0] = szBuffer;
            tlSubItems.Text[1] = T_EmptyString;
            tlSubItems.Count = 2;
            TreeListAddItem(
                g_ctx.TreeList,
                h_tviRootItem,
                TVIF_TEXT | TVIF_STATE,
                (UINT)0,
                (UINT)0,
                T_EmptyString,
                &tlSubItems);

        }
    }

    return h_tviRootItem;
}

/*
* OutNamespaceValue
*
* Purpose:
*
* Add entry to treelist with namespace value information.
*
*/
void OutNamespaceValue(
    _In_ HTREEITEM RootItem,
    _In_ PBYTE Namespace,
    _In_ ULONG ValueOffset,
    _In_ ULONG ValueLength,
    _In_ ULONG NameOffset,
    _In_ ULONG NameLength,
    _In_opt_ ULONG Flags
)
{
    TL_SUBITEMS_FIXED tlSubItems;
    LPWSTR lpValueName = NULL, lpAliasName = NULL;
    WCHAR szBuffer[20];

    //
    // Get value name.
    //
    lpValueName = GetApiSetEntryName(
        Namespace,
        ValueOffset,
        ValueLength);

    //
    // Get value alias if present.
    //
    lpAliasName = GetApiSetEntryName(Namespace,
        NameOffset,
        NameLength);

    RtlSecureZeroMemory(&tlSubItems, sizeof(tlSubItems));

    tlSubItems.Count = 2;

    if (Flags) {
        szBuffer[0] = 0;
        ultostr(Flags, szBuffer);
        tlSubItems.Text[0] = szBuffer;
    }
    else {
        tlSubItems.Text[0] = T_EmptyString;
    }

    if (lpAliasName) {
        TreeList_Expand(g_ctx.TreeList, RootItem, TVE_EXPAND);
        tlSubItems.Text[1] = lpAliasName;
    }
    else {
        tlSubItems.Text[1] = T_EmptyString;
    }

    TreeListAddItem(
        g_ctx.TreeList,
        RootItem,
        TVIF_TEXT | TVIF_STATE,
        (UINT)0,
        (UINT)0,
        lpValueName,
        &tlSubItems);

    if (lpValueName) HeapFree(g_ctx.PluginHeap, 0, lpValueName);
    if (lpAliasName) HeapFree(g_ctx.PluginHeap, 0, lpAliasName);
}

/*
* ListApiSetV2
*
* Purpose:
*
* Parse and output ApiSet Version 2 (Windows 7).
*
*/
APISET_QUERY_ROUTINE(ListApiSetV2)
{
    API_SET_NAMESPACE_ARRAY_V2* Namespace = (API_SET_NAMESPACE_ARRAY_V2*)ApiSetMap;

    ULONG i, j;

    API_SET_NAMESPACE_ENTRY_V2* NsEntry;
    API_SET_VALUE_ARRAY_V2* ValuesArray;
    API_SET_VALUE_ENTRY_V2* ValueEntry;

    HTREEITEM hSubItem;

    LPWSTR lpEntryName;

    for (i = 0; i < Namespace->Count; i++) {

        NsEntry = &Namespace->Array[i];

        lpEntryName = GetApiSetEntryName(
            (PBYTE)Namespace,
            NsEntry->NameOffset,
            NsEntry->NameLength);

        if (lpEntryName) {

            if (FilterByName) {

                if (_strstri(lpEntryName, FilterByName) == NULL)
                    continue;

            }

            hSubItem = OutNamespaceEntry(
                RootItem,
                lpEntryName,
                0);

            //
            // Namespace entry name no longer needed.
            //
            HeapFree(g_ctx.PluginHeap, 0, lpEntryName);

            //
            // List values array.
            //
            ValuesArray = (API_SET_VALUE_ARRAY_V2*)RtlOffsetToPointer(
                Namespace,
                NsEntry->DataOffset);

            for (j = 0; j < ValuesArray->Count; j++) {

                ValueEntry = &ValuesArray->Array[j];

                if (!API_SET_EMPTY_NAMESPACE_VALUE(ValueEntry)) {
                    OutNamespaceValue(
                        hSubItem,
                        (PBYTE)Namespace,
                        ValueEntry->ValueOffset,
                        ValueEntry->ValueLength,
                        ValueEntry->NameOffset,
                        ValueEntry->NameLength,
                        0);
                }
            }

        } //if (lpEntryName)
    }
}

/*
* ListApiSetV4
*
* Purpose:
*
* Parse and output ApiSet Version 4 (Windows 8.x).
*
*/
APISET_QUERY_ROUTINE(ListApiSetV4)
{
    API_SET_NAMESPACE_ARRAY_V4* Namespace = (API_SET_NAMESPACE_ARRAY_V4*)ApiSetMap;

    ULONG i, j;

    API_SET_NAMESPACE_ENTRY_V4* NsEntry;
    API_SET_VALUE_ARRAY_V4* ValuesArray;
    API_SET_VALUE_ENTRY_V4* ValueEntry;

    HTREEITEM hSubItem;

    LPWSTR lpEntryName;

    for (i = 0; i < Namespace->Count; i++) {

        NsEntry = &Namespace->Array[i];

        lpEntryName = GetApiSetEntryName(
            (PBYTE)Namespace,
            NsEntry->NameOffset,
            NsEntry->NameLength);

        if (lpEntryName) {

            if (FilterByName) {

                if (_strstri(lpEntryName, FilterByName) == NULL)
                    continue;

            }

            hSubItem = OutNamespaceEntry(
                RootItem,
                lpEntryName,
                NsEntry->Flags);

            //
            // Namespace entry name no longer needed.
            //
            HeapFree(g_ctx.PluginHeap, 0, lpEntryName);

            //
            // List values array.
            //
            ValuesArray = (API_SET_VALUE_ARRAY_V4*)RtlOffsetToPointer(
                Namespace,
                NsEntry->DataOffset);

            for (j = 0; j < ValuesArray->Count; j++) {

                ValueEntry = &ValuesArray->Array[j];

                if (!API_SET_EMPTY_NAMESPACE_VALUE(ValueEntry)) {
                    OutNamespaceValue(
                        hSubItem,
                        (PBYTE)Namespace,
                        ValueEntry->ValueOffset,
                        ValueEntry->ValueLength,
                        ValueEntry->NameOffset,
                        ValueEntry->NameLength,
                        ValueEntry->Flags);
                }
            }

        } //if (lpEntryName)
    }
}

/*
* ListApiSetV6
*
* Purpose:
*
* Parse and output ApiSet Version 6 (Windows 10).
*
*/
APISET_QUERY_ROUTINE(ListApiSetV6)
{
    API_SET_NAMESPACE_ARRAY_V6* Namespace = (API_SET_NAMESPACE_ARRAY_V6*)ApiSetMap;

    ULONG i, j;

    API_SET_NAMESPACE_ENTRY_V6* NsEntry;
    API_SET_VALUE_ENTRY_V6* ValueEntry;

    HTREEITEM hSubItem;

    LPWSTR lpEntryName;

    NsEntry = (API_SET_NAMESPACE_ENTRY_V6*)RtlOffsetToPointer(
        Namespace,
        Namespace->NamespaceEntryOffset);

    for (i = 0; i < Namespace->Count; i++) {

        lpEntryName = GetApiSetEntryName(
            (PBYTE)Namespace,
            NsEntry->NameOffset,
            NsEntry->NameLength);

        if (lpEntryName) {

            if (FilterByName) {

                if (_strstri(lpEntryName, FilterByName) == NULL) {
                    goto NextEntry;
                }

            }

            hSubItem = OutNamespaceEntry(
                RootItem,
                lpEntryName,
                NsEntry->Flags);

            //
            // List values array.
            //
            ValueEntry = (API_SET_VALUE_ENTRY_V6*)RtlOffsetToPointer(
                Namespace,
                NsEntry->DataOffset);

            for (j = 0; j < NsEntry->Count; j++) {

                if (!API_SET_EMPTY_NAMESPACE_VALUE(ValueEntry)) {
                    OutNamespaceValue(
                        hSubItem,
                        (PBYTE)Namespace,
                        ValueEntry->ValueOffset,
                        ValueEntry->ValueLength,
                        ValueEntry->NameOffset,
                        ValueEntry->NameLength,
                        ValueEntry->Flags);
                }

                ValueEntry = (API_SET_VALUE_ENTRY_V6*)RtlOffsetToPointer(
                    ValueEntry,
                    sizeof(API_SET_VALUE_ENTRY_V6));

            }


        NextEntry:
            HeapFree(g_ctx.PluginHeap, 0, lpEntryName);

        } //if (lpEntryName)

        //
        // Go to next entry.
        //
        NsEntry = (API_SET_NAMESPACE_ENTRY_V6*)RtlOffsetToPointer(
            NsEntry,
            sizeof(API_SET_NAMESPACE_ENTRY_V6));
    }
}

/*
* ResolveDllData
*
* Purpose:
*
* Process apiset file, locate apiset section and schema version.
*
*/
BOOL ResolveDllData(
    _In_ HMODULE DllHandle,
    _Inout_ PVOID* ApiSetData,
    _Out_ PULONG SchemaVersion
)
{
    ULONG dataSize = 0;
    UINT i;
    ULONG schemaVersion = 0;

    PIMAGE_NT_HEADERS ntHeaders;
    IMAGE_SECTION_HEADER* sectionTableEntry;
    PBYTE baseAddress;
    PBYTE dataPtr = NULL;

    *SchemaVersion = 0;

    baseAddress = (PBYTE)(((ULONG_PTR)DllHandle) & ~3);

    ntHeaders = RtlImageNtHeader(baseAddress);

    sectionTableEntry = IMAGE_FIRST_SECTION(ntHeaders);

    i = ntHeaders->FileHeader.NumberOfSections;
    while (i > 0) {
        if (_strncmpi_a((CHAR*)&sectionTableEntry->Name,
            API_SET_SECTION_NAME,
            sizeof(API_SET_SECTION_NAME)) == 0)
        {
            dataSize = sectionTableEntry->SizeOfRawData;

            dataPtr = (PBYTE)RtlOffsetToPointer(
                baseAddress,
                sectionTableEntry->PointerToRawData);

            break;
        }
        i -= 1;
        sectionTableEntry += 1;
    }

    if (dataPtr == NULL || dataSize == 0) {
        return FALSE;
    }

    schemaVersion = *(ULONG*)dataPtr;

    *SchemaVersion = schemaVersion;
    *ApiSetData = dataPtr;

    return TRUE;
}

/*
* ListApiSetFromFileWorker
*
* Purpose:
*
* Processing apiset file.
*
*/
VOID WINAPI ListApiSetFromFileWorker(
    _In_ LPCWSTR SchemaFileName,
    _In_opt_ LPCWSTR FilterByName,
    _In_ PVOID ApiSetData,
    _In_ ULONG SchemaVersion
)
{
    pfnApiSetQueryMap queryMapRoutine;

    WCHAR szBuffer[MAX_PATH * 2];

    HTREEITEM h_tviRootItem, h_tviSubItem;

    //
    // Disable controls.
    //
    EnableWindow(GetDlgItem(g_ctx.MainWindow, IDC_BROWSE_BUTTON), FALSE);

    //
    // Reset output controls.
    //
    SetDlgItemText(g_ctx.MainWindow, IDC_ENTRY_EDIT, T_EmptyString);
    TreeList_ClearTree(g_ctx.TreeList);
    TreeList_RedrawDisable(g_ctx.TreeList);

    StringCchPrintf(szBuffer, MAX_PATH, TEXT("Schema Version %lu"), SchemaVersion);

    //
    // Parse and output apiset.
    //
    h_tviRootItem = TreeListAddItem(
        g_ctx.TreeList,
        (HTREEITEM)NULL,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        (LPWSTR)SchemaFileName,
        (PVOID)NULL);

    if (h_tviRootItem) {

        h_tviSubItem = TreeListAddItem(
            g_ctx.TreeList,
            (HTREEITEM)h_tviRootItem,
            TVIF_TEXT | TVIF_STATE,
            TVIS_EXPANDED,
            TVIS_EXPANDED,
            (LPWSTR)szBuffer,
            (PVOID)NULL);

        if (h_tviSubItem) {

            switch (SchemaVersion) {

            case API_SET_SCHEMA_VERSION_V2:
                queryMapRoutine = (pfnApiSetQueryMap)ListApiSetV2;
                break;

            case API_SET_SCHEMA_VERSION_V4:
                queryMapRoutine = (pfnApiSetQueryMap)ListApiSetV4;
                break;

            case API_SET_SCHEMA_VERSION_V6:
                queryMapRoutine = (pfnApiSetQueryMap)ListApiSetV6;
                break;

            default:
                queryMapRoutine = NULL;
                break;
            }

            __try {

                if (queryMapRoutine)
                    queryMapRoutine(ApiSetData, h_tviSubItem, FilterByName);

            }
            __except (EXCEPTION_EXECUTE_HANDLER) {

                szBuffer[0] = 0;

                StringCchPrintf(
                    szBuffer,
                    MAX_PATH,
                    TEXT("ApiSetView: Exception %lu thrown while processing apiset, schema version %lu"),
                    GetExceptionCode(),
                    SchemaVersion);

                DiplayErrorText(szBuffer);

            }


        }
    }

    //
    // Reenable controls.
    //
    EnableWindow(GetDlgItem(g_ctx.MainWindow, IDC_BROWSE_BUTTON), TRUE);
    TreeList_RedrawEnableAndUpdateNow(g_ctx.TreeList);
}

/*
* ListApiSetFromFile
*
* Purpose:
*
* Load file or use default system apiset and output it contents.
*
*/
VOID ListApiSetFromFile(
    _In_opt_ LPCWSTR FileName,
    _In_opt_ LPCWSTR FilterByName
)
{
    ULONG cch;
    ULONG schemaVersion = 0;
    HMODULE hApiSetDll;
    LPWSTR lpFileName = NULL;
    PVOID dataPtr = NULL;
    WCHAR szErrorMsg[MAX_PATH + 1];
    WCHAR szSystemDirectory[MAX_PATH + 1];

    //
    // Select apiset dll name.
    //
    if (FileName) {
        lpFileName = (LPWSTR)FileName;
    }
    else {
        RtlSecureZeroMemory(&g_ctx.SchemaFileName, sizeof(g_ctx.SchemaFileName));
        RtlSecureZeroMemory(szSystemDirectory, sizeof(szSystemDirectory));
        cch = GetSystemDirectory(szSystemDirectory, MAX_PATH);
        if (cch && cch < MAX_PATH) {
            StringCchPrintf(g_ctx.SchemaFileName,
                RTL_NUMBER_OF(g_ctx.SchemaFileName) - 1,
                TEXT("%s\\apisetschema.dll"),
                szSystemDirectory);
            lpFileName = g_ctx.SchemaFileName;
        }
    }

    if (lpFileName == NULL) {
        DiplayErrorText(TEXT("ApiSet dll filename not specified"));
        return;
    }

    //
    // Load library and locate apiset section.
    //

    hApiSetDll = LoadLibraryEx(lpFileName, NULL, LOAD_LIBRARY_AS_DATAFILE);

    if (hApiSetDll) {

        if (ResolveDllData(hApiSetDll, &dataPtr, &schemaVersion)) {

            if (schemaVersion != API_SET_SCHEMA_VERSION_V2 &&
                schemaVersion != API_SET_SCHEMA_VERSION_V4 &&
                schemaVersion != API_SET_SCHEMA_VERSION_V6)
            {
                StringCchPrintf(szErrorMsg,
                    MAX_PATH,
                    TEXT("ApiSetView: Unknown schema version %lu"), schemaVersion);

                DiplayErrorText(szErrorMsg);
            }
            else {

                ListApiSetFromFileWorker(
                    lpFileName,
                    FilterByName,
                    dataPtr,
                    schemaVersion);

            }
        }
        else {
            DiplayErrorText(TEXT("ApiSetView: could not resolve data, probably not apiset file or data corrupted"));
        }

        FreeLibrary(hApiSetDll);
    }
    else {
        DiplayErrorText(TEXT("ApiSetView: could not load apiset library"));
    }
}
