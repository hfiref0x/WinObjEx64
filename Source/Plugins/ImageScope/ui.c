/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       UI.C
*
*  VERSION:     1.00
*
*  DATE:        22 July 2020
*
*  WinObjEx64 ImageScope UI.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

INT_PTR CALLBACK TabsWndProc(
    _In_ HWND hWnd,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam);

static IMS_TAB ImsTabs[] = {
    { IDD_TABDLG_SECTION, TabIdSection, TabsWndProc, TEXT("Section") },
    { IDD_TABDLG_VSINFO, TabIdVSInfo, TabsWndProc, TEXT("VersionInfo") },
    { IDD_TABDLG_STRINGS, TabIdStrings, TabsWndProc, TEXT("Strings") }
};

static VALUE_DESC PEImageFileChars[] = {
    { TEXT("RelocsStripped"), IMAGE_FILE_RELOCS_STRIPPED },
    { TEXT("Executable"), IMAGE_FILE_EXECUTABLE_IMAGE },
    { TEXT("LineNumsStripped"), IMAGE_FILE_LINE_NUMS_STRIPPED },
    { TEXT("SymsStripped"), IMAGE_FILE_LOCAL_SYMS_STRIPPED },
    { TEXT("AggressiveWsTrim"), IMAGE_FILE_AGGRESIVE_WS_TRIM },
    { TEXT("LargeAddressAware"), IMAGE_FILE_LARGE_ADDRESS_AWARE },
    { TEXT("32bit"), IMAGE_FILE_32BIT_MACHINE },
    { TEXT("DebugStripped"), IMAGE_FILE_DEBUG_STRIPPED },
    { TEXT("RemovableRunFromSwap"), IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP },
    { TEXT("NetRunFromSwap"), IMAGE_FILE_NET_RUN_FROM_SWAP },
    { TEXT("System"), IMAGE_FILE_SYSTEM },
    { TEXT("Dll"), IMAGE_FILE_DLL },
    { TEXT("UpSystemOnly"), IMAGE_FILE_UP_SYSTEM_ONLY }
};

static VALUE_DESC PEDllChars[] = {
    { TEXT("HighEntropyVA"), IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA },
    { TEXT("DynamicBase"), IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE },
    { TEXT("ForceIntegrity"), IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY },
    { TEXT("NXCompat"), IMAGE_DLLCHARACTERISTICS_NX_COMPAT },
    { TEXT("NoIsolation"), IMAGE_DLLCHARACTERISTICS_NO_ISOLATION },
    { TEXT("NoSEH"), IMAGE_DLLCHARACTERISTICS_NO_SEH },
    { TEXT("NoBind"), IMAGE_DLLCHARACTERISTICS_NO_BIND },
    { TEXT("AppContainer"), IMAGE_DLLCHARACTERISTICS_APPCONTAINER },
    { TEXT("WDMDriver"), IMAGE_DLLCHARACTERISTICS_WDM_DRIVER },
    { TEXT("GuardCF"), IMAGE_DLLCHARACTERISTICS_GUARD_CF },
    { TEXT("TerminalServerAware"), IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE }
};

typedef enum _ValueDumpType {
    UlongDump = 0,
    UShortDump,
    UCharDump,
    BooleanDump,
    InvalidDumpType
} ValueDumpType;

VOID SectionDumpUlong(
    _In_ HWND TreeList,
    _In_ HTREEITEM RootItem,
    _In_ ULONG Value,
    _In_ LPWSTR ValueName,
    _In_opt_ LPWSTR ValueDesc,
    _In_ ValueDumpType DumpType
)
{
    TL_SUBITEMS_FIXED subitems;
    LPWSTR lpFormat;
    WCHAR szText[PRINTF_BUFFER_LENGTH];

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    szText[0] = 0;
    subitems.Count = 2;
    subitems.Text[0] = szText;

    if (ValueDesc)
        subitems.Text[1] = ValueDesc;
    else
        subitems.Text[1] = EMPTY_STRING;

    switch (DumpType) {
    case UShortDump:
        lpFormat = TEXT("0x%hX");
        break;
    case UCharDump:
        lpFormat = TEXT("0x%02X");
        break;
    case BooleanDump:
        lpFormat = TEXT("%01u");
        break;
    case UlongDump:
    default:
        lpFormat = TEXT("0x%08lX");
        break;
    }

    StringCchPrintf(
        szText,
        PRINTF_BUFFER_LENGTH,
        lpFormat,
        Value);

    supTreeListAddItem(
        TreeList,
        RootItem,
        TVIF_TEXT | TVIF_STATE,
        (UINT)0,
        (UINT)0,
        ValueName,
        &subitems);

}

VOID SectionDumpFlags(
    _In_ HWND TreeList,
    _In_ HTREEITEM RootItem,
    _In_ ULONG Flags,
    _In_ PVALUE_DESC FlagsDescriptions,
    _In_ ULONG MaxDescriptions,
    _In_ LPWSTR ValueName,
    _In_ ValueDumpType DumpType
)
{
    UINT i, j;
    LPWSTR lpType;
    ULONG scanFlags = Flags;
    TL_SUBITEMS_FIXED subitems;

    WCHAR szValue[PRINTF_BUFFER_LENGTH];

    RtlSecureZeroMemory(&szValue, sizeof(szValue));
    RtlSecureZeroMemory(&subitems, sizeof(subitems));

    j = 0;
    lpType = NULL;
    if (scanFlags) {
        for (i = 0; i < MaxDescriptions; i++) {
            if (scanFlags & FlagsDescriptions[i].dwValue) {
                lpType = FlagsDescriptions[i].lpDescription;
                subitems.Count = 2;

                //add first entry with name
                if (j == 0) {

                    StringCchPrintf(szValue, PRINTF_BUFFER_LENGTH,
                        TEXT("0x%08lX"), scanFlags);

                    subitems.Text[0] = szValue;
                    subitems.Text[1] = lpType;
                }
                else {
                    //add subentry
                    subitems.Text[0] = EMPTY_STRING;
                    subitems.Text[1] = lpType;
                }

                supTreeListAddItem(
                    TreeList,
                    RootItem,
                    TVIF_TEXT | TVIF_STATE,
                    0,
                    0,
                    (j == 0) ? ValueName : EMPTY_STRING,
                    &subitems);

                scanFlags &= ~FlagsDescriptions[i].dwValue;
                j++;
            }
            if (scanFlags == 0) {
                break;
            }
        }
    }
    else {
        SectionDumpUlong(TreeList, RootItem, Flags, ValueName, NULL, DumpType);
    }
}

VOID SectionDumpUnicodeString(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR StringName,
    _In_ PUNICODE_STRING pString
)
{
    HTREEITEM           h_tviSubItem;
    TL_SUBITEMS_FIXED   subitems;
    WCHAR               szValue[PRINTF_BUFFER_LENGTH];

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 2;

    subitems.Text[0] = EMPTY_STRING;
    subitems.Text[1] = TEXT("UNICODE_STRING");

    h_tviSubItem = supTreeListAddItem(
        TreeList,
        hParent,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        0,
        StringName,
        &subitems);


    //
    // Add UNICODE_STRING.Length
    //
    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    RtlSecureZeroMemory(szValue, sizeof(szValue));

    StringCchPrintf(
        szValue, 
        RTL_NUMBER_OF(szValue),
        TEXT("0x%hX"), 
        pString->Length);

    subitems.Count = 2;
    subitems.Text[0] = szValue;
    subitems.Text[1] = EMPTY_STRING;

    supTreeListAddItem(
        TreeList,
        h_tviSubItem,
        TVIF_TEXT | TVIF_STATE,
        0,
        0,
        TEXT("Length"),
        &subitems);

    //
    // Add UNICODE_STRING.MaximumLength
    //
    RtlSecureZeroMemory(szValue, sizeof(szValue));
    RtlSecureZeroMemory(&subitems, sizeof(subitems));

    StringCchPrintf(
        szValue,
        RTL_NUMBER_OF(szValue),
        TEXT("0x%hX"),
        pString->MaximumLength);

    subitems.Count = 2;
    subitems.Text[0] = szValue;
    subitems.Text[1] = EMPTY_STRING;

    supTreeListAddItem(
        TreeList,
        h_tviSubItem,
        TVIF_TEXT | TVIF_STATE,
        0,
        0,
        TEXT("MaximumLength"),
        &subitems);

    //
    // Add UNICODE_STRING.Buffer
    //
    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 2;

    if (pString->Buffer == NULL) {
        subitems.Text[0] = TEXT("NULL");
        subitems.Text[1] = EMPTY_STRING;
    }
    else {
        RtlSecureZeroMemory(&szValue, sizeof(szValue));
        szValue[0] = TEXT('0');
        szValue[1] = TEXT('x');
        u64tohex((ULONG_PTR)pString->Buffer, &szValue[2]);
        subitems.Text[0] = szValue;
        subitems.Text[1] = pString->Buffer;
    }

    supTreeListAddItem(
        TreeList,
        h_tviSubItem,
        TVIF_TEXT | TVIF_STATE,
        0,
        0,
        TEXT("Buffer"),
        &subitems);

}

VOID SectionDumpImageFileName(
    _In_ GUI_CONTEXT *Context
)
{
    OBJECT_NAME_INFORMATION* ObjectNameInfo = NULL;
    PVOID BaseAddress = Context->SectionAddress;
    NTSTATUS ntStatus;
    SIZE_T returnedLength = 0;
    HTREEITEM tviRoot;

    do {

        ntStatus = NtQueryVirtualMemory(
            NtCurrentProcess(),
            BaseAddress,
            MemoryMappedFilenameInformation,
            NULL,
            0,
            &returnedLength);

        if (ntStatus != STATUS_INFO_LENGTH_MISMATCH)
            break;

        //
        // Allocate required buffer.
        //      
        ObjectNameInfo = (OBJECT_NAME_INFORMATION*)supHeapAlloc(returnedLength);
        if (ObjectNameInfo == NULL)
            break;

        //
        // Query information.
        //
        ntStatus = NtQueryVirtualMemory(
            NtCurrentProcess(),
            BaseAddress,
            MemoryMappedFilenameInformation,
            ObjectNameInfo,
            returnedLength,
            &returnedLength);

        if (NT_SUCCESS(ntStatus)) {

            tviRoot = supTreeListAddItem(
                Context->TreeList,
                NULL,
                TVIF_TEXT | TVIF_STATE,
                (UINT)TVIS_EXPANDED,
                (UINT)TVIS_EXPANDED,
                TEXT("OBJECT_NAME_INFORMATION"),
                NULL);

            if (tviRoot) {

                SectionDumpUnicodeString(
                    Context->TreeList,
                    tviRoot,
                    TEXT("Name"),
                    &ObjectNameInfo->Name);

            }

        }

    } while (FALSE);

    if (ObjectNameInfo)
        supHeapFree(ObjectNameInfo);
}

VOID SectionDumpStructs(
    _In_ GUI_CONTEXT* Context
)
{
    BOOL bInternalPresent = FALSE;
    SECTION_IMAGE_INFORMATION sii;
    SECTION_INTERNAL_IMAGE_INFORMATION sii2;
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    HANDLE sectionHandle = NULL;
    SIZE_T returnLength;

    WCHAR szText[PRINTF_BUFFER_LENGTH];

    LPWSTR lpDesc;
    HTREEITEM tviRoot;
    TL_SUBITEMS_FIXED subitems;

    __try {

        ntStatus = Context->ParamBlock.OpenNamedObjectByType(
            &sectionHandle,
            ObjectTypeSection,
            Context->ParamBlock.Object.ObjectDirectory,
            Context->ParamBlock.Object.ObjectName,
            SECTION_QUERY);

        if (!NT_SUCCESS(ntStatus))
            __leave;

        ntStatus = NtQuerySection(
            sectionHandle,
            SectionImageInformation,
            &sii,
            sizeof(SECTION_IMAGE_INFORMATION),
            &returnLength);

        if (!NT_SUCCESS(ntStatus))
            __leave;

        bInternalPresent = NT_SUCCESS(NtQuerySection(
            sectionHandle,
            SectionInternalImageInformation,
            &sii2,
            sizeof(SECTION_INTERNAL_IMAGE_INFORMATION),
            &returnLength));

        NtClose(sectionHandle);
        sectionHandle = NULL;

        tviRoot = supTreeListAddItem(
            Context->TreeList,
            NULL,
            TVIF_TEXT | TVIF_STATE,
            (UINT)TVIS_EXPANDED,
            (UINT)TVIS_EXPANDED,
            TEXT("SECTION_IMAGE_INFORMATION"),
            NULL);

        if (tviRoot) {

            RtlSecureZeroMemory(&subitems, sizeof(subitems));
            szText[0] = 0;
            subitems.Count = 2;
            subitems.Text[0] = szText;
            subitems.Text[1] = EMPTY_STRING;

            StringCchPrintf(szText, PRINTF_BUFFER_LENGTH, TEXT("0x%p"), sii.TransferAddress);
            supTreeListAddItem(
                Context->TreeList,
                tviRoot,
                TVIF_TEXT | TVIF_STATE,
                (UINT)0,
                (UINT)0,
                TEXT("TransferAddress"),
                &subitems);

            SectionDumpUlong(Context->TreeList, tviRoot,
                sii.ZeroBits, TEXT("ZeroBits"), NULL, UlongDump);

            StringCchPrintf(szText, PRINTF_BUFFER_LENGTH, TEXT("0x%I64X"), sii.MaximumStackSize);
            supTreeListAddItem(
                Context->TreeList,
                tviRoot,
                TVIF_TEXT | TVIF_STATE,
                (UINT)0,
                (UINT)0,
                TEXT("MaximumStackSize"),
                &subitems);

            StringCchPrintf(szText, PRINTF_BUFFER_LENGTH, TEXT("0x%I64X"), sii.CommittedStackSize);
            supTreeListAddItem(
                Context->TreeList,
                tviRoot,
                TVIF_TEXT | TVIF_STATE,
                (UINT)0,
                (UINT)0,
                TEXT("CommittedStackSize"),
                &subitems);

            switch (sii.SubSystemType) {
            case IMAGE_SUBSYSTEM_NATIVE:
                lpDesc = TEXT("Native");
                break;
            case IMAGE_SUBSYSTEM_WINDOWS_GUI:
                lpDesc = TEXT("Windows GUI");
                break;
            case IMAGE_SUBSYSTEM_WINDOWS_CUI:
                lpDesc = TEXT("Windows Console");
                break;
            case IMAGE_SUBSYSTEM_OS2_CUI:
                lpDesc = TEXT("OS/2 Console");
                break;
            case IMAGE_SUBSYSTEM_POSIX_CUI:
                lpDesc = TEXT("Posix Console");
                break;
            case IMAGE_SUBSYSTEM_XBOX:
                lpDesc = TEXT("XBox");
                break;
            case IMAGE_SUBSYSTEM_EFI_APPLICATION:
                lpDesc = TEXT("EFI Application");
                break;
            case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
                lpDesc = TEXT("EFI Boot Service Driver");
                break;
            case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
                lpDesc = TEXT("EFI Runtime Driver");
                break;
            case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
                lpDesc = TEXT("Windows Boot Application");
                break;
            case IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG:
                lpDesc = TEXT("XBox Code Catalog");
                break;
            default:
                lpDesc = TEXT("Unknown");
                break;
            }

            SectionDumpUlong(Context->TreeList, tviRoot,
                sii.SubSystemType, TEXT("SubSystemType"), lpDesc, UlongDump);

            StringCchPrintf(
                szText,
                PRINTF_BUFFER_LENGTH,
                TEXT("%hu.%hu"),
                sii.SubSystemMajorVersion,
                sii.SubSystemMinorVersion);

            SectionDumpUlong(Context->TreeList, tviRoot,
                sii.SubSystemVersion, TEXT("SubSystemType"), szText, UlongDump);

            StringCchPrintf(
                szText,
                PRINTF_BUFFER_LENGTH,
                TEXT("%hu.%hu"),
                sii.MajorOperatingSystemVersion,
                sii.MinorOperatingSystemVersion);

            SectionDumpUlong(Context->TreeList, tviRoot,
                sii.OperatingSystemVersion, TEXT("OperatingSystemVersion"), szText, UlongDump);

            SectionDumpFlags(Context->TreeList, tviRoot,
                sii.ImageCharacteristics,
                PEImageFileChars,
                RTL_NUMBER_OF(PEImageFileChars),
                TEXT("ImageCharacteristics"),
                UShortDump);

            SectionDumpFlags(Context->TreeList, tviRoot,
                sii.DllCharacteristics,
                PEDllChars,
                RTL_NUMBER_OF(PEDllChars),
                TEXT("DllCharacteristics"),
                UShortDump);

            switch (sii.Machine) {
            case IMAGE_FILE_MACHINE_I386:
                lpDesc = TEXT("Intel386");
                break;
            case IMAGE_FILE_MACHINE_AMD64:
                lpDesc = TEXT("AMD64");
                break;
            default:
                lpDesc = TEXT("Unknown/Unsupported Machine");
                break;
            }

            SectionDumpUlong(Context->TreeList, tviRoot,
                sii.Machine, TEXT("Machine"), lpDesc, UShortDump);

            SectionDumpUlong(Context->TreeList, tviRoot,
                (ULONG)sii.ImageContainsCode, TEXT("ImageContainsCode"), NULL, BooleanDump);

            SectionDumpUlong(Context->TreeList, tviRoot,
                (ULONG)sii.ImageFlags, TEXT("ImageFlags"), NULL, UCharDump);

            SectionDumpUlong(Context->TreeList, tviRoot,
                sii.LoaderFlags, TEXT("LoaderFlags"), NULL, UlongDump);

            SectionDumpUlong(Context->TreeList, tviRoot,
                sii.ImageFileSize, TEXT("ImageFileSize"), NULL, UlongDump);

            SectionDumpUlong(Context->TreeList, tviRoot,
                sii.CheckSum, TEXT("CheckSum"), NULL, UlongDump);

        }

        SectionDumpImageFileName(Context);

        if (bInternalPresent == FALSE)
            __leave;

        tviRoot = supTreeListAddItem(
            Context->TreeList,
            NULL,
            TVIF_TEXT | TVIF_STATE,
            (UINT)TVIS_EXPANDED,
            (UINT)TVIS_EXPANDED,
            TEXT("SECTION_INTERNAL_IMAGE_INFORMATION"),
            NULL);

        if (tviRoot) {

            SectionDumpUlong(Context->TreeList, tviRoot,
                sii2.ExtendedFlags, TEXT("ExtendedFlags"), NULL, UlongDump);

        }

    }
    __finally {
        if (sectionHandle)
            NtClose(sectionHandle);

        if (!NT_SUCCESS(ntStatus)) {
            StringCchPrintf(szText,
                _countof(szText),
                TEXT("Query status 0x%lx"), ntStatus);
        }
        else {
            _strcpy(szText, TEXT("Query - OK"));
        }

        supStatusBarSetText(
            Context->StatusBar,
            0,
            szText);
    }
}

/*
* VsInfoStringsEnumCallback
*
* Purpose:
*
* VERSION_INFO enumeration callback.
*
*/
BOOL CALLBACK VsInfoStringsEnumCallback(
    _In_ PWCHAR key,
    _In_ PWCHAR value,
    _In_ PWCHAR langid,
    _In_opt_ LPVOID cbparam
)
{
    LV_ITEM lvItem;
    INT itemIndex;
    HWND hwndList = (HWND)cbparam;
    WCHAR szLangId[128];

    if (hwndList == 0)
        return 0;

    RtlSecureZeroMemory(&lvItem, sizeof(lvItem));
    lvItem.mask = LVIF_TEXT;
    lvItem.pszText = key;
    lvItem.iItem = MAXINT;
    itemIndex = ListView_InsertItem(hwndList, &lvItem);

    lvItem.iSubItem = 1;
    lvItem.pszText = value;
    lvItem.iItem = itemIndex;
    ListView_SetItem(hwndList, &lvItem);

    szLangId[0] = 0;
    StringCchPrintf(szLangId, _countof(szLangId), TEXT("0x%ws"), langid);

    lvItem.iSubItem = 2;
    lvItem.pszText = szLangId;
    lvItem.iItem = itemIndex;
    ListView_SetItem(hwndList, &lvItem);

    return TRUE;//continue enum
}

/*
* VsInfoTabOnInit
*
* Purpose:
*
* Initialize VersionInfo tab dialog page.
*
*/
VOID VsInfoTabOnInit(
    _In_ HWND hWndDlg,
    _In_ GUI_CONTEXT* Context
)
{
    WCHAR szText[100];
    HWND hwndList = GetDlgItem(hWndDlg, IDC_LIST);

    supAddListViewColumn(hwndList,
        0,
        0,
        0,
        I_IMAGENONE,
        LVCFMT_LEFT,
        TEXT("Name"),
        120,
        Context->CurrentDPI);

    supAddListViewColumn(hwndList,
        1,
        1,
        1,
        I_IMAGENONE,
        LVCFMT_LEFT,
        TEXT("Value"),
        300,
        Context->CurrentDPI);

    supAddListViewColumn(hwndList,
        2,
        2,
        2,
        I_IMAGENONE,
        LVCFMT_LEFT,
        TEXT("LangId"),
        100,
        Context->CurrentDPI);

    ListView_SetExtendedListViewStyle(hwndList,
        LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP | LVS_EX_DOUBLEBUFFER);

    SetWindowTheme(hwndList, TEXT("Explorer"), NULL);

    if (PEImageEnumVersionFields(
        Context->SectionAddress,
        &VsInfoStringsEnumCallback,
        NULL,
        (LPVOID)hwndList))
    {
        StringCchCopy(szText, _countof(szText), TEXT("Query - OK"));
    }
    else {
        StringCchPrintf(
            szText,
            _countof(szText),
            TEXT("Query Error 0x%lx"), GetLastError());
    }

    supStatusBarSetText(
        Context->StatusBar,
        0,
        szText);
}

/*
* SectionTabOnInit
*
* Purpose:
*
* Initialize Section tab dialog page.
*
*/
VOID SectionTabOnInit(
    _In_ HWND hWndDlg,
    _In_ GUI_CONTEXT* Context
)
{
    RECT rc;
    HWND hwndList;
    HDITEM hdritem;

    GetClientRect(hWndDlg, &rc);
    hwndList = CreateWindowEx(WS_EX_STATICEDGE, WC_TREELIST, NULL,
        WS_VISIBLE | WS_CHILD | WS_TABSTOP | TLSTYLE_COLAUTOEXPAND | TLSTYLE_LINKLINES,
        0, 0,
        rc.right, rc.bottom,
        hWndDlg, NULL, NULL, NULL);

    if (hwndList) {

        RtlSecureZeroMemory(&hdritem, sizeof(hdritem));
        hdritem.mask = HDI_FORMAT | HDI_TEXT | HDI_WIDTH;
        hdritem.fmt = HDF_LEFT | HDF_BITMAP_ON_RIGHT | HDF_STRING;
        hdritem.cxy = ScaleDPI(220, Context->CurrentDPI);
        hdritem.pszText = TEXT("Field");
        TreeList_InsertHeaderItem(hwndList, 0, &hdritem);
        hdritem.cxy = ScaleDPI(130, Context->CurrentDPI);
        hdritem.pszText = TEXT("Value");
        TreeList_InsertHeaderItem(hwndList, 1, &hdritem);
        hdritem.cxy = ScaleDPI(210, Context->CurrentDPI);
        hdritem.pszText = TEXT("Additional Information");
        TreeList_InsertHeaderItem(hwndList, 2, &hdritem);

        Context->TreeList = hwndList;
        SectionDumpStructs(Context);
    }

}

/*
* StringsTabOnShow
*
* Purpose:
*
* Strings page WM_SHOWWINDOW handler.
*
*/
#pragma warning(push)
#pragma warning(disable: 6262)
VOID StringsTabOnShow(
    _In_ HWND hWndDlg,
    _In_ GUI_CONTEXT* Context
)
{
    INT nLength, iItem;
    UINT cUnicode = 0, cAnsi = 0;
    PVOID heapHandle = NULL;
    HWND hwndList = GetDlgItem(hWndDlg, IDC_LIST);
    PSTRING_PTR chain;
    WCHAR szBuffer[UNICODE_STRING_MAX_CHARS];
    LV_ITEM lvItem;

    __try {

        supSetWaitCursor(TRUE);
        ShowWindow(hwndList, SW_HIDE);

        heapHandle = HeapCreate(0, UNICODE_STRING_MAX_CHARS * sizeof(WCHAR), 0);
        if (heapHandle == NULL)
            __leave;

        chain = EnumImageStringsA(
            heapHandle,
            Context->SectionAddress,
            (ULONG)Context->SectionViewSize);

        while (chain) {

            nLength = MultiByteToWideChar(CP_ACP, 0,
                (PCHAR)RtlOffsetToPointer(Context->SectionAddress, chain->ofpstr),
                chain->length,
                szBuffer,
                UNICODE_STRING_MAX_CHARS);

            if (nLength) {

                szBuffer[nLength] = 0;

                lvItem.mask = LVIF_TEXT;
                lvItem.pszText = szBuffer;
                lvItem.iItem = INT_MAX;
                lvItem.iSubItem = 0;
                iItem = ListView_InsertItem(hwndList, &lvItem);

                lvItem.pszText = TEXT("A");
                lvItem.iSubItem = 1;
                lvItem.iItem = iItem;
                ListView_SetItem(hwndList, &lvItem);
                cAnsi++;
            }

            chain = chain->pnext;
        }

        chain = EnumImageStringsW(
            heapHandle,
            Context->SectionAddress,
            (ULONG)Context->SectionViewSize);

        while (chain) {

            _strncpy(szBuffer,
                UNICODE_STRING_MAX_CHARS,
                (PWCHAR)RtlOffsetToPointer(Context->SectionAddress, chain->ofpstr),
                chain->length);

            lvItem.mask = LVIF_TEXT;
            lvItem.pszText = szBuffer;
            lvItem.iItem = INT_MAX;
            lvItem.iSubItem = 0;
            iItem = ListView_InsertItem(hwndList, &lvItem);

            lvItem.pszText = TEXT("U");
            lvItem.iSubItem = 1;
            lvItem.iItem = iItem;
            ListView_SetItem(hwndList, &lvItem);

            cUnicode++;
            chain = chain->pnext;
        }

    }
    __finally {
        supSetWaitCursor(FALSE);
        ShowWindow(hwndList, SW_SHOW);
        if (heapHandle)
            RtlDestroyHeap(heapHandle);

        StringCchPrintf(
            szBuffer,
            _countof(szBuffer),
            TEXT("Strings: %ld (A: %lu, U: %lu)"),
            ListView_GetItemCount(hwndList),
            cAnsi, cUnicode);

        supStatusBarSetText(
            Context->StatusBar,
            0,
            szBuffer);
    }
}
#pragma warning(pop)

/*
* StringsTabOnInit
*
* Purpose:
*
* Initialize Strings tab page dialog.
*
*/
VOID StringsTabOnInit(
    _In_ HWND hWndDlg,
    _In_ GUI_CONTEXT* Context
)
{
    HWND hwndList = GetDlgItem(hWndDlg, IDC_LIST);

    if (hwndList) {

        supAddListViewColumn(hwndList,
            0,
            0,
            0,
            I_IMAGENONE,
            LVCFMT_LEFT,
            TEXT("Printable strings"),
            MAX_PATH,
            Context->CurrentDPI);

        supAddListViewColumn(hwndList,
            1,
            1,
            1,
            I_IMAGENONE,
            LVCFMT_CENTER,
            TEXT("Type"),
            80,
            Context->CurrentDPI);

        ListView_SetExtendedListViewStyle(hwndList, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
        SetWindowTheme(hwndList, TEXT("Explorer"), NULL);
    }
}

/*
* TabOnInit
*
* Purpose:
*
* Tab window WM_INITDIALOG handler.
*
*/
VOID TabOnInit(
    _In_ HWND hWndDlg,
    _In_ GUI_CONTEXT* Context
)
{
    INT iSel;

    if (Context == NULL)
        return;

    iSel = TabCtrl_GetCurSel(Context->TabHeader->hwndTab);

    switch (iSel) {

    case TabIdSection:
        SectionTabOnInit(hWndDlg, Context);
        break;
    case TabIdVSInfo:
        VsInfoTabOnInit(hWndDlg, Context);
        break;
    case TabIdStrings:
        StringsTabOnInit(hWndDlg, Context);
        break;
    default:
        break;
    }
}

/*
* TabOnShow
*
* Purpose:
*
* Tab window WM_SHOWWINDOW handler.
*
*/
INT_PTR TabOnShow(
    _In_ HWND hWndDlg,
    _In_ BOOL fShow
)
{
    INT iSel;
    GUI_CONTEXT* Context = GetProp(hWndDlg, T_IMS_PROP);

    if (Context == NULL)
        return 0;

    iSel = TabCtrl_GetCurSel(Context->TabHeader->hwndTab);

    switch (iSel) {

    case TabIdStrings:
        if (fShow)
            StringsTabOnShow(hWndDlg, Context);
        break;
    default:
        break;
    }

    return 1;
}

/*
* TabsOnContextMenu
*
* Purpose:
*
* Tab control WM_CONTEXTMENU handler.
*
*/
VOID TabsOnContextMenu(
    _In_ HWND hWndDlg
)
{
    INT iSel;
    POINT pt1;
    HMENU hMenu;
    GUI_CONTEXT* Context = GetProp(hWndDlg, T_IMS_PROP);

    if (Context == NULL)
        return;

    iSel = TabCtrl_GetCurSel(Context->TabHeader->hwndTab);

    switch (iSel) {
    case TabIdVSInfo:
    case TabIdStrings:
        if (GetCursorPos(&pt1)) {
            hMenu = CreatePopupMenu();
            if (hMenu) {
                InsertMenu(hMenu, 0, MF_BYCOMMAND, ID_MENU_LIST_DUMP, T_EXPORTTOFILE);
                TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, pt1.x, pt1.y, 0, hWndDlg, NULL);
                DestroyMenu(hMenu);
            }
        }
        break;
    default:
        break;
    }
}

VOID TabsDumpList(
    _In_ HWND hWndDlg
)
{
    INT iSel, iColumns;
    LPWSTR lpFileName;
    GUI_CONTEXT* Context = GetProp(hWndDlg, T_IMS_PROP);
    HWND hwndList = GetDlgItem(hWndDlg, IDC_LIST);

    iSel = TabCtrl_GetCurSel(Context->TabHeader->hwndTab);

    switch (iSel) {
    case TabIdVSInfo:
        lpFileName = TEXT("VersionInfo.csv");
        iColumns = 2;
        break;
    case TabIdStrings:
        lpFileName = TEXT("Strings.csv");
        iColumns = 1;
        break;
    default:
        return;
    }

    supListViewExportToFile(lpFileName, hWndDlg, hwndList, iColumns);
}

/*
* TabsWndProc
*
* Purpose:
*
* Tab control window handler.
*
*/
INT_PTR CALLBACK TabsWndProc(
    _In_ HWND hWnd,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    switch (uMsg) {

    case WM_INITDIALOG:
        SetProp(hWnd, T_IMS_PROP, (HANDLE)lParam);
        TabOnInit(hWnd, (GUI_CONTEXT*)lParam);
        break;

    case WM_COMMAND:

        switch (GET_WM_COMMAND_ID(wParam, lParam)) {
        case ID_MENU_LIST_DUMP:
            TabsDumpList(hWnd);
            break;
        default:
            break;
        }

        break;

    case WM_CONTEXTMENU:
        TabsOnContextMenu(hWnd);
        break;

    case WM_SHOWWINDOW:
        return TabOnShow(hWnd, (wParam != 0));

    case WM_DESTROY:
        RemoveProp(hWnd, T_IMS_PROP);
        break;

    default:
        return 0;
    }

    return 1;
}

/*
* OnTabResize
*
* Purpose:
*
* Tab window WM_RESIZE handler.
*
*/
VOID CALLBACK OnTabResize(
    _In_ TABHDR* TabHeader
)
{
    RECT hwndRect;
    INT iSel;
    HWND hwndList = 0;
    GUI_CONTEXT* Context;

    iSel = TabCtrl_GetCurSel(TabHeader->hwndTab);
    GetClientRect(TabHeader->hwndDisplay, &hwndRect);

    switch (iSel) {

    case TabIdSection:
        Context = (GUI_CONTEXT*)GetProp(TabHeader->hwndDisplay, T_IMS_PROP);
        if (Context) {
            hwndList = Context->TreeList;
        }
        break;

    case TabIdVSInfo:
    case TabIdStrings:
        hwndList = GetDlgItem(TabHeader->hwndDisplay, IDC_LIST);
        break;

    default:
        return;
    }

    if (hwndList) SetWindowPos(hwndList,
        0,
        0,
        0,
        hwndRect.right,
        hwndRect.bottom,
        SWP_NOOWNERZORDER);
}

/*
* OnTabSelChange
*
* Purpose:
*
* Tab window selection change callback.
*
*/
VOID CALLBACK OnTabSelChange(
    _In_ TABHDR* TabHeader,
    _In_ INT SelectedTab
)
{
    UNREFERENCED_PARAMETER(SelectedTab);

    //destroy previous window
    if (TabHeader->hwndDisplay != NULL)
        DestroyWindow(TabHeader->hwndDisplay);
}

/*
* OnResize
*
* Purpose:
*
* WM_SIZE handler.
*
*/
VOID OnResize(
    _In_ HWND hWnd
)
{
    GUI_CONTEXT* Context;
    RECT r, szr;

    Context = (GUI_CONTEXT*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    if (Context) {

        SendMessage(Context->StatusBar, WM_SIZE, 0, 0);
        RedrawWindow(Context->StatusBar, NULL, 0, RDW_ERASE | RDW_INVALIDATE | RDW_ERASENOW);

        GetClientRect(hWnd, &r);
        GetClientRect(Context->StatusBar, &szr);

        //resize of the tab control
        if (Context->TabHeader != NULL) {

            SetWindowPos(Context->TabHeader->hwndTab, HWND_TOP,
                0, 0, r.right, r.bottom - szr.bottom, 0);

            TabResizeTabWindow(Context->TabHeader);

            UpdateWindow(Context->TabHeader->hwndDisplay);

        }
    }
}

/*
* OnNotify
*
* Purpose:
*
* WM_NOTIFY handler.
*
*/
VOID OnNotify(
    _In_ HWND hWnd,
    _In_ LPNMHDR nmhdr
)
{
    GUI_CONTEXT* Context;

    if (g_PluginQuit)
        return;

    Context = (GUI_CONTEXT*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    if (Context) {
        TabOnChangeTab(Context->TabHeader, nmhdr);
    }
}

VOID OnGetMinMax(
    _In_ HWND hWnd,
    _In_ PMINMAXINFO mmInfo
)
{
    GUI_CONTEXT* Context;
    Context = (GUI_CONTEXT*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    if (Context) {
        mmInfo->ptMinTrackSize.x = ScaleDPI(640, Context->CurrentDPI);
        mmInfo->ptMinTrackSize.y = ScaleDPI(480, Context->CurrentDPI);
    }
}

/*
* MainWindowProc
*
* Purpose:
*
* Main window procedure.
*
*/
LRESULT CALLBACK MainWindowProc(
    _In_ HWND hWnd,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    switch (uMsg) {

    case WM_CLOSE:
        PostQuitMessage(0);
        break;

    case WM_SIZE:
        OnResize(hWnd);
        break;

    case WM_NOTIFY:
        OnNotify(hWnd, (LPNMHDR)lParam);
        break;

    case WM_GETMINMAXINFO:
        if (lParam) {
            OnGetMinMax(hWnd, (PMINMAXINFO)lParam);
        }
        break;

    default:
        break;
    }

    return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

/*
* RunUI
*
* Purpose:
*
* Create main window, run message loop.
*
*/
BOOL RunUI(
    _In_ GUI_CONTEXT* Context
)
{
    INT i;
    INITCOMMONCONTROLSEX icex;

    BOOL rv, mAlloc = FALSE;
    MSG msg1;
    SIZE_T sz;
    LPWSTR lpTitle;
    WCHAR szClassName[100];

    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES | ICC_BAR_CLASSES | ICC_TAB_CLASSES;
    InitCommonControlsEx(&icex);

#pragma warning(push)
#pragma warning(disable: 6031)
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
#pragma warning(pop)

    Context->CurrentDPI = Context->ParamBlock.CurrentDPI;

    //
    // Window class once.
    //
    StringCchPrintf(szClassName,
        RTL_NUMBER_OF(szClassName),
        TEXT("%wsWndClass"),
        g_Plugin->Name);

    sz = (MAX_PATH +
        _strlen(Context->ParamBlock.Object.ObjectDirectory) +
        _strlen(Context->ParamBlock.Object.ObjectName)) * sizeof(WCHAR);

    lpTitle = supHeapAlloc(sz);
    if (lpTitle) {

        StringCchPrintf(lpTitle,
            sz / sizeof(WCHAR),
            TEXT("Viewing :: %ws\\%ws"),
            Context->ParamBlock.Object.ObjectDirectory,
            Context->ParamBlock.Object.ObjectName);

        mAlloc = TRUE;
    }
    else
        lpTitle = IMAGESCOPE_WNDTITLE;

    //
    // Create main window.
    //
    Context->MainWindow = CreateWindowEx(
        0,
        szClassName,
        lpTitle,
        WS_VISIBLE | WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        ScaleDPI(640, Context->CurrentDPI),
        ScaleDPI(480, Context->CurrentDPI),
        NULL,
        NULL,
        g_ThisDLL,
        NULL);

    if (mAlloc)
        supHeapFree(lpTitle);

    if (Context->MainWindow == 0) {
        kdDebugPrint("Could not create main window, err = %lu\r\n", GetLastError());
        return FALSE;
    }

    SetWindowLongPtr(Context->MainWindow, GWLP_USERDATA, (LONG_PTR)Context);

    //
    // Status Bar window.
    //
    Context->StatusBar = CreateWindowEx(
        0,
        STATUSCLASSNAME,
        NULL,
        WS_VISIBLE | WS_CHILD,
        0,
        0,
        0,
        0,
        Context->MainWindow,
        NULL,
        g_ThisDLL,
        NULL);

    if (Context->StatusBar == 0) {
        kdDebugPrint("Could not create statusbar window, err = %lu\r\n", GetLastError());
        return FALSE;
    }

    Context->TabHeader = TabCreateControl(
        g_ThisDLL,
        Context->MainWindow,
        NULL,
        (TABSELCHANGECALLBACK)&OnTabSelChange,
        (TABRESIZECALLBACK)&OnTabResize,
        (TABCALLBACK_ALLOCMEM)&supHeapAlloc,
        (TABCALLBACK_FREEMEM)&supHeapFree);

    if (Context->TabHeader == NULL) {
        kdDebugPrint("Could not create tabcontrol window\r\n");
        return FALSE;
    }

    for (i = 0; i < _countof(ImsTabs); i++) {

        TabAddPage(Context->TabHeader,
            ImsTabs[i].ResourceId,
            ImsTabs[i].WndProc,
            ImsTabs[i].TabCaption,
            I_IMAGENONE,
            (LPARAM)Context);

    }

    TabOnSelChanged(Context->TabHeader);

    //call resize
    SendMessage(Context->MainWindow, WM_SIZE, 0, 0);

    do {
        rv = GetMessage(&msg1, NULL, 0, 0);

        if (rv == -1)
            break;

        TranslateMessage(&msg1);
        DispatchMessage(&msg1);

    } while ((rv != 0) && (g_PluginQuit == FALSE));

    DestroyWindow(Context->MainWindow);

    return TRUE;
}
