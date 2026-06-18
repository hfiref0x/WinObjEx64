/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2026
*
*  TITLE:       PROPOBJECTDUMP.C
*
*  VERSION:     2.11
*
*  DATE:        15 Jun 2026
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "treelist/treelist.h"
#include "propTypeConsts.h"
#include "propObjectDumpConsts.h"

typedef struct _OBJECT_DUMP_DLG_CONTEXT {
    HWND TreeList;
    INT tlSubItemHit;
} OBJECT_DUMP_DLG_CONTEXT, * POBJECT_DUMP_DLG_CONTEXT;

typedef VOID(NTAPI* pfnObDumpRoutine)(
    _In_ PROP_OBJECT_INFO* Context,
    _In_ HWND hwndDlg,
    _In_ HWND hwndTreeList);

#define PROP_OBJECT_DUMP_ROUTINE(n) VOID n(   \
    _In_ PROP_OBJECT_INFO* Context,           \
    _In_ HWND hwndDlg,                        \
    _In_ HWND hwndTreeList)

/*
* propObGetTypeDescForValue
*
* Purpose:
*
* Helper routine to find an appropriate text representation of value.
*
*/
LPWSTR propObGetTypeDescForValue(
    _In_ PVALUE_DESC pFlagsTable,
    _In_ ULONG ulFlagsTableCount,
    _In_ ULONG ulCheckedValue)
{
    ULONG i;

    for (i = 0; i < ulFlagsTableCount; i++) {
        if (pFlagsTable[i].dwValue == ulCheckedValue)
            return pFlagsTable[i].lpDescription;

    }
    return NULL;
}

/*
* propObFormatAddress64OrNull
*
* Purpose:
*
* Helper routine to format 64 bit address value.
*
*/
_When_(Address != NULL, _Ret_z_)
LPWSTR propObFormatAddress64OrNull(
    _In_opt_ PVOID Address,
    _Inout_ LPWSTR Buffer
)
{
    if (Address == NULL || Buffer == NULL) {
        return T_NULL;
    }

    Buffer[0] = L'0';
    Buffer[1] = L'x';
    Buffer[2] = UNICODE_NULL;

    u64tohex((ULONG_PTR)Address, &Buffer[2]);

    return Buffer;
}

/*
* propObSetSubitemColors
*
* Purpose:
*
* Helper routine to set subitems color flags and background color.
*
*/
VOID propObSetSubitemColors(
    _Inout_ TL_SUBITEMS_FIXED* SubItems,
    _In_ COLORREF BgColor,
    _In_ COLORREF FontColor
)
{
    if (BgColor != 0) {
        SubItems->ColorFlags |= TLF_BGCOLOR_SET;
        SubItems->BgColor = BgColor;
    }

    if (FontColor != 0) {
        SubItems->ColorFlags |= TLF_FONTCOLOR_SET;
        SubItems->FontColor = FontColor;
    }
}

/*
* propDumpEnumWithNames
*
* Purpose:
*
* Dump given enumeration to the treelist (simple output).
*
*/
VOID propDumpEnumWithNames(
    _In_ HWND TreeList,
    _In_ HTREEITEM ParentItem,
    _In_ LPWSTR EnumName,
    _In_ ULONG EnumValue,
    _In_ PVALUE_DESC EnumNames,
    _In_ ULONG EnumNamesCount
)
{
    ULONG i, mask;
    HTREEITEM treeItem, treeItemLast = NULL;
    TVITEMEX itemex;
    TL_SUBITEMS_FIXED subitems;
    WCHAR szValue[MAX_PATH + 1];

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    szValue[0] = TEXT('0');
    szValue[1] = TEXT('x');
    ultohex(EnumValue, &szValue[2]);
    subitems.Text[0] = szValue;
    subitems.Count = 1;

    treeItem = supTreeListAddItem(
        TreeList,
        ParentItem,
        TVIF_TEXT | TVIF_STATE,
        (UINT)0,
        (UINT)0,
        (LPWSTR)EnumName,
        &subitems);

    if (treeItem) {
        treeItemLast = NULL;
        mask = EnumValue;

        for (i = 0; i < EnumNamesCount; i++) {
            if (mask & EnumNames->dwValue) {
                RtlSecureZeroMemory(&subitems, sizeof(subitems));
                RtlSecureZeroMemory(&szValue, sizeof(szValue));
                szValue[0] = TEXT('0');
                szValue[1] = TEXT('x');
                ultohex(EnumNames->dwValue, &szValue[2]);
                subitems.Text[0] = szValue;
                subitems.Text[1] = EnumNames->lpDescription;
                subitems.Count = 2;

                treeItemLast = supTreeListAddItem(
                    TreeList,
                    treeItem,
                    TVIF_TEXT | TVIF_STATE,
                    (UINT)0,
                    (UINT)0,
                    (LPWSTR)T_EmptyString,
                    &subitems);

                mask &= ~EnumNames->dwValue;
            }

            EnumNames++;
        }

        if (mask != 0) {
            RtlSecureZeroMemory(&subitems, sizeof(subitems));
            RtlSecureZeroMemory(&szValue, sizeof(szValue));
            szValue[0] = TEXT('0');
            szValue[1] = TEXT('x');
            ultohex(mask, &szValue[2]);
            subitems.Text[0] = szValue;
            subitems.Text[1] = TEXT("Unknown bits");
            subitems.Count = 2;

            treeItemLast = supTreeListAddItem(
                TreeList,
                treeItem,
                TVIF_TEXT | TVIF_STATE,
                (UINT)0,
                (UINT)0,
                (LPWSTR)T_EmptyString,
                &subitems);
        }
    }

    //
    // Output dotted corner.
    //
    if (treeItemLast) {
        RtlSecureZeroMemory(&itemex, sizeof(itemex));

        itemex.hItem = treeItemLast;
        itemex.mask = TVIF_TEXT | TVIF_HANDLE;
        itemex.pszText = T_EMPTY;

        TreeList_SetTreeItem(TreeList, &itemex, NULL);
    }
}

/*
* propObDumpGUID
*
* Purpose:
*
* Dump given GUID to the treelist.
*
*/
VOID propObDumpGUID(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_ GUID* Guid
)
{
    TL_SUBITEMS_FIXED  subitems;
    WCHAR              szValue[100];

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 2;

    RtlStringCchPrintfSecure(szValue,
        RTL_NUMBER_OF(szValue),
        TEXT("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}"),
        Guid->Data1, Guid->Data2, Guid->Data3,
        Guid->Data4[0],
        Guid->Data4[1],
        Guid->Data4[2],
        Guid->Data4[3],
        Guid->Data4[4],
        Guid->Data4[5],
        Guid->Data4[6],
        Guid->Data4[7]);

    subitems.Text[0] = szValue;
    subitems.Text[1] = T_GUID;

    supTreeListAddItem(
        TreeList,
        hParent,
        TVIF_TEXT | TVIF_STATE,
        0,
        0,
        lpszName,
        &subitems);
}

/*
* propObDumpAddress
*
* Purpose:
*
* Dump given Address to the treelist.
*
*/
HTREEITEM propObDumpAddress(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_opt_ LPWSTR lpszDesc, //additional text to be displayed
    _In_opt_ PVOID Address,
    _In_ COLORREF BgColor,
    _In_ COLORREF FontColor
)
{
    TL_SUBITEMS_FIXED subitems;
    WCHAR szValue[32];

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 2;

    szValue[0] = UNICODE_NULL;
    subitems.Text[0] = propObFormatAddress64OrNull(Address, szValue);

    if (lpszDesc) {
        propObSetSubitemColors(&subitems, BgColor, FontColor);
        subitems.Text[1] = lpszDesc;
    }
    else {
        subitems.Text[1] = T_EmptyString;
    }

    return supTreeListAddItem(
        TreeList,
        hParent,
        TVIF_TEXT | TVIF_STATE,
        0,
        0,
        lpszName,
        &subitems);
}

/*
* propObDumpAddressWithModuleEx
*
* Purpose:
*
* Dump given Address to the treelist with module check, add offset to output if required.
*
*/
VOID propObDumpAddressWithModuleEx(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR Name,
    _In_opt_ PVOID Address,
    _In_ PRTL_PROCESS_MODULES pModules,
    _In_opt_ PVOID SelfDriverBase,
    _In_ ULONG SelfDriverSize,
    _In_ BOOL AddOffset
)
{
    TL_SUBITEMS_FIXED subitems;
    WCHAR szValue[32], szOffset[64], szModuleName[MAX_PATH * 2];
    PRTL_PROCESS_MODULE_INFORMATION moduleEntry;
    ULONG_PTR offset;

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 2;
    subitems.Text[0] = T_NULL;
    subitems.Text[1] = T_EmptyString;

    if (Address != NULL) {

        RtlSecureZeroMemory(&szValue, sizeof(szValue));
        subitems.Text[0] = propObFormatAddress64OrNull(Address, szValue);

        RtlSecureZeroMemory(&szModuleName, sizeof(szModuleName));

        //if SelfDriverBase & SelfDriverSize present, look if Address routine points to current driver
        if (SelfDriverBase != NULL && SelfDriverSize) {
            if (!IN_REGION(Address, SelfDriverBase, SelfDriverSize)) {
                _strcpy(szModuleName, L"Hooked by ");
                subitems.ColorFlags = TLF_BGCOLOR_SET;
                subitems.BgColor = CLR_HOOK;
            }
        }

        moduleEntry = (PRTL_PROCESS_MODULE_INFORMATION)ntsupFindModuleNameByAddress(pModules,
            Address,
            _strend(szModuleName),
            MAX_PATH);

        if (NULL != moduleEntry) {
            if (AddOffset) {
                offset = (ULONG_PTR)Address - (ULONG_PTR)moduleEntry->ImageBase;
                RtlStringCchPrintfSecure(szOffset, RTL_NUMBER_OF(szOffset), L"+0x%lX", offset);
                _strcat(szModuleName, szOffset);
            }
            subitems.Text[1] = szModuleName;
        }
        else {
            //unknown address outside any visible modules, warn
            subitems.Text[1] = T_Unknown;
            subitems.ColorFlags = TLF_BGCOLOR_SET;
            subitems.BgColor = CLR_WARN;
        }
    }

    supTreeListAddItem(
        TreeList,
        hParent,
        TVIF_TEXT | TVIF_STATE,
        0,
        0,
        Name,
        &subitems);
}

#define propObDumpAddressWithModule(TreeList, hParent, Name, Address, pModules, SelfDriverBase, SelfDriverSize) \
    propObDumpAddressWithModuleEx(TreeList, hParent, Name, Address, pModules, SelfDriverBase, SelfDriverSize, FALSE)


/*
* propObDumpAddressWithModuleIfNotNull
*
* Purpose:
*
* Dump given Address to the treelist with module check, add offset to output if required.
*
*/
VOID propObDumpAddressWithModuleIfNotNull(
    _In_ HWND TreeList,
    _In_ HTREEITEM ParentItem,
    _In_ LPWSTR Name,
    _In_opt_ PVOID Address,
    _In_ PRTL_PROCESS_MODULES LoadedModules
)
{
    if (Address) {
        propObDumpAddressWithModule(TreeList,
            ParentItem,
            Name,
            Address,
            LoadedModules,
            NULL,
            0);
    }
}

/*
* propObDumpPushLock
*
* Purpose:
*
* Dump EX_PUSH_LOCK to the treelist.
*
*/
VOID propObDumpPushLock(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ PVOID PushLockPtr,
    _In_ COLORREF BgColor,
    _In_ COLORREF FontColor
)
{
    TL_SUBITEMS_FIXED   subitems;
    HTREEITEM treeItem;

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 2;
    subitems.Text[0] = T_EmptyString;
    subitems.Text[1] = T_EX_PUSH_LOCK;

    treeItem = supTreeListAddItem(
        TreeList,
        hParent,
        TVIF_TEXT | TVIF_STATE,
        0,
        0,
        TEXT("Lock"),
        &subitems);

    if (treeItem) {
        propObDumpAddress(TreeList, treeItem, TEXT("Ptr"), NULL, PushLockPtr, BgColor, FontColor);
    }
}

/*
* propObDumpByte
*
* Purpose:
*
* Dump BYTE to the treelist.
* Dump BOOL if IsBool set.
* You must handle BOOLEAN differently.
*
*/
VOID propObDumpByte(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_opt_ LPWSTR lpszDesc,
    _In_ BYTE Value,
    _In_ COLORREF BgColor,
    _In_ COLORREF FontColor,
    _In_ BOOL IsBool
)
{
    TL_SUBITEMS_FIXED subitems;
    WCHAR szValue[32];

    RtlSecureZeroMemory(&subitems, sizeof(subitems));

    subitems.Count = 1;
    if (lpszDesc != NULL) {
        subitems.Count = 2;
        subitems.Text[1] = lpszDesc;
    }

    RtlSecureZeroMemory(szValue, sizeof(szValue));
    if (IsBool) {
        _strcpy(szValue, (BOOL)(Value) ? L"TRUE" : L"FALSE");
    }
    else {

        RtlStringCchPrintfSecure(szValue,
            RTL_NUMBER_OF(szValue),
            FORMAT_HEXBYTE,
            Value);

    }

    subitems.Text[0] = szValue;
    propObSetSubitemColors(&subitems, BgColor, FontColor);

    supTreeListAddItem(
        TreeList,
        hParent,
        TVIF_TEXT | TVIF_STATE,
        0,
        0,
        lpszName,
        &subitems);
}

/*
* propObDumpSetString
*
* Purpose:
*
* Put string to the treelist.
*
*/
HTREEITEM propObDumpSetString(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_opt_ LPWSTR lpszDesc,
    _In_opt_ LPWSTR lpszValue,
    _In_ COLORREF BgColor,
    _In_ COLORREF FontColor
)
{
    TL_SUBITEMS_FIXED   subitems;

    RtlSecureZeroMemory(&subitems, sizeof(subitems));

    subitems.Count = 1;
    if (lpszValue) {
        subitems.Text[0] = lpszValue;
    }
    else {
        subitems.Text[0] = T_EmptyString;
    }

    if (lpszDesc != NULL) {
        subitems.Count = 2;
        subitems.Text[1] = lpszDesc;
    }

    propObSetSubitemColors(&subitems, BgColor, FontColor);

    return supTreeListAddItem(
        TreeList,
        hParent,
        TVIF_TEXT | TVIF_STATE,
        0,
        0,
        lpszName,
        &subitems);
}

/*
* propObDumpUlong
*
* Purpose:
*
* Dump ULONG 4 bytes / USHORT 2 bytes to the treelist.
*
*/
HTREEITEM propObDumpUlong(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPCWSTR lpszName,
    _In_opt_ LPCWSTR lpszDesc, //additional text to be displayed
    _In_ ULONG Value,
    _In_ BOOL HexDump,
    _In_ BOOL IsUShort,
    _In_ COLORREF BgColor,
    _In_ COLORREF FontColor
)
{
    TL_SUBITEMS_FIXED   subitems;
    WCHAR               szValue[32];

    RtlSecureZeroMemory(&szValue, sizeof(szValue));
    RtlSecureZeroMemory(&subitems, sizeof(subitems));

    if (lpszDesc != NULL) {
        subitems.Count = 2;
        subitems.Text[1] = (LPTSTR)lpszDesc;
    }
    else {
        subitems.Count = 1;
    }

    if (HexDump) {
        if (IsUShort) {

            RtlStringCchPrintfSecure(szValue,
                RTL_NUMBER_OF(szValue),
                FORMAT_HEXUSHORT,
                Value);

        }
        else {
            szValue[0] = L'0';
            szValue[1] = L'x';
            ultohex(Value, &szValue[2]);
        }
    }
    else {
        if (IsUShort) {

            RtlStringCchPrintfSecure(szValue,
                RTL_NUMBER_OF(szValue),
                FORMAT_USHORT,
                Value);

        }
        else {
            ultostr(Value, szValue);
        }
    }

    subitems.Text[0] = szValue;
    propObSetSubitemColors(&subitems, BgColor, FontColor);

    return supTreeListAddItem(
        TreeList,
        hParent,
        TVIF_TEXT | TVIF_STATE,
        0,
        0,
        (LPWSTR)lpszName,
        &subitems);
}

/*
* propObDumpLong
*
* Purpose:
*
* Dump LONG 4 bytes to the treelist.
*
*/
HTREEITEM propObDumpLong(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_opt_ LPWSTR lpszDesc, //additional text to be displayed
    _In_ LONG Value,
    _In_ BOOL HexDump,
    _In_ COLORREF BgColor,
    _In_ COLORREF FontColor
)
{
    TL_SUBITEMS_FIXED subitems;
    WCHAR szValue[32];

    RtlSecureZeroMemory(&szValue, sizeof(szValue));
    RtlSecureZeroMemory(&subitems, sizeof(subitems));

    if (lpszDesc != NULL) {
        subitems.Count = 2;
        subitems.Text[1] = lpszDesc;
    }
    else {
        subitems.Count = 1;
    }

    if (HexDump) {
        RtlStringCchPrintfSecure(szValue,
            RTL_NUMBER_OF(szValue),
            FORMAT_HEXLONG, Value);
    }
    else {

        itostr(Value, szValue);

    }

    subitems.Text[0] = szValue;
    propObSetSubitemColors(&subitems, BgColor, FontColor);

    return supTreeListAddItem(
        TreeList,
        hParent,
        TVIF_TEXT | TVIF_STATE,
        0,
        0,
        lpszName,
        &subitems);
}

/*
* propObDumpUlong64
*
* Purpose:
*
* Dump ULONG 8 byte to the treelist.
*
*/
VOID propObDumpUlong64(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_opt_ LPWSTR lpszDesc, //additional text to be displayed
    _In_ ULONG64 Value,
    _In_ BOOL OutAsHex,
    _In_ COLORREF BgColor,
    _In_ COLORREF FontColor
)
{
    TL_SUBITEMS_FIXED subitems;
    WCHAR szValue[32];

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 2;

    RtlSecureZeroMemory(&szValue, sizeof(szValue));

    if (OutAsHex) {
        szValue[0] = TEXT('0');
        szValue[1] = TEXT('x');
        u64tohex(Value, &szValue[2]);
    }
    else {
        u64tostr(Value, szValue);
    }
    subitems.Text[0] = szValue;

    if (lpszDesc) {
        propObSetSubitemColors(&subitems, BgColor, FontColor);
        subitems.Text[1] = lpszDesc;
    }
    else {
        subitems.Text[1] = T_EmptyString;
    }

    supTreeListAddItem(
        TreeList,
        hParent,
        TVIF_TEXT | TVIF_STATE,
        0,
        0,
        lpszName,
        &subitems);
}

/*
* propObDumpLong64
*
* Purpose:
*
* Dump LONG 8 byte to the treelist.
*
*/
VOID propObDumpLong64(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_opt_ LPWSTR lpszDesc, //additional text to be displayed
    _In_ LONG64 Value,
    _In_ BOOL OutAsHex,
    _In_ COLORREF BgColor,
    _In_ COLORREF FontColor
)
{
    TL_SUBITEMS_FIXED subitems;
    WCHAR szValue[32];

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 2;

    RtlSecureZeroMemory(&szValue, sizeof(szValue));

    if (OutAsHex) {
        szValue[0] = TEXT('0');
        szValue[1] = TEXT('x');
        u64tohex((ULONG64)Value, &szValue[2]);
    }
    else {
        i64tostr(Value, szValue);
    }
    subitems.Text[0] = szValue;

    if (lpszDesc) {
        propObSetSubitemColors(&subitems, BgColor, FontColor);
        subitems.Text[1] = lpszDesc;
    }
    else {
        subitems.Text[1] = T_EmptyString;
    }

    supTreeListAddItem(
        TreeList,
        hParent,
        TVIF_TEXT | TVIF_STATE,
        0,
        0,
        lpszName,
        &subitems);
}

/*
* propObAddHexValue
*
* Purpose:
*
* Add ULONG/ULONG64 value as hex to the treelist.
*
*/
HTREEITEM propObAddHexValue(
    _In_ HWND TreeList,
    _In_ HTREEITEM ParentItem,
    _In_ LPWSTR EntryName,
    _In_ ULONG64 Value,
    _In_ BOOL AsPointer
)
{
    WCHAR szValue[32];
    TL_SUBITEMS_FIXED subitems;

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 1;

    if (AsPointer && Value == 0) {
        subitems.Text[0] = T_NULL;
    }
    else {
        RtlSecureZeroMemory(&szValue, sizeof(szValue));
        szValue[0] = L'0';
        szValue[1] = L'x';

        if (Value > MAXULONG32) {
            u64tohex(Value, &szValue[2]);
        }
        else {
            if (AsPointer) {
                u64tohex(Value, &szValue[2]);
            }
            else {
                ultohex((ULONG)Value, &szValue[2]);
            }
        }
        subitems.Text[0] = szValue;
    }

    return supTreeListAddItem(
        TreeList,
        ParentItem,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        0,
        EntryName,
        &subitems);
}

/*
* propObDumpULargeInteger
*
* Purpose:
*
* Dump ULARGE_INTEGER members to the treelist.
*
*/
VOID propObDumpULargeInteger(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR ListEntryName,
    _In_opt_ PULARGE_INTEGER Value
)
{
    HTREEITEM treeItem;

    treeItem = supTreeListAddItem(
        TreeList,
        hParent,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        0,
        ListEntryName,
        NULL);

    if (treeItem && Value) {
        //add large integer entry item to treelist and exit if value is null
        propObAddHexValue(TreeList, treeItem, L"LowPart", Value->LowPart, FALSE);
        propObAddHexValue(TreeList, treeItem, L"HighPart", Value->HighPart, FALSE);
    }
}

/*
* propObDumpListEntry
*
* Purpose:
*
* Dump LIST_ENTRY members to the treelist.
*
*/
VOID propObDumpListEntry(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR ListEntryName,
    _In_opt_ PLIST_ENTRY ListEntry
)
{
    HTREEITEM         treeItem;
    TL_SUBITEMS_FIXED subitems;

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 2;
    subitems.Text[0] = T_EmptyString;
    subitems.Text[1] = T_LIST_ENTRY;

    treeItem = supTreeListAddItem(
        TreeList,
        hParent,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        0,
        ListEntryName,
        &subitems);

    if (treeItem && ListEntry) {
        //add list entry item to treelist and exit if listentry is null
        propObAddHexValue(TreeList, treeItem, L"Flink", (ULONG64)ListEntry->Flink, TRUE);
        propObAddHexValue(TreeList, treeItem, L"Blink", (ULONG64)ListEntry->Blink, TRUE);
    }
}

/*
* propObDumpUSHORT
*
* Purpose:
*
* Dump USHORT value to the treelist.
*
*/
VOID propObDumpUSHORT(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR Name,
    _In_ USHORT Value,
    _In_ BOOLEAN HexOutput
)
{
    LPCWSTR lpFormat;
    TL_SUBITEMS_FIXED subitems;
    WCHAR szValue[32];

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    RtlSecureZeroMemory(szValue, sizeof(szValue));

    lpFormat = (HexOutput) ? FORMAT_HEXUSHORT : FORMAT_USHORT;

    RtlStringCchPrintfSecure(szValue,
        RTL_NUMBER_OF(szValue),
        lpFormat,
        Value);

    subitems.Count = 2;
    subitems.Text[0] = szValue;
    subitems.Text[1] = T_EmptyString;

    supTreeListAddItem(
        TreeList,
        hParent,
        TVIF_TEXT | TVIF_STATE,
        0,
        0,
        Name,
        &subitems);
}

/*
* propObDumpUnicodeStringInternal
*
* Purpose:
*
* Dump UNICODE_STRING members to the treelist.
*
*/
VOID propObDumpUnicodeStringInternal(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR StringName,
    _In_opt_ PUNICODE_STRING String,
    _In_opt_ PVOID ReferenceBufferAddress,
    _In_ BOOLEAN IsKernelPointer
)
{
    BOOL bNormalized = FALSE;
    HTREEITEM treeItem;
    TL_SUBITEMS_FIXED subitems;
    WCHAR szValue[32];
    UNICODE_STRING displayString;

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 2;

    subitems.Text[0] = T_EmptyString;
    subitems.Text[1] = (IsKernelPointer) ? T_PUNICODE_STRING : T_UNICODE_STRING;

    //
    // Add root node.
    //
    treeItem = supTreeListAddItem(
        TreeList,
        hParent,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        0,
        StringName,
        &subitems);

    //
    // String points to nowhere, only root entry added.
    //
    if (String == NULL) {
        return;
    }

    if (treeItem) {

        //
        // UNICODE_STRING.Length
        //
        propObDumpUSHORT(TreeList,
            treeItem,
            T_LENGTH,
            String->Length,
            TRUE);

        //
        // UNICODE_STRING.MaximumLength
        //
        propObDumpUSHORT(TreeList,
            treeItem,
            T_MAXIMUMLENGTH,
            String->MaximumLength,
            TRUE);

        //
        // UNICODDE_STRING.Buffer
        //

        if (String->Buffer == NULL) {
            subitems.Text[0] = T_NULL;
            subitems.Text[1] = T_EmptyString;
        }
        else {

            RtlSecureZeroMemory(&szValue, sizeof(szValue));
            subitems.Text[0] = propObFormatAddress64OrNull(ReferenceBufferAddress, szValue);

            bNormalized = supNormalizeUnicodeStringForDisplay(g_obexHeap,
                String,
                &displayString);
            if (bNormalized)
            {
                subitems.Text[1] = displayString.Buffer;
            }
            else {
                subitems.Text[1] = String->Buffer;
            }

        }

        supTreeListAddItem(
            TreeList,
            treeItem,
            TVIF_TEXT | TVIF_STATE,
            0,
            0,
            T_BUFFER,
            &subitems);

    }

    if (bNormalized)
        supFreeDuplicatedUnicodeString(g_obexHeap, &displayString, FALSE);
}

/*
* propObDumpUnicodeString
*
* Purpose:
*
* Dump UNICODE_STRING members to the treelist.
*
*/
VOID propObDumpUnicodeString(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR StringName,
    _In_ PUNICODE_STRING InputString,
    _In_ BOOLEAN IsKernelPointer
)
{
    UNICODE_STRING dumpedString;
    PVOID pvRefAddr;
    BOOL bDumpOk;

    RtlInitEmptyUnicodeString(&dumpedString, NULL, 0);

    bDumpOk = kdDumpUnicodeString(InputString,
        &dumpedString,
        &pvRefAddr,
        IsKernelPointer);

    propObDumpUnicodeStringInternal(TreeList,
        hParent,
        StringName,
        &dumpedString,
        pvRefAddr,
        IsKernelPointer);

    if (bDumpOk)
        supHeapFree(dumpedString.Buffer);
}

/*
* propDumpBitFlags
*
* Purpose:
*
* Dump object bit flags as an array to the treelist.
*
*/
VOID propDumpBitFlags(
    _In_ HWND hwndTreeList,
    _In_ HTREEITEM h_tviRootItem,
    _In_ ULONG ulFlags,
    _In_ PVALUE_DESC pFlagsTable,
    _In_ ULONG ulFlagsTableCount,
    _In_ UINT uiState,
    _In_ LPCWSTR lpLabel
)
{
    WCHAR szValue1[32];
    TL_SUBITEMS_FIXED subitems;
    LPCWSTR lpType;
    ULONG i, j;

    RtlSecureZeroMemory(&szValue1, sizeof(szValue1));
    RtlSecureZeroMemory(&subitems, sizeof(subitems));

    if (ulFlags == 0) {
        //add named entry with zero data
        propObDumpUlong(hwndTreeList, h_tviRootItem, lpLabel, NULL, 0, TRUE, FALSE, 0, 0);
        return;
    }

    j = 0;
    for (i = 0; i < ulFlagsTableCount; i++) {
        if (ulFlags & pFlagsTable[i].dwValue) {
            lpType = pFlagsTable[i].lpDescription;
            subitems.Count = 2;

            if (j == 0) {
                //add first entry with flag description
                szValue1[0] = L'0';
                szValue1[1] = L'x';
                ultohex(ulFlags, &szValue1[2]);

                subitems.Text[0] = szValue1;
                subitems.Text[1] = (LPTSTR)lpType;
            }
            else {
                //add subentry
                subitems.Text[0] = T_EmptyString;
                subitems.Text[1] = (LPTSTR)lpType;
            }

            supTreeListAddItem(hwndTreeList,
                h_tviRootItem,
                TVIF_TEXT | TVIF_STATE,
                0,
                uiState,
                (j == 0) ? (LPWSTR)lpLabel : T_EmptyString,
                &subitems);

            ulFlags &= ~pFlagsTable[i].dwValue;
            j++;
        }
        if (ulFlags == 0)
            break;
    }
}

/*
* propDumpQueryFullNamespaceNormalizedPath
*
* Purpose:
*
* Query full namespace path for object with a normalization for output.
*
*/
_Success_(return)
BOOL propDumpQueryFullNamespaceNormalizedPath(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PUNICODE_STRING NormalizedPath
)
{
    BOOL bResult = FALSE;
    UNICODE_STRING objectName;

    if (ObQueryFullNamespacePath(ObjectAddress, &objectName)) {

        bResult = supNormalizeUnicodeStringForDisplay(g_obexHeap,
            &objectName, NormalizedPath);

        supFreeUnicodeString(g_obexHeap, &objectName);
    }

    return bResult;
}

/*
* propDumpObjectForAddress
*
* Purpose:
*
* Dump object name (if present) with full namespace path to the treelist.
*
*/
VOID propDumpObjectForAddress(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpObjectLiteral,
    _In_ PVOID pvObject,
    _In_ COLORREF crErrorBgColor,
    _In_ LPWSTR lpErrorLiteral
)
{
    BOOL bOkay = FALSE;
    COLORREF bgColor = 0;
    ULONG_PTR objectAddress = (ULONG_PTR)pvObject;
    LPWSTR lpName = NULL;

    UNICODE_STRING normalizedName;

    if (objectAddress) {

        bOkay = propDumpQueryFullNamespaceNormalizedPath(objectAddress, &normalizedName);
        if (bOkay) {
            lpName = normalizedName.Buffer;
        }
        else {
            lpName = lpErrorLiteral;
            bgColor = crErrorBgColor;
        }

    }

    propObDumpAddress(TreeList,
        hParent,
        lpObjectLiteral,
        lpName,
        pvObject,
        (COLORREF)bgColor,
        (COLORREF)0);

    if (bOkay)
        supFreeUnicodeString(g_obexHeap, &normalizedName);
}

/*
* propObDumpDispatcherHeader
*
* Purpose:
*
* Dump DISPATCHER_HEADER members to the treelist.
*
*/
VOID propObDumpDispatcherHeader(
    _In_ HWND TreeList,
    _In_ HTREEITEM ParentItem,
    _In_ DISPATCHER_HEADER * Header,
    _In_opt_ LPWSTR lpDescType,
    _In_opt_ LPWSTR lpDescSignalState,
    _In_opt_ LPWSTR lpDescSize
)
{
    HTREEITEM treeItem;

    treeItem = supTreeListAddItem(
        TreeList,
        ParentItem,
        TVIF_TEXT | TVIF_STATE,
        0,
        0,
        TEXT("Header"),
        NULL);

    if (treeItem) {
        //Header->Type
        propObDumpUlong(TreeList, treeItem, L"Type", lpDescType, Header->Type, TRUE, TRUE, 0, 0);
        //Header->Absolute
        propObDumpUlong(TreeList, treeItem, L"Absolute", NULL, Header->Absolute, TRUE, TRUE, 0, 0);
        //Header->Size
        propObDumpUlong(TreeList, treeItem, L"Size", lpDescSize, Header->Size, TRUE, TRUE, 0, 0);
        //Header->Inserted
        propObDumpByte(TreeList, treeItem, L"Inserted", NULL, Header->Inserted, 0, 0, TRUE);
        //Header->SignalState
        propObDumpUlong(TreeList, treeItem, L"SignalState", lpDescSignalState, Header->SignalState, TRUE, FALSE, 0, 0);
        //Header->WaitListHead
        propObDumpListEntry(TreeList, treeItem, L"WaitListHead", &Header->WaitListHead);
    }
}

/*
* propObDumpSqos
*
* Purpose:
*
* Dump SECURITY_QUALITY_OF_SERVICE to the treelist.
*
*/
VOID propObDumpSqos(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ SECURITY_QUALITY_OF_SERVICE * SecurityQos
)
{
    LPWSTR lpType;
    HTREEITEM treeItem;
    TL_SUBITEMS_FIXED subitems;

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 2;
    subitems.Text[0] = T_EmptyString;
    subitems.Text[1] = TEXT("SECURITY_QUALITY_OF_SERVICE");

    treeItem = supTreeListAddItem(
        TreeList,
        hParent,
        TVIF_TEXT,
        0,
        0,
        TEXT("SecurityQos"),
        &subitems);

    if (treeItem) {

        propObDumpUlong(
            TreeList,
            treeItem,
            TEXT("Length"),
            NULL,
            SecurityQos->Length,
            TRUE,
            FALSE,
            0,
            0);

        switch (SecurityQos->ImpersonationLevel) {
        case SecurityIdentification:
            lpType = TEXT("SecurityIdentification");
            break;
        case SecurityImpersonation:
            lpType = TEXT("SecurityImpersonation");
            break;
        case SecurityDelegation:
            lpType = TEXT("SecurityDelegation");
            break;
        case SecurityAnonymous:
            lpType = TEXT("SecurityAnonymous");
            break;
        default:
            lpType = T_UnknownType;
            break;
        }

        propObDumpUlong(
            TreeList,
            treeItem,
            TEXT("ImpersonationLevel"),
            lpType,
            SecurityQos->ImpersonationLevel,
            FALSE,
            FALSE,
            0,
            0);

        lpType = (SecurityQos->ContextTrackingMode) ? TEXT("SECURITY_DYNAMIC_TRACKING") : TEXT("SECURITY_STATIC_TRACKING");
        propObDumpByte(
            TreeList,
            treeItem,
            TEXT("ContextTrackingMode"),
            lpType,
            SecurityQos->ContextTrackingMode,
            0,
            0,
            TRUE);

        propObDumpByte(
            TreeList,
            treeItem,
            TEXT("EffectiveOnly"),
            NULL,
            SecurityQos->EffectiveOnly,
            0,
            0,
            TRUE);

    }
}

/*
* propObDumpDriverExtension
*
* Purpose:
*
* Dump DRIVER_EXTENSION members to the treelist.
*
*/
VOID propObDumpDriverExtension(
    _In_ HWND TreeList,
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDRIVER_EXTENSION DriverExtension,
    _In_ PRTL_PROCESS_MODULES ModulesList,
    _In_ PLDR_DATA_TABLE_ENTRY LoaderEntry
)
{
    union {
        union {
            DRIVER_EXTENSION* DriverExtensionCompatible;
            DRIVER_EXTENSION_V2* DriverExtensionV2;
            DRIVER_EXTENSION_V3* DriverExtensionV3;
            DRIVER_EXTENSION_V4* DriverExtensionV4;
        } Versions;
        PVOID Ref;
    } driverExtension;

    BOOL pathAllocated;
    ULONG objectSize = 0, objectVersion = 0;
    COLORREF bgColor;
    HTREEITEM treeItem;
    PDRIVER_OBJECT selfDriverObject;
    LPWSTR lpDesc;
    UNICODE_STRING normalizedPath;

    driverExtension.Ref = ObDumpDriverExtensionVersionAware((ULONG_PTR)DriverExtension,
        &objectSize,
        &objectVersion);

    if (driverExtension.Ref) {

        treeItem = supTreeListAddItem(
            TreeList,
            NULL,
            TVIF_TEXT | TVIF_STATE,
            TVIS_EXPANDED,
            0,
            TEXT("DRIVER_EXTENSION"),
            NULL);

        if (treeItem) {

            //
            // DRIVER_EXTENSION.DriverObject
            //
            bgColor = 0;
            lpDesc = NULL;
            pathAllocated = FALSE;

            //must be self-ref
            selfDriverObject = driverExtension.Versions.DriverExtensionCompatible->DriverObject;

            if ((ULONG_PTR)selfDriverObject != (ULONG_PTR)DriverObject) {
                lpDesc = T_BADDRIVEROBJECT;
                bgColor = CLR_WARN;
            }
            else {
                //find ref
                if (selfDriverObject != NULL) {

                    pathAllocated = propDumpQueryFullNamespaceNormalizedPath(
                        (ULONG_PTR)selfDriverObject, &normalizedPath);
                    if (pathAllocated) {
                        lpDesc = normalizedPath.Buffer;
                    }
                    else {
                        //sef-ref not found, notify, could be object outside directory so we don't know it name etc
                        lpDesc = T_REFNOTFOUND;
                        bgColor = CLR_INVL;
                    }

                }
            }

            propObDumpAddress(TreeList, treeItem, T_FIELD_DRIVER_OBJECT,
                lpDesc, selfDriverObject, bgColor, 0);

            if (pathAllocated)
                supFreeDuplicatedUnicodeString(g_obexHeap, &normalizedPath, FALSE);

            //AddDevice
            propObDumpAddressWithModule(TreeList,
                treeItem,
                TEXT("AddDevice"),
                driverExtension.Versions.DriverExtensionCompatible->AddDevice,
                ModulesList,
                LoaderEntry->DllBase,
                LoaderEntry->SizeOfImage);

            //Count
            propObDumpUlong(TreeList, treeItem, TEXT("Count"), NULL,
                driverExtension.Versions.DriverExtensionCompatible->Count, FALSE, FALSE, 0, 0);

            //ServiceKeyName
            propObDumpUnicodeString(TreeList, treeItem, T_FIELD_SERVICE_KEYNAME,
                &driverExtension.Versions.DriverExtensionCompatible->ServiceKeyName,
                FALSE);

            // All brand new private fields
            if (objectVersion > OBVERSION_DRIVER_EXTENSION_V1) {
                propObDumpAddress(TreeList, treeItem, TEXT("ClientDriverExtension"),
                    TEXT("PIO_CLIENT_EXTENSION"), driverExtension.Versions.DriverExtensionV2->ClientDriverExtension, 0, 0);
                propObDumpAddress(TreeList, treeItem, TEXT("FsFilterCallbacks"),
                    TEXT("PFS_FILTER_CALLBACKS"), driverExtension.Versions.DriverExtensionV2->FsFilterCallbacks, 0, 0);
            }

            if (objectVersion > OBVERSION_DRIVER_EXTENSION_V2) {
                propObDumpAddress(TreeList, treeItem, TEXT("KseCallbacks"),
                    NULL, driverExtension.Versions.DriverExtensionV3->KseCallbacks, 0, 0);
                propObDumpAddress(TreeList, treeItem, TEXT("DvCallbacks"),
                    NULL, driverExtension.Versions.DriverExtensionV3->DvCallbacks, 0, 0);
            }

            if (objectVersion > OBVERSION_DRIVER_EXTENSION_V3) {
                propObDumpAddress(TreeList, treeItem, TEXT("VerifierContext"),
                    NULL, driverExtension.Versions.DriverExtensionV4->VerifierContext, 0, 0);
            }
        }

        supVirtualFree(driverExtension.Ref);
    }
}

/*
* propObDumpDriverObject
*
* Purpose:
*
* Dump DRIVER_OBJECT members to the treelist.
*
*/
PROP_OBJECT_DUMP_ROUTINE(propObDumpDriverObject)
{
    BOOL                    bDataRead = FALSE;
    INT                     i;
    HTREEITEM               treeRootItem, treeSubItem;
    PRTL_PROCESS_MODULES    pModules = NULL;
    PVOID                   pObj, pIopInvalidDeviceRequest;
    LPWSTR                  lpType;
    DRIVER_OBJECT           drvObject;
    FAST_IO_DISPATCH        fastIoDispatch;
    LDR_DATA_TABLE_ENTRY    ldrEntry;
    TL_SUBITEMS_FIXED       subitems;
    COLORREF                BgColor;
    WCHAR                   szValue1[MAX_PATH + 1];

    //
    // Collect modules first.
    //
    pModules = (PRTL_PROCESS_MODULES)supGetLoadedModulesList(NULL);
    if (pModules == NULL) {
        supObDumpShowError(hwndDlg, TEXT("Cannot query loaded modules list"));
        return;
    }

    //
    // Dump object, abort on any error.
    //
    RtlSecureZeroMemory(&drvObject, sizeof(drvObject));
    RtlSecureZeroMemory(&ldrEntry, sizeof(ldrEntry));

    do {

        //dump drvObject
        if (!kdReadSystemMemory(
            Context->ObjectInfo.ObjectAddress,
            &drvObject,
            sizeof(drvObject)))
        {
            break;
        }

        //we need to dump drvObject
        //consider dump failures for anything else as not critical
        bDataRead = TRUE;

        //dump drvObject->DriverSection
        if (!kdReadSystemMemory(
            (ULONG_PTR)drvObject.DriverSection,
            &ldrEntry,
            sizeof(ldrEntry)))
        {
            break;
        }

    } while (FALSE);

    //
    // Any errors - abort.
    //
    if (!bDataRead) {
        supHeapFree(pModules);
        supObDumpShowError(hwndDlg, NULL);
        return;
    }

    //
    // Remember IopInvalidDeviceRequest.
    //
    if (g_kdctx.Data->IopInvalidDeviceRequest == NULL) {
        g_kdctx.Data->IopInvalidDeviceRequest = kdQueryIopInvalidDeviceRequest();
    }
    pIopInvalidDeviceRequest = g_kdctx.Data->IopInvalidDeviceRequest;

    //
    // DRIVER_OBJECT
    //
    treeRootItem = supTreeListAddItem(
        hwndTreeList,
        NULL,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        TEXT("DRIVER_OBJECT"),
        NULL);

    if (treeRootItem) {

        //Type
        BgColor = 0;
        lpType = TEXT("IO_TYPE_DRIVER");
        if (drvObject.Type != IO_TYPE_DRIVER) {
            lpType = TEXT("! Must be IO_TYPE_DRIVER");
            BgColor = CLR_WARN;
        }
        propObDumpUlong(hwndTreeList, treeRootItem, TEXT("Type"), lpType, drvObject.Type, TRUE, TRUE, BgColor, 0);

        //Size
        BgColor = 0;
        lpType = NULL;
        if (drvObject.Size != sizeof(DRIVER_OBJECT)) {
            lpType = TEXT("! Must be sizeof(DRIVER_OBJECT)");
            BgColor = CLR_WARN;
        }
        propObDumpUlong(hwndTreeList, treeRootItem, TEXT("Size"), lpType, drvObject.Size, TRUE, TRUE, BgColor, 0);

        //DeviceObject
        propDumpObjectForAddress(hwndTreeList, treeRootItem,
            TEXT("DeviceObject"), drvObject.DeviceObject, CLR_LGRY, T_UNNAMED);

        //Flags
        propDumpBitFlags(hwndTreeList, treeRootItem, drvObject.Flags, T_DrvFlags, RTL_NUMBER_OF(T_DrvFlags), TVIS_EXPANDED, T_FLAGS);

        //DriverStart
        propObDumpAddress(hwndTreeList, treeRootItem, TEXT("DriverStart"), NULL, drvObject.DriverStart, 0, 0);

        //DriverSize
        propObDumpUlong(hwndTreeList, treeRootItem, TEXT("DriverSize"), NULL, drvObject.DriverSize, TRUE, FALSE, 0, 0);

        //DriverSection
        propObDumpAddress(hwndTreeList, treeRootItem, TEXT("DriverSection"), T_PLDR_DATA_TABLE_ENTRY, drvObject.DriverSection, 0, 0);

        //DriverExtension
        propObDumpAddress(hwndTreeList, treeRootItem, T_FIELD_DRIVER_EXTENSION, T_PDRIVER_EXTENSION, drvObject.DriverExtension, 0, 0);

        //DriverName
        propObDumpUnicodeString(hwndTreeList, treeRootItem, TEXT("DriverName"), &drvObject.DriverName, FALSE);

        //HardwareDatabase
        propObDumpUnicodeString(hwndTreeList, treeRootItem, TEXT("HardwareDatabase"), drvObject.HardwareDatabase, TRUE);

        //FastIoDispatch
        propObDumpAddress(hwndTreeList, treeRootItem, TEXT("FastIoDispatch"), T_PFAST_IO_DISPATCH, drvObject.FastIoDispatch, 0, 0);

        //DriverInit
        propObDumpAddress(hwndTreeList, treeRootItem, TEXT("DriverInit"), NULL, drvObject.DriverInit, 0, 0);

        //DriverStartIo
        propObDumpAddress(hwndTreeList, treeRootItem, TEXT("DriverStartIo"), NULL, drvObject.DriverStartIo, 0, 0);

        //DriverUnload
        propObDumpAddress(hwndTreeList, treeRootItem, TEXT("DriverUnload"), NULL, drvObject.DriverUnload, 0, 0);

        //MajorFunction
        RtlSecureZeroMemory(&szValue1, sizeof(szValue1));
        RtlSecureZeroMemory(&subitems, sizeof(subitems));
        subitems.Count = 2;
        subitems.Text[0] = TEXT("{...}");
        subitems.Text[1] = T_EmptyString;

        treeSubItem = supTreeListAddItem(
            hwndTreeList,
            treeRootItem,
            TVIF_TEXT | TVIF_STATE,
            0,
            0,
            TEXT("MajorFunction"),
            &subitems);

        if (treeSubItem) {

            for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {

                if (drvObject.MajorFunction[i] == NULL) {
                    continue;
                }

                //
                // Skip ntoskrnl default IRP handler.
                // 
                // WARNING: This may skip actual trampoline hook.
                //
                if (pIopInvalidDeviceRequest) {
                    if ((ULONG_PTR)drvObject.MajorFunction[i] == (ULONG_PTR)pIopInvalidDeviceRequest) {

                        propObDumpAddress(
                            hwndTreeList,
                            treeSubItem,
                            T_IRP_MJ_FUNCTION[i],
                            T_INVALID_REQUEST,
                            drvObject.MajorFunction[i],
                            CLR_INVL,
                            0);

                        continue;
                    }
                }

                //DRIVER_OBJECT->MajorFunction[i]
                propObDumpAddressWithModuleEx(hwndTreeList,
                    treeSubItem,
                    T_IRP_MJ_FUNCTION[i],
                    drvObject.MajorFunction[i],
                    pModules,
                    ldrEntry.DllBase,
                    ldrEntry.SizeOfImage,
                    TRUE);
            }
        } //treeSubItem
    } //treeRootItem

    //
    // LDR_DATA_TABLE_ENTRY
    //
    if (drvObject.DriverSection != NULL) {

        //root itself
        treeRootItem = supTreeListAddItem(
            hwndTreeList,
            NULL,
            TVIF_TEXT | TVIF_STATE,
            TVIS_EXPANDED,
            0,
            T_LDR_DATA_TABLE_ENTRY,
            NULL);

        if (treeRootItem) {

            //InLoadOrderLinks
            propObDumpListEntry(hwndTreeList, treeRootItem, TEXT("InLoadOrderLinks"), &ldrEntry.InLoadOrderLinks);

            //InMemoryOrderLinks
            propObDumpListEntry(hwndTreeList, treeRootItem, TEXT("InMemoryOrderLinks"), &ldrEntry.InMemoryOrderLinks);

            //InInitializationOrderLinks/InProgressLinks
            lpType = (g_NtBuildNumber >= NT_WIN8_BLUE) ? TEXT("InProgressLinks") : TEXT("InInitializationOrderLinks");
            propObDumpListEntry(hwndTreeList, treeRootItem, lpType, &ldrEntry.DUMMYUNION0.InInitializationOrderLinks);

            //DllBase
            propObDumpAddress(hwndTreeList, treeRootItem, TEXT("DllBase"), NULL, ldrEntry.DllBase, 0, 0);

            //EntryPoint
            propObDumpAddress(hwndTreeList, treeRootItem, TEXT("EntryPoint"), NULL, ldrEntry.EntryPoint, 0, 0);

            //SizeOfImage
            propObDumpUlong(hwndTreeList, treeRootItem, TEXT("SizeOfImage"), NULL, ldrEntry.SizeOfImage, TRUE, FALSE, 0, 0);

            //FullDllName
            propObDumpUnicodeString(hwndTreeList, treeRootItem, TEXT("FullDllName"), &ldrEntry.FullDllName, FALSE);

            //BaseDllName
            propObDumpUnicodeString(hwndTreeList, treeRootItem, TEXT("BaseDllName"), &ldrEntry.BaseDllName, FALSE);

            //Flags
            propObDumpUlong(hwndTreeList, treeRootItem, T_FLAGS, NULL, ldrEntry.ENTRYFLAGSUNION.Flags, TRUE, FALSE, 0, 0);

            //LoadCount
            lpType = (g_NtBuildNumber < NT_WIN8_RTM) ? TEXT("LoadCount") : TEXT("ObsoleteLoadCount");
            propObDumpUlong(hwndTreeList, treeRootItem, lpType, NULL, ldrEntry.ObsoleteLoadCount, TRUE, TRUE, 0, 0);

            //TlsIndex
            propObDumpUlong(hwndTreeList, treeRootItem, TEXT("TlsIndex"), NULL, ldrEntry.TlsIndex, TRUE, TRUE, 0, 0);

            //SectionPointer
            propObDumpAddress(hwndTreeList, treeRootItem, TEXT("SectionPointer"), NULL, ldrEntry.DUMMYUNION1.SectionPointer, 0, 0);

            //CheckSum
            propObDumpUlong(hwndTreeList, treeRootItem, TEXT("CheckSum"), NULL, ldrEntry.DUMMYUNION1.CheckSum, TRUE, FALSE, 0, 0);

            //LoadedImports
            if (g_NtBuildNumber < NT_WIN8_RTM) {
                propObDumpAddress(hwndTreeList, treeRootItem, TEXT("LoadedImports"), NULL, ldrEntry.DUMMYUNION2.LoadedImports, 0, 0);
            }
        } //treeRootItem
    } //LDR_DATA_TABLE_ENTRY

    //
    // FAST_IO_DISPATCH
    //
    if (drvObject.FastIoDispatch != NULL) {

        RtlSecureZeroMemory(&fastIoDispatch, sizeof(fastIoDispatch));
        if (kdReadSystemMemory(
            (ULONG_PTR)drvObject.FastIoDispatch,
            &fastIoDispatch,
            sizeof(fastIoDispatch)))
        {
            bDataRead = TRUE;
            treeRootItem = supTreeListAddItem(
                hwndTreeList,
                NULL,
                TVIF_TEXT | TVIF_STATE,
                0,
                0,
                TEXT("FAST_IO_DISPATCH"),
                NULL);

            if (treeRootItem) {

                //SizeOfFastIoDispatch
                BgColor = 0;
                lpType = NULL;

                if (fastIoDispatch.SizeOfFastIoDispatch != sizeof(FAST_IO_DISPATCH)) {
                    lpType = TEXT("! Must be sizeof(FAST_IO_DISPATCH)");
                    BgColor = CLR_WARN;
                    bDataRead = FALSE;//<-set flag invalid structure
                }

                propObDumpUlong(hwndTreeList,
                    treeRootItem,
                    TEXT("SizeOfFastIoDispatch"),
                    lpType,
                    fastIoDispatch.SizeOfFastIoDispatch,
                    TRUE,
                    FALSE,
                    BgColor,
                    0);

                //valid structure
                if (bDataRead) {
                    for (i = 0; i < RTL_NUMBER_OF(T_FAST_IO_DISPATCH); i++) {
                        pObj = ((PVOID*)(&fastIoDispatch.FastIoCheckIfPossible))[i];
                        if (pObj == NULL) {
                            continue;
                        }

                        propObDumpAddressWithModule(hwndTreeList,
                            treeRootItem,
                            T_FAST_IO_DISPATCH[i],
                            pObj,
                            pModules,
                            ldrEntry.DllBase,
                            ldrEntry.SizeOfImage);

                    }
                }
            } //treeRootItem
        } //kdReadSystemMemory
    } //if

    //
    // PDRIVER_EXTENSION
    //
    if (drvObject.DriverExtension != NULL) {

        propObDumpDriverExtension(hwndTreeList,
            (PDRIVER_OBJECT)Context->ObjectInfo.ObjectAddress,
            drvObject.DriverExtension,
            pModules,
            &ldrEntry);

    }

    //
    // Cleanup
    //
    supHeapFree(pModules);
}

/*
* propObDumpDeviceObject
*
* Purpose:
*
* Dump DEVICE_OBJECT members to the treelist.
*
*/
PROP_OBJECT_DUMP_ROUTINE(propObDumpDeviceObject)
{
    BOOL                bOkay;
    HTREEITEM           treeRootItem, treeItemWcb, treeSubItem, treeWaitEntryItem;
    LPWSTR              lpType;
    DEVICE_OBJECT       devObject;
    DEVOBJ_EXTENSION    devObjExt;
    COLORREF            bgColor;

    bOkay = FALSE;

    //dump devObject
    RtlSecureZeroMemory(&devObject, sizeof(devObject));

    if (!kdReadSystemMemory(
        Context->ObjectInfo.ObjectAddress,
        &devObject,
        sizeof(devObject)))
    {
        supObDumpShowError(hwndDlg, NULL);
        return;
    }

    //
    //DEVICE_OBJECT
    //

    treeRootItem = supTreeListAddItem(hwndTreeList,
        NULL,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        L"DEVICE_OBJECT",
        NULL);

    if (treeRootItem == NULL) {
        supObDumpShowError(hwndDlg, NULL);
        return;
    }

    //Type
    bgColor = 0;
    lpType = L"IO_TYPE_DEVICE";
    if (devObject.Type != IO_TYPE_DEVICE) {
        lpType = L"! Must be IO_TYPE_DEVICE";
        bgColor = CLR_WARN;
    }
    propObDumpUlong(hwndTreeList, treeRootItem, L"Type", lpType, devObject.Type, TRUE, TRUE, bgColor, 0);

    //Size
    propObDumpUlong(hwndTreeList, treeRootItem, L"Size", NULL, devObject.Size, TRUE, TRUE, 0, 0);

    //ReferenceCount
    propObDumpUlong(hwndTreeList, treeRootItem, L"ReferenceCount", NULL, devObject.ReferenceCount, FALSE, FALSE, 0, 0);

    //
    // DriverObject
    //
    propDumpObjectForAddress(hwndTreeList, treeRootItem, T_FIELD_DRIVER_OBJECT, devObject.DriverObject, CLR_INVL, T_REFNOTFOUND);

    //
    // NextDevice
    //
    propDumpObjectForAddress(hwndTreeList, treeRootItem, L"NextDevice", devObject.NextDevice, CLR_LGRY, T_UNNAMED);

    //
    // AttachedDevice
    //
    propDumpObjectForAddress(hwndTreeList, treeRootItem, L"AttachedDevice", devObject.AttachedDevice, CLR_LGRY, T_UNNAMED);

    //CurrentIrp
    propObDumpAddress(hwndTreeList, treeRootItem, L"CurrentIrp", NULL, devObject.CurrentIrp, 0, 0);

    //Timer
    lpType = L"PIO_TIMER";
    propObDumpAddress(hwndTreeList, treeRootItem, L"Timer", lpType, devObject.Timer, 0, 0);

    //Flags
    propDumpBitFlags(hwndTreeList, treeRootItem, devObject.Flags, T_DevFlags, RTL_NUMBER_OF(T_DevFlags), TVIS_EXPANDED, T_FLAGS);

    //Characteristics
    propDumpBitFlags(hwndTreeList, treeRootItem, devObject.Characteristics, T_DevChars, RTL_NUMBER_OF(T_DevChars), 0, T_CHARACTERISTICS);

    //Vpb
    lpType = L"PVPB";
    propObDumpAddress(hwndTreeList, treeRootItem, L"Vpb", lpType, devObject.Vpb, 0, 0);

    //DeviceExtension
    bgColor = 0;
    lpType = NULL;

    //
    // Check DeviceExtension to be valid as it size is a part of total DEVICE_OBJECT allocation size.
    //
    if (devObject.DeviceExtension != NULL) {
        if (devObject.Size == sizeof(DEVICE_OBJECT)) {
            bgColor = CLR_WARN;
            lpType = L"! Must be NULL";
        }
    }
    propObDumpAddress(hwndTreeList, treeRootItem, L"DeviceExtension", lpType, devObject.DeviceExtension, bgColor, 0);

    //DeviceType
    lpType = propObGetTypeDescForValue(T_DevObjChars, RTL_NUMBER_OF(T_DevObjChars), devObject.DeviceType);
    propObDumpUlong(hwndTreeList, treeRootItem, L"DeviceType", lpType, devObject.DeviceType, TRUE, FALSE, 0, 0);

    //StackSize
    propObDumpUlong(hwndTreeList, treeRootItem, L"StackSize", NULL, devObject.StackSize, FALSE, FALSE, 0, 0);

    //Queue
    treeSubItem = supTreeListAddItem(hwndTreeList, treeRootItem, TVIF_TEXT | TVIF_STATE, 0,
        TVIS_EXPANDED, L"Queue", NULL);
    if (treeSubItem) {

        //Queue->Wcb
        treeItemWcb = supTreeListAddItem(hwndTreeList, treeSubItem, TVIF_TEXT | TVIF_STATE, 0,
            TVIS_EXPANDED, L"Wcb", NULL);

        if (treeItemWcb) {

            //Queue->Wcb->WaitQueueEntry
            treeWaitEntryItem = supTreeListAddItem(hwndTreeList, treeItemWcb, TVIF_TEXT | TVIF_STATE, 0,
                TVIS_EXPANDED, L"WaitQueueEntry", NULL);

            if (treeWaitEntryItem) {
                //Queue->Wcb->WaitQueueEntry->DeviceListEntry
                propObDumpListEntry(hwndTreeList, treeWaitEntryItem, L"DeviceListEntry", &devObject.Queue.Wcb.WaitQueueEntry.DeviceListEntry);
                //Queue->Wcb->WaitQueueEntry->SortKey
                propObDumpUlong(hwndTreeList, treeWaitEntryItem, L"SortKey", NULL, devObject.Queue.Wcb.WaitQueueEntry.SortKey, TRUE, FALSE, 0, 0);
                //Queue->Wcb->WaitQueueEntry->Inserted
                propObDumpByte(hwndTreeList, treeWaitEntryItem, L"Inserted", NULL, devObject.Queue.Wcb.WaitQueueEntry.Inserted, 0, 0, TRUE);
            }

            //Queue->Wcb->DmaWaitEntry
            propObDumpListEntry(hwndTreeList, treeItemWcb, L"DmaWaitEntry", &devObject.Queue.Wcb.DmaWaitEntry);

            //Queue->Wcb->NumberOfChannels
            propObDumpUlong(hwndTreeList, treeItemWcb, L"NumberOfChannels", NULL, devObject.Queue.Wcb.NumberOfChannels, FALSE, FALSE, 0, 0);

            //Queue->Wcb->SyncCallback
            propObDumpUlong(hwndTreeList, treeItemWcb, L"SyncCallback", NULL, devObject.Queue.Wcb.SyncCallback, FALSE, FALSE, 0, 0);

            //Queue->Wcb->DmaContext
            propObDumpUlong(hwndTreeList, treeItemWcb, L"DmaContext", NULL, devObject.Queue.Wcb.DmaContext, FALSE, FALSE, 0, 0);

            //Queue->Wcb->DeviceRoutine
            propObDumpAddress(hwndTreeList, treeItemWcb, L"DeviceRoutine", L"PDRIVER_CONTROL", devObject.Queue.Wcb.DeviceRoutine, 0, 0);

            //Queue->Wcb->DeviceContext
            propObDumpAddress(hwndTreeList, treeItemWcb, L"DeviceContext", NULL, devObject.Queue.Wcb.DeviceContext, 0, 0);

            //Queue->Wcb->NumberOfMapRegisters
            propObDumpUlong(hwndTreeList, treeItemWcb, L"NumberOfMapRegisters", NULL, devObject.Queue.Wcb.NumberOfMapRegisters, FALSE, FALSE, 0, 0);

            //Queue->Wcb->DeviceObject
            propDumpObjectForAddress(hwndTreeList, treeItemWcb, L"DeviceObject", devObject.Queue.Wcb.DeviceObject, CLR_LGRY, T_UNNAMED);

            //Queue->Wcb->CurrentIrp
            propObDumpAddress(hwndTreeList, treeItemWcb, L"CurrentIrp", NULL, devObject.Queue.Wcb.CurrentIrp, 0, 0);

            //Queue->Wcb->BufferChainingDpc
            lpType = T_PKDPC;
            propObDumpAddress(hwndTreeList, treeItemWcb, L"BufferChainingDpc", lpType, devObject.Queue.Wcb.BufferChainingDpc, 0, 0);

        }//treeSubItem
    } //treeItemWcb

    //AlignmentRequirement
    lpType = propObGetTypeDescForValue(T_FileAlign, RTL_NUMBER_OF(T_FileAlign), devObject.AlignmentRequirement);
    propObDumpUlong(hwndTreeList, treeRootItem, L"AlignmentRequirement", lpType, devObject.AlignmentRequirement, TRUE, FALSE, 0, 0);

    //DeviceQueue
    treeSubItem = supTreeListAddItem(hwndTreeList, treeRootItem, TVIF_TEXT | TVIF_STATE, 0, TVIS_EXPANDED, L"DeviceQueue", NULL);
    if (treeSubItem) {
        //DeviceQueue->Type
        lpType = L"KOBJECTS";
        propObDumpUlong(hwndTreeList, treeSubItem, L"Type", lpType, devObject.DeviceQueue.Type, TRUE, TRUE, 0, 0);

        //DeviceQueue->Size
        propObDumpUlong(hwndTreeList, treeSubItem, L"Size", NULL, devObject.DeviceQueue.Size, TRUE, TRUE, 0, 0);

        //DeviceQueue->DeviceListHead
        propObDumpListEntry(hwndTreeList, treeSubItem, L"DeviceListHead", &devObject.DeviceQueue.DeviceListHead);

        //DeviceQueue->Lock
        propObDumpAddress(hwndTreeList, treeSubItem, L"Lock", NULL, (PVOID)devObject.DeviceQueue.Lock, 0, 0);

        //DeviceQueue->Busy
        propObDumpByte(hwndTreeList, treeSubItem, L"Busy", NULL, devObject.DeviceQueue.Busy, 0, 0, TRUE);

        //DeviceQueue->Hint
        propObDumpAddress(hwndTreeList, treeSubItem, L"Hint", NULL, (PVOID)devObject.DeviceQueue.Hint, 0, 0);
    } //treeSubItem

    //
    // DEVICE_OBJECT->Dpc
    //
    treeSubItem = supTreeListAddItem(hwndTreeList, treeRootItem, TVIF_TEXT | TVIF_STATE, 0,
        TVIS_EXPANDED, L"Dpc", NULL);
    if (treeSubItem) {

        //Dpc->Type
        lpType = NULL;
        if (devObject.Dpc.Type == DPC_NORMAL) lpType = L"DPC_NORMAL";
        if (devObject.Dpc.Type == DPC_THREADED) lpType = L"DPC_THREADED";
        propObDumpUlong(hwndTreeList, treeSubItem, L"Type", lpType, devObject.Dpc.Type, TRUE, TRUE, 0, 0);

        //Dpc->Importance
        lpType = NULL;
        switch (devObject.Dpc.Importance) {
        case LowImportance:
            lpType = L"LowImportance";
            break;
        case MediumImportance:
            lpType = L"MediumImportance";
            break;
        default:
            lpType = L"HighImportance";
            break;
        }
        propObDumpUlong(hwndTreeList, treeSubItem, L"Importance", lpType, devObject.Dpc.Importance, TRUE, TRUE, 0, 0);

        //Dpc->Number
        propObDumpUlong(hwndTreeList, treeSubItem, L"Number", NULL, devObject.Dpc.Number, TRUE, TRUE, 0, 0);

        //Dpc->DpcListEntry
        propObDumpAddress(hwndTreeList, treeSubItem, L"DpcListEntry", NULL, (PVOID)devObject.Dpc.DpcListEntry.Next, 0, 0);

        //Dpc->ProcessorHistory
        propObDumpAddress(hwndTreeList, treeSubItem, L"ProcessorHistory", NULL, (PVOID)devObject.Dpc.ProcessorHistory, 0, 0);

        //Dpc->DeferredRoutine
        propObDumpAddress(hwndTreeList, treeSubItem, L"DeferredRoutine", NULL, devObject.Dpc.DeferredRoutine, 0, 0);

        //Dpc->DeferredContext
        propObDumpAddress(hwndTreeList, treeSubItem, L"DeferredContext", NULL, devObject.Dpc.DeferredContext, 0, 0);

        //Dpc->SystemArgument1
        propObDumpAddress(hwndTreeList, treeSubItem, L"SystemArgument1", NULL, devObject.Dpc.SystemArgument1, 0, 0);

        //Dpc->SystemArgument2
        propObDumpAddress(hwndTreeList, treeSubItem, L"SystemArgument2", NULL, devObject.Dpc.SystemArgument2, 0, 0);

    } //treeSubItem

    //ActiveThreadCount
    propObDumpUlong(hwndTreeList, treeRootItem, L"ActiveThreadCount", NULL, devObject.ActiveThreadCount, FALSE, FALSE, 0, 0);

    //SecurityDescriptor
    lpType = L"PSECURITY_DESCRIPTOR";
    propObDumpAddress(hwndTreeList, treeRootItem, L"SecurityDescriptor", lpType, devObject.SecurityDescriptor, 0, 0);

    //DeviceLock
    treeWaitEntryItem = supTreeListAddItem(hwndTreeList, treeRootItem, TVIF_TEXT | TVIF_STATE, 0,
        TVIS_EXPANDED, L"DeviceLock", NULL);
    if (treeWaitEntryItem) {
        //DeviceLock->Header
        propObDumpDispatcherHeader(hwndTreeList, treeWaitEntryItem, &devObject.DeviceLock.Header, NULL, NULL, NULL);
    }

    //SectorSize
    propObDumpUlong(hwndTreeList, treeRootItem, L"SectorSize", NULL, devObject.SectorSize, TRUE, TRUE, 0, 0);
    //Spare
    propObDumpUlong(hwndTreeList, treeRootItem, L"Spare1", NULL, devObject.Spare1, TRUE, TRUE, 0, 0);

    //DeviceObjectExtension
    lpType = L"PDEVOBJ_EXTENSION";
    propObDumpAddress(hwndTreeList, treeRootItem, L"DeviceObjectExtension", lpType, devObject.DeviceObjectExtension, 0, 0);

    //Reserved
    propObDumpAddress(hwndTreeList, treeRootItem, L"Reserved", NULL, devObject.Reserved, 0, 0);

    //
    // DEVOBJ_EXTENSION
    //
    if (devObject.DeviceObjectExtension) {

        RtlSecureZeroMemory(&devObjExt, sizeof(devObjExt));

        if (!kdReadSystemMemory(
            (ULONG_PTR)devObject.DeviceObjectExtension,
            &devObjExt,
            sizeof(devObjExt)))
        {
            return; //safe to exit, nothing after this
        }

        treeRootItem = supTreeListAddItem(hwndTreeList, NULL, TVIF_TEXT | TVIF_STATE, 0,
            TVIS_EXPANDED, L"DEVOBJ_EXTENSION", NULL);

        if (treeRootItem) {

            bgColor = 0;
            lpType = L"IO_TYPE_DEVICE_OBJECT_EXTENSION";
            if (devObjExt.Type != IO_TYPE_DEVICE_OBJECT_EXTENSION) {
                lpType = L"! Must be IO_TYPE_DEVICE_OBJECT_EXTENSION";
                bgColor = CLR_WARN;
            }
            //Type
            propObDumpUlong(hwndTreeList, treeRootItem, L"Type", lpType, devObjExt.Type, TRUE, TRUE, bgColor, 0);
            //Size
            propObDumpUlong(hwndTreeList, treeRootItem, L"Size", NULL, devObjExt.Size, TRUE, TRUE, 0, 0);
            //DeviceObject
            propDumpObjectForAddress(hwndTreeList, treeRootItem, L"DeviceObject", devObjExt.DeviceObject, CLR_LGRY, T_UNNAMED);
            //PowerFlags
            propObDumpUlong(hwndTreeList, treeRootItem, L"PowerFlags", NULL, devObjExt.PowerFlags, TRUE, FALSE, 0, 0);
            //Dope
            propObDumpAddress(hwndTreeList, treeRootItem, L"Dope", L"PDEVICE_OBJECT_POWER_EXTENSION", devObjExt.Dope, 0, 0);
            //ExtensionFlags
            propObDumpUlong(hwndTreeList, treeRootItem, L"ExtensionFlags", NULL, devObjExt.ExtensionFlags, TRUE, FALSE, 0, 0);
            //DeviceNode
            propObDumpAddress(hwndTreeList, treeRootItem, L"DeviceNode", L"PDEVICE_NODE", devObjExt.DeviceNode, 0, 0);
            //AttachedTo
            propDumpObjectForAddress(hwndTreeList, treeRootItem, L"AttachedTo", devObjExt.AttachedTo, CLR_LGRY, T_UNNAMED);

        } //treeRootItem
    }
}

/*
* propObDumpSessionIdVersionAware
*
* Purpose:
*
* Dump OBJECT_DIRECTORY SessionId.
*
*/
VOID propObDumpSessionIdVersionAware(
    _In_ HWND hwndTreeList,
    _In_ HTREEITEM h_tviRootItem,
    _In_ ULONG SessionId
)
{
    LPWSTR lpType = (SessionId == OBJ_INVALID_SESSION_ID) ? T_OBJ_INVALID_SESSION_ID : NULL;
    propObDumpUlong(hwndTreeList, h_tviRootItem, TEXT("SessionId"), lpType, SessionId, TRUE, FALSE, 0, 0);
}

/*
* propObDumpDeviceMap
*
* Purpose:
*
* Dump DEVICE_MAP to the treelist.
*
*/
VOID propObDumpDeviceMap(
    _In_ HWND TreeList,
    _In_ HTREEITEM ParentItem,
    _In_ PDEVICE_MAP DeviceMapAddress
)
{
    union {
        union {
            DEVICE_MAP_V1* DeviceMapV1;
            DEVICE_MAP_V2* DeviceMapV2;
            DEVICE_MAP_V3* DeviceMapV3;
            DEVICE_MAP_V2* DeviceMapCompat;
        } Versions;
        PVOID Ref;
    } deviceMapStruct;

    HTREEITEM treeItem, treeDriveTypeItem;
    TL_SUBITEMS_FIXED subitems;

    LPWSTR lpType;
    ULONG objectSize = 0, objectVersion = 0;
    ULONG i, driveMap;

    BYTE driveType;
    WCHAR szBuffer[MAX_PATH + 1];

    deviceMapStruct.Ref = ObDumpDeviceMapVersionAware((ULONG_PTR)DeviceMapAddress,
        &objectSize,
        &objectVersion);

    if (deviceMapStruct.Ref) {

        RtlSecureZeroMemory(&subitems, sizeof(subitems));
        subitems.Count = 2;

        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        subitems.Text[0] = propObFormatAddress64OrNull(DeviceMapAddress, szBuffer);
        subitems.Text[1] = T_PDEVICE_MAP;

        treeItem = supTreeListAddItem(TreeList,
            ParentItem,
            TVIF_TEXT | TVIF_STATE,
            0,
            0,
            T_FIELD_DEVICE_MAP,
            &subitems);

        if (treeItem) {

            lpType = (deviceMapStruct.Versions.DeviceMapCompat->DosDevicesDirectory != NULL) ? T_POBJECT_DIRECTORY : T_EMPTY;
            propObDumpAddress(TreeList, treeItem, T_DEVICEMAP_DOSDEVICESDIRECTORY, lpType,
                (PVOID)deviceMapStruct.Versions.DeviceMapCompat->DosDevicesDirectory, 0, 0);

            lpType = (deviceMapStruct.Versions.DeviceMapCompat->GlobalDosDevicesDirectory != NULL) ? T_POBJECT_DIRECTORY : T_EMPTY;
            propObDumpAddress(TreeList, treeItem, T_DEVICEMAP_GLOBALDOSDEVICESDIRECTORY, lpType,
                (PVOID)deviceMapStruct.Versions.DeviceMapCompat->GlobalDosDevicesDirectory, 0, 0);

            if (objectVersion > OBVERSION_DEVICE_MAP_V2) {
                propObDumpAddress(TreeList, treeItem, T_DEVICEMAP_DOSDEVICESDIRECTORYHANDLE, NULL,
                    (PVOID)deviceMapStruct.Versions.DeviceMapV3->DosDevicesDirectoryHandle, 0, 0);
            }
            else {

                propObDumpAddress(TreeList, treeItem, T_DEVICEMAP_DOSDEVICESDIRECTORYHANDLE, NULL,
                    (PVOID)deviceMapStruct.Versions.DeviceMapCompat->DosDevicesDirectoryHandle, 0, 0);

            }

            //
            // ReferenceCount
            //
            switch (objectVersion) {
            case OBVERSION_DEVICE_MAP_V1:
                propObDumpUlong(TreeList, treeItem, T_REFERENCECOUNT, NULL,
                    deviceMapStruct.Versions.DeviceMapV1->ReferenceCount, TRUE, FALSE, 0, 0);
                break;
            case OBVERSION_DEVICE_MAP_V2:
                propObDumpLong(TreeList, treeItem, T_REFERENCECOUNT, NULL,
                    deviceMapStruct.Versions.DeviceMapV2->ReferenceCount, TRUE, 0, 0);
                break;
            case OBVERSION_DEVICE_MAP_V3:
            default:
                propObDumpLong64(TreeList, treeItem, T_REFERENCECOUNT, NULL,
                    deviceMapStruct.Versions.DeviceMapV3->ReferenceCount, TRUE, 0, 0);
                break;
            }

            //
            // DriveMap
            //
            if (objectVersion > OBVERSION_DEVICE_MAP_V2) {
                driveMap = deviceMapStruct.Versions.DeviceMapV3->DriveMap;
            }
            else {
                driveMap = deviceMapStruct.Versions.DeviceMapCompat->DriveMap;
            }

            propObDumpUlong(TreeList, treeItem, T_DRIVEMAP, NULL,
                driveMap, TRUE, FALSE, 0, 0);

            //
            // Display DriveType array.
            //
            RtlSecureZeroMemory(&subitems, sizeof(subitems));

            subitems.Count = 2;
            subitems.Text[0] = T_EmptyString;
            subitems.Text[1] = T_EmptyString;

            treeDriveTypeItem = supTreeListAddItem(TreeList,
                treeItem,
                TVIF_TEXT | TVIF_STATE,
                0,
                0,
                T_DRIVETYPE,
                &subitems);

            if (treeDriveTypeItem) {

                RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

                for (i = 0; i < RTL_NUMBER_OF(deviceMapStruct.Versions.DeviceMapCompat->DriveType); i++) {

                    RtlStringCchPrintfSecure(szBuffer,
                        RTL_NUMBER_OF(szBuffer),
                        TEXT("[ %i ]"),
                        i);

                    if (objectVersion > OBVERSION_DEVICE_MAP_V2) {
                        driveType = deviceMapStruct.Versions.DeviceMapV3->DriveType[i];
                    }
                    else {
                        driveType = deviceMapStruct.Versions.DeviceMapCompat->DriveType[i];
                    }

                    lpType = propObGetTypeDescForValue(T_DosDeviceDriveType,
                        RTL_NUMBER_OF(T_DosDeviceDriveType), driveType);

                    propObDumpByte(TreeList, treeDriveTypeItem,
                        szBuffer,
                        (lpType == NULL) ? T_UnknownType : lpType,
                        driveType,
                        0,
                        0,
                        FALSE);

                }
            }
            if (objectVersion > OBVERSION_DEVICE_MAP_V1) {

                if (objectVersion > OBVERSION_DEVICE_MAP_V2) {
                    propObDumpAddress(TreeList, treeItem, T_SERVERSILO, T_PEJOB,
                        (PVOID)deviceMapStruct.Versions.DeviceMapV3->ServerSilo, 0, 0);
                }
                else {
                    propObDumpAddress(TreeList, treeItem, T_SERVERSILO, T_PEJOB,
                        (PVOID)deviceMapStruct.Versions.DeviceMapCompat->ServerSilo, 0, 0);
                }
            }

        }

        supVirtualFree(deviceMapStruct.Ref);
    }
    else {

        //
        // Output as is in case of error.
        //
        propObDumpAddress(TreeList, ParentItem, T_FIELD_DEVICE_MAP, T_PDEVICE_MAP,
            (PVOID)DeviceMapAddress, 0, 0);

    }
}

/*
* propObDumpDirectoryObjectInternal
*
* Purpose:
*
* Dump OBJECT_DIRECTORY members (including ShadowDirectory) to the treelist.
*
*/
VOID propObDumpDirectoryObjectInternal(
    _In_ HWND TreeList,
    _In_ HTREEITEM RootItem,
    _In_opt_ HWND ParentWindow,
    _In_ ULONG_PTR ObjectAddress,
    _In_ BOOLEAN DumpShadow,
    _In_ BOOLEAN ShowErrors
)
{
    INT                     i;
    ULONG                   objectVersion = 0, objectSize = 0;
    ULONG                   sessionId, objectFlags;
    PVOID                   objectEntry, namespaceEntry, shadowDirectory;
    HTREEITEM               treeRootItem, treeSubItem, treeEntryItem;
    LPWSTR                  lpType;
    TL_SUBITEMS_FIXED       subitems;
    WCHAR                   szId[100], szValue[100];

    OBJECT_DIRECTORY_ENTRY dirEntry;
    LIST_ENTRY             chainLink;

    union {
        union {
            OBJECT_DIRECTORY* DirObjectV1;
            OBJECT_DIRECTORY_V2* DirObjectV2;
            OBJECT_DIRECTORY_V3* DirObjectV3;
            OBJECT_DIRECTORY_V3* CompatDirObject;//has all field members
        } Versions;
        PVOID Ref;
    } directoryObject;

    directoryObject.Ref = ObDumpDirectoryObjectVersionAware(ObjectAddress,
        &objectSize,
        &objectVersion);

    if (directoryObject.Ref == NULL) {
        if (ShowErrors)
            supObDumpShowError(ParentWindow, NULL);
        return;
    }

    //
    // OBJECT_DIRECTORY
    //
    treeRootItem = RootItem;

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 1;
    subitems.Text[0] = TEXT("{...}");

    treeSubItem = supTreeListAddItem(TreeList,
        treeRootItem,
        TVIF_TEXT | TVIF_STATE,
        0,
        0,
        TEXT("HashBuckets"),
        &subitems);

    if (treeSubItem) {

        for (i = 0; i < NUMBER_HASH_BUCKETS; i++) {
            RtlSecureZeroMemory(&subitems, sizeof(subitems));
            subitems.Count = 2;

            RtlSecureZeroMemory(szId, sizeof(szId));

            RtlStringCchPrintfSecure(szId,
                RTL_NUMBER_OF(szId),
                TEXT("[ %i ]"),
                i);

            objectEntry = directoryObject.Versions.CompatDirObject->HashBuckets[i];

            RtlSecureZeroMemory(szValue, sizeof(szValue));
            subitems.Text[0] = propObFormatAddress64OrNull(objectEntry, szValue);
            subitems.Text[1] = (objectEntry == NULL) ? T_EmptyString : T_POBJECT_DIRECTORY_ENTRY;

            treeEntryItem = supTreeListAddItem(TreeList,
                treeSubItem,
                TVIF_TEXT | TVIF_STATE,
                0,
                0,
                szId,
                &subitems);

            //dump entry if available
            if (treeEntryItem && objectEntry) {

                RtlSecureZeroMemory(&dirEntry, sizeof(dirEntry));

                if (kdReadSystemMemory((ULONG_PTR)objectEntry,
                    &dirEntry,
                    sizeof(dirEntry)))
                {
                    chainLink.Blink = NULL;
                    chainLink.Flink = NULL;
                    lpType = TEXT("ChainLink");
                    if (dirEntry.ChainLink == NULL) {
                        propObDumpAddress(TreeList, treeEntryItem, lpType, T_EMPTY, NULL, 0, 0);
                    }
                    else {
                        if (kdReadSystemMemory(
                            (ULONG_PTR)dirEntry.ChainLink,
                            &chainLink,
                            sizeof(chainLink)))
                        {
                            propObDumpListEntry(TreeList, treeEntryItem, lpType, &chainLink);
                        }
                        else {
                            //
                            // Failed to read listentry, display as is.
                            //
                            propObDumpAddress(TreeList, treeEntryItem, lpType, T_PLIST_ENTRY, dirEntry.ChainLink, 0, 0);
                        }
                    }
                    propObDumpAddress(TreeList, treeEntryItem, TEXT("Object"), NULL, dirEntry.Object, 0, 0);
                    propObDumpUlong(TreeList, treeEntryItem, TEXT("HashValue"), NULL, dirEntry.HashValue, TRUE, FALSE, 0, 0);
                }
            }
        }
    }

    //EX_PUSH_LOCK
    propObDumpPushLock(TreeList, treeRootItem,
        directoryObject.Versions.CompatDirObject->Lock.Ptr, 0, 0);

    //DeviceMap
    if (DumpShadow) {
        propObDumpDeviceMap(TreeList, treeRootItem,
            directoryObject.Versions.CompatDirObject->DeviceMap);
    }
    else {
        propObDumpAddress(TreeList, treeRootItem, TEXT("DeviceMap"), NULL,
            directoryObject.Versions.CompatDirObject->DeviceMap, 0, 0);
    }

    //ShadowDirectory
    if (objectVersion != OBVERSION_DIRECTORY_V1) {
        shadowDirectory = directoryObject.Versions.CompatDirObject->ShadowDirectory;
        if (shadowDirectory) {
            if (DumpShadow) {

                RtlSecureZeroMemory(&subitems, sizeof(subitems));
                subitems.Count = 2;

                RtlSecureZeroMemory(&szValue, sizeof(szValue));
                subitems.Text[0] = propObFormatAddress64OrNull(shadowDirectory, szValue);;
                subitems.Text[1] = T_POBJECT_DIRECTORY;

                treeSubItem = supTreeListAddItem(TreeList,
                    treeRootItem,
                    TVIF_TEXT | TVIF_STATE,
                    0,
                    0,
                    T_FIELD_SHADOW_DIRECTORY,
                    &subitems);
                if (treeSubItem) {
                    propObDumpDirectoryObjectInternal(TreeList,
                        treeSubItem,
                        ParentWindow,
                        (ULONG_PTR)shadowDirectory,
                        FALSE, //do not allow recursion, only first level dir listed.
                        FALSE);
                }
            }
        }
        else {
            //
            // No ShadowDirectory, display 0
            //
            propObDumpAddress(TreeList,
                treeRootItem,
                T_FIELD_SHADOW_DIRECTORY,
                T_POBJECT_DIRECTORY,
                0,
                0,
                0);

        }
    }

    //
    // Handle different object versions fields order.
    //

    //
    // SessionId
    //
    switch (objectVersion) {
    case OBVERSION_DIRECTORY_V1:
        sessionId = directoryObject.Versions.DirObjectV1->SessionId;
        break;
    case OBVERSION_DIRECTORY_V2:
        sessionId = directoryObject.Versions.DirObjectV2->SessionId;
        break;
    case OBVERSION_DIRECTORY_V3:
    default:
        sessionId = directoryObject.Versions.DirObjectV3->SessionId;
        break;

    }

    //
    // SessionId is the last member of OBJECT_DIRECTORY_V3, so it will be listed in the end of routine.
    //
    //
    if (objectVersion != OBVERSION_DIRECTORY_V3) {
        propObDumpSessionIdVersionAware(TreeList, treeRootItem, sessionId);
    }

    //
    // NamespaceEntry
    //
    switch (objectVersion) {
    case OBVERSION_DIRECTORY_V1:
        namespaceEntry = directoryObject.Versions.DirObjectV1->NamespaceEntry;
        break;
    case OBVERSION_DIRECTORY_V2:
        namespaceEntry = directoryObject.Versions.DirObjectV2->NamespaceEntry;
        break;
    case OBVERSION_DIRECTORY_V3:
    default:
        namespaceEntry = directoryObject.Versions.DirObjectV3->NamespaceEntry;
        break;

    }

    propObDumpAddress(TreeList, treeRootItem, TEXT("NamespaceEntry"), NULL, namespaceEntry, 0, 0);

    //
    // SessionObject
    //
    if (objectVersion == OBVERSION_DIRECTORY_V3) {

        propObDumpAddress(TreeList,
            treeRootItem,
            TEXT("SessionObject"),
            NULL,
            directoryObject.Versions.DirObjectV3->SessionObject,
            0, 0);

    }

    //
    // ObjectDirectory flags.
    //       
    switch (objectVersion) {
    case OBVERSION_DIRECTORY_V1:
        objectFlags = directoryObject.Versions.DirObjectV1->Flags;
        break;
    case OBVERSION_DIRECTORY_V2:
        objectFlags = directoryObject.Versions.DirObjectV2->Flags;
        break;
    case OBVERSION_DIRECTORY_V3:
    default:
        objectFlags = directoryObject.Versions.DirObjectV3->Flags;
        break;

    }

    propDumpBitFlags(TreeList, treeRootItem, objectFlags, T_ObjDirFlags, RTL_NUMBER_OF(T_ObjDirFlags), 0, T_FLAGS);

    //
    // SessionId is the last member of OBJECT_DIRECTORY_V3
    //
    if (objectVersion == OBVERSION_DIRECTORY_V3) {

        propObDumpSessionIdVersionAware(TreeList,
            treeRootItem,
            sessionId);
    }

    supVirtualFree(directoryObject.Ref);
}

/*
* propObDumpDirectoryObject
*
* Purpose:
*
* Initialize treelist for dump, creates root node and call actual dump function.
*
*/
PROP_OBJECT_DUMP_ROUTINE(propObDumpDirectoryObject)
{
    HTREEITEM rootItem;

    if (Context->ObjectInfo.ObjectAddress == 0) {
        supObDumpShowError(hwndDlg, NULL);
        return;
    }

    //
    //OBJECT_DIRECTORY
    //
    rootItem = supTreeListAddItem(hwndTreeList,
        NULL,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        T_OBJECT_DIRECTORY,
        NULL);

    if (rootItem) {

        propObDumpDirectoryObjectInternal(
            hwndTreeList,
            rootItem,
            hwndDlg,
            (ULONG_PTR)Context->ObjectInfo.ObjectAddress,
            TRUE,
            TRUE);

    }
}

/*
* propObDumpSyncObject
*
* Purpose:
*
* Dump KEVENT/KMUTANT/KSEMAPHORE/KTIMER members to the treelist.
*
*/
PROP_OBJECT_DUMP_ROUTINE(propObDumpSyncObject)
{
    PKMUTANT            Mutant = NULL;
    PKEVENT             Event = NULL;
    PKSEMAPHORE         Semaphore = NULL;
    PKTIMER             Timer = NULL;
    PDISPATCHER_HEADER  Header = NULL;

    HTREEITEM treeRootItem;
    LPWSTR    lpType = NULL, lpDescType = NULL, lpDesc1 = NULL, lpDesc2 = NULL;
    PVOID     object = NULL;
    ULONG     objectSize = 0UL;
    WCHAR     szValue[MAX_PATH + 1];


    switch (Context->ObjectTypeIndex) {

    case ObjectTypeEvent:
        objectSize = sizeof(KEVENT);
        break;

    case ObjectTypeMutant:
        objectSize = sizeof(KMUTANT);
        break;

    case ObjectTypeSemaphore:
        objectSize = sizeof(KSEMAPHORE);
        break;

    case ObjectTypeTimer:
        objectSize = sizeof(KTIMER);
        break;
    }

    object = supHeapAlloc(objectSize);
    if (object == NULL) {
        supObDumpShowError(hwndDlg, NULL);
        return;
    }

    //dump object
    if (!kdReadSystemMemory(
        Context->ObjectInfo.ObjectAddress,
        object,
        objectSize))
    {
        supObDumpShowError(hwndDlg, NULL);
        supHeapFree(object);
        return;
    }

    //
    // Object name
    //
    Header = NULL;
    switch (Context->ObjectTypeIndex) {
    case ObjectTypeEvent:
        lpType = T_KEVENT;
        Event = (KEVENT*)object;
        Header = &Event->Header;

        lpDescType = T_UnknownType;
        switch (Header->Type) {
        case NotificationEvent:
            lpDescType = T_EVENT_NOTIFICATION;
            break;
        case SynchronizationEvent:
            lpDescType = T_EVENT_SYNC;
            break;
        }

        //Event state
        lpDesc1 = T_Unknown;
        switch (Header->SignalState) {
        case 0:
            lpDesc1 = T_NONSIGNALED;
            break;
        case 1:
            lpDesc1 = T_SIGNALED;
            break;
        }

        lpDesc2 = NULL;
        if (Header->Size == (sizeof(KEVENT) / sizeof(ULONG))) {
            lpDesc2 = TEXT("sizeof(KEVENT)/sizeof(ULONG)");
        }
        break;

    case ObjectTypeMutant:
        lpType = T_KMUTANT;
        Mutant = (KMUTANT*)object;
        Header = &Mutant->Header;
        lpDesc1 = TEXT("Not Held");

        RtlSecureZeroMemory(szValue, sizeof(szValue));
        if (Mutant->OwnerThread != NULL) {

            RtlStringCchPrintfSecure(szValue,
                RTL_NUMBER_OF(szValue),
                TEXT("Held %d times"),
                Header->SignalState);

            lpDesc1 = szValue;
        }

        lpDesc2 = NULL;
        if (Header->Size == (sizeof(KMUTANT) / sizeof(ULONG))) {
            lpDesc2 = TEXT("sizeof(KMUTANT)/sizeof(ULONG)");
        }
        break;

    case ObjectTypeSemaphore:
        lpType = T_KSEMAPHORE;
        Semaphore = (KSEMAPHORE*)object;
        Header = &Semaphore->Header;

        lpDesc1 = TEXT("Count");
        lpDesc2 = NULL;
        if (Header->Size == (sizeof(KSEMAPHORE) / sizeof(ULONG))) {
            lpDesc2 = TEXT("sizeof(KSEMAPHORE)/sizeof(ULONG)");
        }
        break;

    case ObjectTypeTimer:
        lpType = T_KTIMER;
        Timer = (KTIMER*)object;
        Header = &Timer->Header;

        lpDescType = T_TIMER_SYNC;
        if (Header->TimerType == TimerNotificationObject) {
            lpDescType = T_TIMER_NOTIFICATION;
        }
        //Timer state
        lpDesc1 = T_Unknown;
        switch (Header->SignalState) {
        case 0:
            lpDesc1 = T_NONSIGNALED;
            break;
        case 1:
            lpDesc1 = T_SIGNALED;
            break;
        }
        lpDesc2 = NULL;
        break;

    }

    if (Header == NULL) {
        supObDumpShowError(hwndDlg, NULL);
        supHeapFree(object);
        return;
    }

    treeRootItem = supTreeListAddItem(
        hwndTreeList,
        NULL,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        lpType,
        NULL);

    if (treeRootItem) {

        //Header
        propObDumpDispatcherHeader(hwndTreeList, treeRootItem, Header, lpDescType, lpDesc1, lpDesc2);

        //type specific values
        switch (Context->ObjectTypeIndex) {
        case ObjectTypeMutant:
            if (Mutant) {
                propObDumpListEntry(hwndTreeList, treeRootItem, L"MutantListEntry", &Mutant->MutantListEntry);
                propObDumpAddress(hwndTreeList, treeRootItem, L"OwnerThread", T_PKTHREAD, Mutant->OwnerThread, 0, 0);
                propObDumpByte(hwndTreeList, treeRootItem, L"Abandoned", NULL, Mutant->Abandoned, 0, 0, TRUE);
                propObDumpByte(hwndTreeList, treeRootItem, L"ApcDisable", NULL, Mutant->ApcDisable, 0, 0, FALSE);
            }
            break;

        case ObjectTypeSemaphore:
            if (Semaphore) {
                propObDumpUlong(hwndTreeList, treeRootItem, L"Limit", NULL, Semaphore->Limit, TRUE, FALSE, 0, 0);
            }
            break;

        case ObjectTypeTimer:
            if (Timer) {
                propObDumpULargeInteger(hwndTreeList, treeRootItem, L"DueTime", &Timer->DueTime); //dumped as hex, not important
                propObDumpListEntry(hwndTreeList, treeRootItem, L"TimerListEntry", &Timer->TimerListEntry);
                propObDumpAddress(hwndTreeList, treeRootItem, L"Dpc", T_PKDPC, Timer->Dpc, 0, 0);
                propObDumpUlong(hwndTreeList, treeRootItem, L"Processor", NULL, Timer->Processor, TRUE, FALSE, 0, 0);
                propObDumpUlong(hwndTreeList, treeRootItem, L"Period", NULL, Timer->Period, TRUE, FALSE, 0, 0);
            }
            break;

        }
    }

    supHeapFree(object);
}

/*
* propObDumpObjectTypeFlags
*
* Purpose:
*
* Dump ObjectTypeFlags/ObjectTypeFlags2 bits to the treelist.
*
*/
VOID propObDumpObjectTypeFlags(
    _In_ HWND TreeList,
    _In_ LPWSTR EntryName,
    _In_ UCHAR ObjectTypeFlags,
    _In_ HTREEITEM h_tviSubItem,
    _In_ LPWSTR * ObjectTypeFlagsText,
    _In_ BOOLEAN SetEntry
)
{
    ULONG i, j;
    LPWSTR lpType;
    TL_SUBITEMS_FIXED subitems;

    WCHAR szValue[32];

    if (ObjectTypeFlags) {

        RtlSecureZeroMemory(&subitems, sizeof(subitems));
        subitems.Count = 2;

        j = 0;
        for (i = 0; i < 8; i++) {
            if (GET_BIT(ObjectTypeFlags, i)) {
                lpType = (LPWSTR)ObjectTypeFlagsText[i];
                subitems.Text[0] = T_EmptyString;
                if (j == 0) {

                    RtlSecureZeroMemory(szValue, sizeof(szValue));
                    RtlStringCchPrintfSecure(szValue,
                        RTL_NUMBER_OF(szValue),
                        FORMAT_HEXBYTE,
                        ObjectTypeFlags);

                    subitems.Text[0] = szValue;
                }
                subitems.Text[1] = lpType;
                supTreeListAddItem(TreeList,
                    h_tviSubItem,
                    TVIF_TEXT | TVIF_STATE,
                    0,
                    0,
                    (j == 0) ? ((SetEntry) ? EntryName : T_EmptyString) : T_EmptyString,
                    &subitems);
                j++;
            }
        }
    }
    else {
        if (SetEntry)
            propObDumpByte(TreeList, h_tviSubItem, EntryName, NULL, ObjectTypeFlags, 0, 0, FALSE);
    }
}

/*
* propObDumpObjectType
*
* Purpose:
*
* Dump OBJECT_TYPE members to the treelist.
*
*/
PROP_OBJECT_DUMP_ROUTINE(propObDumpObjectType)
{
    BOOLEAN bOkay, bSetEntry;
    USHORT waitObjectFlagOffset, waitObjectPointerOffset;
    UINT i;
    ULONG objectSize = 0, objectVersion = 0;
    ULONG keyValue;
    ULONG waitObjectFlagMask;
    ULONG selfDriverSize;
    PVOID selfDriverBase, lockPtr;
    HTREEITEM treeRootItem, treeSubItem, treeGenericMappingItem;
    LPWSTR lpType = NULL;
    POBEX_OBJECT_INFORMATION currentObject = NULL;
    PRTL_PROCESS_MODULES modulesList = NULL;

    PLIST_ENTRY pListEntry;
    TL_SUBITEMS_FIXED subItems;
    PVOID typeProcs[RTL_NUMBER_OF(T_OBJECT_TYPE_PROCS)];

    union {
        union {
            OBJECT_TYPE_COMPATIBLE* ObjectTypeCompatible;
            OBJECT_TYPE_7* ObjectType_7;
            OBJECT_TYPE_8* ObjectType_8;
            OBJECT_TYPE_RS1* ObjectType_RS1;
            OBJECT_TYPE_RS2* ObjectType_RS2;
        } Versions;
        PVOID Ref;
    } objectType;

    objectType.Ref = NULL;

    do {

        bOkay = FALSE;

        //
        // Get loaded modules list.
        //
        modulesList = (PRTL_PROCESS_MODULES)supGetLoadedModulesList(NULL);
        if (modulesList == NULL)
            break;

        //
        // Get the reference to the object.
        //
        currentObject = ObQueryObjectInDirectory(
            &Context->NtObjectName,
            ObGetPredefinedUnicodeString(OBP_OBTYPES));

        if (currentObject == NULL)
            break;

        //
        // Dump object information version aware.
        //
        objectType.Ref = ObDumpObjectTypeVersionAware(
            currentObject->ObjectAddress,
            &objectSize,
            &objectVersion);

        if (objectType.Ref == NULL)
            break;

        //
       // Add treelist root item ("OBJECT_TYPE").
       //
        treeRootItem = supTreeListAddItem(
            hwndTreeList,
            NULL,
            TVIF_TEXT | TVIF_STATE,
            TVIS_EXPANDED,
            TVIS_EXPANDED,
            T_OBJECT_TYPE,
            NULL);

        if (treeRootItem == NULL)
            break;

        //
        // This fields are structure version unaware.
        //
        propObDumpListEntry(hwndTreeList, treeRootItem, TEXT("TypeList"),
            &objectType.Versions.ObjectTypeCompatible->TypeList);

        propObDumpUnicodeString(hwndTreeList, treeRootItem, TEXT("Name"),
            &objectType.Versions.ObjectTypeCompatible->Name, FALSE);

        propObDumpAddress(hwndTreeList, treeRootItem, TEXT("DefaultObject"), NULL,
            objectType.Versions.ObjectTypeCompatible->DefaultObject, 0, 0);

        propObDumpByte(hwndTreeList, treeRootItem, T_TYPEINDEX, NULL,
            objectType.Versions.ObjectTypeCompatible->Index, 0, 0, FALSE);

        propObDumpUlong(hwndTreeList, treeRootItem, TEXT("TotalNumberOfObjects"), NULL,
            objectType.Versions.ObjectTypeCompatible->TotalNumberOfObjects, TRUE, FALSE, 0, 0);

        propObDumpUlong(hwndTreeList, treeRootItem, TEXT("TotalNumberOfHandles"), NULL,
            objectType.Versions.ObjectTypeCompatible->TotalNumberOfHandles, TRUE, FALSE, 0, 0);

        propObDumpUlong(hwndTreeList, treeRootItem, TEXT("HighWaterNumberOfObjects"), NULL,
            objectType.Versions.ObjectTypeCompatible->HighWaterNumberOfObjects, TRUE, FALSE, 0, 0);

        propObDumpUlong(hwndTreeList, treeRootItem, TEXT("HighWaterNumberOfHandles"), NULL,
            objectType.Versions.ObjectTypeCompatible->HighWaterNumberOfHandles, TRUE, FALSE, 0, 0);

        //
        // OBJECT_TYPE_INITIALIZER
        //
        RtlSecureZeroMemory(&subItems, sizeof(subItems));

        subItems.Count = 2;
        subItems.Text[0] = T_EmptyString;
        subItems.Text[1] = T_OBJECT_TYPE_INITIALIZER;
        treeSubItem = supTreeListAddItem(hwndTreeList, treeRootItem, TVIF_TEXT | TVIF_STATE, 0,
            0, TEXT("TypeInfo"), &subItems);

        if (treeSubItem) {
            propObDumpUlong(hwndTreeList, treeSubItem, T_LENGTH, NULL,
                objectType.Versions.ObjectTypeCompatible->TypeInfo.Length, TRUE, TRUE, 0, 0);

            //
            // Dump Object Type Flags / Extended Object Type Flags
            //
            propObDumpObjectTypeFlags(hwndTreeList,
                T_OBJECT_TYPE_FLAGS,
                objectType.Versions.ObjectTypeCompatible->TypeInfo.ObjectTypeFlags,
                treeSubItem,
                (LPWSTR*)T_ObjectTypeFlags,
                TRUE);

            if (objectVersion > OBVERSION_OBJECT_TYPE_V2) {

                if (objectVersion == OBVERSION_OBJECT_TYPE_V3) {
                    bSetEntry = TRUE;
                    lpType = T_OBJECT_TYPE_FLAGS2; //fu ms
                }
                else {
                    bSetEntry = FALSE;
                    lpType = T_OBJECT_TYPE_FLAGS;
                }

                propObDumpObjectTypeFlags(hwndTreeList,
                    lpType,
                    objectType.Versions.ObjectType_RS1->TypeInfo.ObjectTypeFlags2,
                    treeSubItem,
                    (LPWSTR*)T_ObjectTypeFlags2,
                    bSetEntry);

            }

            //
            // Structure version independent fields.
            //
            propObDumpUlong(hwndTreeList, treeSubItem, TEXT("ObjectTypeCode"), NULL,
                objectType.Versions.ObjectTypeCompatible->TypeInfo.ObjectTypeCode, TRUE, FALSE, 0, 0);

            propObDumpUlong(hwndTreeList, treeSubItem, TEXT("InvalidAttributes"), NULL,
                objectType.Versions.ObjectTypeCompatible->TypeInfo.InvalidAttributes, TRUE, FALSE, 0, 0);

            RtlSecureZeroMemory(&subItems, sizeof(subItems));
            subItems.Count = 2;
            subItems.Text[0] = T_EmptyString;
            subItems.Text[1] = T_GENERIC_MAPPING;

            //
            // GenericMapping
            //
            treeGenericMappingItem = supTreeListAddItem(hwndTreeList, treeSubItem, TVIF_TEXT | TVIF_STATE, 0,
                0, TEXT("GenericMapping"), &subItems);
            if (treeGenericMappingItem) {
                propObDumpUlong(hwndTreeList, treeGenericMappingItem, TEXT("GenericRead"), NULL,
                    objectType.Versions.ObjectTypeCompatible->TypeInfo.GenericMapping.GenericRead, TRUE, FALSE, 0, 0);
                propObDumpUlong(hwndTreeList, treeGenericMappingItem, TEXT("GenericWrite"), NULL,
                    objectType.Versions.ObjectTypeCompatible->TypeInfo.GenericMapping.GenericWrite, TRUE, FALSE, 0, 0);
                propObDumpUlong(hwndTreeList, treeGenericMappingItem, TEXT("GenericExecute"), NULL,
                    objectType.Versions.ObjectTypeCompatible->TypeInfo.GenericMapping.GenericExecute, TRUE, FALSE, 0, 0);
                propObDumpUlong(hwndTreeList, treeGenericMappingItem, TEXT("GenericAll"), NULL,
                    objectType.Versions.ObjectTypeCompatible->TypeInfo.GenericMapping.GenericAll, TRUE, FALSE, 0, 0);
            }

            propObDumpUlong(hwndTreeList, treeSubItem, TEXT("ValidAccessMask"), NULL,
                objectType.Versions.ObjectTypeCompatible->TypeInfo.ValidAccessMask, TRUE, FALSE, 0, 0);
            propObDumpUlong(hwndTreeList, treeSubItem, TEXT("RetainAccess"), NULL,
                objectType.Versions.ObjectTypeCompatible->TypeInfo.RetainAccess, TRUE, FALSE, 0, 0);

            //Pool Type
            lpType = T_Unknown;
            for (i = 0; i < RTL_NUMBER_OF(a_PoolTypes); i++) {
                if (objectType.Versions.ObjectTypeCompatible->TypeInfo.PoolType == (POOL_TYPE)a_PoolTypes[i].dwValue) {
                    lpType = a_PoolTypes[i].lpDescription;
                    break;
                }
            }

            propObDumpUlong(hwndTreeList, treeSubItem, TEXT("PoolType"), lpType,
                objectType.Versions.ObjectTypeCompatible->TypeInfo.PoolType, TRUE, FALSE, 0, 0);

            propObDumpUlong(hwndTreeList, treeSubItem, TEXT("DefaultPagedPoolCharge"), NULL,
                objectType.Versions.ObjectTypeCompatible->TypeInfo.DefaultPagedPoolCharge, TRUE, FALSE, 0, 0);

            propObDumpUlong(hwndTreeList, treeSubItem, TEXT("DefaultNonPagedPoolCharge"), NULL,
                objectType.Versions.ObjectTypeCompatible->TypeInfo.DefaultNonPagedPoolCharge, TRUE, FALSE, 0, 0);

            //
            // List callback procedures.
            //
            // Copy type procedures to temp array, assume DumpProcedure always first.
            //
            RtlSecureZeroMemory(typeProcs, sizeof(typeProcs));

            RtlCopyMemory(&typeProcs,  //-V512
                &objectType.Versions.ObjectTypeCompatible->TypeInfo.DumpProcedure,
                sizeof(typeProcs));

            //assume ntoskrnl first in list and list initialized
            selfDriverBase = modulesList->Modules[0].ImageBase;
            selfDriverSize = modulesList->Modules[0].ImageSize;

            for (i = 0; i < RTL_NUMBER_OF(T_OBJECT_TYPE_PROCS); i++) {
                if (typeProcs[i]) {
                    propObDumpAddressWithModule(hwndTreeList, treeSubItem, T_OBJECT_TYPE_PROCS[i], typeProcs[i],
                        modulesList, selfDriverBase, selfDriverSize);
                }
                else {
                    propObDumpAddress(hwndTreeList, treeSubItem, T_OBJECT_TYPE_PROCS[i], NULL, typeProcs[i], 0, 0);
                }
            }

            if (objectVersion > OBVERSION_OBJECT_TYPE_V1) {

                switch (objectVersion) {
                case OBVERSION_OBJECT_TYPE_V2:
                    waitObjectFlagMask = objectType.Versions.ObjectType_8->TypeInfo.WaitObjectFlagMask;
                    waitObjectFlagOffset = objectType.Versions.ObjectType_8->TypeInfo.WaitObjectFlagOffset;
                    waitObjectPointerOffset = objectType.Versions.ObjectType_8->TypeInfo.WaitObjectPointerOffset;
                    break;
                case OBVERSION_OBJECT_TYPE_V3:
                    waitObjectFlagMask = objectType.Versions.ObjectType_RS1->TypeInfo.WaitObjectFlagMask;
                    waitObjectFlagOffset = objectType.Versions.ObjectType_RS1->TypeInfo.WaitObjectFlagOffset;
                    waitObjectPointerOffset = objectType.Versions.ObjectType_RS1->TypeInfo.WaitObjectPointerOffset;
                    break;
                default:
                    waitObjectFlagMask = objectType.Versions.ObjectType_RS2->TypeInfo.WaitObjectFlagMask;
                    waitObjectFlagOffset = objectType.Versions.ObjectType_RS2->TypeInfo.WaitObjectFlagOffset;
                    waitObjectPointerOffset = objectType.Versions.ObjectType_RS2->TypeInfo.WaitObjectPointerOffset;
                    break;
                }

                propObDumpUlong(hwndTreeList, treeSubItem, TEXT("WaitObjectFlagMask"), NULL, waitObjectFlagMask, TRUE, FALSE, 0, 0);
                propObDumpUlong(hwndTreeList, treeSubItem, TEXT("WaitObjectFlagOffset"), NULL, waitObjectFlagOffset, TRUE, TRUE, 0, 0);
                propObDumpUlong(hwndTreeList, treeSubItem, TEXT("WaitObjectPointerOffset"), NULL, waitObjectPointerOffset, TRUE, TRUE, 0, 0);
            }
        }//treeSubItem

        //
        // Rest of OBJECT_TYPE
        //
        switch (objectVersion) {
        case OBVERSION_OBJECT_TYPE_V1: //7
            keyValue = objectType.Versions.ObjectType_7->Key;
            lockPtr = objectType.Versions.ObjectType_7->TypeLock.Ptr;
            pListEntry = &objectType.Versions.ObjectType_7->CallbackList;
            break;

        case OBVERSION_OBJECT_TYPE_V2: //8+
            keyValue = objectType.Versions.ObjectType_8->Key;
            lockPtr = objectType.Versions.ObjectType_8->TypeLock.Ptr;
            pListEntry = &objectType.Versions.ObjectType_8->CallbackList;
            break;

        case OBVERSION_OBJECT_TYPE_V3: //RS1
            keyValue = objectType.Versions.ObjectType_RS1->Key;
            lockPtr = objectType.Versions.ObjectType_RS1->TypeLock.Ptr;
            pListEntry = &objectType.Versions.ObjectType_RS1->CallbackList;
            break;

        default: //RS2+
            keyValue = objectType.Versions.ObjectType_RS2->Key;
            lockPtr = objectType.Versions.ObjectType_RS2->TypeLock.Ptr;
            pListEntry = &objectType.Versions.ObjectType_RS2->CallbackList;
            break;
        }

        propObDumpPushLock(hwndTreeList, treeRootItem, lockPtr, 0, 0);
        propObDumpUlong(hwndTreeList, treeRootItem, TEXT("Key"), NULL, keyValue, TRUE, FALSE, 0, 0);
        propObDumpListEntry(hwndTreeList, treeRootItem, TEXT("CallbackList"), pListEntry);

        bOkay = TRUE;

    } while (FALSE);

    //
    // Cleanup.
    //
    if (modulesList) supHeapFree(modulesList);
    if (objectType.Ref) supVirtualFree(objectType.Ref);
    if (currentObject) supHeapFree(currentObject);

    //
    // Show error message on failure.
    //
    if (bOkay == FALSE) {
        supObDumpShowError(hwndDlg, NULL);
        return;
    }
}

/*
* propObDumpQueueObject
*
* Purpose:
*
* Dump KQUEUE members to the treelist.
*
*/
PROP_OBJECT_DUMP_ROUTINE(propObDumpQueueObject)
{
    HTREEITEM treeRootItem;
    LPWSTR    lpDesc2;
    KQUEUE    Queue;

    //dump Queue object
    RtlSecureZeroMemory(&Queue, sizeof(Queue));

    if (!kdReadSystemMemory(
        Context->ObjectInfo.ObjectAddress,
        &Queue,
        sizeof(Queue)))
    {
        supObDumpShowError(hwndDlg, NULL);
        return;
    }

    lpDesc2 = NULL;
    if (Queue.Header.Size == (sizeof(KQUEUE) / sizeof(ULONG))) {
        lpDesc2 = TEXT("sizeof(KQUEUE)/sizeof(ULONG)");
    }

    treeRootItem = supTreeListAddItem(
        hwndTreeList,
        NULL,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        T_KQUEUE,
        NULL);

    if (treeRootItem) {
        //Header
        propObDumpDispatcherHeader(hwndTreeList, treeRootItem, &Queue.Header, NULL, NULL, lpDesc2);

        //EntryListHead
        propObDumpListEntry(hwndTreeList, treeRootItem, TEXT("EntryListHead"), &Queue.EntryListHead);

        //CurrentCount
        propObDumpUlong(hwndTreeList, treeRootItem, TEXT("CurrentCount"), NULL, Queue.CurrentCount, TRUE, FALSE, 0, 0);

        //MaximumCount
        propObDumpUlong(hwndTreeList, treeRootItem, TEXT("MaximumCount"), NULL, Queue.MaximumCount, TRUE, FALSE, 0, 0);

        //ThreadListHead
        propObDumpListEntry(hwndTreeList, treeRootItem, TEXT("ThreadListHead"), &Queue.ThreadListHead);
    }
}

/*
* propObxComposeFltFilterCompatibleForm
*
* Purpose:
*
* Build easy to access object structure from different structure variants.
*
*/
VOID propObxComposeFltFilterCompatibleForm(
    _In_ PVOID ObjectBuffer,
    _In_ ULONG ObjectVersion,
    _Out_ FLT_FILTER_COMPATIBLE * ComposedObject
)
{
    union {
        union {
            FLT_FILTER_V1* V1;
            FLT_FILTER_V2* V2;
            FLT_FILTER_V3* V3;
            FLT_FILTER_V4* V4;
            FLT_FILTER_V5* V5;
        } u1;
        PBYTE Ref;
    } FltFilter;

    RtlSecureZeroMemory(ComposedObject, sizeof(FLT_FILTER_COMPATIBLE));

    FltFilter.Ref = (PBYTE)ObjectBuffer;

    if (ObjectVersion == OBVERSION_FLT_FILTER_V5)
    {
        RtlCopyMemory(&ComposedObject->Base, &FltFilter.u1.V5->Base, sizeof(FLT_OBJECT_V3));
    }
    else {
        //
        // Same offset.
        //
        RtlCopyMemory(&ComposedObject->Base, &FltFilter.u1.V1->Base, sizeof(FLT_OBJECT));

        //
        // UniqueIdentifier
        //
        if (ObjectVersion >= OBVERSION_FLT_FILTER_V3)
            ComposedObject->Base.UniqueIdentifier = FltFilter.u1.V3->Base.UniqueIdentifier;
    }

    switch (ObjectVersion) {

    case OBVERSION_FLT_FILTER_V1:
    case OBVERSION_FLT_FILTER_V2:
        ComposedObject->Frame = FltFilter.u1.V1->Frame;
        ComposedObject->Name = FltFilter.u1.V1->Name;
        ComposedObject->DefaultAltitude = FltFilter.u1.V1->DefaultAltitude;
        ComposedObject->DriverObject = FltFilter.u1.V1->DriverObject;
        ComposedObject->VerifiedFiltersLink = FltFilter.u1.V1->VerifiedFiltersLink;
        ComposedObject->FilterUnload = FltFilter.u1.V1->FilterUnload;
        ComposedObject->InstanceSetup = FltFilter.u1.V1->InstanceSetup;
        ComposedObject->InstanceQueryTeardown = FltFilter.u1.V1->InstanceQueryTeardown;
        ComposedObject->InstanceTeardownStart = FltFilter.u1.V1->InstanceTeardownStart;
        ComposedObject->InstanceTeardownComplete = FltFilter.u1.V1->InstanceTeardownComplete;
        ComposedObject->PreVolumeMount = FltFilter.u1.V1->PreVolumeMount;
        ComposedObject->PostVolumeMount = FltFilter.u1.V1->PostVolumeMount;
        ComposedObject->GenerateFileName = FltFilter.u1.V1->GenerateFileName;
        ComposedObject->NormalizeNameComponent = FltFilter.u1.V1->NormalizeNameComponent;
        ComposedObject->NormalizeNameComponentEx = FltFilter.u1.V1->NormalizeNameComponentEx;
        ComposedObject->NormalizeContextCleanup = FltFilter.u1.V1->NormalizeContextCleanup;
        ComposedObject->KtmNotification = FltFilter.u1.V1->KtmNotification;
        if (ObjectVersion == OBVERSION_FLT_FILTER_V2) {
            ComposedObject->SectionNotification = FltFilter.u1.V2->SectionNotification;
            ComposedObject->OldDriverUnload = FltFilter.u1.V2->OldDriverUnload;
        }
        else {
            ComposedObject->OldDriverUnload = FltFilter.u1.V1->OldDriverUnload;
        }

        break;

    case OBVERSION_FLT_FILTER_V3:
    case OBVERSION_FLT_FILTER_V4:
        ComposedObject->Frame = FltFilter.u1.V3->Frame;
        ComposedObject->Name = FltFilter.u1.V3->Name;
        ComposedObject->DefaultAltitude = FltFilter.u1.V3->DefaultAltitude;
        ComposedObject->DriverObject = FltFilter.u1.V3->DriverObject;
        ComposedObject->VerifiedFiltersLink = FltFilter.u1.V3->VerifiedFiltersLink;
        ComposedObject->FilterUnload = FltFilter.u1.V3->FilterUnload;
        ComposedObject->InstanceSetup = FltFilter.u1.V3->InstanceSetup;
        ComposedObject->InstanceQueryTeardown = FltFilter.u1.V3->InstanceQueryTeardown;
        ComposedObject->InstanceTeardownStart = FltFilter.u1.V3->InstanceTeardownStart;
        ComposedObject->InstanceTeardownComplete = FltFilter.u1.V3->InstanceTeardownComplete;
        ComposedObject->PreVolumeMount = FltFilter.u1.V3->PreVolumeMount;
        ComposedObject->PostVolumeMount = FltFilter.u1.V3->PostVolumeMount;
        ComposedObject->GenerateFileName = FltFilter.u1.V3->GenerateFileName;
        ComposedObject->NormalizeNameComponent = FltFilter.u1.V3->NormalizeNameComponent;
        ComposedObject->NormalizeNameComponentEx = FltFilter.u1.V3->NormalizeNameComponentEx;
        ComposedObject->NormalizeContextCleanup = FltFilter.u1.V3->NormalizeContextCleanup;
        ComposedObject->KtmNotification = FltFilter.u1.V3->KtmNotification;
        ComposedObject->SectionNotification = FltFilter.u1.V3->SectionNotification;
        ComposedObject->OldDriverUnload = FltFilter.u1.V3->OldDriverUnload;
        break;
    case OBVERSION_FLT_FILTER_V5:
    default:
        ComposedObject->Frame = FltFilter.u1.V5->Frame;
        ComposedObject->Name = FltFilter.u1.V5->Name;
        ComposedObject->DefaultAltitude = FltFilter.u1.V5->DefaultAltitude;
        ComposedObject->DriverObject = FltFilter.u1.V5->DriverObject;
        ComposedObject->VerifiedFiltersLink = FltFilter.u1.V5->VerifiedFiltersLink;
        ComposedObject->FilterUnload = FltFilter.u1.V5->FilterUnload;
        ComposedObject->InstanceSetup = FltFilter.u1.V5->InstanceSetup;
        ComposedObject->InstanceQueryTeardown = FltFilter.u1.V5->InstanceQueryTeardown;
        ComposedObject->InstanceTeardownStart = FltFilter.u1.V5->InstanceTeardownStart;
        ComposedObject->InstanceTeardownComplete = FltFilter.u1.V5->InstanceTeardownComplete;
        ComposedObject->PreVolumeMount = FltFilter.u1.V5->PreVolumeMount;
        ComposedObject->PostVolumeMount = FltFilter.u1.V5->PostVolumeMount;
        ComposedObject->GenerateFileName = FltFilter.u1.V5->GenerateFileName;
        ComposedObject->NormalizeNameComponent = FltFilter.u1.V5->NormalizeNameComponent;
        ComposedObject->NormalizeNameComponentEx = FltFilter.u1.V5->NormalizeNameComponentEx;
        ComposedObject->NormalizeContextCleanup = FltFilter.u1.V5->NormalizeContextCleanup;
        ComposedObject->KtmNotification = FltFilter.u1.V5->KtmNotification;
        ComposedObject->SectionNotification = FltFilter.u1.V5->SectionNotification;
        ComposedObject->OldDriverUnload = FltFilter.u1.V5->OldDriverUnload;
        break;
    }
}

typedef struct _FLT_FILTER_CALLBACK_ENTRY {
    LPWSTR Name;
    PVOID Address;
} FLT_FILTER_CALLBACK_ENTRY, * PFLT_FILTER_CALLBACK_ENTRY;

/*
* propObxDumpFltFilter
*
* Purpose:
*
* Dump FLT_FILTER members to the treelist.
*
*/
VOID propObxDumpFltFilter(
    _In_ HWND TreeList,
    _In_ HTREEITEM RootItem,
    _In_ PVOID Address,
    _In_ PRTL_PROCESS_MODULES LoadedModules
)
{
    HTREEITEM parentSubItem, subItem;
    ULONG objectVersion, objectSize = 0;
    PVOID pvFltObject;
    TL_SUBITEMS_FIXED subitems;
    WCHAR szValue[MAX_TEXT_CONVERSION_ULONG64];

    FLT_FILTER_COMPATIBLE compatObject;

    pvFltObject = ObDumpFltFilterObjectVersionAware((ULONG_PTR)Address, &objectSize, &objectVersion);
    if (pvFltObject == NULL) {
        //
        // Cannot read, abort.
        //
        propObDumpAddress(TreeList, RootItem, T_FILTER, T_PFLT_FILTER, Address, 0, 0);
        return;
    }

    propObxComposeFltFilterCompatibleForm(pvFltObject, objectVersion, &compatObject);

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    szValue[0] = UNICODE_NULL;
    subitems.Text[0] = propObFormatAddress64OrNull(Address, szValue);
    subitems.Text[1] = T_PFLT_FILTER;
    subitems.Count = 2;

    parentSubItem = supTreeListAddItem(
        TreeList,
        RootItem,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        T_FILTER,
        &subitems);

    if (parentSubItem) {

        //
        // Base (FLT_OBJECT)
        //

        RtlSecureZeroMemory(&subitems, sizeof(subitems));
        subitems.Text[0] = T_EmptyString;
        subitems.Text[1] = T_FLT_OBJECT;
        subitems.Count = 2;

        subItem = supTreeListAddItem(
            TreeList,
            parentSubItem,
            TVIF_TEXT | TVIF_STATE,
            TVIS_EXPANDED,
            TVIS_EXPANDED,
            TEXT("Base"),
            &subitems);

        if (subItem) {

            propObDumpUlong(TreeList,
                subItem,
                T_FLAGS,
                NULL,
                compatObject.Base.Flags, //FLT_OBJECT_FLAGS
                TRUE, FALSE,
                (COLORREF)0,
                (COLORREF)0);

            propObDumpUlong(TreeList,
                subItem,
                TEXT("PointerCount"),
                NULL,
                compatObject.Base.PointerCount,
                TRUE, FALSE,
                (COLORREF)0,
                (COLORREF)0);

            propObDumpAddress(TreeList,
                subItem,
                TEXT("RundownRef"),
                T_EX_RUNDOWN_REF,
                compatObject.Base.RundownRef.Ptr,
                (COLORREF)0,
                (COLORREF)0);

            propObDumpListEntry(TreeList,
                subItem,
                TEXT("PrimaryLinks"),
                &compatObject.Base.PrimaryLink);

            if (objectVersion >= OBVERSION_FLT_FILTER_V3) {
                propObDumpGUID(TreeList,
                    subItem,
                    TEXT("UniqueIdentifier"),
                    &compatObject.Base.UniqueIdentifier);
            }

        } // FLT_OBJECT Base

        //
        // Frame.
        //
        propObDumpAddress(TreeList, parentSubItem, TEXT("Frame"), T_PFLTP_FRAME, compatObject.Frame, 0, 0);

        //
        // Name.
        //        
        propObDumpUnicodeString(TreeList,
            parentSubItem,
            TEXT("Name"),
            &compatObject.Name,
            FALSE);

        //
        // DefaultAltitude.
        //
        propObDumpUnicodeString(TreeList,
            parentSubItem,
            TEXT("DefaultAltitude"),
            &compatObject.DefaultAltitude,
            FALSE);

        //
        // DriverObject.
        //
        propDumpObjectForAddress(TreeList,
            parentSubItem,
            T_FIELD_DRIVER_OBJECT,
            compatObject.DriverObject,
            CLR_INVL,
            T_REFNOTFOUND);

        FLT_FILTER_CALLBACK_ENTRY callbacks[] = {
            { TEXT("FilterUnload"), compatObject.FilterUnload },
            { TEXT("InstanceSetup"), compatObject.InstanceSetup },
            { TEXT("InstanceQueryTeardown"), compatObject.InstanceQueryTeardown },
            { TEXT("InstanceTeardownStart"), compatObject.InstanceTeardownStart },
            { TEXT("InstanceTeardownComplete"), compatObject.InstanceTeardownComplete },
            { TEXT("PreVolumeMount"), compatObject.PreVolumeMount },
            { TEXT("PostVolumeMount"), compatObject.PostVolumeMount },
            { TEXT("GenerateFileName"), compatObject.GenerateFileName },
            { TEXT("NormalizeNameComponent"), compatObject.NormalizeNameComponent },
            { TEXT("NormalizeNameComponentEx"), compatObject.NormalizeNameComponentEx },
            { TEXT("NormalizeContextCleanup"), compatObject.NormalizeContextCleanup },
            { TEXT("KtmNotification"), compatObject.KtmNotification },
            { TEXT("SectionNotification"), compatObject.SectionNotification },
            { TEXT("OldDriverUnload"), compatObject.OldDriverUnload }
        };

        for (ULONG i = 0; i < RTL_NUMBER_OF(callbacks); i++) {
            propObDumpAddressWithModuleIfNotNull(TreeList,
                parentSubItem,
                callbacks[i].Name,
                callbacks[i].Address,
                LoadedModules);
        }
    }

    supVirtualFree(pvFltObject);
}

/*
* propObDumpFltServerPort
*
* Purpose:
*
* Dump FLT_SERVER_PORT_OBJECT members to the treelist.
*
*/
PROP_OBJECT_DUMP_ROUTINE(propObDumpFltServerPort)
{
    HTREEITEM treeRootItem;
    PRTL_PROCESS_MODULES pModules = NULL;
    FLT_SERVER_PORT_OBJECT FltServerPortObject;

    //dump PortObject
    RtlSecureZeroMemory(&FltServerPortObject, sizeof(FltServerPortObject));

    if (!kdReadSystemMemory(
        Context->ObjectInfo.ObjectAddress,
        &FltServerPortObject,
        sizeof(FltServerPortObject)))
    {
        supObDumpShowError(hwndDlg, NULL);
        return;
    }

    pModules = (PRTL_PROCESS_MODULES)supGetLoadedModulesList(NULL);
    if (pModules) {

        treeRootItem = supTreeListAddItem(
            hwndTreeList,
            NULL,
            TVIF_TEXT | TVIF_STATE,
            TVIS_EXPANDED,
            TVIS_EXPANDED,
            T_FLT_SERVER_PORT_OBJECT,
            NULL);

        if (treeRootItem) {

            propObDumpListEntry(hwndTreeList, treeRootItem, L"FilterLink", &FltServerPortObject.FilterLink);

            propObDumpAddressWithModule(hwndTreeList, treeRootItem, L"ConnectNotify",
                FltServerPortObject.ConnectNotify, pModules, NULL, 0);

            propObDumpAddressWithModule(hwndTreeList, treeRootItem, L"DisconnectNotify",
                FltServerPortObject.DisconnectNotify, pModules, NULL, 0);

            propObDumpAddressWithModule(hwndTreeList, treeRootItem, L"MessageNotify",
                FltServerPortObject.MessageNotify, pModules, NULL, 0);

            propObxDumpFltFilter(hwndTreeList, treeRootItem, FltServerPortObject.Filter, pModules);

            propObDumpAddress(hwndTreeList, treeRootItem, L"Cookie", NULL, FltServerPortObject.Cookie, 0, 0);
            propObDumpUlong(hwndTreeList, treeRootItem, L"Flags", NULL, FltServerPortObject.Flags, TRUE, FALSE, 0, 0);
            propObDumpLong(hwndTreeList, treeRootItem, L"NumberOfConnections", NULL, FltServerPortObject.NumberOfConnections, TRUE, 0, 0);
            propObDumpLong(hwndTreeList, treeRootItem, L"MaxConnections", NULL, FltServerPortObject.MaxConnections, TRUE, 0, 0);

        }

        supHeapFree(pModules);
    }
    else {
        supObDumpShowError(hwndDlg, NULL);
    }
}

/*
* propObxDumpAlpcPortCommunicationInfo
*
* Purpose:
*
* Dump ALPC_PORT->CommunicationInfo substructure to the treelist.
*
*/
VOID propObxDumpAlpcPortCommunicationInfo(
    _In_ HWND TreeList,
    _In_ ULONG StructureVersion,
    _In_ ULONG_PTR StructureAddress,
    _In_ HTREEITEM h_tviRootItem
)
{
    HTREEITEM treeRootItem;
    PBYTE dumpBuffer = NULL;
    ULONG bufferSize = 0, readSize = 0;

    union {
        union {
            ALPC_COMMUNICATION_INFO_V1* CommInfoV1;
            ALPC_COMMUNICATION_INFO_V2* CommInfoV2;
        } u1;
        PBYTE Ref;
    } AlpcPortCommunicationInfo;

    if ((StructureVersion == 0) || (StructureVersion > 2)) return;

    if (StructureVersion == 1) {
        bufferSize = sizeof(ALPC_COMMUNICATION_INFO_V1);
    }
    else {
        bufferSize = sizeof(ALPC_COMMUNICATION_INFO_V2);
    }

    readSize = bufferSize;
    bufferSize = ALIGN_UP_BY(bufferSize, PAGE_SIZE);
    dumpBuffer = (PBYTE)supVirtualAlloc(bufferSize);
    if (dumpBuffer == NULL)
        return;

    if (!kdReadSystemMemory(
        StructureAddress,
        dumpBuffer,
        readSize))
    {
        supVirtualFree(dumpBuffer);
        return;
    }

    AlpcPortCommunicationInfo.Ref = dumpBuffer;

    //
    // Dump version unaffected fields.
    //
    propObDumpAddress(
        TreeList,
        h_tviRootItem,
        TEXT("ConnectionPort"),
        T_PALPC_PORT_OBJECT,
        (PVOID)AlpcPortCommunicationInfo.u1.CommInfoV1->ConnectionPort,
        0,
        0);

    propObDumpAddress(
        TreeList,
        h_tviRootItem,
        TEXT("ServerCommunicationPort"),
        T_PALPC_PORT_OBJECT,
        (PVOID)AlpcPortCommunicationInfo.u1.CommInfoV1->ServerCommunicationPort,
        0,
        0);

    propObDumpAddress(
        TreeList,
        h_tviRootItem,
        TEXT("ClientCommunicationPort"),
        T_PALPC_PORT_OBJECT,
        (PVOID)AlpcPortCommunicationInfo.u1.CommInfoV1->ClientCommunicationPort,
        0,
        0);

    propObDumpListEntry(
        TreeList,
        h_tviRootItem,
        TEXT("CommunicationList"),
        &AlpcPortCommunicationInfo.u1.CommInfoV1->CommunicationList);

    //
    //  PALPC_HANDLE_ENTRY dump.
    //
    treeRootItem = supTreeListAddItem(
        TreeList,
        h_tviRootItem,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        T_ALPC_HANDLE_TABLE,
        NULL);
    if (treeRootItem) {
        propObDumpAddress(
            TreeList,
            treeRootItem,
            TEXT("Handles"),
            TEXT("PALPC_HANDLE_ENTRY"),
            (PVOID)AlpcPortCommunicationInfo.u1.CommInfoV1->HandleTable.Handles,
            0,
            0);

        propObDumpUlong(
            TreeList,
            treeRootItem,
            TEXT("TotalHandles"),
            NULL,
            AlpcPortCommunicationInfo.u1.CommInfoV1->HandleTable.TotalHandles,
            TRUE,
            FALSE,
            0,
            0);

        propObDumpUlong(
            TreeList,
            treeRootItem,
            TEXT("Flags"),
            NULL,
            AlpcPortCommunicationInfo.u1.CommInfoV1->HandleTable.Flags,
            TRUE,
            FALSE,
            0,
            0);

        propObDumpPushLock(
            TreeList,
            treeRootItem,
            AlpcPortCommunicationInfo.u1.CommInfoV1->HandleTable.Lock.Ptr,
            0,
            0);

    } //treeRootItem

    //
    // Version specific field.
    //
    if (StructureVersion == 2) {
        propObDumpAddress(
            TreeList,
            h_tviRootItem,
            TEXT("CloseMessage"),
            TEXT("PKALPC_MESSAGE"),
            (PVOID)AlpcPortCommunicationInfo.u1.CommInfoV2->CloseMessage,
            0,
            0);
    }
    supVirtualFree(dumpBuffer);
}

/*
* propObDumpAlpcPort
*
* Purpose:
*
* Dump ALPC_PORT members to the treelist.
*
*/
PROP_OBJECT_DUMP_ROUTINE(propObDumpAlpcPort)
{
    ULONG objectSize = 0, objectVersion = 0, i, c;
    HTREEITEM treeRootItem, treeSubItem;

    ALPC_PORT_ATTRIBUTES* portAttributes;
    ALPC_PORT_STATE portState;
    TL_SUBITEMS_FIXED subitems;

    WCHAR szValue[32];

    union {
        union {
            ALPC_PORT_7600* Port7600;
            ALPC_PORT_9200* Port9200;
            ALPC_PORT_9600* Port9600;
            ALPC_PORT_10240* Port10240;
        } u1;
        PBYTE Ref;
    } AlpcPort;

    AlpcPort.Ref = (PBYTE)ObDumpAlpcPortObjectVersionAware(
        Context->ObjectInfo.ObjectAddress,
        &objectSize,
        &objectVersion);

    if (AlpcPort.Ref == NULL) {
        supObDumpShowError(hwndDlg, NULL);
        return;
    }

    treeRootItem = supTreeListAddItem(
        hwndTreeList,
        NULL,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        T_ALPC_PORT_OBJECT,
        NULL);

    if (treeRootItem == NULL) {
        supVirtualFree(AlpcPort.Ref);
        supObDumpShowError(hwndDlg, NULL);
        return;
    }

    //
    //  Dump AlpcPort->PortListEntry, same offset for every supported Windows.
    //   
    propObDumpListEntry(
        hwndTreeList,
        treeRootItem,
        TEXT("PortListEntry"),
        &AlpcPort.u1.Port7600->PortListEntry);

    //
    //  Dump AlpcPort->CommunicationInfo, same offset for every supported Windows, however target structure is version aware.
    // 

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 2;
    szValue[0] = UNICODE_NULL;
    subitems.Text[0] = propObFormatAddress64OrNull(AlpcPort.u1.Port7600->CommunicationInfo, szValue);
    subitems.Text[1] = TEXT("PALPC_COMMUNICATION_INFO");

    treeSubItem = supTreeListAddItem(
        hwndTreeList,
        treeRootItem,
        TVIF_TEXT,
        0,
        0,
        TEXT("CommunicationInfo"),
        &subitems);
    if (treeSubItem) {
        propObxDumpAlpcPortCommunicationInfo(hwndTreeList,
            (objectVersion > OBVERSION_ALPCPORT_V2) ? 2 : 1,
            (ULONG_PTR)AlpcPort.u1.Port7600->CommunicationInfo,
            treeSubItem);
    }

    //
    //  Dump AlpcPort->OwnerProcess, same offset for every supported Windows, however target structure is version aware.
    //
    propObDumpAddress(
        hwndTreeList,
        treeRootItem,
        TEXT("Owner"),
        TEXT("PEPROCESS"),
        (PVOID)AlpcPort.u1.Port7600->OwnerProcess,
        0,
        0);

    //
    //  Dump AlpcPort->CompletionPort, same offset for every supported Windows.
    //
    propObDumpAddress(
        hwndTreeList,
        treeRootItem,
        TEXT("CompletionPort"),
        NULL,
        (PVOID)AlpcPort.u1.Port7600->CompletionPort,
        0,
        0);

    //
    //  Dump AlpcPort->CompletionKey, same offset for every supported Windows.
    //
    propObDumpAddress(
        hwndTreeList,
        treeRootItem,
        TEXT("CompletionKey"),
        NULL,
        (PVOID)AlpcPort.u1.Port7600->CompletionKey,
        0,
        0);

    //
    //  Dump AlpcPort->CompletionPacketLookaside, same offset for every supported Windows, however target structure is version aware.
    //
    propObDumpAddress(
        hwndTreeList,
        treeRootItem,
        TEXT("CompletionPacketLookaside"),
        TEXT("PALPC_COMPLETION_PACKET_LOOKASIDE"),
        (PVOID)AlpcPort.u1.Port7600->CompletionPacketLookaside,
        0,
        0);

    //
    //  Dump AlpcPort->PortContext, same offset for every supported Windows.
    //
    propObDumpAddress(
        hwndTreeList,
        treeRootItem,
        TEXT("PortContext"),
        NULL,
        (PVOID)AlpcPort.u1.Port7600->PortContext,
        0,
        0);

    //
    //  Dump AlpcPort->StaticSecurity, same offset for every supported Windows.
    //
    /*
    propObDumpSqos(
        hwndTreeList,
        treeRootItem,
        &AlpcPort.u1.Port7600->StaticSecurity.SecurityQos);
    */

    //
    // Dump AlpcPort->PortAttributes, offset is version aware.
    //
    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 2;
    subitems.Text[0] = T_EmptyString;
    subitems.Text[1] = TEXT("ALPC_PORT_ATTRIBUTES");

    treeSubItem = supTreeListAddItem(
        hwndTreeList,
        treeRootItem,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        TEXT("PortAttributes"),
        &subitems);

    switch (objectVersion) {
    case OBVERSION_ALPCPORT_V1:
        portAttributes = &AlpcPort.u1.Port7600->PortAttributes;
        break;
    case OBVERSION_ALPCPORT_V2:
        portAttributes = &AlpcPort.u1.Port9200->PortAttributes;
        break;
    case OBVERSION_ALPCPORT_V3:
        portAttributes = &AlpcPort.u1.Port9600->PortAttributes;
        break;
    case OBVERSION_ALPCPORT_V4:
        portAttributes = &AlpcPort.u1.Port10240->PortAttributes;
        break;
    default:
        portAttributes = NULL;
        break;
    }

    if (portAttributes && treeSubItem) {

        propObDumpUlong(
            hwndTreeList,
            treeSubItem,
            T_FLAGS,
            NULL,
            portAttributes->Flags,
            TRUE,
            FALSE,
            0,
            0);

        propObDumpSqos(
            hwndTreeList,
            treeSubItem,
            &portAttributes->SecurityQos);

        propObDumpUlong64(
            hwndTreeList,
            treeSubItem,
            TEXT("MaxMessageLength"),
            NULL,
            (ULONG64)portAttributes->MaxMessageLength,
            FALSE,
            0,
            0);

        propObDumpUlong64(
            hwndTreeList,
            treeSubItem,
            TEXT("MemoryBandwidth"),
            NULL,
            (ULONG64)portAttributes->MemoryBandwidth,
            FALSE,
            0,
            0);

        propObDumpUlong64(
            hwndTreeList,
            treeSubItem,
            TEXT("MaxPoolUsage"),
            NULL,
            (ULONG64)portAttributes->MaxPoolUsage,
            FALSE,
            0,
            0);

        propObDumpUlong64(
            hwndTreeList,
            treeSubItem,
            TEXT("MaxSectionSize"),
            NULL,
            (ULONG64)portAttributes->MaxSectionSize,
            FALSE,
            0,
            0);

        propObDumpUlong64(
            hwndTreeList,
            treeSubItem,
            TEXT("MaxViewSize"),
            NULL,
            (ULONG64)portAttributes->MaxViewSize,
            FALSE,
            0,
            0);

        propObDumpUlong64(
            hwndTreeList,
            treeSubItem,
            TEXT("MaxTotalSectionSize"),
            NULL,
            (ULONG64)portAttributes->MaxTotalSectionSize,
            FALSE,
            0,
            0);

        propObDumpUlong(
            hwndTreeList,
            treeSubItem,
            TEXT("DupObjectTypes"),
            NULL,
            portAttributes->DupObjectTypes,
            FALSE,
            FALSE,
            0,
            0);
    }

    //
    // Dump AlpcPort->State, offset is version aware.
    //
    treeSubItem = supTreeListAddItem(
        hwndTreeList,
        treeRootItem,
        TVIF_TEXT,
        0,
        0,
        TEXT("State"),
        NULL);

    if (treeSubItem) {
        portState.State = 0;

        switch (objectVersion) {
        case OBVERSION_ALPCPORT_V1:
            portState.State = AlpcPort.u1.Port7600->u1.State;
            break;
        case OBVERSION_ALPCPORT_V2:
            portState.State = AlpcPort.u1.Port9200->u1.State;
            break;
        case OBVERSION_ALPCPORT_V3:
            portState.State = AlpcPort.u1.Port9600->u1.State;
            break;
        case OBVERSION_ALPCPORT_V4:
            portState.State = AlpcPort.u1.Port10240->u1.State;
            break;
        }

        for (i = 0; i < RTL_NUMBER_OF(T_ALPC_PORT_STATE); i++) {
            if (i == 1) {
                c = (BYTE)portState.s1.Type;
            }
            else {
                c = GET_BIT(portState.State, i);
            }
            propObDumpByte(
                hwndTreeList,
                treeSubItem,
                T_ALPC_PORT_STATE[i],
                NULL,
                (BYTE)c,
                0,
                0,
                FALSE);

        }
    }
    supVirtualFree(AlpcPort.Ref);
}

/*
* propObDumpCallback
*
* Purpose:
*
* Dump CALLBACK_OBJECT callback members to the treelist.
*
*/
PROP_OBJECT_DUMP_ROUTINE(propObDumpCallback)
{
    SIZE_T callbacksCount;
    ULONG_PTR listHead;
    LPWSTR objectName;
    HTREEITEM treeRootItem;
    PRTL_PROCESS_MODULES pModules;
    LIST_ENTRY listEntry;
    CALLBACK_OBJECT objectDump;
    CALLBACK_REGISTRATION callbackRegistration;
    UNICODE_STRING normalizedName;

    //
    // Read object body.
    //
    RtlSecureZeroMemory(&objectDump, sizeof(CALLBACK_OBJECT));

    if (!kdReadSystemMemory(
        Context->ObjectInfo.ObjectAddress,
        (PVOID)&objectDump,
        sizeof(CALLBACK_OBJECT)))
    {
        supObDumpShowError(hwndDlg, NULL);
        return;
    }

    //
    // Verify object signature.
    //
    if (objectDump.Signature != EX_CALLBACK_SIGNATURE) {
        supObDumpShowError(hwndDlg, NULL);
        return;
    }

    //
    // Create a snapshot list of loaded modules.
    //
    pModules = (PRTL_PROCESS_MODULES)supGetLoadedModulesList(NULL);
    if (pModules == NULL) {
        supObDumpShowError(hwndDlg, NULL);
        return;
    }

    //
    // Add root item to the treelist in expanded state.
    //
    treeRootItem = supTreeListAddItem(
        hwndTreeList,
        NULL,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        TEXT("Callbacks"),
        NULL);

    RtlInitEmptyUnicodeString(&normalizedName, NULL, 0);
    callbacksCount = 0;

    if (treeRootItem) {
        //
        // Walk RegisteredCallback list entry.
        //
        listHead = Context->ObjectInfo.ObjectAddress + FIELD_OFFSET(CALLBACK_OBJECT, RegisteredCallbacks);
        listEntry.Flink = objectDump.RegisteredCallbacks.Flink;

        if (supNormalizeUnicodeStringForDisplay(g_obexHeap, &Context->NtObjectName, &normalizedName)) {
            objectName = normalizedName.Buffer;
        }
        else {
            objectName = Context->NtObjectName.Buffer;
        }

        while ((ULONG_PTR)listEntry.Flink != listHead) {

            //
            // Read callback registration data.
            //
            RtlSecureZeroMemory(&callbackRegistration, sizeof(callbackRegistration));
            if (!kdReadSystemMemory((ULONG_PTR)listEntry.Flink,
                (PVOID)&callbackRegistration,
                sizeof(callbackRegistration)))
            {
                //
                // Abort all output on error.
                //
                supObDumpShowError(hwndDlg, NULL);
                break;
            }

            callbacksCount += 1;
            listEntry.Flink = callbackRegistration.Link.Flink;

            propObDumpAddressWithModule(hwndTreeList,
                treeRootItem,
                objectName,
                callbackRegistration.CallbackFunction,
                pModules,
                NULL,
                0);
        }
    } //treeRootItem

    //
    // If nothing found (or possible query error) output this message.
    //
    if (callbacksCount == 0) {
        supObDumpShowError(hwndDlg,
            TEXT("This object has no registered callbacks or there is an query error."));
    }

    supFreeDuplicatedUnicodeString(g_obexHeap, &normalizedName, FALSE);
    supHeapFree(pModules);
}

/*
* propObDumpSymbolicLink
*
* Purpose:
*
* Dump OBJECT_SYMBOLIC_LINK members to the treelist.
*
*/
PROP_OBJECT_DUMP_ROUTINE(propObDumpSymbolicLink)
{
    BOOLEAN isCallbackLink = FALSE;
    ULONG objectSize = 0, objectVersion = 0;
    HTREEITEM treeRootItem;
    LPWSTR integrityLevelString;
    TL_SUBITEMS_FIXED subitems;
    PRTL_PROCESS_MODULES pModules;

    union {
        union {
            OBJECT_SYMBOLIC_LINK_V1* LinkV1;
            OBJECT_SYMBOLIC_LINK_V2* LinkV2;
            OBJECT_SYMBOLIC_LINK_V3* LinkV3;
            OBJECT_SYMBOLIC_LINK_V4* LinkV4;
            OBJECT_SYMBOLIC_LINK_V5* LinkV5;
        } u1;
        PBYTE Ref;
    } symbolicLink;

    WCHAR szTime[64], szConvert[64];

    symbolicLink.Ref = (PBYTE)ObDumpSymbolicLinkObjectVersionAware(
        Context->ObjectInfo.ObjectAddress,
        &objectSize,
        &objectVersion);

    if (symbolicLink.Ref == NULL) {
        supObDumpShowError(hwndDlg, NULL);
        return;
    }

    //
    // Add root item to the treelist in expanded state.
    //
    treeRootItem = supTreeListAddItem(
        hwndTreeList,
        NULL,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        T_OBJECT_SYMBOLIC_LINK,
        NULL);

    if (treeRootItem) {

        //
        // Output CreationTime.
        //
        szTime[0] = 0;
        supPrintTimeConverted(&symbolicLink.u1.LinkV1->CreationTime, szTime, RTL_NUMBER_OF(szTime));

        RtlSecureZeroMemory(&subitems, sizeof(subitems));

        szConvert[0] = TEXT('0');
        szConvert[1] = TEXT('x');
        szConvert[2] = 0;
        u64tohex((ULONG64)symbolicLink.u1.LinkV1->CreationTime.QuadPart, &szConvert[2]);

        subitems.Count = 2;
        subitems.Text[0] = szConvert;
        subitems.Text[1] = szTime;

        supTreeListAddItem(
            hwndTreeList,
            treeRootItem,
            TVIF_TEXT,
            0,
            0,
            TEXT("CreationTime"),
            &subitems);

        //
        // Output callback or LinkTarget depending on Link flags.
        //
        if (objectVersion > OBVERSION_OBJECT_SYMBOLIC_LINK_V3) {
            isCallbackLink = (symbolicLink.u1.LinkV4->Flags & 0x10);
        }

        if (isCallbackLink) {

            pModules = (PRTL_PROCESS_MODULES)supGetLoadedModulesList(NULL);
            if (pModules) {

                propObDumpAddressWithModule(hwndTreeList, treeRootItem, TEXT("Callback"),
                    symbolicLink.u1.LinkV4->u1.Callback, pModules, NULL, 0);

                supHeapFree(pModules);
            }
            else {

                propObDumpAddress(hwndTreeList, treeRootItem, TEXT("Callback"), NULL,
                    symbolicLink.u1.LinkV4->u1.Callback, 0, 0);

            }

            propObDumpAddress(hwndTreeList, treeRootItem, TEXT("CallbackContext"), NULL,
                symbolicLink.u1.LinkV4->u1.CallbackContext, 0, 0);
        }
        else {
            propObDumpUnicodeString(hwndTreeList, treeRootItem, TEXT("LinkTarget"), &symbolicLink.u1.LinkV1->LinkTarget, FALSE);
        }

        propObDumpUlong(hwndTreeList, treeRootItem, TEXT("DosDeviceDriveIndex"), NULL, symbolicLink.u1.LinkV1->DosDeviceDriveIndex, TRUE, FALSE, 0, 0);

        //
        // Output new Windows 10 values.
        //
        if (objectVersion > OBVERSION_OBJECT_SYMBOLIC_LINK_V1)
            propObDumpUlong(hwndTreeList, treeRootItem, TEXT("Flags"), NULL,
                symbolicLink.u1.LinkV2->Flags, TRUE, FALSE, 0, 0);

        if (objectVersion > OBVERSION_OBJECT_SYMBOLIC_LINK_V2)
            propObDumpUlong(hwndTreeList, treeRootItem, TEXT("AccessMask"), NULL,
                symbolicLink.u1.LinkV3->AccessMask, TRUE, FALSE, 0, 0);

        if (objectVersion > OBVERSION_OBJECT_SYMBOLIC_LINK_V4) {
            integrityLevelString = supIntegrityToString(symbolicLink.u1.LinkV5->IntegrityLevel);
            propObDumpUlong(hwndTreeList, treeRootItem, TEXT("IntegrityLevel"), integrityLevelString,
                symbolicLink.u1.LinkV5->IntegrityLevel, TRUE, FALSE, 0, 0);
        }
    }
    supVirtualFree(symbolicLink.Ref);
}

/*
* ObjectDumpOnInit
*
* Purpose:
*
* Object window WM_INITDIALOG handler.
*
* Show load banner and proceed with actual info dump.
*
*/
INT_PTR ObjectDumpOnInit(
    _In_ HWND hwndDlg,
    _In_ LPARAM lParam
)
{
    OBJECT_DUMP_DLG_CONTEXT* pvDlgContext;
    pfnObDumpRoutine pObDumpRoutine = NULL;
    PROP_OBJECT_INFO* Context = NULL;
    PROPSHEETPAGE* pSheet = (PROPSHEETPAGE*)lParam;

    Context = (PROP_OBJECT_INFO*)pSheet->lParam;
    if (Context == NULL)
        return 1;

    //
    // Allocate dlg context to hold specific window data.
    //
    pvDlgContext = (OBJECT_DUMP_DLG_CONTEXT*)supHeapAlloc(sizeof(OBJECT_DUMP_DLG_CONTEXT));
    if (pvDlgContext == NULL)
        return 1;

    pvDlgContext->tlSubItemHit = -1;
    SetProp(hwndDlg, T_DLGCONTEXT, (HANDLE)pvDlgContext);

    switch (Context->ObjectTypeIndex) {

    case ObjectTypeDirectory:
        pObDumpRoutine = (pfnObDumpRoutine)propObDumpDirectoryObject;
        break;

    case ObjectTypeDriver:
        pObDumpRoutine = (pfnObDumpRoutine)propObDumpDriverObject;
        break;

    case ObjectTypeDevice:
        pObDumpRoutine = (pfnObDumpRoutine)propObDumpDeviceObject;
        break;

    case ObjectTypeEvent:
    case ObjectTypeMutant:
    case ObjectTypeSemaphore:
    case ObjectTypeTimer:
        pObDumpRoutine = (pfnObDumpRoutine)propObDumpSyncObject;
        break;

    case ObjectTypePort:
        pObDumpRoutine = (pfnObDumpRoutine)propObDumpAlpcPort;
        break;

    case ObjectTypeIoCompletion:
        pObDumpRoutine = (pfnObDumpRoutine)propObDumpQueueObject;
        break;

    case ObjectTypeFltConnPort:
        pObDumpRoutine = (pfnObDumpRoutine)propObDumpFltServerPort;
        break;

    case ObjectTypeCallback:
        pObDumpRoutine = (pfnObDumpRoutine)propObDumpCallback;
        break;

    case ObjectTypeSymbolicLink:
        pObDumpRoutine = (pfnObDumpRoutine)propObDumpSymbolicLink;
        break;

    case ObjectTypeType:
        pObDumpRoutine = (pfnObDumpRoutine)propObDumpObjectType;
        break;

    default:
        pObDumpRoutine = NULL;
        break;
    }

    if (pObDumpRoutine) {

        //
        // Initialize treelist, abort on error.
        //
        if (supInitTreeListForDump(hwndDlg, &pvDlgContext->TreeList)) {
            supTreeListEnableRedraw(pvDlgContext->TreeList, FALSE);

            pObDumpRoutine(Context, hwndDlg, pvDlgContext->TreeList);

            supTreeListEnableRedraw(pvDlgContext->TreeList, TRUE);
        }
        else {
            supObDumpShowError(hwndDlg, NULL);
        }
    }

    return 1;
}

/*
* ObjectDumpOnDestroy
*
* Purpose:
*
* Object window WM_DESTROY handler.
*
*/
VOID ObjectDumpOnDestroy(
    _In_ HWND hwndDlg
)
{
    OBJECT_DUMP_DLG_CONTEXT* pDlgContext;

    pDlgContext = (OBJECT_DUMP_DLG_CONTEXT*)RemoveProp(hwndDlg, T_DLGCONTEXT);
    if (pDlgContext) {
        DestroyWindow(pDlgContext->TreeList);
        supHeapFree(pDlgContext);
    }

}

/*
* ObjectDumpOnWMCommand
*
* Purpose:
*
* Object window WM_COMMAND handler.
*
*/
VOID ObjectDumpOnWMCommand(
    _In_ HWND hwndDlg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    OBJECT_DUMP_DLG_CONTEXT* pvDlgContext;

    UNREFERENCED_PARAMETER(lParam);

    pvDlgContext = (OBJECT_DUMP_DLG_CONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
    if (pvDlgContext == NULL)
        return;

    switch (GET_WM_COMMAND_ID(wParam, lParam)) {
    case ID_OBJECT_COPY:

        supTreeListCopyItemValueToClipboard(pvDlgContext->TreeList,
            pvDlgContext->tlSubItemHit);

        break;
    }
}

/*
* ObjectDumpOnWMContextMenu
*
* Purpose:
*
* Object window WM_CONTEXTMENU handler.
*
*/
VOID ObjectDumpOnWMContextMenu(
    _In_ HWND hwndDlg,
    _In_ LPARAM lParam
)
{
    OBJECT_DUMP_DLG_CONTEXT* pvDlgContext;

    pvDlgContext = (OBJECT_DUMP_DLG_CONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
    if (pvDlgContext == NULL)
        return;

    supObjectDumpHandlePopupMenu(hwndDlg,
        pvDlgContext->TreeList,
        &pvDlgContext->tlSubItemHit,
        lParam);
}

/*
* ObjectDumpDialogProc
*
* Purpose:
*
* Object window procedure and object dump select.
*
*/
INT_PTR CALLBACK ObjectDumpDialogProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam
)
{
    switch (uMsg) {

    case WM_CONTEXTMENU:
        ObjectDumpOnWMContextMenu(hwndDlg, lParam);
        break;

    case WM_COMMAND:
        ObjectDumpOnWMCommand(hwndDlg, wParam, lParam);
        break;

    case WM_DESTROY:
        ObjectDumpOnDestroy(hwndDlg);
        break;

    case WM_INITDIALOG:

        return ObjectDumpOnInit(
            hwndDlg,
            lParam);

    }
    return 0;
}
