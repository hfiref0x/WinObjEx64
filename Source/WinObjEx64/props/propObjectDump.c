/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2023
*
*  TITLE:       PROPOBJECTDUMP.C
*
*  VERSION:     2.01
*
*  DATE:        06 Feb 2023
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

    if (Address == NULL) {
        subitems.Text[0] = T_NULL;
    }
    else {
        RtlSecureZeroMemory(&szValue, sizeof(szValue));
        szValue[0] = L'0';
        szValue[1] = L'x';
        u64tohex((ULONG_PTR)Address, &szValue[2]);
        subitems.Text[0] = szValue;
    }
    if (lpszDesc) {
        if (BgColor != 0) {
            subitems.ColorFlags |= TLF_BGCOLOR_SET;
            subitems.BgColor = BgColor;
        }
        if (FontColor != 0) {
            subitems.ColorFlags |= TLF_FONTCOLOR_SET;
            subitems.FontColor = FontColor;
        }
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
        szValue[0] = L'0';
        szValue[1] = L'x';
        u64tohex((ULONG_PTR)Address, &szValue[2]);
        subitems.Text[0] = szValue;

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
    HTREEITEM h_tviSubItem;

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 2;
    subitems.Text[0] = T_EmptyString;
    subitems.Text[1] = T_EX_PUSH_LOCK;

    h_tviSubItem = supTreeListAddItem(
        TreeList,
        hParent,
        TVIF_TEXT | TVIF_STATE,
        0,
        0,
        TEXT("Lock"),
        &subitems);

    propObDumpAddress(TreeList, h_tviSubItem, TEXT("Ptr"), NULL, PushLockPtr, BgColor, FontColor);
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

    if (BgColor != 0) {
        subitems.ColorFlags |= TLF_BGCOLOR_SET;
        subitems.BgColor = BgColor;
    }
    if (FontColor != 0) {
        subitems.ColorFlags |= TLF_FONTCOLOR_SET;
        subitems.FontColor = FontColor;
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

    if (BgColor != 0) {
        subitems.ColorFlags |= TLF_BGCOLOR_SET;
        subitems.BgColor = BgColor;
    }
    if (FontColor != 0) {
        subitems.ColorFlags |= TLF_FONTCOLOR_SET;
        subitems.FontColor = FontColor;
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
    _In_ LPWSTR lpszName,
    _In_opt_ LPWSTR lpszDesc, //additional text to be displayed
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
        subitems.Text[1] = lpszDesc;
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

    if (BgColor != 0) {
        subitems.ColorFlags |= TLF_BGCOLOR_SET;
        subitems.BgColor = BgColor;
    }
    if (FontColor != 0) {
        subitems.ColorFlags |= TLF_FONTCOLOR_SET;
        subitems.FontColor = FontColor;
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

    if (BgColor != 0) {
        subitems.ColorFlags |= TLF_BGCOLOR_SET;
        subitems.BgColor = BgColor;
    }
    if (FontColor != 0) {
        subitems.ColorFlags |= TLF_FONTCOLOR_SET;
        subitems.FontColor = FontColor;
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
        if (BgColor != 0) {
            subitems.ColorFlags |= TLF_BGCOLOR_SET;
            subitems.BgColor = BgColor;
        }
        if (FontColor != 0) {
            subitems.ColorFlags |= TLF_FONTCOLOR_SET;
            subitems.FontColor = FontColor;
        }
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
        if (BgColor != 0) {
            subitems.ColorFlags |= TLF_BGCOLOR_SET;
            subitems.BgColor = BgColor;
        }
        if (FontColor != 0) {
            subitems.ColorFlags |= TLF_FONTCOLOR_SET;
            subitems.FontColor = FontColor;
        }
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
    HTREEITEM h_tviSubItem;

    h_tviSubItem = supTreeListAddItem(
        TreeList,
        hParent,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        0,
        ListEntryName,
        NULL);

    if (h_tviSubItem == NULL) {
        return;
    }

    //add large integer entry item to treelist and exit if value is null
    if (Value) {
        propObAddHexValue(TreeList, h_tviSubItem, L"LowPart", Value->LowPart, FALSE);
        propObAddHexValue(TreeList, h_tviSubItem, L"HighPart", Value->HighPart, FALSE);
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
    HTREEITEM         h_tviSubItem;
    TL_SUBITEMS_FIXED subitems;

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 2;
    subitems.Text[0] = T_EmptyString;
    subitems.Text[1] = T_LIST_ENTRY;

    h_tviSubItem = supTreeListAddItem(
        TreeList,
        hParent,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        0,
        ListEntryName,
        &subitems);

    if (h_tviSubItem == NULL) {
        return;
    }

    //add list entry item to treelist and exit if listentry is null
    if (ListEntry) {
        propObAddHexValue(TreeList, h_tviSubItem, L"Flink", (ULONG64)ListEntry->Flink, TRUE);
        propObAddHexValue(TreeList, h_tviSubItem, L"Blink", (ULONG64)ListEntry->Blink, TRUE);
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
    HTREEITEM h_tviSubItem;
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
    h_tviSubItem = supTreeListAddItem(
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

    if (h_tviSubItem) {

        //
        // UNICODE_STRING.Length
        //
        propObDumpUSHORT(TreeList,
            h_tviSubItem,
            T_LENGTH,
            String->Length,
            TRUE);

        //
        // UNICODE_STRING.MaximumLength
        //
        propObDumpUSHORT(TreeList,
            h_tviSubItem,
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
            if (ReferenceBufferAddress == NULL) {
                subitems.Text[0] = T_NULL;
            }
            else {
                RtlSecureZeroMemory(&szValue, sizeof(szValue));
                szValue[0] = TEXT('0');
                szValue[1] = TEXT('x');
                u64tohex((ULONG_PTR)ReferenceBufferAddress, &szValue[2]);
                subitems.Text[0] = szValue;
            }

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
            h_tviSubItem,
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
    _In_ DISPATCHER_HEADER* Header,
    _In_opt_ LPWSTR lpDescType,
    _In_opt_ LPWSTR lpDescSignalState,
    _In_opt_ LPWSTR lpDescSize
)
{
    HTREEITEM h_tviSubItem;

    h_tviSubItem = supTreeListAddItem(
        TreeList,
        ParentItem,
        TVIF_TEXT | TVIF_STATE,
        0,
        0,
        TEXT("Header"),
        NULL);

    if (h_tviSubItem) {

        //Header->Type
        propObDumpUlong(TreeList, h_tviSubItem, L"Type", lpDescType, Header->Type, TRUE, TRUE, 0, 0);
        //Header->Absolute
        propObDumpUlong(TreeList, h_tviSubItem, L"Absolute", NULL, Header->Absolute, TRUE, TRUE, 0, 0);
        //Header->Size
        propObDumpUlong(TreeList, h_tviSubItem, L"Size", lpDescSize, Header->Size, TRUE, TRUE, 0, 0);
        //Header->Inserted
        propObDumpByte(TreeList, h_tviSubItem, L"Inserted", NULL, Header->Inserted, 0, 0, TRUE);
        //Header->SignalState
        propObDumpUlong(TreeList, h_tviSubItem, L"SignalState", lpDescSignalState, Header->SignalState, TRUE, FALSE, 0, 0);
        //Header->WaitListHead
        propObDumpListEntry(TreeList, h_tviSubItem, L"WaitListHead", &Header->WaitListHead);
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
    _In_ SECURITY_QUALITY_OF_SERVICE* SecurityQos
)
{
    LPWSTR lpType;
    HTREEITEM h_tviSubItem;
    TL_SUBITEMS_FIXED subitems;

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 2;
    subitems.Text[0] = T_EmptyString;
    subitems.Text[1] = TEXT("SECURITY_QUALITY_OF_SERVICE");

    h_tviSubItem = supTreeListAddItem(
        TreeList,
        hParent,
        TVIF_TEXT,
        0,
        0,
        TEXT("SecurityQos"),
        &subitems);

    propObDumpUlong(
        TreeList,
        h_tviSubItem,
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
        h_tviSubItem,
        TEXT("ImpersonationLevel"),
        lpType,
        SecurityQos->ImpersonationLevel,
        FALSE,
        FALSE,
        0,
        0);

    if (SecurityQos->ContextTrackingMode)
        lpType = TEXT("SECURITY_DYNAMIC_TRACKING");
    else
        lpType = TEXT("SECURITY_STATIC_TRACKING");

    propObDumpByte(
        TreeList,
        h_tviSubItem,
        TEXT("ContextTrackingMode"),
        lpType,
        SecurityQos->ContextTrackingMode,
        0,
        0,
        TRUE);

    propObDumpByte(
        TreeList,
        h_tviSubItem,
        TEXT("EffectiveOnly"),
        NULL,
        SecurityQos->EffectiveOnly,
        0,
        0,
        TRUE);
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
    } DrvExt;

    BOOL bPathAllocated;

    HTREEITEM h_tviRootItem;

    COLORREF BgColor;
    PDRIVER_OBJECT SelfDriverObject;
    LPWSTR lpDesc;
    PVOID DriverExtensionPtr;
    ULONG ObjectSize = 0;
    ULONG ObjectVersion = 0;

    UNICODE_STRING normalizedPath;

    DriverExtensionPtr = ObDumpDriverExtensionVersionAware((ULONG_PTR)DriverExtension,
        &ObjectSize,
        &ObjectVersion);

    if (DriverExtensionPtr) {

        DrvExt.Ref = DriverExtensionPtr;

        h_tviRootItem = supTreeListAddItem(
            TreeList,
            NULL,
            TVIF_TEXT | TVIF_STATE,
            TVIS_EXPANDED,
            0,
            TEXT("DRIVER_EXTENSION"),
            NULL);

        if (h_tviRootItem) {

            //
            // DRIVER_EXTENSION.DriverObject
            //
            BgColor = 0;
            lpDesc = NULL;
            bPathAllocated = FALSE;

            //must be self-ref
            SelfDriverObject = DrvExt.Versions.DriverExtensionCompatible->DriverObject;

            if ((ULONG_PTR)SelfDriverObject != (ULONG_PTR)DriverObject) {
                lpDesc = T_BADDRIVEROBJECT;
                BgColor = CLR_WARN;
            }
            else {
                //find ref
                if (SelfDriverObject != NULL) {

                    bPathAllocated = propDumpQueryFullNamespaceNormalizedPath(
                        (ULONG_PTR)SelfDriverObject, &normalizedPath);
                    if (bPathAllocated) {
                        lpDesc = normalizedPath.Buffer;
                    }
                    else {
                        //sef-ref not found, notify, could be object outside directory so we don't know it name etc
                        lpDesc = T_REFNOTFOUND;
                        BgColor = CLR_INVL;
                    }

                }
            }

            propObDumpAddress(TreeList, h_tviRootItem, T_FIELD_DRIVER_OBJECT,
                lpDesc, SelfDriverObject, BgColor, 0);

            if (bPathAllocated)
                supFreeDuplicatedUnicodeString(g_obexHeap, &normalizedPath, FALSE);

            //AddDevice
            propObDumpAddressWithModule(TreeList, 
                h_tviRootItem, 
                TEXT("AddDevice"),
                DrvExt.Versions.DriverExtensionCompatible->AddDevice,
                ModulesList,
                LoaderEntry->DllBase,
                LoaderEntry->SizeOfImage);

            //Count
            propObDumpUlong(TreeList, h_tviRootItem, TEXT("Count"), NULL,
                DrvExt.Versions.DriverExtensionCompatible->Count, FALSE, FALSE, 0, 0);

            //ServiceKeyName
            propObDumpUnicodeString(TreeList, h_tviRootItem, T_FIELD_SERVICE_KEYNAME,
                &DrvExt.Versions.DriverExtensionCompatible->ServiceKeyName,
                FALSE);

            // All brand new private fields
            if (ObjectVersion > OBVERSION_DRIVER_EXTENSION_V1) {

                propObDumpAddress(TreeList, h_tviRootItem, TEXT("ClientDriverExtension"),
                    TEXT("PIO_CLIENT_EXTENSION"), DrvExt.Versions.DriverExtensionV2->ClientDriverExtension, 0, 0);

                propObDumpAddress(TreeList, h_tviRootItem, TEXT("FsFilterCallbacks"),
                    TEXT("PFS_FILTER_CALLBACKS"), DrvExt.Versions.DriverExtensionV2->FsFilterCallbacks, 0, 0);
            }

            if (ObjectVersion > OBVERSION_DRIVER_EXTENSION_V2) {
                propObDumpAddress(TreeList, h_tviRootItem, TEXT("KseCallbacks"),
                    NULL, DrvExt.Versions.DriverExtensionV3->KseCallbacks, 0, 0);
                propObDumpAddress(TreeList, h_tviRootItem, TEXT("DvCallbacks"),
                    NULL, DrvExt.Versions.DriverExtensionV3->DvCallbacks, 0, 0);
            }

            if (ObjectVersion > OBVERSION_DRIVER_EXTENSION_V3) {
                propObDumpAddress(TreeList, h_tviRootItem, TEXT("VerifierContext"),
                    NULL, DrvExt.Versions.DriverExtensionV4->VerifierContext, 0, 0);
            }
        }

        supVirtualFree(DriverExtensionPtr);
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
    BOOL                    bOkay;
    INT                     i, j;
    HTREEITEM               h_tviRootItem, h_tviSubItem;
    PRTL_PROCESS_MODULES    pModules;
    PVOID                   pObj, IopInvalidDeviceRequest;
    LPWSTR                  lpType;
    DRIVER_OBJECT           drvObject;
    FAST_IO_DISPATCH        fastIoDispatch;
    LDR_DATA_TABLE_ENTRY    ldrEntry, ntosEntry;
    TL_SUBITEMS_FIXED       subitems;
    COLORREF                BgColor;
    WCHAR                   szValue1[MAX_PATH + 1];

    bOkay = FALSE;

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
        bOkay = TRUE;

        //dump drvObject->DriverSection
        if (!kdReadSystemMemory(
            (ULONG_PTR)drvObject.DriverSection,
            &ldrEntry,
            sizeof(ldrEntry)))
        {
            break;
        }

    } while (FALSE);

    //any errors - abort
    if (!bOkay) {
        supObDumpShowError(hwndDlg, NULL);
        return;
    }

    //
    //DRIVER_OBJECT
    //

    h_tviRootItem = supTreeListAddItem(
        hwndTreeList,
        NULL,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        TEXT("DRIVER_OBJECT"),
        NULL);

    //Type
    BgColor = 0;
    lpType = TEXT("IO_TYPE_DRIVER");
    if (drvObject.Type != IO_TYPE_DRIVER) {
        lpType = TEXT("! Must be IO_TYPE_DRIVER");
        BgColor = CLR_WARN;
    }
    propObDumpUlong(hwndTreeList, h_tviRootItem, TEXT("Type"), lpType, drvObject.Type, TRUE, TRUE, BgColor, 0);

    //Size
    BgColor = 0;
    lpType = NULL;
    if (drvObject.Size != sizeof(DRIVER_OBJECT)) {
        lpType = TEXT("! Must be sizeof(DRIVER_OBJECT)");
        BgColor = CLR_WARN;
    }
    propObDumpUlong(hwndTreeList, h_tviRootItem, TEXT("Size"), lpType, drvObject.Size, TRUE, TRUE, BgColor, 0);

    //DeviceObject
    propDumpObjectForAddress(hwndTreeList, h_tviRootItem,
        TEXT("DeviceObject"), drvObject.DeviceObject, CLR_LGRY, T_UNNAMED);

    //Flags
    RtlSecureZeroMemory(&szValue1, sizeof(szValue1));
    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    j = 0;
    lpType = NULL;
    if (drvObject.Flags) {
        for (i = 0; i < MAX_KNOWN_DRV_FLAGS; i++) {
            if (drvObject.Flags & drvFlags[i].dwValue) {
                lpType = drvFlags[i].lpDescription;
                subitems.Count = 2;

                //add first entry with name
                if (j == 0) {
                    szValue1[0] = L'0';
                    szValue1[1] = L'x';
                    ultohex(drvObject.Flags, &szValue1[2]);

                    subitems.Text[0] = szValue1;
                    subitems.Text[1] = lpType;
                }
                else {
                    //add subentry
                    subitems.Text[0] = T_EmptyString;
                    subitems.Text[1] = lpType;
                }

                supTreeListAddItem(
                    hwndTreeList,
                    h_tviRootItem,
                    TVIF_TEXT | TVIF_STATE,
                    0,
                    0,
                    (j == 0) ? T_FLAGS : T_EmptyString,
                    &subitems);

                drvObject.Flags &= ~drvFlags[i].dwValue;
                j++;
            }
            if (drvObject.Flags == 0) {
                break;
            }
        }
    }
    else {
        //add named entry with zero data
        propObDumpUlong(hwndTreeList, h_tviRootItem, T_FLAGS, NULL, 0, TRUE, FALSE, 0, 0);
    }

    //DriverStart
    propObDumpAddress(hwndTreeList, h_tviRootItem, TEXT("DriverStart"), NULL, drvObject.DriverStart, 0, 0);

    //DriverSize
    propObDumpUlong(hwndTreeList, h_tviRootItem, TEXT("DriverSize"), NULL, drvObject.DriverSize, TRUE, FALSE, 0, 0);

    //DriverSection
    propObDumpAddress(hwndTreeList, h_tviRootItem, TEXT("DriverSection"), T_PLDR_DATA_TABLE_ENTRY, drvObject.DriverSection, 0, 0);

    //DriverExtension
    propObDumpAddress(hwndTreeList, h_tviRootItem, T_FIELD_DRIVER_EXTENSION, T_PDRIVER_EXTENSION, drvObject.DriverExtension, 0, 0);

    //DriverName
    propObDumpUnicodeString(hwndTreeList, h_tviRootItem, TEXT("DriverName"), &drvObject.DriverName, FALSE);

    //HardwareDatabase
    propObDumpUnicodeString(hwndTreeList, h_tviRootItem, TEXT("HardwareDatabase"), drvObject.HardwareDatabase, TRUE);

    //FastIoDispatch
    propObDumpAddress(hwndTreeList, h_tviRootItem, TEXT("FastIoDispatch"), T_PFAST_IO_DISPATCH, drvObject.FastIoDispatch, 0, 0);

    //DriverInit
    propObDumpAddress(hwndTreeList, h_tviRootItem, TEXT("DriverInit"), NULL, drvObject.DriverInit, 0, 0);

    //DriverStartIo
    propObDumpAddress(hwndTreeList, h_tviRootItem, TEXT("DriverStartIo"), NULL, drvObject.DriverStartIo, 0, 0);

    //DriverUnload
    propObDumpAddress(hwndTreeList, h_tviRootItem, TEXT("DriverUnload"), NULL, drvObject.DriverUnload, 0, 0);

    //MajorFunction
    RtlSecureZeroMemory(&szValue1, sizeof(szValue1));
    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 2;
    subitems.Text[0] = TEXT("{...}");
    subitems.Text[1] = T_EmptyString;

    h_tviSubItem = supTreeListAddItem(
        hwndTreeList,
        h_tviRootItem,
        TVIF_TEXT | TVIF_STATE,
        0,
        0,
        TEXT("MajorFunction"),
        &subitems);

    RtlSecureZeroMemory(&ntosEntry, sizeof(ntosEntry));
    pModules = (PRTL_PROCESS_MODULES)supGetLoadedModulesList(NULL);

    if (g_kdctx.Data->IopInvalidDeviceRequest == NULL) {
        g_kdctx.Data->IopInvalidDeviceRequest = kdQueryIopInvalidDeviceRequest();
    }

    IopInvalidDeviceRequest = g_kdctx.Data->IopInvalidDeviceRequest;

    for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {

        if (drvObject.MajorFunction[i] == NULL) {
            continue;
        }

        //
        // Skip ntoskrnl default IRP handler.
        // 
        // WARNING: This may skip actual trampoline hook.
        //
        if (IopInvalidDeviceRequest) {
            if ((ULONG_PTR)drvObject.MajorFunction[i] == (ULONG_PTR)IopInvalidDeviceRequest) {

                propObDumpAddress(
                    hwndTreeList,
                    h_tviSubItem,
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
            h_tviSubItem,
            T_IRP_MJ_FUNCTION[i],
            drvObject.MajorFunction[i],
            pModules,
            ldrEntry.DllBase,
            ldrEntry.SizeOfImage,
            TRUE);
    }

    //
    //LDR_DATA_TABLE_ENTRY
    //

    if (drvObject.DriverSection != NULL) {

        //root itself
        h_tviRootItem = supTreeListAddItem(
            hwndTreeList,
            NULL,
            TVIF_TEXT | TVIF_STATE,
            TVIS_EXPANDED,
            0,
            T_LDR_DATA_TABLE_ENTRY,
            NULL);

        //InLoadOrderLinks
        propObDumpListEntry(hwndTreeList, h_tviRootItem, TEXT("InLoadOrderLinks"), &ldrEntry.InLoadOrderLinks);

        //InMemoryOrderLinks
        propObDumpListEntry(hwndTreeList, h_tviRootItem, TEXT("InMemoryOrderLinks"), &ldrEntry.InMemoryOrderLinks);

        //InInitializationOrderLinks/InProgressLinks
        lpType = TEXT("InInitializationOrderLinks");
        if (g_NtBuildNumber >= NT_WIN8_BLUE) {
            lpType = TEXT("InProgressLinks");
        }
        propObDumpListEntry(hwndTreeList, h_tviRootItem, lpType, &ldrEntry.DUMMYUNION0.InInitializationOrderLinks);

        //DllBase
        propObDumpAddress(hwndTreeList, h_tviRootItem, TEXT("DllBase"), NULL, ldrEntry.DllBase, 0, 0);

        //EntryPoint
        propObDumpAddress(hwndTreeList, h_tviRootItem, TEXT("EntryPoint"), NULL, ldrEntry.EntryPoint, 0, 0);

        //SizeOfImage
        propObDumpUlong(hwndTreeList, h_tviRootItem, TEXT("SizeOfImage"), NULL, ldrEntry.SizeOfImage, TRUE, FALSE, 0, 0);

        //FullDllName
        propObDumpUnicodeString(hwndTreeList, h_tviRootItem, TEXT("FullDllName"), &ldrEntry.FullDllName, FALSE);

        //BaseDllName
        propObDumpUnicodeString(hwndTreeList, h_tviRootItem, TEXT("BaseDllName"), &ldrEntry.BaseDllName, FALSE);

        //Flags
        propObDumpUlong(hwndTreeList, h_tviRootItem, T_FLAGS, NULL, ldrEntry.ENTRYFLAGSUNION.Flags, TRUE, FALSE, 0, 0);

        //LoadCount
        lpType = TEXT("ObsoleteLoadCount");
        if (g_NtBuildNumber < NT_WIN8_RTM) {
            lpType = TEXT("LoadCount");
        }
        propObDumpUlong(hwndTreeList, h_tviRootItem, lpType, NULL, ldrEntry.ObsoleteLoadCount, TRUE, TRUE, 0, 0);

        //TlsIndex
        propObDumpUlong(hwndTreeList, h_tviRootItem, TEXT("TlsIndex"), NULL, ldrEntry.TlsIndex, TRUE, TRUE, 0, 0);

        //SectionPointer
        propObDumpAddress(hwndTreeList, h_tviRootItem, TEXT("SectionPointer"), NULL, ldrEntry.DUMMYUNION1.SectionPointer, 0, 0);

        //CheckSum
        propObDumpUlong(hwndTreeList, h_tviRootItem, TEXT("CheckSum"), NULL, ldrEntry.DUMMYUNION1.CheckSum, TRUE, FALSE, 0, 0);

        //LoadedImports
        if (g_NtBuildNumber < NT_WIN8_RTM) {
            propObDumpAddress(hwndTreeList, h_tviRootItem, TEXT("LoadedImports"), NULL, ldrEntry.DUMMYUNION2.LoadedImports, 0, 0);
        }

    } //LDR_DATA_TABLE_ENTRY


    //
    //FAST_IO_DISPATCH
    //

    if (drvObject.FastIoDispatch != NULL) {

        RtlSecureZeroMemory(&fastIoDispatch, sizeof(fastIoDispatch));

        if (kdReadSystemMemory(
            (ULONG_PTR)drvObject.FastIoDispatch,
            &fastIoDispatch,
            sizeof(fastIoDispatch)))
        {

            h_tviRootItem = supTreeListAddItem(
                hwndTreeList,
                NULL,
                TVIF_TEXT | TVIF_STATE,
                0,
                0,
                TEXT("FAST_IO_DISPATCH"),
                NULL);

            //SizeOfFastIoDispatch
            BgColor = 0;
            lpType = NULL;

            if (fastIoDispatch.SizeOfFastIoDispatch != sizeof(FAST_IO_DISPATCH)) {
                lpType = TEXT("! Must be sizeof(FAST_IO_DISPATCH)");
                BgColor = CLR_WARN;
                bOkay = FALSE;//<-set flag invalid structure
            }

            propObDumpUlong(hwndTreeList,
                h_tviRootItem,
                TEXT("SizeOfFastIoDispatch"),
                lpType,
                fastIoDispatch.SizeOfFastIoDispatch,
                TRUE,
                FALSE,
                BgColor,
                0);

            //valid structure
            if (bOkay) {
                for (i = 0; i < RTL_NUMBER_OF(T_FAST_IO_DISPATCH); i++) {
                    pObj = ((PVOID*)(&fastIoDispatch.FastIoCheckIfPossible))[i];
                    if (pObj == NULL) {
                        continue;
                    }

                    propObDumpAddressWithModule(hwndTreeList,
                        h_tviRootItem,
                        T_FAST_IO_DISPATCH[i],
                        pObj,
                        pModules,
                        ldrEntry.DllBase,
                        ldrEntry.SizeOfImage);

                }
            }

        } //kdReadSystemMemory
    } //if

    //
    //PDRIVER_EXTENSION
    //
    if (drvObject.DriverExtension != NULL) {

        propObDumpDriverExtension(hwndTreeList,
            (PDRIVER_OBJECT)Context->ObjectInfo.ObjectAddress,
            drvObject.DriverExtension,
            pModules,
            &ldrEntry);

    }


    //
    //Cleanup
    //
    if (pModules) {
        supHeapFree(pModules);
    }

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
    INT                 i, j;
    HTREEITEM           h_tviRootItem, h_tviWcb, h_tviSubItem, h_tviWaitEntry;
    LPWSTR              lpType;
    TL_SUBITEMS_FIXED   subitems;
    DEVICE_OBJECT       devObject;
    DEVOBJ_EXTENSION    devObjExt;
    COLORREF            BgColor;
    WCHAR               szValue1[MAX_PATH + 1];

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

    h_tviRootItem = supTreeListAddItem(hwndTreeList,
        NULL,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        L"DEVICE_OBJECT",
        NULL);

    //Type
    BgColor = 0;
    lpType = L"IO_TYPE_DEVICE";
    if (devObject.Type != IO_TYPE_DEVICE) {
        lpType = L"! Must be IO_TYPE_DEVICE";
        BgColor = CLR_WARN;
    }
    propObDumpUlong(hwndTreeList, h_tviRootItem, L"Type", lpType, devObject.Type, TRUE, TRUE, BgColor, 0);

    //Size
    propObDumpUlong(hwndTreeList, h_tviRootItem, L"Size", NULL, devObject.Size, TRUE, TRUE, 0, 0);

    //ReferenceCount
    propObDumpUlong(hwndTreeList, h_tviRootItem, L"ReferenceCount", NULL, devObject.ReferenceCount, FALSE, FALSE, 0, 0);

    //
    // DriverObject
    //
    propDumpObjectForAddress(hwndTreeList, h_tviRootItem, T_FIELD_DRIVER_OBJECT,
        devObject.DriverObject, CLR_INVL, T_REFNOTFOUND);

    //
    // NextDevice
    //
    propDumpObjectForAddress(hwndTreeList, h_tviRootItem, L"NextDevice",
        devObject.NextDevice, CLR_LGRY, T_UNNAMED);

    //
    // AttachedDevice
    //
    propDumpObjectForAddress(hwndTreeList, h_tviRootItem, L"AttachedDevice",
        devObject.AttachedDevice, CLR_LGRY, T_UNNAMED);

    //CurrentIrp
    propObDumpAddress(hwndTreeList, h_tviRootItem, L"CurrentIrp", NULL, devObject.CurrentIrp, 0, 0);

    //Timer
    lpType = L"PIO_TIMER";
    propObDumpAddress(hwndTreeList, h_tviRootItem, L"Timer", lpType, devObject.Timer, 0, 0);

    //Flags
    RtlSecureZeroMemory(&szValue1, sizeof(szValue1));
    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    lpType = NULL;
    j = 0;
    if (devObject.Flags) {
        for (i = 0; i < MAX_KNOWN_DEV_FLAGS; i++) {
            if (devObject.Flags & devFlags[i].dwValue) {
                lpType = devFlags[i].lpDescription;
                subitems.Count = 2;

                if (j == 0) {
                    //add first entry with flag description
                    szValue1[0] = L'0';
                    szValue1[1] = L'x';
                    ultohex(devObject.Flags, &szValue1[2]);

                    subitems.Text[0] = szValue1;
                    subitems.Text[1] = lpType;
                }
                else {
                    //add subentry
                    subitems.Text[0] = T_EmptyString;
                    subitems.Text[1] = lpType;
                }

                supTreeListAddItem(hwndTreeList,
                    h_tviRootItem,
                    TVIF_TEXT | TVIF_STATE,
                    0,
                    TVIS_EXPANDED,
                    (j == 0) ? T_FLAGS : T_EmptyString,
                    &subitems);

                devObject.Flags &= ~devFlags[i].dwValue;
                j++;
            }
            if (devObject.Flags == 0) {
                break;
            }
        }
    }
    else {
        //add named entry with zero data
        propObDumpUlong(hwndTreeList, h_tviRootItem, T_FLAGS, NULL, 0, TRUE, FALSE, 0, 0);
    }

    //Characteristics
    RtlSecureZeroMemory(&szValue1, sizeof(szValue1));
    RtlSecureZeroMemory(&subitems, sizeof(subitems));

    lpType = NULL;
    j = 0;
    if (devObject.Characteristics) {
        for (i = 0; i < MAX_KNOWN_CHR_FLAGS; i++) {

            if (devObject.Characteristics & devChars[i].dwValue) {
                lpType = devChars[i].lpDescription;
                subitems.Count = 2;

                if (j == 0) {
                    //add first entry with chr description
                    szValue1[0] = L'0';
                    szValue1[1] = L'x';
                    ultohex(devObject.Characteristics, &szValue1[2]);
                    subitems.Text[0] = szValue1;
                    subitems.Text[1] = lpType;
                }
                else {
                    //add subentry
                    subitems.Text[0] = T_EmptyString;
                    subitems.Text[1] = lpType;
                }

                supTreeListAddItem(hwndTreeList,
                    h_tviRootItem,
                    TVIF_TEXT | TVIF_STATE,
                    0,
                    0,
                    (j == 0) ? T_CHARACTERISTICS : T_EmptyString,
                    &subitems);

                devObject.Characteristics &= ~devChars[i].dwValue;
                j++;
            }

            if (devObject.Characteristics == 0) {
                break;
            }
        }
    }
    else {
        //add zero value
        propObDumpUlong(hwndTreeList, h_tviRootItem, T_CHARACTERISTICS, NULL, 0, TRUE, FALSE, 0, 0);
    }

    //Vpb
    lpType = L"PVPB";
    propObDumpAddress(hwndTreeList, h_tviRootItem, L"Vpb", lpType, devObject.Vpb, 0, 0);

    //DeviceExtension
    BgColor = 0;
    lpType = NULL;

    //
    // Check DeviceExtension to be valid as it size is a part of total DEVICE_OBJECT allocation size.
    //
    if (devObject.DeviceExtension != NULL) {
        if (devObject.Size == sizeof(DEVICE_OBJECT)) {
            BgColor = CLR_WARN;
            lpType = L"! Must be NULL";
        }
    }
    propObDumpAddress(hwndTreeList, h_tviRootItem, L"DeviceExtension", lpType, devObject.DeviceExtension, BgColor, 0);

    //DeviceType
    lpType = NULL;
    for (i = 0; i < MAX_DEVOBJ_CHARS; i++) {
        if (devObjChars[i].dwValue == devObject.DeviceType) {
            lpType = devObjChars[i].lpDescription;
            break;
        }
    }
    propObDumpUlong(hwndTreeList, h_tviRootItem, L"DeviceType", lpType, devObject.DeviceType, TRUE, FALSE, 0, 0);

    //StackSize
    propObDumpUlong(hwndTreeList, h_tviRootItem, L"StackSize", NULL, devObject.StackSize, FALSE, FALSE, 0, 0);

    //Queue
    h_tviSubItem = supTreeListAddItem(hwndTreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0,
        TVIS_EXPANDED, L"Queue", NULL);

    //Queue->Wcb
    h_tviWcb = supTreeListAddItem(hwndTreeList, h_tviSubItem, TVIF_TEXT | TVIF_STATE, 0,
        TVIS_EXPANDED, L"Wcb", NULL);

    //Queue->Wcb->WaitQueueEntry
    h_tviWaitEntry = supTreeListAddItem(hwndTreeList, h_tviWcb, TVIF_TEXT | TVIF_STATE, 0,
        TVIS_EXPANDED, L"WaitQueueEntry", NULL);

    //Queue->Wcb->WaitQueueEntry->DeviceListEntry
    propObDumpListEntry(hwndTreeList, h_tviWaitEntry, L"DeviceListEntry", &devObject.Queue.Wcb.WaitQueueEntry.DeviceListEntry);

    //Queue->Wcb->WaitQueueEntry->SortKey
    propObDumpUlong(hwndTreeList, h_tviWaitEntry, L"SortKey", NULL, devObject.Queue.Wcb.WaitQueueEntry.SortKey, TRUE, FALSE, 0, 0);

    //Queue->Wcb->WaitQueueEntry->Inserted
    propObDumpByte(hwndTreeList, h_tviWaitEntry, L"Inserted", NULL, devObject.Queue.Wcb.WaitQueueEntry.Inserted, 0, 0, TRUE);

    //Queue->Wcb->DmaWaitEntry
    propObDumpListEntry(hwndTreeList, h_tviWcb, L"DmaWaitEntry", &devObject.Queue.Wcb.DmaWaitEntry);

    //Queue->Wcb->NumberOfChannels
    propObDumpUlong(hwndTreeList, h_tviWcb, L"NumberOfChannels", NULL, devObject.Queue.Wcb.NumberOfChannels, FALSE, FALSE, 0, 0);

    //Queue->Wcb->SyncCallback
    propObDumpUlong(hwndTreeList, h_tviWcb, L"SyncCallback", NULL, devObject.Queue.Wcb.SyncCallback, FALSE, FALSE, 0, 0);

    //Queue->Wcb->DmaContext
    propObDumpUlong(hwndTreeList, h_tviWcb, L"DmaContext", NULL, devObject.Queue.Wcb.DmaContext, FALSE, FALSE, 0, 0);

    //Queue->Wcb->DeviceRoutine
    lpType = L"PDRIVER_CONTROL";
    propObDumpAddress(hwndTreeList, h_tviWcb, L"DeviceRoutine", lpType, devObject.Queue.Wcb.DeviceRoutine, 0, 0);

    //Queue->Wcb->DeviceContext
    propObDumpAddress(hwndTreeList, h_tviWcb, L"DeviceContext", NULL, devObject.Queue.Wcb.DeviceContext, 0, 0);

    //Queue->Wcb->NumberOfMapRegisters
    propObDumpUlong(hwndTreeList, h_tviWcb, L"DeviceContext", NULL, devObject.Queue.Wcb.NumberOfMapRegisters, FALSE, FALSE, 0, 0);

    //Queue->Wcb->DeviceObject
    propDumpObjectForAddress(hwndTreeList, h_tviWcb, L"DeviceObject",
        devObject.Queue.Wcb.DeviceObject,
        CLR_LGRY,
        T_UNNAMED);

    //Queue->Wcb->CurrentIrp
    propObDumpAddress(hwndTreeList, h_tviWcb, L"CurrentIrp", NULL, devObject.Queue.Wcb.CurrentIrp, 0, 0);

    //Queue->Wcb->BufferChainingDpc
    lpType = T_PKDPC;
    propObDumpAddress(hwndTreeList, h_tviWcb, L"BufferChainingDpc", lpType, devObject.Queue.Wcb.BufferChainingDpc, 0, 0);

    //AlignmentRequirement
    lpType = NULL;
    for (i = 0; i < MAX_KNOWN_FILEALIGN; i++) {
        if (fileAlign[i].dwValue == devObject.AlignmentRequirement) {
            lpType = fileAlign[i].lpDescription;
            break;
        }
    }
    propObDumpUlong(hwndTreeList, h_tviRootItem, L"AlignmentRequirement", lpType, devObject.AlignmentRequirement, TRUE, FALSE, 0, 0);

    //DeviceQueue
    h_tviSubItem = supTreeListAddItem(hwndTreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0,
        TVIS_EXPANDED, L"DeviceQueue", NULL);

    //DeviceQueue->Type
    lpType = L"KOBJECTS";
    propObDumpUlong(hwndTreeList, h_tviSubItem, L"Type", lpType, devObject.DeviceQueue.Type, TRUE, TRUE, 0, 0);

    //DeviceQueue->Size
    propObDumpUlong(hwndTreeList, h_tviSubItem, L"Size", NULL, devObject.DeviceQueue.Size, TRUE, TRUE, 0, 0);

    //DeviceQueue->DeviceListHead
    propObDumpListEntry(hwndTreeList, h_tviSubItem, L"DeviceListHead", &devObject.DeviceQueue.DeviceListHead);

    //DeviceQueue->Lock
    propObDumpAddress(hwndTreeList, h_tviSubItem, L"Lock", NULL, (PVOID)devObject.DeviceQueue.Lock, 0, 0);

    //DeviceQueue->Busy
    propObDumpByte(hwndTreeList, h_tviSubItem, L"Busy", NULL, devObject.DeviceQueue.Busy, 0, 0, TRUE);

    //DeviceQueue->Hint
    propObDumpAddress(hwndTreeList, h_tviSubItem, L"Hint", NULL, (PVOID)devObject.DeviceQueue.Hint, 0, 0);

    //
    //DEVICE_OBJECT->Dpc
    //
    h_tviSubItem = supTreeListAddItem(hwndTreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0,
        TVIS_EXPANDED, L"Dpc", NULL);

    lpType = NULL;
    if (devObject.Dpc.Type == DPC_NORMAL) lpType = L"DPC_NORMAL";
    if (devObject.Dpc.Type == DPC_THREADED) lpType = L"DPC_THREADED";
    propObDumpUlong(hwndTreeList, h_tviSubItem, L"Type", lpType, devObject.Dpc.Type, TRUE, TRUE, 0, 0);
    lpType = NULL;
    if (devObject.Dpc.Importance == LowImportance) lpType = L"LowImportance";
    if (devObject.Dpc.Importance == MediumImportance) lpType = L"MediumImportance";
    if (devObject.Dpc.Importance == HighImportance) lpType = L"HighImportance";
    propObDumpUlong(hwndTreeList, h_tviSubItem, L"Importance", lpType, devObject.Dpc.Importance, TRUE, TRUE, 0, 0);
    propObDumpUlong(hwndTreeList, h_tviSubItem, L"Number", NULL, devObject.Dpc.Number, TRUE, TRUE, 0, 0);

    //Dpc->DpcListEntry
    propObDumpAddress(hwndTreeList, h_tviSubItem, L"DpcListEntry", NULL, (PVOID)devObject.Dpc.DpcListEntry.Next, 0, 0);

    //Dpc->ProcessorHistory
    propObDumpAddress(hwndTreeList, h_tviSubItem, L"ProcessorHistory", NULL, (PVOID)devObject.Dpc.ProcessorHistory, 0, 0);

    //Dpc->DeferredRoutine
    propObDumpAddress(hwndTreeList, h_tviSubItem, L"DeferredRoutine", NULL, devObject.Dpc.DeferredRoutine, 0, 0);

    //Dpc->DeferredContext
    propObDumpAddress(hwndTreeList, h_tviSubItem, L"DeferredContext", NULL, devObject.Dpc.DeferredContext, 0, 0);

    //Dpc->SystemArgument1
    propObDumpAddress(hwndTreeList, h_tviSubItem, L"SystemArgument1", NULL, devObject.Dpc.SystemArgument1, 0, 0);

    //Dpc->SystemArgument2
    propObDumpAddress(hwndTreeList, h_tviSubItem, L"SystemArgument2", NULL, devObject.Dpc.SystemArgument2, 0, 0);

    //ActiveThreadCount
    propObDumpUlong(hwndTreeList, h_tviRootItem, L"ActiveThreadCount", NULL, devObject.ActiveThreadCount, FALSE, FALSE, 0, 0);

    //SecurityDescriptor
    lpType = L"PSECURITY_DESCRIPTOR";
    propObDumpAddress(hwndTreeList, h_tviRootItem, L"SecurityDescriptor", lpType, devObject.SecurityDescriptor, 0, 0);

    //DeviceLock
    h_tviWaitEntry = supTreeListAddItem(hwndTreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0,
        TVIS_EXPANDED, L"DeviceLock", NULL);

    //DeviceLock->Header
    propObDumpDispatcherHeader(hwndTreeList, h_tviWaitEntry, &devObject.DeviceLock.Header, NULL, NULL, NULL);

    //SectorSize
    propObDumpUlong(hwndTreeList, h_tviRootItem, L"SectorSize", NULL, devObject.SectorSize, TRUE, TRUE, 0, 0);
    //Spare
    propObDumpUlong(hwndTreeList, h_tviRootItem, L"Spare1", NULL, devObject.Spare1, TRUE, TRUE, 0, 0);

    //DeviceObjectExtension
    lpType = L"PDEVOBJ_EXTENSION";
    propObDumpAddress(hwndTreeList, h_tviRootItem, L"DeviceObjectExtension", lpType, devObject.DeviceObjectExtension, 0, 0);

    //Reserved
    propObDumpAddress(hwndTreeList, h_tviRootItem, L"Reserved", NULL, devObject.Reserved, 0, 0);

    //
    //DEVOBJ_EXTENSION
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

        h_tviRootItem = supTreeListAddItem(hwndTreeList, NULL, TVIF_TEXT | TVIF_STATE, 0,
            TVIS_EXPANDED, L"DEVOBJ_EXTENSION", NULL);

        BgColor = 0;
        lpType = L"IO_TYPE_DEVICE_OBJECT_EXTENSION";
        if (devObjExt.Type != IO_TYPE_DEVICE_OBJECT_EXTENSION) {
            lpType = L"! Must be IO_TYPE_DEVICE_OBJECT_EXTENSION";
            BgColor = CLR_WARN;
        }
        //Type
        propObDumpUlong(hwndTreeList, h_tviRootItem, L"Type", lpType, devObjExt.Type, TRUE, TRUE, BgColor, 0);
        //Size
        propObDumpUlong(hwndTreeList, h_tviRootItem, L"Size", NULL, devObjExt.Size, TRUE, TRUE, 0, 0);

        //DeviceObject
        propDumpObjectForAddress(hwndTreeList, h_tviRootItem, L"DeviceObject",
            devObjExt.DeviceObject,
            CLR_LGRY,
            T_UNNAMED);

        //PowerFlags
        propObDumpUlong(hwndTreeList, h_tviRootItem, L"PowerFlags", NULL, devObjExt.PowerFlags, TRUE, FALSE, 0, 0);

        //Dope
        lpType = L"PDEVICE_OBJECT_POWER_EXTENSION";
        propObDumpAddress(hwndTreeList, h_tviRootItem, L"Dope", lpType, devObjExt.Dope, 0, 0);

        //ExtensionFlags
        propObDumpUlong(hwndTreeList, h_tviRootItem, L"ExtensionFlags", NULL, devObjExt.ExtensionFlags, TRUE, FALSE, 0, 0);

        //DeviceNode
        lpType = L"PDEVICE_NODE";
        propObDumpAddress(hwndTreeList, h_tviRootItem, L"DeviceNode", lpType, devObjExt.DeviceNode, 0, 0);

        //AttachedTo
        propDumpObjectForAddress(hwndTreeList, h_tviRootItem, L"AttachedTo",
            devObjExt.AttachedTo,
            CLR_LGRY,
            T_UNNAMED);

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
    LPWSTR lpType;

    if (SessionId == OBJ_INVALID_SESSION_ID)
        lpType = T_OBJ_INVALID_SESSION_ID;
    else
        lpType = NULL;

    propObDumpUlong(hwndTreeList, h_tviRootItem, TEXT("SessionId"), lpType, SessionId, TRUE, FALSE, 0, 0);
}

LPWSTR propObGetDosDriveTypeDesc(
    _In_ UCHAR DosDrive)
{
    ULONG i;

    for (i = 0; i < MAX_KNOWN_DOS_DRIVE_TYPE; i++) {
        if (dosDeviceDriveType[i].dwValue == DosDrive)
            return dosDeviceDriveType[i].lpDescription;

    }

    return T_UnknownType;
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
    } DeviceMapStruct;

    HTREEITEM h_tviSubItem, h_tviDriveType;
    TL_SUBITEMS_FIXED subitems;

    LPWSTR lpType;
    PVOID DeviceMapPtr;
    ULONG ObjectSize = 0;
    ULONG ObjectVersion = 0;
    ULONG i, driveMap;

    BYTE driveType;
    WCHAR szBuffer[MAX_PATH + 1];

    DeviceMapPtr = ObDumpDeviceMapVersionAware((ULONG_PTR)DeviceMapAddress,
        &ObjectSize,
        &ObjectVersion);

    if (DeviceMapPtr) {

        DeviceMapStruct.Ref = DeviceMapPtr;

        RtlSecureZeroMemory(&subitems, sizeof(subitems));
        subitems.Count = 2;

        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        szBuffer[0] = L'0';
        szBuffer[1] = L'x';
        u64tohex((ULONG_PTR)DeviceMapAddress, &szBuffer[2]);

        subitems.Text[0] = szBuffer;
        subitems.Text[1] = T_PDEVICE_MAP;

        h_tviSubItem = supTreeListAddItem(TreeList,
            ParentItem,
            TVIF_TEXT | TVIF_STATE,
            0,
            0,
            T_FIELD_DEVICE_MAP,
            &subitems);

        if (h_tviSubItem) {

            if (DeviceMapStruct.Versions.DeviceMapCompat->DosDevicesDirectory)
                lpType = T_POBJECT_DIRECTORY;
            else
                lpType = T_EMPTY;

            propObDumpAddress(TreeList, h_tviSubItem, T_DEVICEMAP_DOSDEVICESDIRECTORY, lpType,
                (PVOID)DeviceMapStruct.Versions.DeviceMapCompat->DosDevicesDirectory, 0, 0);

            if (DeviceMapStruct.Versions.DeviceMapCompat->GlobalDosDevicesDirectory)
                lpType = T_POBJECT_DIRECTORY;
            else
                lpType = T_EMPTY;

            propObDumpAddress(TreeList, h_tviSubItem, T_DEVICEMAP_GLOBALDOSDEVICESDIRECTORY, lpType,
                (PVOID)DeviceMapStruct.Versions.DeviceMapCompat->GlobalDosDevicesDirectory, 0, 0);

            if (ObjectVersion > OBVERSION_DEVICE_MAP_V2) {
                propObDumpAddress(TreeList, h_tviSubItem, T_DEVICEMAP_DOSDEVICESDIRECTORYHANDLE, NULL,
                    (PVOID)DeviceMapStruct.Versions.DeviceMapV3->DosDevicesDirectoryHandle, 0, 0);
            }
            else {

                propObDumpAddress(TreeList, h_tviSubItem, T_DEVICEMAP_DOSDEVICESDIRECTORYHANDLE, NULL,
                    (PVOID)DeviceMapStruct.Versions.DeviceMapCompat->DosDevicesDirectoryHandle, 0, 0);

            }

            //
            // ReferenceCount
            //
            switch (ObjectVersion) {
            case OBVERSION_DEVICE_MAP_V1:
                propObDumpUlong(TreeList, h_tviSubItem, T_REFERENCECOUNT, NULL,
                    DeviceMapStruct.Versions.DeviceMapV1->ReferenceCount, TRUE, FALSE, 0, 0);
                break;
            case OBVERSION_DEVICE_MAP_V2:
                propObDumpLong(TreeList, h_tviSubItem, T_REFERENCECOUNT, NULL,
                    DeviceMapStruct.Versions.DeviceMapV2->ReferenceCount, TRUE, 0, 0);
                break;
            case OBVERSION_DEVICE_MAP_V3:
            default:
                propObDumpLong64(TreeList, h_tviSubItem, T_REFERENCECOUNT, NULL,
                    DeviceMapStruct.Versions.DeviceMapV3->ReferenceCount, TRUE, 0, 0);
                break;
            }

            //
            // DriveMap
            //
            if (ObjectVersion > OBVERSION_DEVICE_MAP_V2) {
                driveMap = DeviceMapStruct.Versions.DeviceMapV3->DriveMap;
            }
            else {
                driveMap = DeviceMapStruct.Versions.DeviceMapCompat->DriveMap;
            }

            propObDumpUlong(TreeList, h_tviSubItem, T_DRIVEMAP, NULL,
                driveMap, TRUE, FALSE, 0, 0);

            //
            // Display DriveType array.
            //
            RtlSecureZeroMemory(&subitems, sizeof(subitems));

            subitems.Count = 2;
            subitems.Text[0] = T_EmptyString;
            subitems.Text[1] = T_EmptyString;

            h_tviDriveType = supTreeListAddItem(TreeList,
                h_tviSubItem,
                TVIF_TEXT | TVIF_STATE,
                0,
                0,
                T_DRIVETYPE,
                &subitems);

            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

            for (i = 0; i < RTL_NUMBER_OF(DeviceMapStruct.Versions.DeviceMapCompat->DriveType); i++) {

                RtlStringCchPrintfSecure(szBuffer,
                    MAX_PATH,
                    TEXT("[ %i ]"),
                    i);

                if (ObjectVersion > OBVERSION_DEVICE_MAP_V2) {
                    driveType = DeviceMapStruct.Versions.DeviceMapV3->DriveType[i];
                }
                else {
                    driveType = DeviceMapStruct.Versions.DeviceMapCompat->DriveType[i];
                }

                lpType = propObGetDosDriveTypeDesc(driveType);

                propObDumpByte(TreeList, h_tviDriveType,
                    szBuffer,
                    lpType,
                    driveType,
                    0,
                    0,
                    FALSE);

            }

            if (ObjectVersion > OBVERSION_DEVICE_MAP_V1) {

                if (ObjectVersion > OBVERSION_DEVICE_MAP_V2) {
                    propObDumpAddress(TreeList, h_tviSubItem, T_SERVERSILO, T_PEJOB,
                        (PVOID)DeviceMapStruct.Versions.DeviceMapV3->ServerSilo, 0, 0);
                }
                else {
                    propObDumpAddress(TreeList, h_tviSubItem, T_SERVERSILO, T_PEJOB,
                        (PVOID)DeviceMapStruct.Versions.DeviceMapCompat->ServerSilo, 0, 0);
                }
            }

        }

        supVirtualFree(DeviceMapPtr);
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
    INT                     i, j;
    ULONG                   SessionId, ObjectFlags;
    HTREEITEM               h_tviRootItem, h_tviSubItem, h_tviEntry;
    LPWSTR                  lpType;
    TL_SUBITEMS_FIXED       subitems;
    WCHAR                   szId[MAX_PATH + 1], szValue[MAX_PATH + 1];

    ULONG ObjectVersion = 0;
    ULONG ObjectSize = 0;

    PVOID DirectoryObjectPtr = NULL, NamespaceEntry;
    OBJECT_DIRECTORY_ENTRY dirEntry;
    LIST_ENTRY             ChainLink;

    union {
        union {
            OBJECT_DIRECTORY* DirObjectV1;
            OBJECT_DIRECTORY_V2* DirObjectV2;
            OBJECT_DIRECTORY_V3* DirObjectV3;
            OBJECT_DIRECTORY_V3* CompatDirObject;//has all field members
        } Versions;
        PVOID Ref;
    } DirObject;


    DirectoryObjectPtr = ObDumpDirectoryObjectVersionAware(ObjectAddress,
        &ObjectSize,
        &ObjectVersion);

    if (DirectoryObjectPtr == NULL) {
        if (ShowErrors)
            supObDumpShowError(ParentWindow, NULL);
        return;
    }

    DirObject.Ref = DirectoryObjectPtr;

    //
    //OBJECT_DIRECTORY
    //
    h_tviRootItem = RootItem;

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 1;
    subitems.Text[0] = TEXT("{...}");

    h_tviSubItem = supTreeListAddItem(TreeList,
        h_tviRootItem,
        TVIF_TEXT | TVIF_STATE,
        0,
        0,
        TEXT("HashBuckets"),
        &subitems);

    for (i = 0; i < NUMBER_HASH_BUCKETS; i++) {
        RtlSecureZeroMemory(&subitems, sizeof(subitems));
        subitems.Count = 2;

        RtlSecureZeroMemory(szId, sizeof(szId));

        RtlStringCchPrintfSecure(szId,
            MAX_PATH,
            TEXT("[ %i ]"),
            i);


        if (DirObject.Versions.CompatDirObject->HashBuckets[i]) {
            RtlSecureZeroMemory(szValue, sizeof(szValue));
            szValue[0] = TEXT('0');
            szValue[1] = TEXT('x');
            u64tohex((ULONG_PTR)DirObject.Versions.CompatDirObject->HashBuckets[i], &szValue[2]);
            subitems.Text[0] = szValue;
            subitems.Text[1] = T_POBJECT_DIRECTORY_ENTRY;
        }
        else {
            subitems.Text[0] = T_NULL;
            subitems.Text[1] = T_EmptyString;
        }

        h_tviEntry = supTreeListAddItem(TreeList,
            h_tviSubItem,
            TVIF_TEXT | TVIF_STATE,
            0,
            0,
            szId,
            &subitems);

        //dump entry if available
        if (DirObject.Versions.CompatDirObject->HashBuckets[i]) {

            RtlSecureZeroMemory(&dirEntry, sizeof(dirEntry));

            if (kdReadSystemMemory((ULONG_PTR)DirObject.Versions.CompatDirObject->HashBuckets[i],
                &dirEntry,
                sizeof(dirEntry)))
            {

                ChainLink.Blink = NULL;
                ChainLink.Flink = NULL;
                lpType = TEXT("ChainLink");
                if (dirEntry.ChainLink == NULL) {
                    propObDumpAddress(TreeList, h_tviEntry, lpType, T_EMPTY, NULL, 0, 0);
                }
                else {
                    if (kdReadSystemMemory(
                        (ULONG_PTR)dirEntry.ChainLink,
                        &ChainLink,
                        sizeof(ChainLink)))
                    {
                        propObDumpListEntry(TreeList, h_tviEntry, lpType, &ChainLink);
                    }
                    else {
                        //
                        // Failed to read listentry, display as is.
                        //
                        propObDumpAddress(TreeList, h_tviEntry, lpType, T_PLIST_ENTRY, dirEntry.ChainLink, 0, 0);
                    }
                }
                propObDumpAddress(TreeList, h_tviEntry, TEXT("Object"), NULL, dirEntry.Object, 0, 0);
                propObDumpUlong(TreeList, h_tviEntry, TEXT("HashValue"), NULL, dirEntry.HashValue, TRUE, FALSE, 0, 0);
            }
        }
    }

    //EX_PUSH_LOCK
    propObDumpPushLock(TreeList, h_tviRootItem,
        DirObject.Versions.CompatDirObject->Lock.Ptr, 0, 0);

    //DeviceMap
    if (DumpShadow) {
        propObDumpDeviceMap(TreeList, h_tviRootItem,
            DirObject.Versions.CompatDirObject->DeviceMap);
    }
    else {
        propObDumpAddress(TreeList, h_tviRootItem, TEXT("DeviceMap"), NULL,
            DirObject.Versions.CompatDirObject->DeviceMap, 0, 0);
    }

    //ShadowDirectory
    if (ObjectVersion != OBVERSION_DIRECTORY_V1) {


        if (DirObject.Versions.CompatDirObject->ShadowDirectory) {
            if (DumpShadow) {

                RtlSecureZeroMemory(&subitems, sizeof(subitems));
                subitems.Count = 2;

                RtlSecureZeroMemory(&szValue, sizeof(szValue));
                szValue[0] = L'0';
                szValue[1] = L'x';
                u64tohex((ULONG_PTR)DirObject.Versions.CompatDirObject->ShadowDirectory, &szValue[2]);

                subitems.Text[0] = szValue;
                subitems.Text[1] = T_POBJECT_DIRECTORY;

                h_tviSubItem = supTreeListAddItem(TreeList,
                    h_tviRootItem,
                    TVIF_TEXT | TVIF_STATE,
                    0,
                    0,
                    T_FIELD_SHADOW_DIRECTORY,
                    &subitems);

                propObDumpDirectoryObjectInternal(TreeList,
                    h_tviSubItem,
                    ParentWindow,
                    (ULONG_PTR)DirObject.Versions.CompatDirObject->ShadowDirectory,
                    FALSE, //do not allow recursion, only first level dir listed.
                    FALSE);
            }
        }
        else {
            //
            // No ShadowDirectory, display 0
            //
            propObDumpAddress(TreeList,
                h_tviRootItem,
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
    switch (ObjectVersion) {
    case OBVERSION_DIRECTORY_V1:
        SessionId = DirObject.Versions.DirObjectV1->SessionId;
        break;
    case OBVERSION_DIRECTORY_V2:
        SessionId = DirObject.Versions.DirObjectV2->SessionId;
        break;
    case OBVERSION_DIRECTORY_V3:
    default:
        SessionId = DirObject.Versions.DirObjectV3->SessionId;
        break;

    }

    //
    // SessionId is the last member of OBJECT_DIRECTORY_V3, so it will be listed in the end of routine.
    //
    //
    if (ObjectVersion != OBVERSION_DIRECTORY_V3) {
        propObDumpSessionIdVersionAware(TreeList, h_tviRootItem, SessionId);
    }

    //
    // NamespaceEntry
    //
    switch (ObjectVersion) {
    case OBVERSION_DIRECTORY_V1:
        NamespaceEntry = DirObject.Versions.DirObjectV1->NamespaceEntry;
        break;
    case OBVERSION_DIRECTORY_V2:
        NamespaceEntry = DirObject.Versions.DirObjectV2->NamespaceEntry;
        break;
    case OBVERSION_DIRECTORY_V3:
    default:
        NamespaceEntry = DirObject.Versions.DirObjectV3->NamespaceEntry;
        break;

    }

    propObDumpAddress(TreeList, h_tviRootItem, TEXT("NamespaceEntry"), NULL, NamespaceEntry, 0, 0);

    //
    // SessionObject
    //
    if (ObjectVersion == OBVERSION_DIRECTORY_V3) {

        propObDumpAddress(TreeList,
            h_tviRootItem,
            TEXT("SessionObject"),
            NULL,
            DirObject.Versions.DirObjectV3->SessionObject,
            0, 0);

    }

    //
    // ObjectDirectory flags.
    //       
    switch (ObjectVersion) {
    case OBVERSION_DIRECTORY_V1:
        ObjectFlags = DirObject.Versions.DirObjectV1->Flags;
        break;
    case OBVERSION_DIRECTORY_V2:
        ObjectFlags = DirObject.Versions.DirObjectV2->Flags;
        break;
    case OBVERSION_DIRECTORY_V3:
    default:
        ObjectFlags = DirObject.Versions.DirObjectV3->Flags;
        break;

    }

    if (ObjectFlags == 0) {
        propObDumpUlong(TreeList, h_tviRootItem, TEXT("Flags"), NULL, 0, TRUE, FALSE, 0, 0);
    }
    else {

        //
        // List flags.
        //
        RtlSecureZeroMemory(&szValue, sizeof(szValue));
        RtlSecureZeroMemory(&subitems, sizeof(subitems));
        j = 0;
        lpType = NULL;
        for (i = 0; i < MAX_KNOWN_OBJ_DIR_FLAGS; i++) {
            if (ObjectFlags & objDirFlags[i].dwValue) {
                lpType = objDirFlags[i].lpDescription;
                subitems.Count = 2;
                //add first entry with name
                if (j == 0) {
                    szValue[0] = L'0';
                    szValue[1] = L'x';
                    ultohex(ObjectFlags, &szValue[2]);

                    subitems.Text[0] = szValue;
                    subitems.Text[1] = lpType;
                }
                else {
                    //add subentry
                    subitems.Text[0] = T_EmptyString;
                    subitems.Text[1] = lpType;
                }

                supTreeListAddItem(
                    TreeList,
                    h_tviRootItem,
                    TVIF_TEXT | TVIF_STATE,
                    0,
                    0,
                    (j == 0) ? T_FLAGS : T_EmptyString,
                    &subitems);

                ObjectFlags &= ~objDirFlags[i].dwValue;
                j++;

            }
            if (ObjectFlags == 0) {
                break;
            }
        }

    }

    //
    // SessionId is the last member of OBJECT_DIRECTORY_V3
    //
    if (ObjectVersion == OBVERSION_DIRECTORY_V3) {

        propObDumpSessionIdVersionAware(TreeList,
            h_tviRootItem,
            SessionId);
    }

    supVirtualFree(DirectoryObjectPtr);
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

    HTREEITEM h_tviRootItem;
    LPWSTR    lpType = NULL, lpDescType = NULL, lpDesc1 = NULL, lpDesc2 = NULL;
    PVOID     Object = NULL;
    ULONG     ObjectSize = 0UL;
    WCHAR     szValue[MAX_PATH + 1];


    switch (Context->ObjectTypeIndex) {

    case ObjectTypeEvent:
        ObjectSize = sizeof(KEVENT);
        break;

    case ObjectTypeMutant:
        ObjectSize = sizeof(KMUTANT);
        break;

    case ObjectTypeSemaphore:
        ObjectSize = sizeof(KSEMAPHORE);
        break;

    case ObjectTypeTimer:
        ObjectSize = sizeof(KTIMER);
        break;

    }

    Object = supHeapAlloc(ObjectSize);
    if (Object == NULL) {
        supObDumpShowError(hwndDlg, NULL);
        return;
    }

    //dump object
    if (!kdReadSystemMemory(
        Context->ObjectInfo.ObjectAddress,
        Object,
        ObjectSize))
    {
        supObDumpShowError(hwndDlg, NULL);
        supHeapFree(Object);
        return;
    }

    //
    // Object name
    //
    Header = NULL;
    switch (Context->ObjectTypeIndex) {
    case ObjectTypeEvent:
        lpType = T_KEVENT;
        Event = (KEVENT*)Object;
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
        Mutant = (KMUTANT*)Object;
        Header = &Mutant->Header;
        lpDesc1 = TEXT("Not Held");

        RtlSecureZeroMemory(szValue, sizeof(szValue));
        if (Mutant->OwnerThread != NULL) {

            RtlStringCchPrintfSecure(szValue,
                MAX_PATH,
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
        Semaphore = (KSEMAPHORE*)Object;
        Header = &Semaphore->Header;

        lpDesc1 = TEXT("Count");
        lpDesc2 = NULL;
        if (Header->Size == (sizeof(KSEMAPHORE) / sizeof(ULONG))) {
            lpDesc2 = TEXT("sizeof(KSEMAPHORE)/sizeof(ULONG)");
        }
        break;

    case ObjectTypeTimer:
        lpType = T_KTIMER;
        Timer = (KTIMER*)Object;
        Header = &Timer->Header;

        lpDescType = T_TIMER_SYNC;
        if (Header->TimerType == 8) {
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
        supHeapFree(Object);
        return;
    }

    h_tviRootItem = supTreeListAddItem(
        hwndTreeList,
        NULL,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        lpType,
        NULL);

    //Header
    propObDumpDispatcherHeader(hwndTreeList, h_tviRootItem, Header, lpDescType, lpDesc1, lpDesc2);

    //type specific values
    switch (Context->ObjectTypeIndex) {
    case ObjectTypeMutant:
        if (Mutant) {
            propObDumpListEntry(hwndTreeList, h_tviRootItem, L"MutantListEntry", &Mutant->MutantListEntry);
            propObDumpAddress(hwndTreeList, h_tviRootItem, L"OwnerThread", T_PKTHREAD, Mutant->OwnerThread, 0, 0);
            propObDumpByte(hwndTreeList, h_tviRootItem, L"Abandoned", NULL, Mutant->Abandoned, 0, 0, TRUE);
            propObDumpByte(hwndTreeList, h_tviRootItem, L"ApcDisable", NULL, Mutant->ApcDisable, 0, 0, FALSE);
        }
        break;

    case ObjectTypeSemaphore:
        if (Semaphore) {
            propObDumpUlong(hwndTreeList, h_tviRootItem, L"Limit", NULL, Semaphore->Limit, TRUE, FALSE, 0, 0);
        }
        break;

    case ObjectTypeTimer:
        if (Timer) {
            propObDumpULargeInteger(hwndTreeList, h_tviRootItem, L"DueTime", &Timer->DueTime); //dumped as hex, not important
            propObDumpListEntry(hwndTreeList, h_tviRootItem, L"TimerListEntry", &Timer->TimerListEntry);
            propObDumpAddress(hwndTreeList, h_tviRootItem, L"Dpc", T_PKDPC, Timer->Dpc, 0, 0);
            propObDumpUlong(hwndTreeList, h_tviRootItem, L"Processor", NULL, Timer->Processor, TRUE, FALSE, 0, 0);
            propObDumpUlong(hwndTreeList, h_tviRootItem, L"Period", NULL, Timer->Period, TRUE, FALSE, 0, 0);
        }
        break;

    }

    supHeapFree(Object);

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
    _In_ LPWSTR* ObjectTypeFlagsText,
    _In_ BOOLEAN SetEntry
)
{
    ULONG i, j;
    LPWSTR lpType;
    TL_SUBITEMS_FIXED TreeListSubitems;

    WCHAR szValue[32];

    if (ObjectTypeFlags) {

        RtlSecureZeroMemory(&TreeListSubitems, sizeof(TreeListSubitems));
        TreeListSubitems.Count = 2;

        j = 0;
        for (i = 0; i < 8; i++) {
            if (GET_BIT(ObjectTypeFlags, i)) {
                lpType = (LPWSTR)ObjectTypeFlagsText[i];
                TreeListSubitems.Text[0] = T_EmptyString;
                if (j == 0) {

                    RtlSecureZeroMemory(szValue, sizeof(szValue));
                    RtlStringCchPrintfSecure(szValue,
                        RTL_NUMBER_OF(szValue),
                        FORMAT_HEXBYTE,
                        ObjectTypeFlags);

                    TreeListSubitems.Text[0] = szValue;
                }
                TreeListSubitems.Text[1] = lpType;
                supTreeListAddItem(TreeList,
                    h_tviSubItem,
                    TVIF_TEXT | TVIF_STATE,
                    0,
                    0,
                    (j == 0) ? ((SetEntry) ? EntryName : T_EmptyString) : T_EmptyString,
                    &TreeListSubitems);
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
    BOOL bOkay;
    HTREEITEM h_tviRootItem, h_tviSubItem, h_tviGenericMapping;
    UINT i;
    LPWSTR lpType = NULL;
    PVOID ObjectTypeInformation = NULL;
    PRTL_PROCESS_MODULES ModulesList = NULL;
    TL_SUBITEMS_FIXED TreeListSubItems;
    PVOID TypeProcs[MAX_KNOWN_OBJECT_TYPE_PROCEDURES];
    PVOID SelfDriverBase;
    ULONG SelfDriverSize;

    POBEX_OBJECT_INFORMATION CurrentObject = NULL;
    ULONG ObjectSize = 0;
    ULONG ObjectVersion = 0;

    BOOLEAN bSetEntry;

    ULONG Key;
    PVOID LockPtr;
    PLIST_ENTRY pListEntry;
    ULONG WaitObjectFlagMask;
    USHORT WaitObjectFlagOffset;
    USHORT WaitObjectPointerOffset;

    union {
        union {
            OBJECT_TYPE_COMPATIBLE* ObjectTypeCompatible;
            OBJECT_TYPE_7* ObjectType_7;
            OBJECT_TYPE_8* ObjectType_8;
            OBJECT_TYPE_RS1* ObjectType_RS1;
            OBJECT_TYPE_RS2* ObjectType_RS2;
        } Versions;
        PVOID Ref;
    } ObjectType;

    do {

        bOkay = FALSE;

        //
        // Get loaded modules list.
        //
        ModulesList = (PRTL_PROCESS_MODULES)supGetLoadedModulesList(NULL);
        if (ModulesList == NULL)
            break;

        //
        // Get the reference to the object.
        //
        CurrentObject = ObQueryObjectInDirectory(
            &Context->NtObjectName,
            ObGetPredefinedUnicodeString(OBP_OBTYPES));

        if (CurrentObject == NULL)
            break;

        //
        // Dump object information version aware.
        //
        ObjectTypeInformation = ObDumpObjectTypeVersionAware(
            CurrentObject->ObjectAddress,
            &ObjectSize,
            &ObjectVersion);

        if (ObjectTypeInformation == NULL)
            break;

        //
        // For listing common fields.
        //
        ObjectType.Ref = ObjectTypeInformation;

        //
        // Add treelist root item ("OBJECT_TYPE").
        //
        h_tviRootItem = supTreeListAddItem(
            hwndTreeList,
            NULL,
            TVIF_TEXT | TVIF_STATE,
            TVIS_EXPANDED,
            TVIS_EXPANDED,
            T_OBJECT_TYPE,
            NULL);

        //
        // This fields are structure version unaware.
        //
        propObDumpListEntry(hwndTreeList, h_tviRootItem, TEXT("TypeList"),
            &ObjectType.Versions.ObjectTypeCompatible->TypeList);

        propObDumpUnicodeString(hwndTreeList, h_tviRootItem, TEXT("Name"),
            &ObjectType.Versions.ObjectTypeCompatible->Name, FALSE);

        propObDumpAddress(hwndTreeList, h_tviRootItem, TEXT("DefaultObject"), NULL,
            ObjectType.Versions.ObjectTypeCompatible->DefaultObject, 0, 0);

        propObDumpByte(hwndTreeList, h_tviRootItem, T_TYPEINDEX, NULL,
            ObjectType.Versions.ObjectTypeCompatible->Index, 0, 0, FALSE);

        propObDumpUlong(hwndTreeList, h_tviRootItem, TEXT("TotalNumberOfObjects"), NULL,
            ObjectType.Versions.ObjectTypeCompatible->TotalNumberOfObjects, TRUE, FALSE, 0, 0);

        propObDumpUlong(hwndTreeList, h_tviRootItem, TEXT("TotalNumberOfHandles"), NULL,
            ObjectType.Versions.ObjectTypeCompatible->TotalNumberOfHandles, TRUE, FALSE, 0, 0);

        propObDumpUlong(hwndTreeList, h_tviRootItem, TEXT("HighWaterNumberOfObjects"), NULL,
            ObjectType.Versions.ObjectTypeCompatible->HighWaterNumberOfObjects, TRUE, FALSE, 0, 0);

        propObDumpUlong(hwndTreeList, h_tviRootItem, TEXT("HighWaterNumberOfHandles"), NULL,
            ObjectType.Versions.ObjectTypeCompatible->HighWaterNumberOfHandles, TRUE, FALSE, 0, 0);

        //
        // OBJECT_TYPE_INITIALIZER
        //
        RtlSecureZeroMemory(&TreeListSubItems, sizeof(TreeListSubItems));

        TreeListSubItems.Count = 2;
        TreeListSubItems.Text[0] = T_EmptyString;
        TreeListSubItems.Text[1] = T_OBJECT_TYPE_INITIALIZER;
        h_tviSubItem = supTreeListAddItem(hwndTreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0,
            0, TEXT("TypeInfo"), &TreeListSubItems);

        propObDumpUlong(hwndTreeList, h_tviSubItem, T_LENGTH, NULL,
            ObjectType.Versions.ObjectTypeCompatible->TypeInfo.Length, TRUE, TRUE, 0, 0);

        //
        // Dump Object Type Flags / Extended Object Type Flags
        //
        propObDumpObjectTypeFlags(hwndTreeList,
            T_OBJECT_TYPE_FLAGS,
            ObjectType.Versions.ObjectTypeCompatible->TypeInfo.ObjectTypeFlags,
            h_tviSubItem,
            (LPWSTR*)T_ObjectTypeFlags,
            TRUE);

        if (ObjectVersion > OBVERSION_OBJECT_TYPE_V2) {

            if (ObjectVersion == OBVERSION_OBJECT_TYPE_V3) {
                bSetEntry = TRUE;
                lpType = T_OBJECT_TYPE_FLAGS2; //fu ms
            }
            else {
                bSetEntry = FALSE;
                lpType = T_OBJECT_TYPE_FLAGS;
            }

            propObDumpObjectTypeFlags(hwndTreeList,
                lpType,
                ObjectType.Versions.ObjectType_RS1->TypeInfo.ObjectTypeFlags2,
                h_tviSubItem,
                (LPWSTR*)T_ObjectTypeFlags2,
                bSetEntry);

        }

        //
        // Structure version independent fields.
        //
        propObDumpUlong(hwndTreeList, h_tviSubItem, TEXT("ObjectTypeCode"), NULL,
            ObjectType.Versions.ObjectTypeCompatible->TypeInfo.ObjectTypeCode, TRUE, FALSE, 0, 0);

        propObDumpUlong(hwndTreeList, h_tviSubItem, TEXT("InvalidAttributes"), NULL,
            ObjectType.Versions.ObjectTypeCompatible->TypeInfo.InvalidAttributes, TRUE, FALSE, 0, 0);

        RtlSecureZeroMemory(&TreeListSubItems, sizeof(TreeListSubItems));
        TreeListSubItems.Count = 2;
        TreeListSubItems.Text[0] = T_EmptyString;
        TreeListSubItems.Text[1] = T_GENERIC_MAPPING;
        h_tviGenericMapping = supTreeListAddItem(hwndTreeList, h_tviSubItem, TVIF_TEXT | TVIF_STATE, 0,
            0, TEXT("GenericMapping"), &TreeListSubItems);

        propObDumpUlong(hwndTreeList, h_tviGenericMapping, TEXT("GenericRead"), NULL,
            ObjectType.Versions.ObjectTypeCompatible->TypeInfo.GenericMapping.GenericRead, TRUE, FALSE, 0, 0);

        propObDumpUlong(hwndTreeList, h_tviGenericMapping, TEXT("GenericWrite"), NULL,
            ObjectType.Versions.ObjectTypeCompatible->TypeInfo.GenericMapping.GenericWrite, TRUE, FALSE, 0, 0);

        propObDumpUlong(hwndTreeList, h_tviGenericMapping, TEXT("GenericExecute"), NULL,
            ObjectType.Versions.ObjectTypeCompatible->TypeInfo.GenericMapping.GenericExecute, TRUE, FALSE, 0, 0);

        propObDumpUlong(hwndTreeList, h_tviGenericMapping, TEXT("GenericAll"), NULL,
            ObjectType.Versions.ObjectTypeCompatible->TypeInfo.GenericMapping.GenericAll, TRUE, FALSE, 0, 0);

        propObDumpUlong(hwndTreeList, h_tviSubItem, TEXT("ValidAccessMask"), NULL,
            ObjectType.Versions.ObjectTypeCompatible->TypeInfo.ValidAccessMask, TRUE, FALSE, 0, 0);
        propObDumpUlong(hwndTreeList, h_tviSubItem, TEXT("RetainAccess"), NULL,
            ObjectType.Versions.ObjectTypeCompatible->TypeInfo.RetainAccess, TRUE, FALSE, 0, 0);

        //Pool Type
        lpType = T_Unknown;
        for (i = 0; i < MAX_KNOWN_POOL_TYPES; i++) {
            if (ObjectType.Versions.ObjectTypeCompatible->TypeInfo.PoolType == (POOL_TYPE)a_PoolTypes[i].dwValue) {
                lpType = a_PoolTypes[i].lpDescription;
                break;
            }
        }

        propObDumpUlong(hwndTreeList, h_tviSubItem, TEXT("PoolType"), lpType,
            ObjectType.Versions.ObjectTypeCompatible->TypeInfo.PoolType, TRUE, FALSE, 0, 0);

        propObDumpUlong(hwndTreeList, h_tviSubItem, TEXT("DefaultPagedPoolCharge"), NULL,
            ObjectType.Versions.ObjectTypeCompatible->TypeInfo.DefaultPagedPoolCharge, TRUE, FALSE, 0, 0);

        propObDumpUlong(hwndTreeList, h_tviSubItem, TEXT("DefaultNonPagedPoolCharge"), NULL,
            ObjectType.Versions.ObjectTypeCompatible->TypeInfo.DefaultNonPagedPoolCharge, TRUE, FALSE, 0, 0);

        //
        // List callback procedures.
        //
        // Copy type procedures to temp array, assume DumpProcedure always first.
        //
        RtlSecureZeroMemory(TypeProcs, sizeof(TypeProcs));

        RtlCopyMemory(&TypeProcs, 
            &ObjectType.Versions.ObjectTypeCompatible->TypeInfo.DumpProcedure, 
            sizeof(TypeProcs));

        //assume ntoskrnl first in list and list initialized
        SelfDriverBase = ModulesList->Modules[0].ImageBase;
        SelfDriverSize = ModulesList->Modules[0].ImageSize;

        for (i = 0; i < MAX_KNOWN_OBJECT_TYPE_PROCEDURES; i++) {
            if (TypeProcs[i]) {
                propObDumpAddressWithModule(hwndTreeList, h_tviSubItem, T_TYPEPROCEDURES[i], TypeProcs[i],
                    ModulesList, SelfDriverBase, SelfDriverSize);
            }
            else {
                propObDumpAddress(hwndTreeList, h_tviSubItem, T_TYPEPROCEDURES[i], NULL, TypeProcs[i], 0, 0);
            }
        }

        if (ObjectVersion > OBVERSION_OBJECT_TYPE_V1) {

            switch (ObjectVersion) {
            case OBVERSION_OBJECT_TYPE_V2:
                WaitObjectFlagMask = ObjectType.Versions.ObjectType_8->TypeInfo.WaitObjectFlagMask;
                WaitObjectFlagOffset = ObjectType.Versions.ObjectType_8->TypeInfo.WaitObjectFlagOffset;
                WaitObjectPointerOffset = ObjectType.Versions.ObjectType_8->TypeInfo.WaitObjectPointerOffset;
                break;
            case OBVERSION_OBJECT_TYPE_V3:
                WaitObjectFlagMask = ObjectType.Versions.ObjectType_RS1->TypeInfo.WaitObjectFlagMask;
                WaitObjectFlagOffset = ObjectType.Versions.ObjectType_RS1->TypeInfo.WaitObjectFlagOffset;
                WaitObjectPointerOffset = ObjectType.Versions.ObjectType_RS1->TypeInfo.WaitObjectPointerOffset;
                break;
            default:
                WaitObjectFlagMask = ObjectType.Versions.ObjectType_RS2->TypeInfo.WaitObjectFlagMask;
                WaitObjectFlagOffset = ObjectType.Versions.ObjectType_RS2->TypeInfo.WaitObjectFlagOffset;
                WaitObjectPointerOffset = ObjectType.Versions.ObjectType_RS2->TypeInfo.WaitObjectPointerOffset;
                break;
            }

            propObDumpUlong(hwndTreeList, h_tviSubItem, TEXT("WaitObjectFlagMask"), NULL, WaitObjectFlagMask, TRUE, FALSE, 0, 0);
            propObDumpUlong(hwndTreeList, h_tviSubItem, TEXT("WaitObjectFlagOffset"), NULL, WaitObjectFlagOffset, TRUE, TRUE, 0, 0);
            propObDumpUlong(hwndTreeList, h_tviSubItem, TEXT("WaitObjectPointerOffset"), NULL, WaitObjectPointerOffset, TRUE, TRUE, 0, 0);

        }

        //
        // Rest of OBJECT_TYPE
        //
        switch (ObjectVersion) {
        case OBVERSION_OBJECT_TYPE_V1: //7
            Key = ObjectType.Versions.ObjectType_7->Key;
            LockPtr = ObjectType.Versions.ObjectType_7->TypeLock.Ptr;
            pListEntry = &ObjectType.Versions.ObjectType_7->CallbackList;
            break;

        case OBVERSION_OBJECT_TYPE_V2: //8+
            Key = ObjectType.Versions.ObjectType_8->Key;
            LockPtr = ObjectType.Versions.ObjectType_8->TypeLock.Ptr;
            pListEntry = &ObjectType.Versions.ObjectType_8->CallbackList;
            break;

        case OBVERSION_OBJECT_TYPE_V3: //RS1
            Key = ObjectType.Versions.ObjectType_RS1->Key;
            LockPtr = ObjectType.Versions.ObjectType_RS1->TypeLock.Ptr;
            pListEntry = &ObjectType.Versions.ObjectType_RS1->CallbackList;
            break;

        default: //RS2+
            Key = ObjectType.Versions.ObjectType_RS2->Key;
            LockPtr = ObjectType.Versions.ObjectType_RS2->TypeLock.Ptr;
            pListEntry = &ObjectType.Versions.ObjectType_RS2->CallbackList;
            break;
        }

        propObDumpPushLock(hwndTreeList, h_tviRootItem, LockPtr, 0, 0);
        propObDumpUlong(hwndTreeList, h_tviRootItem, TEXT("Key"), NULL, Key, TRUE, FALSE, 0, 0);
        propObDumpListEntry(hwndTreeList, h_tviRootItem, TEXT("CallbackList"), pListEntry);

        bOkay = TRUE;

    } while (FALSE);

    //
    // Cleanup.
    //
    if (ModulesList) supHeapFree(ModulesList);
    if (ObjectTypeInformation) supVirtualFree(ObjectTypeInformation);
    if (CurrentObject) supHeapFree(CurrentObject);

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
    HTREEITEM h_tviRootItem;
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

    h_tviRootItem = supTreeListAddItem(
        hwndTreeList,
        NULL,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        T_KQUEUE,
        NULL);

    //Header
    propObDumpDispatcherHeader(hwndTreeList, h_tviRootItem, &Queue.Header, NULL, NULL, lpDesc2);

    //EntryListHead
    propObDumpListEntry(hwndTreeList, h_tviRootItem, TEXT("EntryListHead"), &Queue.EntryListHead);

    //CurrentCount
    propObDumpUlong(hwndTreeList, h_tviRootItem, TEXT("CurrentCount"), NULL, Queue.CurrentCount, TRUE, FALSE, 0, 0);

    //MaximumCount
    propObDumpUlong(hwndTreeList, h_tviRootItem, TEXT("MaximumCount"), NULL, Queue.MaximumCount, TRUE, FALSE, 0, 0);

    //ThreadListHead
    propObDumpListEntry(hwndTreeList, h_tviRootItem, TEXT("ThreadListHead"), &Queue.ThreadListHead);

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
    _Out_ FLT_FILTER_COMPATIBLE* ComposedObject
)
{
    union {
        union {
            FLT_FILTER_V1* V1;
            FLT_FILTER_V2* V2;
            FLT_FILTER_V3* V3;
            FLT_FILTER_V4* V4;
        } u1;
        PBYTE Ref;
    } FltFilter;

    RtlSecureZeroMemory(ComposedObject, sizeof(FLT_FILTER_COMPATIBLE));

    FltFilter.Ref = (PBYTE)ObjectBuffer;


    //
    // Same offset.
    //
    RtlCopyMemory(&ComposedObject->Base, &FltFilter.u1.V1->Base, sizeof(FLT_OBJECT));

    //
    // UniqueIdentifier
    //
    if (ObjectVersion >= OBVERSION_FLT_FILTER_V3)
        ComposedObject->Base.UniqueIdentifier = FltFilter.u1.V3->Base.UniqueIdentifier;

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
    default:
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
    }
}

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
    szValue[0] = L'0';
    szValue[1] = L'x';
    szValue[2] = 0;
    u64tohex((ULONG_PTR)Address, &szValue[2]);
    subitems.Text[0] = szValue;
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

        } // FLT_OBJECT Base;

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

        if (compatObject.FilterUnload) {
            propObDumpAddressWithModule(TreeList,
                parentSubItem,
                TEXT("FilterUnload"),
                compatObject.FilterUnload,
                LoadedModules,
                NULL, 0);
        }

        if (compatObject.InstanceSetup) {
            propObDumpAddressWithModule(TreeList,
                parentSubItem,
                TEXT("InstanceSetup"),
                compatObject.InstanceSetup,
                LoadedModules,
                NULL, 0);
        }

        if (compatObject.InstanceQueryTeardown) {
            propObDumpAddressWithModule(TreeList,
                parentSubItem,
                TEXT("InstanceQueryTeardown"),
                compatObject.InstanceQueryTeardown,
                LoadedModules,
                NULL, 0);
        }

        if (compatObject.InstanceTeardownStart) {
            propObDumpAddressWithModule(TreeList,
                parentSubItem,
                TEXT("InstanceTeardownStart"),
                compatObject.InstanceTeardownStart,
                LoadedModules,
                NULL, 0);
        }

        if (compatObject.InstanceTeardownComplete) {
            propObDumpAddressWithModule(TreeList,
                parentSubItem,
                TEXT("InstanceTeardownComplete"),
                compatObject.InstanceTeardownComplete,
                LoadedModules,
                NULL, 0);
        }

        if (compatObject.PreVolumeMount) {
            propObDumpAddressWithModule(TreeList,
                parentSubItem,
                TEXT("PreVolumeMount"),
                compatObject.PreVolumeMount,
                LoadedModules,
                NULL, 0);
        }

        if (compatObject.PostVolumeMount) {
            propObDumpAddressWithModule(TreeList,
                parentSubItem,
                TEXT("PostVolumeMount"),
                compatObject.PostVolumeMount,
                LoadedModules,
                NULL, 0);
        }

        if (compatObject.GenerateFileName) {
            propObDumpAddressWithModule(TreeList,
                parentSubItem,
                TEXT("GenerateFileName"),
                compatObject.GenerateFileName,
                LoadedModules,
                NULL, 0);
        }

        if (compatObject.NormalizeNameComponent) {
            propObDumpAddressWithModule(TreeList,
                parentSubItem,
                TEXT("NormalizeNameComponent"),
                compatObject.NormalizeNameComponent,
                LoadedModules,
                NULL, 0);
        }

        if (compatObject.NormalizeNameComponentEx) {
            propObDumpAddressWithModule(TreeList,
                parentSubItem,
                TEXT("NormalizeNameComponentEx"),
                compatObject.NormalizeNameComponentEx,
                LoadedModules,
                NULL, 0);
        }

        if (compatObject.NormalizeContextCleanup) {
            propObDumpAddressWithModule(TreeList,
                parentSubItem,
                TEXT("NormalizeContextCleanup"),
                compatObject.NormalizeContextCleanup,
                LoadedModules,
                NULL, 0);
        }

        if (compatObject.KtmNotification) {
            propObDumpAddressWithModule(TreeList,
                parentSubItem,
                TEXT("KtmNotification"),
                compatObject.KtmNotification,
                LoadedModules,
                NULL, 0);
        }


        if (compatObject.SectionNotification) {
            propObDumpAddressWithModule(TreeList,
                parentSubItem,
                TEXT("SectionNotification"),
                compatObject.SectionNotification,
                LoadedModules,
                NULL, 0);
        }


        if (compatObject.OldDriverUnload) {
            propObDumpAddressWithModule(TreeList,
                parentSubItem,
                TEXT("OldDriverUnload"),
                compatObject.OldDriverUnload,
                LoadedModules,
                NULL, 0);
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
    HTREEITEM h_tviRootItem;
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

        h_tviRootItem = supTreeListAddItem(
            hwndTreeList,
            NULL,
            TVIF_TEXT | TVIF_STATE,
            TVIS_EXPANDED,
            TVIS_EXPANDED,
            T_FLT_SERVER_PORT_OBJECT,
            NULL);

        if (h_tviRootItem) {

            propObDumpListEntry(hwndTreeList, h_tviRootItem, L"FilterLink", &FltServerPortObject.FilterLink);

            propObDumpAddressWithModule(hwndTreeList, h_tviRootItem, L"ConnectNotify",
                FltServerPortObject.ConnectNotify, pModules, NULL, 0);

            propObDumpAddressWithModule(hwndTreeList, h_tviRootItem, L"DisconnectNotify",
                FltServerPortObject.DisconnectNotify, pModules, NULL, 0);

            propObDumpAddressWithModule(hwndTreeList, h_tviRootItem, L"MessageNotify",
                FltServerPortObject.MessageNotify, pModules, NULL, 0);

            propObxDumpFltFilter(hwndTreeList, h_tviRootItem, FltServerPortObject.Filter, pModules);

            propObDumpAddress(hwndTreeList, h_tviRootItem, L"Cookie", NULL, FltServerPortObject.Cookie, 0, 0);
            propObDumpUlong(hwndTreeList, h_tviRootItem, L"Flags", NULL, FltServerPortObject.Flags, TRUE, FALSE, 0, 0);
            propObDumpLong(hwndTreeList, h_tviRootItem, L"NumberOfConnections", NULL, FltServerPortObject.NumberOfConnections, TRUE, 0, 0);
            propObDumpLong(hwndTreeList, h_tviRootItem, L"MaxConnections", NULL, FltServerPortObject.MaxConnections, TRUE, 0, 0);

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
    HTREEITEM h_tviSubItem;
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
    h_tviSubItem = supTreeListAddItem(
        TreeList,
        h_tviRootItem,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        T_ALPC_HANDLE_TABLE,
        NULL);

    propObDumpAddress(
        TreeList,
        h_tviSubItem,
        TEXT("Handles"),
        TEXT("PALPC_HANDLE_ENTRY"),
        (PVOID)AlpcPortCommunicationInfo.u1.CommInfoV1->HandleTable.Handles,
        0,
        0);

    propObDumpUlong(
        TreeList,
        h_tviSubItem,
        TEXT("TotalHandles"),
        NULL,
        AlpcPortCommunicationInfo.u1.CommInfoV1->HandleTable.TotalHandles,
        TRUE,
        FALSE,
        0,
        0);

    propObDumpUlong(
        TreeList,
        h_tviSubItem,
        TEXT("Flags"),
        NULL,
        AlpcPortCommunicationInfo.u1.CommInfoV1->HandleTable.Flags,
        TRUE,
        FALSE,
        0,
        0);

    propObDumpPushLock(
        TreeList,
        h_tviSubItem,
        AlpcPortCommunicationInfo.u1.CommInfoV1->HandleTable.Lock.Ptr,
        0,
        0);

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
    ULONG BufferSize = 0, ObjectVersion = 0, i, c;
    HTREEITEM h_tviRootItem, h_tviSubItem;

    PBYTE PortDumpBuffer = NULL;
    ALPC_PORT_ATTRIBUTES* PortAttributes;
    ALPC_PORT_STATE PortState;
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

    PortDumpBuffer = (PBYTE)ObDumpAlpcPortObjectVersionAware(
        Context->ObjectInfo.ObjectAddress,
        &BufferSize,
        &ObjectVersion);

    if (PortDumpBuffer == NULL) {
        supObDumpShowError(hwndDlg, NULL);
        return;
    }

    AlpcPort.Ref = PortDumpBuffer;

    h_tviRootItem = supTreeListAddItem(
        hwndTreeList,
        NULL,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        T_ALPC_PORT_OBJECT,
        NULL);

    //
    //  Dump AlpcPort->PortListEntry, same offset for every supported Windows.
    //   
    propObDumpListEntry(
        hwndTreeList,
        h_tviRootItem,
        TEXT("PortListEntry"),
        &AlpcPort.u1.Port7600->PortListEntry);

    //
    //  Dump AlpcPort->CommunicationInfo, same offset for every supported Windows, however target structure is version aware.
    // 

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 2;

    szValue[0] = L'0';
    szValue[1] = L'x';
    szValue[2] = 0;
    u64tohex((ULONG_PTR)AlpcPort.u1.Port7600->CommunicationInfo, &szValue[2]);
    subitems.Text[0] = szValue;
    subitems.Text[1] = TEXT("PALPC_COMMUNICATION_INFO");

    h_tviSubItem = supTreeListAddItem(
        hwndTreeList,
        h_tviRootItem,
        TVIF_TEXT,
        0,
        0,
        TEXT("CommunicationInfo"),
        &subitems);

    propObxDumpAlpcPortCommunicationInfo(hwndTreeList,
        (ObjectVersion > OBVERSION_ALPCPORT_V2) ? 2 : 1,
        (ULONG_PTR)AlpcPort.u1.Port7600->CommunicationInfo,
        h_tviSubItem);

    //
    //  Dump AlpcPort->OwnerProcess, same offset for every supported Windows, however target structure is version aware.
    //
    propObDumpAddress(
        hwndTreeList,
        h_tviRootItem,
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
        h_tviRootItem,
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
        h_tviRootItem,
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
        h_tviRootItem,
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
        h_tviRootItem,
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
        h_tviRootItem,
        &AlpcPort.u1.Port7600->StaticSecurity.SecurityQos);
    */

    //
    // Dump AlpcPort->PortAttributes, offset is version aware.
    //
    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 2;
    subitems.Text[0] = T_EmptyString;
    subitems.Text[1] = TEXT("ALPC_PORT_ATTRIBUTES");

    h_tviSubItem = supTreeListAddItem(
        hwndTreeList,
        h_tviRootItem,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        TEXT("PortAttributes"),
        &subitems);

    switch (ObjectVersion) {
    case OBVERSION_ALPCPORT_V1:
        PortAttributes = &AlpcPort.u1.Port7600->PortAttributes;
        break;
    case OBVERSION_ALPCPORT_V2:
        PortAttributes = &AlpcPort.u1.Port9200->PortAttributes;
        break;
    case OBVERSION_ALPCPORT_V3:
        PortAttributes = &AlpcPort.u1.Port9600->PortAttributes;
        break;
    case OBVERSION_ALPCPORT_V4:
        PortAttributes = &AlpcPort.u1.Port10240->PortAttributes;
        break;
    default:
        PortAttributes = NULL;
        break;
    }

    if (PortAttributes) {

        propObDumpUlong(
            hwndTreeList,
            h_tviSubItem,
            T_FLAGS,
            NULL,
            PortAttributes->Flags,
            TRUE,
            FALSE,
            0,
            0);

        propObDumpSqos(
            hwndTreeList,
            h_tviSubItem,
            &PortAttributes->SecurityQos);

        propObDumpUlong64(
            hwndTreeList,
            h_tviSubItem,
            TEXT("MaxMessageLength"),
            NULL,
            (ULONG64)PortAttributes->MaxMessageLength,
            FALSE,
            0,
            0);

        propObDumpUlong64(
            hwndTreeList,
            h_tviSubItem,
            TEXT("MemoryBandwidth"),
            NULL,
            (ULONG64)PortAttributes->MemoryBandwidth,
            FALSE,
            0,
            0);

        propObDumpUlong64(
            hwndTreeList,
            h_tviSubItem,
            TEXT("MaxPoolUsage"),
            NULL,
            (ULONG64)PortAttributes->MaxPoolUsage,
            FALSE,
            0,
            0);

        propObDumpUlong64(
            hwndTreeList,
            h_tviSubItem,
            TEXT("MaxSectionSize"),
            NULL,
            (ULONG64)PortAttributes->MaxSectionSize,
            FALSE,
            0,
            0);

        propObDumpUlong64(
            hwndTreeList,
            h_tviSubItem,
            TEXT("MaxViewSize"),
            NULL,
            (ULONG64)PortAttributes->MaxViewSize,
            FALSE,
            0,
            0);

        propObDumpUlong64(
            hwndTreeList,
            h_tviSubItem,
            TEXT("MaxTotalSectionSize"),
            NULL,
            (ULONG64)PortAttributes->MaxTotalSectionSize,
            FALSE,
            0,
            0);

        propObDumpUlong(
            hwndTreeList,
            h_tviSubItem,
            TEXT("DupObjectTypes"),
            NULL,
            PortAttributes->DupObjectTypes,
            FALSE,
            FALSE,
            0,
            0);
    }

    //
    // Dump AlpcPort->State, offset is version aware.
    //
    h_tviSubItem = supTreeListAddItem(
        hwndTreeList,
        h_tviRootItem,
        TVIF_TEXT,
        0,
        0,
        TEXT("State"),
        NULL);

    PortState.State = 0;

    switch (ObjectVersion) {
    case OBVERSION_ALPCPORT_V1:
        PortState.State = AlpcPort.u1.Port7600->u1.State;
        break;
    case OBVERSION_ALPCPORT_V2:
        PortState.State = AlpcPort.u1.Port9200->u1.State;
        break;
    case OBVERSION_ALPCPORT_V3:
        PortState.State = AlpcPort.u1.Port9600->u1.State;
        break;
    case OBVERSION_ALPCPORT_V4:
        PortState.State = AlpcPort.u1.Port10240->u1.State;
        break;
    }

    for (i = 0; i < RTL_NUMBER_OF(T_ALPC_PORT_STATE); i++) {
        if (i == 1) {
            c = (BYTE)PortState.s1.Type;
        }
        else {
            c = GET_BIT(PortState.State, i);
        }
        propObDumpByte(
            hwndTreeList,
            h_tviSubItem,
            T_ALPC_PORT_STATE[i],
            NULL,
            (BYTE)c,
            0,
            0,
            FALSE);

    }
    supVirtualFree(PortDumpBuffer);
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
    SIZE_T Count;
    ULONG_PTR ListHead;
    HTREEITEM h_tviRootItem;

    LIST_ENTRY ListEntry;

    PRTL_PROCESS_MODULES Modules;

    CALLBACK_OBJECT ObjectDump;
    CALLBACK_REGISTRATION CallbackRegistration;

    UNICODE_STRING NormalizedName;
    LPWSTR ObjectName;

    //
    // Read object body.
    //
    RtlSecureZeroMemory(&ObjectDump, sizeof(CALLBACK_OBJECT));

    if (!kdReadSystemMemory(
        Context->ObjectInfo.ObjectAddress,
        (PVOID)&ObjectDump,
        sizeof(ObjectDump)))
    {
        supObDumpShowError(hwndDlg, NULL);
        return;
    }

    //
    // Verify object signature.
    //
    if (ObjectDump.Signature != EX_CALLBACK_SIGNATURE) {
        supObDumpShowError(hwndDlg, NULL);
        return;
    }

    //
    // Create a snapshot list of loaded modules.
    //
    Modules = (PRTL_PROCESS_MODULES)supGetLoadedModulesList(NULL);
    if (Modules == NULL) {
        supObDumpShowError(hwndDlg, NULL);
        return;
    }

    //
    // Add root item to the treelist in expanded state.
    //
    h_tviRootItem = supTreeListAddItem(
        hwndTreeList,
        NULL,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        TEXT("Callbacks"),
        NULL);

    //
    // Walk RegisteredCallback list entry.
    //
    ListHead = Context->ObjectInfo.ObjectAddress + FIELD_OFFSET(CALLBACK_OBJECT, RegisteredCallbacks);
    ListEntry.Flink = ObjectDump.RegisteredCallbacks.Flink;
    Count = 0;

    if (supNormalizeUnicodeStringForDisplay(g_obexHeap, &Context->NtObjectName, &NormalizedName)) {
        ObjectName = NormalizedName.Buffer;
    }
    else {
        ObjectName = Context->NtObjectName.Buffer;
    }

    while ((ULONG_PTR)ListEntry.Flink != ListHead) {

        //
        // Read callback registration data.
        //
        RtlSecureZeroMemory(&CallbackRegistration, sizeof(CallbackRegistration));
        if (!kdReadSystemMemory((ULONG_PTR)ListEntry.Flink,
            (PVOID)&CallbackRegistration,
            sizeof(CallbackRegistration)))
        {
            //
            // Abort all output on error.
            //
            supObDumpShowError(hwndDlg, NULL);
            break;
        }

        Count += 1;
        ListEntry.Flink = CallbackRegistration.Link.Flink;

        propObDumpAddressWithModule(hwndTreeList,
            h_tviRootItem,
            ObjectName,
            CallbackRegistration.CallbackFunction,
            Modules,
            NULL,
            0);
    }

    //
    // If nothing found (or possible query error) output this message.
    //
    if (Count == 0) {
        supObDumpShowError(hwndDlg,
            TEXT("This object has no registered callbacks or there is an query error."));
    }

    supFreeDuplicatedUnicodeString(g_obexHeap, &NormalizedName, FALSE);
    supHeapFree(Modules);
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
    BOOLEAN IsCallbackLink = FALSE;
    HTREEITEM h_tviRootItem;

    LPWSTR IntegrityLevelString;

    PBYTE SymLinkDumpBuffer = NULL;

    ULONG BufferSize = 0, ObjectVersion = 0;

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
    } SymbolicLink;

    WCHAR szTime[64], szConvert[64];


    SymLinkDumpBuffer = (PBYTE)ObDumpSymbolicLinkObjectVersionAware(
        Context->ObjectInfo.ObjectAddress,
        &BufferSize,
        &ObjectVersion);

    if (SymLinkDumpBuffer == NULL) {
        supObDumpShowError(hwndDlg, NULL);
        return;
    }

    SymbolicLink.Ref = SymLinkDumpBuffer;

    //
    // Add root item to the treelist in expanded state.
    //
    h_tviRootItem = supTreeListAddItem(
        hwndTreeList,
        NULL,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        T_OBJECT_SYMBOLIC_LINK,
        NULL);

    //
    // Output CreationTime.
    //
    szTime[0] = 0;
    supPrintTimeConverted(&SymbolicLink.u1.LinkV1->CreationTime, szTime, RTL_NUMBER_OF(szTime));

    RtlSecureZeroMemory(&subitems, sizeof(subitems));

    szConvert[0] = TEXT('0');
    szConvert[1] = TEXT('x');
    szConvert[2] = 0;
    u64tohex((ULONG64)SymbolicLink.u1.LinkV1->CreationTime.QuadPart, &szConvert[2]);

    subitems.Count = 2;
    subitems.Text[0] = szConvert;
    subitems.Text[1] = szTime;

    supTreeListAddItem(
        hwndTreeList,
        h_tviRootItem,
        TVIF_TEXT,
        0,
        0,
        TEXT("CreationTime"),
        &subitems);

    if (ObjectVersion > OBVERSION_OBJECT_SYMBOLIC_LINK_V3) {
        IsCallbackLink = (SymbolicLink.u1.LinkV4->Flags & 0x10);
    }

    if (IsCallbackLink) {

        pModules = (PRTL_PROCESS_MODULES)supGetLoadedModulesList(NULL);
        if (pModules) {

            propObDumpAddressWithModule(hwndTreeList, h_tviRootItem, TEXT("Callback"),
                SymbolicLink.u1.LinkV4->u1.Callback, pModules, NULL, 0);

            supHeapFree(pModules);
        }
        else {

            propObDumpAddress(hwndTreeList, h_tviRootItem, TEXT("Callback"), NULL,
                SymbolicLink.u1.LinkV4->u1.Callback, 0, 0);

        }

        propObDumpAddress(hwndTreeList, h_tviRootItem, TEXT("CallbackContext"), NULL,
            SymbolicLink.u1.LinkV4->u1.CallbackContext, 0, 0);
    }
    else {
        propObDumpUnicodeString(hwndTreeList, h_tviRootItem, TEXT("LinkTarget"), &SymbolicLink.u1.LinkV1->LinkTarget, FALSE);
    }

    propObDumpUlong(hwndTreeList, h_tviRootItem, TEXT("DosDeviceDriveIndex"), NULL, SymbolicLink.u1.LinkV1->DosDeviceDriveIndex, TRUE, FALSE, 0, 0);

    //
    // Output new Windows 10 values.
    //
    if (ObjectVersion > OBVERSION_OBJECT_SYMBOLIC_LINK_V1)
        propObDumpUlong(hwndTreeList, h_tviRootItem, TEXT("Flags"), NULL,
            SymbolicLink.u1.LinkV2->Flags, TRUE, FALSE, 0, 0);

    if (ObjectVersion > OBVERSION_OBJECT_SYMBOLIC_LINK_V2)
        propObDumpUlong(hwndTreeList, h_tviRootItem, TEXT("AccessMask"), NULL,
            SymbolicLink.u1.LinkV3->AccessMask, TRUE, FALSE, 0, 0);

    if (ObjectVersion > OBVERSION_OBJECT_SYMBOLIC_LINK_V4) {
        IntegrityLevelString = supIntegrityToString(SymbolicLink.u1.LinkV5->IntegrityLevel);

        propObDumpUlong(hwndTreeList, h_tviRootItem, TEXT("IntegrityLevel"), IntegrityLevelString,
            SymbolicLink.u1.LinkV5->IntegrityLevel, TRUE, FALSE, 0, 0);
    }

    supVirtualFree(SymLinkDumpBuffer);
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
    pfnObDumpRoutine ObDumpRoutine = NULL;
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
        ObDumpRoutine = (pfnObDumpRoutine)propObDumpDirectoryObject;
        break;

    case ObjectTypeDriver:
        ObDumpRoutine = (pfnObDumpRoutine)propObDumpDriverObject;
        break;

    case ObjectTypeDevice:
        ObDumpRoutine = (pfnObDumpRoutine)propObDumpDeviceObject;
        break;

    case ObjectTypeEvent:
    case ObjectTypeMutant:
    case ObjectTypeSemaphore:
    case ObjectTypeTimer:
        ObDumpRoutine = (pfnObDumpRoutine)propObDumpSyncObject;
        break;

    case ObjectTypePort:
        ObDumpRoutine = (pfnObDumpRoutine)propObDumpAlpcPort;
        break;

    case ObjectTypeIoCompletion:
        ObDumpRoutine = (pfnObDumpRoutine)propObDumpQueueObject;
        break;

    case ObjectTypeFltConnPort:
        ObDumpRoutine = (pfnObDumpRoutine)propObDumpFltServerPort;
        break;

    case ObjectTypeCallback:
        ObDumpRoutine = (pfnObDumpRoutine)propObDumpCallback;
        break;

    case ObjectTypeSymbolicLink:
        ObDumpRoutine = (pfnObDumpRoutine)propObDumpSymbolicLink;
        break;

    case ObjectTypeType:
        ObDumpRoutine = (pfnObDumpRoutine)propObDumpObjectType;
        break;

    default:
        ObDumpRoutine = NULL;
        break;
    }

    if (ObDumpRoutine) {

        //
        // Initialize treelist, abort on error.
        //
        if (supInitTreeListForDump(hwndDlg, &pvDlgContext->TreeList)) {
            supTreeListEnableRedraw(pvDlgContext->TreeList, FALSE);

            ObDumpRoutine(Context, hwndDlg, pvDlgContext->TreeList);

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
