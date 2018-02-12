/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       PROPOBJECTDUMP.C
*
*  VERSION:     1.52
*
*  DATE:        13 Jan 2018
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "treelist.h"
#include "propDlg.h"
#include "propObjectDumpConsts.h"
#include "propTypeConsts.h"

//global variables for TreeList
HWND g_TreeList;
ATOM g_TreeListAtom;

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
    TVINSERTSTRUCT  tvitem;
    PTL_SUBITEMS    si = (PTL_SUBITEMS)subitems;

    RtlSecureZeroMemory(&tvitem, sizeof(tvitem));
    tvitem.hParent = hParent;
    tvitem.item.mask = mask;
    tvitem.item.state = state;
    tvitem.item.stateMask = stateMask;
    tvitem.item.pszText = pszText;
    return TreeList_InsertTreeItem(TreeList, &tvitem, si);
}

/*
* ObDumpShowError
*
* Purpose:
*
* Hide all windows for given hwnd and display error text.
*
*/
VOID ObDumpShowError(
    _In_ HWND hwndDlg
)
{
    RECT rGB;

    if (GetWindowRect(hwndDlg, &rGB)) {
        EnumChildWindows(hwndDlg, supEnumHideChildWindows, (LPARAM)&rGB);
    }
    ShowWindow(GetDlgItem(hwndDlg, ID_OBJECTDUMPERROR), SW_SHOW);
}

/*
* ObDumpAddress
*
* Purpose:
*
* Dump given Address to the treelist.
*
*/
VOID ObDumpAddress(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_opt_ LPWSTR lpszDesc, //additional text to be displayed
    _In_opt_ PVOID Address,
    _In_ COLORREF BgColor,
    _In_ COLORREF FontColor
)
{
    TL_SUBITEMS_FIXED  subitems;
    WCHAR              szValue[100];

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
    TreeListAddItem(TreeList, hParent, TVIF_TEXT | TVIF_STATE, 0,
        0, lpszName, &subitems);
}

/*
* ObDumpAddressWithModule
*
* Purpose:
*
* Dump given Address to the treelist with module check.
*
*/
VOID ObDumpAddressWithModule(
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_opt_ PVOID Address,
    _In_ PVOID pModules,
    _In_opt_ PVOID SelfDriverBase,
    _In_opt_ ULONG SelfDriverSize
)
{
    TL_SUBITEMS_FIXED   subitems;
    WCHAR               szValue[100], szModuleName[MAX_PATH * 2];

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 2;
    subitems.Text[0] = T_NULL;
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
        if (supFindModuleNameByAddress(pModules, Address, _strend(szModuleName), MAX_PATH)) {
            subitems.Text[1] = szModuleName;
        }
        else {
            //unknown address outside any visible modules, warn
            subitems.Text[1] = T_Unknown;
            subitems.ColorFlags = TLF_BGCOLOR_SET;
            subitems.BgColor = CLR_WARN;
        }
    }
    TreeListAddItem(g_TreeList, hParent, TVIF_TEXT | TVIF_STATE, 0,
        0, lpszName, &subitems);
}

/*
* ObDumpByte
*
* Purpose:
*
* Dump BYTE to the treelist.
* Dump BOOL if IsBool set.
* You must handle BOOLEAN differently.
*
*/
VOID ObDumpByte(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_opt_ LPWSTR lpszDesc,
    _In_ BYTE Value,
    _In_opt_ COLORREF BgColor,
    _In_opt_ COLORREF FontColor,
    _In_ BOOL IsBool
)
{
    TL_SUBITEMS_FIXED   subitems;
    WCHAR               szValue[100];

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
        wsprintf(szValue, FORMAT_HEXBYTE, Value);
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

    TreeListAddItem(TreeList, hParent, TVIF_TEXT | TVIF_STATE, 0,
        0, lpszName, &subitems);
}


/*
* ObDumpUlong
*
* Purpose:
*
* Dump ULONG 4 bytes / USHORT 2 bytes to the treelist.
*
*/
VOID ObDumpUlong(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_opt_ LPWSTR lpszDesc, //additional text to be displayed
    _In_ ULONG Value,
    _In_ BOOL HexDump,
    _In_ BOOL IsUShort,
    _In_opt_ COLORREF BgColor,
    _In_opt_ COLORREF FontColor
)
{
    TL_SUBITEMS_FIXED   subitems;
    WCHAR               szValue[100];

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
            wsprintf(szValue, FORMAT_HEXUSHORT, Value);
        }
        else {
            szValue[0] = L'0';
            szValue[1] = L'x';
            ultohex(Value, &szValue[2]);
        }
    }
    else {
        if (IsUShort) {
            wsprintf(szValue, FORMAT_USHORT, Value);
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

    TreeListAddItem(TreeList, hParent, TVIF_TEXT | TVIF_STATE, 0,
        0, lpszName, &subitems);
}

/*
* ObDumpULargeInteger
*
* Purpose:
*
* Dump ULARGE_INTEGER members to the treelist.
*
*/
VOID ObDumpULargeInteger(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR ListEntryName,
    _In_opt_ PULARGE_INTEGER Value
)
{
    HTREEITEM           h_tviSubItem;
    TL_SUBITEMS_FIXED   subitems;
    WCHAR               szValue[100];

    h_tviSubItem = TreeListAddItem(g_TreeList, hParent, TVIF_TEXT | TVIF_STATE, TVIS_EXPANDED,
        0, ListEntryName, NULL);

    if (h_tviSubItem == NULL) {
        return;
    }

    //add large integer entry item to treelist and exit if value is null
    if (Value == NULL) {
        return;
    }

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 1;

    RtlSecureZeroMemory(&szValue, sizeof(szValue));
    szValue[0] = L'0';
    szValue[1] = L'x';
    ultohex(Value->LowPart, &szValue[2]);
    subitems.Text[0] = szValue;
    TreeListAddItem(g_TreeList, h_tviSubItem, TVIF_TEXT | TVIF_STATE, TVIS_EXPANDED,
        0, L"LowPart", &subitems);

    RtlSecureZeroMemory(&szValue, sizeof(szValue));
    szValue[0] = L'0';
    szValue[1] = L'x';
    ultohex(Value->HighPart, &szValue[2]);
    subitems.Text[0] = szValue;
    TreeListAddItem(TreeList, h_tviSubItem, TVIF_TEXT | TVIF_STATE, TVIS_EXPANDED,
        0, L"HighPart", &subitems);
}

/*
* ObDumpListEntry
*
* Purpose:
*
* Dump LIST_ENTRY members to the treelist.
*
*/
VOID ObDumpListEntry(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR ListEntryName,
    _In_opt_ PLIST_ENTRY ListEntry
)
{
    HTREEITEM           h_tviSubItem;
    TL_SUBITEMS_FIXED   subitems;
    WCHAR               szValue[100];

    h_tviSubItem = TreeListAddItem(g_TreeList, hParent, TVIF_TEXT | TVIF_STATE, TVIS_EXPANDED,
        0, ListEntryName, NULL);

    if (h_tviSubItem == NULL) {
        return;
    }

    //add list entry item to treelist and exit if listentry is null
    if (ListEntry == NULL) {
        return;
    }

    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 1;

    if (ListEntry->Flink == NULL) {
        subitems.Text[0] = T_NULL;
    }
    else {
        RtlSecureZeroMemory(&szValue, sizeof(szValue));
        szValue[0] = L'0';
        szValue[1] = L'x';
        u64tohex((ULONG_PTR)ListEntry->Flink, &szValue[2]);
        subitems.Text[0] = szValue;
    }
    TreeListAddItem(g_TreeList, h_tviSubItem, TVIF_TEXT | TVIF_STATE, TVIS_EXPANDED,
        0, L"Flink", &subitems);

    if (ListEntry->Blink == NULL) {
        subitems.Text[0] = T_NULL;
    }
    else {
        RtlSecureZeroMemory(&szValue, sizeof(szValue));
        szValue[0] = L'0';
        szValue[1] = L'x';
        u64tohex((ULONG_PTR)ListEntry->Blink, &szValue[2]);
        subitems.Text[0] = szValue;
    }
    TreeListAddItem(TreeList, h_tviSubItem, TVIF_TEXT | TVIF_STATE, 0,
        0, L"Blink", &subitems);
}

/*
* ObDumpUnicodeString
*
* Purpose:
*
* Dump UNICODE_STRING members to the treelist.
* Support PUNICODE_STRING, address must point to kernel memory.
*
*/
VOID ObDumpUnicodeString(
    _In_ HTREEITEM hParent,
    _In_ LPWSTR StringName,
    _In_opt_ PUNICODE_STRING pString,
    _In_ BOOL NeedDump
)
{
    LPWSTR              lpObjectName;
    HTREEITEM           h_tviSubItem;
    TL_SUBITEMS_FIXED   subitems;
    UNICODE_STRING      uStr;
    WCHAR               szValue[100];

    RtlSecureZeroMemory(&uStr, sizeof(uStr));
    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 2;

    //add root entry
    //if pString points to kernel mode address, dump it, otherwise simple copy
    if (NeedDump) {
        //check if NULL, add entry
        if (pString == NULL) {
            subitems.Text[0] = T_NULL;
        }
        else {
            //pString->Buffer need to be dumped
            RtlSecureZeroMemory(&szValue, sizeof(szValue));
            szValue[0] = L'0';
            szValue[1] = L'x';
            u64tohex((ULONG_PTR)pString, &szValue[2]);
            subitems.Text[0] = szValue;
            subitems.Text[1] = T_PUNICODE_STRING;
            kdReadSystemMemory((ULONG_PTR)pString, &uStr, sizeof(UNICODE_STRING));
        }
    }
    else {
        if (pString) {
            uStr.Buffer = pString->Buffer;
            uStr.Length = pString->Length;
            uStr.MaximumLength = pString->MaximumLength;
        }
        else {
            uStr.Buffer = NULL;
            uStr.Length = 0;
            uStr.MaximumLength = 0;
        }
    }
    h_tviSubItem = TreeListAddItem(g_TreeList, hParent, TVIF_TEXT | TVIF_STATE, TVIS_EXPANDED,
        0, StringName, NeedDump ? &subitems : NULL);

    //string points to nowhere, only root entry added
    if (pString == NULL) {
        return;
    }

    //
    //UNICODE_STRING.Length
    //
    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    RtlSecureZeroMemory(&szValue, sizeof(szValue));
    wsprintf(szValue, FORMAT_HEXUSHORT, uStr.Length);
    subitems.Count = 2;
    subitems.Text[0] = szValue;
    TreeListAddItem(g_TreeList, h_tviSubItem, TVIF_TEXT | TVIF_STATE, 0,
        0, T_LENGTH, &subitems);

    //
    //UNICODE_STRING.MaximumLength
    //
    RtlSecureZeroMemory(&szValue, sizeof(szValue));
    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    wsprintf(szValue, FORMAT_HEXUSHORT, uStr.MaximumLength);
    subitems.Count = 2;
    subitems.Text[0] = szValue;
    TreeListAddItem(g_TreeList, h_tviSubItem, TVIF_TEXT | TVIF_STATE, 0,
        0, L"MaximumLength", &subitems);

    //
    //UNICODE_STRING.Buffer
    //
    RtlSecureZeroMemory(&subitems, sizeof(subitems));
    subitems.Count = 2;

    lpObjectName = NULL;
    if (uStr.Buffer == NULL) {
        subitems.Text[0] = T_NULL;
    }
    else {
        RtlSecureZeroMemory(&szValue, sizeof(szValue));
        szValue[0] = L'0';
        szValue[1] = L'x';
        u64tohex((ULONG_PTR)uStr.Buffer, &szValue[2]);
        subitems.Text[0] = szValue;

        //dump unicode string buffer
        lpObjectName = supHeapAlloc(uStr.Length + sizeof(UNICODE_NULL));
        if (lpObjectName) {
            kdReadSystemMemory((ULONG_PTR)uStr.Buffer,
                lpObjectName, uStr.Length);
        }
        subitems.Text[1] = lpObjectName;
    }

    TreeListAddItem(g_TreeList, h_tviSubItem, TVIF_TEXT | TVIF_STATE, 0,
        0, L"Buffer", &subitems);

    if (lpObjectName) {
        supHeapFree(lpObjectName);
    }
}

/*
* ObDumpDispatcherHeader
*
* Purpose:
*
* Dump DISPATCHER_HEADER members to the treelist.
*
*/
VOID ObDumpDispatcherHeader(
    _In_ HTREEITEM hParent,
    _In_ DISPATCHER_HEADER *Header,
    _In_opt_ LPWSTR lpDescType,
    _In_opt_ LPWSTR lpDescSignalState,
    _In_opt_ LPWSTR lpDescSize
)
{
    HTREEITEM h_tviSubItem;

    h_tviSubItem = TreeListAddItem(g_TreeList, hParent, TVIF_TEXT | TVIF_STATE, 0,
        0, L"Header", NULL);

    if (h_tviSubItem == NULL) {
        return;
    }

    //Header->Type
    ObDumpUlong(g_TreeList, h_tviSubItem, L"Type", lpDescType, Header->Type, TRUE, TRUE, 0, 0);
    //Header->Absolute
    ObDumpUlong(g_TreeList, h_tviSubItem, L"Absolute", NULL, Header->Absolute, TRUE, TRUE, 0, 0);
    //Header->Size
    ObDumpUlong(g_TreeList, h_tviSubItem, L"Size", lpDescSize, Header->Size, TRUE, TRUE, 0, 0);
    //Header->Inserted
    ObDumpByte(g_TreeList, h_tviSubItem, L"Inserted", NULL, Header->Inserted, 0, 0, TRUE);
    //Header->SignalState
    ObDumpUlong(g_TreeList, h_tviSubItem, L"SignalState", lpDescSignalState, Header->SignalState, TRUE, FALSE, 0, 0);
    //Header->WaitListHead
    ObDumpListEntry(g_TreeList, h_tviSubItem, L"WaitListHead", &Header->WaitListHead);
}

/*
* ObDumpDriverObject
*
* Purpose:
*
* Dump DRIVER_OBJECT members to the treelist.
*
*/
VOID ObDumpDriverObject(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    BOOL                    cond, bOkay;
    INT                     i, j;
    HTREEITEM               h_tviRootItem, h_tviSubItem;
    PVOID                   pModules, pObj;
    POBJREF                 LookupObject;
    LPWSTR                  lpType;
    DRIVER_OBJECT           drvObject;
    DRIVER_EXTENSION        drvExtension;
    FAST_IO_DISPATCH        fastIoDispatch;
    LDR_DATA_TABLE_ENTRY    ldrEntry, ntosEntry;
    TL_SUBITEMS_FIXED       subitems;
    COLORREF                BgColor;
    WCHAR                   szValue1[MAX_PATH + 1];

    if (Context == NULL) {
        return;
    }

    bOkay = FALSE;
    cond = FALSE;

    __try {

        RtlSecureZeroMemory(&drvObject, sizeof(drvObject));
        RtlSecureZeroMemory(&ldrEntry, sizeof(ldrEntry));

        do {

            //dump drvObject
            if (!kdReadSystemMemory(Context->ObjectInfo.ObjectAddress, &drvObject, sizeof(drvObject))) {
                break;
            }

            //we need to dump drvObject
            //consider dump failures for anything else as not critical
            bOkay = TRUE;

            //dump drvObject->DriverSection
            if (!kdReadSystemMemory((ULONG_PTR)drvObject.DriverSection, &ldrEntry, sizeof(ldrEntry))) {
                break;
            }

        } while (cond);

        //any errors - abort
        if (!bOkay) {
            ObDumpShowError(hwndDlg);
            return;
        }

        g_TreeList = 0;
        g_TreeListAtom = 0;
        if (!supInitTreeListForDump(hwndDlg, &g_TreeListAtom, &g_TreeList)) {
            ObDumpShowError(hwndDlg);
            return;
        }

        //
        //DRIVER_OBJECT
        //

        h_tviRootItem = TreeListAddItem(g_TreeList, NULL, TVIF_TEXT | TVIF_STATE, TVIS_EXPANDED,
            TVIS_EXPANDED, L"DRIVER_OBJECT", NULL);

        //Type
        BgColor = 0;
        lpType = L"IO_TYPE_DRIVER";
        if (drvObject.Type != IO_TYPE_DRIVER) {
            lpType = L"! Must be IO_TYPE_DRIVER";
            BgColor = CLR_WARN;
        }
        ObDumpUlong(g_TreeList, h_tviRootItem, L"Type", lpType, drvObject.Type, TRUE, TRUE, BgColor, 0);

        //Size
        BgColor = 0;
        lpType = NULL;
        if (drvObject.Size != sizeof(DRIVER_OBJECT)) {
            lpType = L"! Must be sizeof(DRIVER_OBJECT)";
            BgColor = CLR_WARN;
        }
        ObDumpUlong(g_TreeList, h_tviRootItem, L"Size", lpType, drvObject.Size, TRUE, TRUE, BgColor, 0);

        //DeviceObject
        lpType = NULL;
        BgColor = 0;
        if (drvObject.DeviceObject != NULL) {
            LookupObject = ObListFindByAddress(&g_kdctx.ObjectList, (ULONG_PTR)drvObject.DeviceObject);
            if (LookupObject != NULL) {
                lpType = LookupObject->ObjectName;
            }
            else {
                lpType = T_UNNAMED;
                BgColor = CLR_LGRY;
            }
        }
        ObDumpAddress(g_TreeList, h_tviRootItem, L"DeviceObject", lpType, drvObject.DeviceObject, BgColor, 0);

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
                        subitems.Text[0] = NULL;
                        subitems.Text[1] = lpType;
                    }

                    TreeListAddItem(g_TreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0,
                        0, (j == 0) ? T_FLAGS : NULL, &subitems);

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
            ObDumpUlong(g_TreeList, h_tviRootItem, T_FLAGS, NULL, 0, TRUE, FALSE, 0, 0);
        }

        //DriverStart
        ObDumpAddress(g_TreeList, h_tviRootItem, L"DriverStart", NULL, drvObject.DriverStart, 0, 0);

        //DriverSection
        ObDumpAddress(g_TreeList, h_tviRootItem, L"DriverSection", L"PLDR_DATA_TABLE_ENTRY", drvObject.DriverSection, 0, 0);

        //DriverExtension
        ObDumpAddress(g_TreeList, h_tviRootItem, L"DriverExtension", L"PDRIVER_EXTENSION", drvObject.DriverExtension, 0, 0);

        //DriverName
        ObDumpUnicodeString(h_tviRootItem, L"DriverName", &drvObject.DriverName, FALSE);

        //HardwareDatabase
        ObDumpUnicodeString(h_tviRootItem, L"HardwareDatabase", drvObject.HardwareDatabase, TRUE);

        //FastIoDispatch
        ObDumpAddress(g_TreeList, h_tviRootItem, L"FastIoDispatch", L"PFAST_IO_DISPATCH", drvObject.FastIoDispatch, 0, 0);

        //DriverInit
        ObDumpAddress(g_TreeList, h_tviRootItem, L"DriverInit", NULL, drvObject.DriverInit, 0, 0);

        //DriverStartIo
        ObDumpAddress(g_TreeList, h_tviRootItem, L"DriverStartIo", NULL, drvObject.DriverStartIo, 0, 0);

        //DriverUnload
        ObDumpAddress(g_TreeList, h_tviRootItem, L"DriverUnload", NULL, drvObject.DriverUnload, 0, 0);

        //MajorFunction
        RtlSecureZeroMemory(&szValue1, sizeof(szValue1));
        RtlSecureZeroMemory(&subitems, sizeof(subitems));
        subitems.Count = 2;
        subitems.Text[0] = L"{...}";
        subitems.Text[1] = NULL;
        h_tviSubItem = TreeListAddItem(g_TreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0,
            0, L"MajorFunction", &subitems);

        RtlSecureZeroMemory(&ntosEntry, sizeof(ntosEntry));
        pModules = supGetSystemInfo(SystemModuleInformation);

        for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {

            if (drvObject.MajorFunction[i] == NULL) {
                continue;
            }

            //skip ntoskrnl default irp handler
            //warning may skip actual trampoline hook
            if (g_kdctx.IopInvalidDeviceRequest) {
                if ((ULONG_PTR)drvObject.MajorFunction[i] == (ULONG_PTR)g_kdctx.IopInvalidDeviceRequest) {

                    ObDumpAddress(g_TreeList, h_tviSubItem, T_IRP_MJ_FUNCTION[i],
                        L"nt!IopInvalidDeviceRequest", drvObject.MajorFunction[i], CLR_INVL, 0);

                    continue;
                }
            }

            //DRIVER_OBJECT->MajorFunction[i]
            ObDumpAddressWithModule(h_tviSubItem, T_IRP_MJ_FUNCTION[i], drvObject.MajorFunction[i],
                pModules, ldrEntry.DllBase, ldrEntry.SizeOfImage);
        }

        //
        //LDR_DATA_TABLE_ENTRY
        //

        if (drvObject.DriverSection != NULL) {

            //root itself
            h_tviRootItem = TreeListAddItem(g_TreeList, NULL, TVIF_TEXT | TVIF_STATE, TVIS_EXPANDED,
                0, T_LDR_DATA_TABLE_ENTRY, NULL);

            //InLoadOrderLinks
            ObDumpListEntry(g_TreeList, h_tviRootItem, L"InLoadOrderLinks", &ldrEntry.InLoadOrderLinks);

            //InMemoryOrderLinks
            ObDumpListEntry(g_TreeList, h_tviRootItem, L"InMemoryOrderLinks", &ldrEntry.InMemoryOrderLinks);

            //InInitializationOrderLinks/InProgressLinks
            lpType = L"InInitializationOrderLinks";
            if (g_WinObj.osver.dwBuildNumber >= 9600) {
                lpType = L"InProgressLinks";
            }
            ObDumpListEntry(g_TreeList, h_tviRootItem, lpType, &ldrEntry.DUMMYUNION0.InInitializationOrderLinks);

            //DllBase
            ObDumpAddress(g_TreeList, h_tviRootItem, L"DllBase", NULL, ldrEntry.DllBase, 0, 0);

            //EntryPoint
            ObDumpAddress(g_TreeList, h_tviRootItem, L"EntryPoint", NULL, ldrEntry.EntryPoint, 0, 0);

            //SizeOfImage
            ObDumpUlong(g_TreeList, h_tviRootItem, L"SizeOfImage", NULL, ldrEntry.SizeOfImage, TRUE, FALSE, 0, 0);

            //FullDllName
            ObDumpUnicodeString(h_tviRootItem, L"FullDllName", &ldrEntry.FullDllName, FALSE);

            //BaseDllName
            ObDumpUnicodeString(h_tviRootItem, L"BaseDllName", &ldrEntry.BaseDllName, FALSE);

            //Flags
            ObDumpUlong(g_TreeList, h_tviRootItem, T_FLAGS, NULL, ldrEntry.ENTRYFLAGSUNION.Flags, TRUE, FALSE, 0, 0);

            //LoadCount
            lpType = L"ObsoleteLoadCount";
            if (g_WinObj.osver.dwBuildNumber < 9200) {
                lpType = L"LoadCount";
            }
            ObDumpUlong(g_TreeList, h_tviRootItem, lpType, NULL, ldrEntry.ObsoleteLoadCount, TRUE, TRUE, 0, 0);

            //TlsIndex
            ObDumpUlong(g_TreeList, h_tviRootItem, L"TlsIndex", NULL, ldrEntry.TlsIndex, TRUE, TRUE, 0, 0);

            //SectionPointer
            ObDumpAddress(g_TreeList, h_tviRootItem, L"SectionPointer", NULL, ldrEntry.DUMMYUNION1.SectionPointer, 0, 0);

            //CheckSum
            ObDumpUlong(g_TreeList, h_tviRootItem, L"CheckSum", NULL, ldrEntry.DUMMYUNION1.CheckSum, TRUE, FALSE, 0, 0);

            //LoadedImports
            if (g_WinObj.osver.dwBuildNumber < 9200) {
                ObDumpAddress(g_TreeList, h_tviRootItem, L"LoadedImports", NULL, ldrEntry.DUMMYUNION2.LoadedImports, 0, 0);
            }

        } //LDR_DATA_TABLE_ENTRY


        //
        //FAST_IO_DISPATCH
        //

        if (drvObject.FastIoDispatch != NULL) {
            RtlSecureZeroMemory(&fastIoDispatch, sizeof(fastIoDispatch));
            if (kdReadSystemMemory((ULONG_PTR)drvObject.FastIoDispatch, &fastIoDispatch, sizeof(fastIoDispatch))) {

                h_tviRootItem = TreeListAddItem(g_TreeList, NULL, TVIF_TEXT | TVIF_STATE, 0,
                    0, L"FAST_IO_DISPATCH", NULL);

                //SizeOfFastIoDispatch
                BgColor = 0;
                lpType = NULL;
                bOkay = TRUE;
                if (fastIoDispatch.SizeOfFastIoDispatch != sizeof(FAST_IO_DISPATCH)) {
                    lpType = L"! Must be sizeof(FAST_IO_DISPATCH)";
                    BgColor = CLR_WARN;
                    bOkay = FALSE;//<-set flag invalid structure
                }
                ObDumpUlong(g_TreeList, h_tviRootItem, L"SizeOfFastIoDispatch", lpType, fastIoDispatch.SizeOfFastIoDispatch, TRUE, FALSE, BgColor, 0);

                //valid structure
                if (bOkay) {
                    for (i = 0; i < 27; i++) {
                        pObj = ((PVOID *)(&fastIoDispatch.FastIoCheckIfPossible))[i];
                        if (pObj == NULL) {
                            continue;
                        }
                        ObDumpAddressWithModule(h_tviRootItem, T_FAST_IO_DISPATCH[i], pObj,
                            pModules, ldrEntry.DllBase, ldrEntry.SizeOfImage);
                    }
                }

            } //kdReadSystemMemory
        } //if

        //
        //PDRIVER_EXTENSION
        //
        if (drvObject.DriverExtension != NULL) {
            //dump drvObject->DriverExtension
            RtlSecureZeroMemory(&drvExtension, sizeof(drvExtension));
            if (kdReadSystemMemory((ULONG_PTR)drvObject.DriverExtension, &drvExtension, sizeof(drvExtension))) {

                h_tviRootItem = TreeListAddItem(g_TreeList, NULL, TVIF_TEXT | TVIF_STATE, TVIS_EXPANDED,
                    0, L"DRIVER_EXTENSION", NULL);

                //DriverObject
                BgColor = 0;
                lpType = NULL;

                //must be self-ref
                if ((ULONG_PTR)drvExtension.DriverObject != (ULONG_PTR)Context->ObjectInfo.ObjectAddress) {
                    lpType = L"! Bad DRIVER_OBJECT";
                    BgColor = CLR_WARN;
                }
                else {
                    //find ref
                    LookupObject = ObListFindByAddress(&g_kdctx.ObjectList, (ULONG_PTR)drvExtension.DriverObject);
                    if (LookupObject != NULL) {
                        lpType = LookupObject->ObjectName;
                    }
                    else {
                        //sef-ref not found, notify, could be object outside directory so we don't know it name etc
                        lpType = T_REFNOTFOUND;
                        BgColor = CLR_INVL;
                    }
                }

                ObDumpAddress(g_TreeList, h_tviRootItem, L"DriverObject", lpType, drvExtension.DriverObject, BgColor, 0);

                //AddDevice
                ObDumpAddressWithModule(h_tviRootItem, L"AddDevice", drvExtension.AddDevice,
                    pModules, ldrEntry.DllBase, ldrEntry.SizeOfImage);

                //Count
                ObDumpUlong(g_TreeList, h_tviRootItem, L"Count", NULL, drvExtension.Count, FALSE, FALSE, 0, 0);

                //ServiceKeyName
                ObDumpUnicodeString(h_tviRootItem, L"ServiceKeyName", &drvExtension.ServiceKeyName, FALSE);
            }
        }
        //
        //Cleanup
        //
        if (pModules) {
            supHeapFree(pModules);
        }

    }
    __except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
        return;
    }
}

/*
* ObDumpDeviceObject
*
* Purpose:
*
* Dump DEVICE_OBJECT members to the treelist.
*
*/
VOID ObDumpDeviceObject(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    BOOL                    bOkay;
    INT                     i, j;
    HTREEITEM               h_tviRootItem, h_tviWcb, h_tviSubItem, h_tviWaitEntry;
    POBJREF                 LookupObject;
    LPWSTR                  lpType;
    TL_SUBITEMS_FIXED       subitems;
    DEVICE_OBJECT           devObject;
    DEVOBJ_EXTENSION        devObjExt;
    COLORREF                BgColor;
    WCHAR                   szValue1[MAX_PATH + 1];

    if (Context == NULL) {
        return;
    }

    bOkay = FALSE;

    __try {

        //dump devObject
        RtlSecureZeroMemory(&devObject, sizeof(devObject));
        if (!kdReadSystemMemory(Context->ObjectInfo.ObjectAddress, &devObject, sizeof(devObject))) {
            ObDumpShowError(hwndDlg);
            return;
        }

        g_TreeList = 0;
        g_TreeListAtom = 0;
        if (!supInitTreeListForDump(hwndDlg, &g_TreeListAtom, &g_TreeList)) {
            ObDumpShowError(hwndDlg);
            return;
        }

        //
        //DEVICE_OBJECT
        //

        h_tviRootItem = TreeListAddItem(g_TreeList, NULL, TVIF_TEXT | TVIF_STATE, TVIS_EXPANDED,
            TVIS_EXPANDED, L"DEVICE_OBJECT", NULL);

        //Type
        BgColor = 0;
        lpType = L"IO_TYPE_DEVICE";
        if (devObject.Type != IO_TYPE_DEVICE) {
            lpType = L"! Must be IO_TYPE_DEVICE";
            BgColor = CLR_WARN;
        }
        ObDumpUlong(g_TreeList, h_tviRootItem, L"Type", lpType, devObject.Type, TRUE, TRUE, BgColor, 0);

        //Size
        ObDumpUlong(g_TreeList, h_tviRootItem, L"Size", NULL, devObject.Size, TRUE, TRUE, 0, 0);

        //ReferenceCount
        ObDumpUlong(g_TreeList, h_tviRootItem, L"ReferenceCount", NULL, devObject.ReferenceCount, FALSE, FALSE, 0, 0);

        //DriverObject
        lpType = NULL;
        BgColor = 0;
        LookupObject = ObListFindByAddress(&g_kdctx.ObjectList, (ULONG_PTR)devObject.DriverObject);
        if (LookupObject != NULL) {
            lpType = LookupObject->ObjectName;
        }
        else {
            lpType = T_REFNOTFOUND;
            BgColor = CLR_INVL; //object can be outside directory so we don't know about it
        }
        ObDumpAddress(g_TreeList, h_tviRootItem, L"DriverObject", lpType, devObject.DriverObject, BgColor, 0);

        //NextDevice
        lpType = NULL;
        LookupObject = ObListFindByAddress(&g_kdctx.ObjectList, (ULONG_PTR)devObject.NextDevice);
        if (LookupObject != NULL) {
            lpType = LookupObject->ObjectName;
        }
        else {
            lpType = NULL;
        }
        ObDumpAddress(g_TreeList, h_tviRootItem, L"NextDevice", lpType, devObject.NextDevice, 0, 0);

        //AttachedDevice
        lpType = NULL;
        LookupObject = ObListFindByAddress(&g_kdctx.ObjectList, (ULONG_PTR)devObject.AttachedDevice);
        if (LookupObject != NULL) {
            lpType = LookupObject->ObjectName;
        }
        else {
            lpType = NULL;
        }
        ObDumpAddress(g_TreeList, h_tviRootItem, L"AttachedDevice", lpType, devObject.AttachedDevice, 0, 0);

        //CurrentIrp
        ObDumpAddress(g_TreeList, h_tviRootItem, L"CurrentIrp", NULL, devObject.CurrentIrp, 0, 0);

        //Timer
        lpType = L"PIO_TIMER";
        ObDumpAddress(g_TreeList, h_tviRootItem, L"Timer", lpType, devObject.Timer, 0, 0);

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
                        subitems.Text[0] = NULL;
                        subitems.Text[1] = lpType;
                    }

                    TreeListAddItem(g_TreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0,
                        TVIS_EXPANDED, (j == 0) ? T_FLAGS : NULL, &subitems);

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
            ObDumpUlong(g_TreeList, h_tviRootItem, T_FLAGS, NULL, 0, TRUE, FALSE, 0, 0);
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
                        subitems.Text[0] = NULL;
                        subitems.Text[1] = lpType;
                    }

                    TreeListAddItem(g_TreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0,
                        0, (j == 0) ? T_CHARACTERISTICS : NULL, &subitems);

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
            ObDumpUlong(g_TreeList, h_tviRootItem, T_CHARACTERISTICS, NULL, 0, TRUE, FALSE, 0, 0);
        }

        //Vpb
        lpType = L"PVPB";
        ObDumpAddress(g_TreeList, h_tviRootItem, L"Vpb", lpType, devObject.Vpb, 0, 0);

        //DeviceExtension
        ObDumpAddress(g_TreeList, h_tviRootItem, L"DeviceExtension", NULL, devObject.DeviceExtension, 0, 0);

        //DeviceType
        lpType = NULL;
        for (i = 0; i < MAX_DEVOBJ_CHARS; i++) {
            if (devObjChars[i].dwValue == devObject.DeviceType) {
                lpType = devObjChars[i].lpDescription;
                break;
            }
        }
        ObDumpUlong(g_TreeList, h_tviRootItem, L"DeviceType", lpType, devObject.DeviceType, TRUE, FALSE, 0, 0);

        //StackSize
        ObDumpUlong(g_TreeList, h_tviRootItem, L"StackSize", NULL, devObject.StackSize, FALSE, FALSE, 0, 0);

        //Queue
        h_tviSubItem = TreeListAddItem(g_TreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0,
            TVIS_EXPANDED, L"Queue", NULL);

        //Queue->Wcb
        h_tviWcb = TreeListAddItem(g_TreeList, h_tviSubItem, TVIF_TEXT | TVIF_STATE, 0,
            TVIS_EXPANDED, L"Wcb", NULL);

        //Queue->Wcb->WaitQueueEntry
        h_tviWaitEntry = TreeListAddItem(g_TreeList, h_tviWcb, TVIF_TEXT | TVIF_STATE, 0,
            TVIS_EXPANDED, L"WaitQueueEntry", NULL);

        //Queue->Wcb->WaitQueueEntry->DeviceListEntry
        ObDumpListEntry(g_TreeList, h_tviWaitEntry, L"DeviceListEntry", &devObject.Queue.Wcb.WaitQueueEntry.DeviceListEntry);

        //Queue->Wcb->WaitQueueEntry->SortKey
        ObDumpUlong(g_TreeList, h_tviWaitEntry, L"SortKey", NULL, devObject.Queue.Wcb.WaitQueueEntry.SortKey, TRUE, FALSE, 0, 0);

        //Queue->Wcb->WaitQueueEntry->Inserted
        ObDumpByte(g_TreeList, h_tviWaitEntry, L"Inserted", NULL, devObject.Queue.Wcb.WaitQueueEntry.Inserted, 0, 0, TRUE);

        //Queue->Wcb->DmaWaitEntry
        ObDumpListEntry(g_TreeList, h_tviWcb, L"DmaWaitEntry", &devObject.Queue.Wcb.DmaWaitEntry);

        //Queue->Wcb->NumberOfChannels
        ObDumpUlong(g_TreeList, h_tviWcb, L"NumberOfChannels", NULL, devObject.Queue.Wcb.NumberOfChannels, FALSE, FALSE, 0, 0);

        //Queue->Wcb->SyncCallback
        ObDumpUlong(g_TreeList, h_tviWcb, L"SyncCallback", NULL, devObject.Queue.Wcb.SyncCallback, FALSE, FALSE, 0, 0);

        //Queue->Wcb->DmaContext
        ObDumpUlong(g_TreeList, h_tviWcb, L"DmaContext", NULL, devObject.Queue.Wcb.DmaContext, FALSE, FALSE, 0, 0);

        //Queue->Wcb->DeviceRoutine
        lpType = L"PDRIVER_CONTROL";
        ObDumpAddress(g_TreeList, h_tviWcb, L"DeviceRoutine", lpType, devObject.Queue.Wcb.DeviceRoutine, 0, 0);

        //Queue->Wcb->DeviceContext
        ObDumpAddress(g_TreeList, h_tviWcb, L"DeviceContext", NULL, devObject.Queue.Wcb.DeviceContext, 0, 0);

        //Queue->Wcb->NumberOfMapRegisters
        ObDumpUlong(g_TreeList, h_tviWcb, L"DeviceContext", NULL, devObject.Queue.Wcb.NumberOfMapRegisters, FALSE, FALSE, 0, 0);

        //Queue->Wcb->DeviceObject
        lpType = NULL;
        BgColor = 0;
        if (devObject.Queue.Wcb.DeviceObject != NULL) {
            LookupObject = ObListFindByAddress(&g_kdctx.ObjectList, (ULONG_PTR)devObject.Queue.Wcb.DeviceObject);
            if (LookupObject != NULL) {
                lpType = LookupObject->ObjectName;
            }
            else {
                lpType = L"Unnamed";
                BgColor = CLR_LGRY;
            }
        }
        ObDumpAddress(g_TreeList, h_tviWcb, L"DeviceObject", lpType, devObject.Queue.Wcb.DeviceObject, BgColor, 0);

        //Queue->Wcb->CurrentIrp
        ObDumpAddress(g_TreeList, h_tviWcb, L"CurrentIrp", NULL, devObject.Queue.Wcb.CurrentIrp, 0, 0);

        //Queue->Wcb->BufferChainingDpc
        lpType = T_PKDPC;
        ObDumpAddress(g_TreeList, h_tviWcb, L"BufferChainingDpc", lpType, devObject.Queue.Wcb.BufferChainingDpc, 0, 0);

        //AlignmentRequirement
        lpType = NULL;
        for (i = 0; i < MAX_KNOWN_FILEALIGN; i++) {
            if (fileAlign[i].dwValue == devObject.AlignmentRequirement) {
                lpType = fileAlign[i].lpDescription;
                break;
            }
        }
        ObDumpUlong(g_TreeList, h_tviRootItem, L"AlignmentRequirement", lpType, devObject.AlignmentRequirement, TRUE, FALSE, 0, 0);

        //DeviceQueue
        h_tviSubItem = TreeListAddItem(g_TreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0,
            TVIS_EXPANDED, L"DeviceQueue", NULL);

        //DeviceQueue->Type
        lpType = L"KOBJECTS";
        ObDumpUlong(g_TreeList, h_tviSubItem, L"Type", lpType, devObject.DeviceQueue.Type, TRUE, TRUE, 0, 0);

        //DeviceQueue->Size
        ObDumpUlong(g_TreeList, h_tviSubItem, L"Size", NULL, devObject.DeviceQueue.Size, TRUE, TRUE, 0, 0);

        //DeviceQueue->DeviceListHead
        ObDumpListEntry(g_TreeList, h_tviSubItem, L"DeviceListHead", &devObject.DeviceQueue.DeviceListHead);

        //DeviceQueue->Lock
        ObDumpAddress(g_TreeList, h_tviSubItem, L"Lock", NULL, (PVOID)devObject.DeviceQueue.Lock, 0, 0);

        //DeviceQueue->Busy
        ObDumpByte(g_TreeList, h_tviSubItem, L"Busy", NULL, devObject.DeviceQueue.Busy, 0, 0, TRUE);

        //DeviceQueue->Hint
        ObDumpAddress(g_TreeList, h_tviSubItem, L"Hint", NULL, (PVOID)devObject.DeviceQueue.Hint, 0, 0);

        //
        //DEVICE_OBJECT->Dpc
        //
        h_tviSubItem = TreeListAddItem(g_TreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0,
            TVIS_EXPANDED, L"Dpc", NULL);

        lpType = NULL;
        if (devObject.Dpc.Type == DPC_NORMAL) lpType = L"DPC_NORMAL";
        if (devObject.Dpc.Type == DPC_THREADED) lpType = L"DPC_THREADED";
        ObDumpUlong(g_TreeList, h_tviSubItem, L"Type", lpType, devObject.Dpc.Type, TRUE, TRUE, 0, 0);
        lpType = NULL;
        if (devObject.Dpc.Importance == LowImportance) lpType = L"LowImportance";
        if (devObject.Dpc.Importance == MediumImportance) lpType = L"MediumImportance";
        if (devObject.Dpc.Importance == HighImportance) lpType = L"HighImportance";
        ObDumpUlong(g_TreeList, h_tviSubItem, L"Importance", lpType, devObject.Dpc.Importance, TRUE, TRUE, 0, 0);
        ObDumpUlong(g_TreeList, h_tviSubItem, L"Number", NULL, devObject.Dpc.Number, TRUE, TRUE, 0, 0);

        //Dpc->DpcListEntry
        ObDumpAddress(g_TreeList, h_tviSubItem, L"DpcListEntry", NULL, (PVOID)devObject.Dpc.DpcListEntry.Next, 0, 0);

        //Dpc->ProcessorHistory
        ObDumpAddress(g_TreeList, h_tviSubItem, L"ProcessorHistory", NULL, (PVOID)devObject.Dpc.ProcessorHistory, 0, 0);

        //Dpc->DeferredRoutine
        ObDumpAddress(g_TreeList, h_tviSubItem, L"DeferredRoutine", NULL, devObject.Dpc.DeferredRoutine, 0, 0);

        //Dpc->DeferredContext
        ObDumpAddress(g_TreeList, h_tviSubItem, L"DeferredContext", NULL, devObject.Dpc.DeferredContext, 0, 0);

        //Dpc->SystemArgument1
        ObDumpAddress(g_TreeList, h_tviSubItem, L"SystemArgument1", NULL, devObject.Dpc.SystemArgument1, 0, 0);

        //Dpc->SystemArgument2
        ObDumpAddress(g_TreeList, h_tviSubItem, L"SystemArgument2", NULL, devObject.Dpc.SystemArgument2, 0, 0);

        //ActiveThreadCount
        ObDumpUlong(g_TreeList, h_tviRootItem, L"ActiveThreadCount", NULL, devObject.ActiveThreadCount, FALSE, FALSE, 0, 0);

        //SecurityDescriptor
        lpType = L"PSECURITY_DESCRIPTOR";
        ObDumpAddress(g_TreeList, h_tviRootItem, L"SecurityDescriptor", lpType, devObject.SecurityDescriptor, 0, 0);

        //DeviceLock
        h_tviWaitEntry = TreeListAddItem(g_TreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0,
            TVIS_EXPANDED, L"DeviceLock", NULL);

        //DeviceLock->Header
        ObDumpDispatcherHeader(h_tviWaitEntry, &devObject.DeviceLock.Header, NULL, NULL, NULL);

        //SectorSize
        ObDumpUlong(g_TreeList, h_tviRootItem, L"SectorSize", NULL, devObject.SectorSize, TRUE, TRUE, 0, 0);
        //Spare
        ObDumpUlong(g_TreeList, h_tviRootItem, L"Spare1", NULL, devObject.Spare1, TRUE, TRUE, 0, 0);

        //DeviceObjectExtension
        lpType = L"PDEVOBJ_EXTENSION";
        ObDumpAddress(g_TreeList, h_tviRootItem, L"DeviceObjectExtension", lpType, devObject.DeviceObjectExtension, 0, 0);

        //Reserved
        ObDumpAddress(g_TreeList, h_tviRootItem, L"Reserved", NULL, devObject.Reserved, 0, 0);

        //
        //DEVOBJ_EXTENSION
        //

        if (devObject.DeviceObjectExtension) {

            RtlSecureZeroMemory(&devObjExt, sizeof(devObjExt));
            if (!kdReadSystemMemory((ULONG_PTR)devObject.DeviceObjectExtension, &devObjExt, sizeof(devObjExt))) {
                return; //safe to exit, nothing after this
            }

            h_tviRootItem = TreeListAddItem(g_TreeList, NULL, TVIF_TEXT | TVIF_STATE, 0,
                TVIS_EXPANDED, L"DEVOBJ_EXTENSION", NULL);

            BgColor = 0;
            lpType = L"IO_TYPE_DEVICE_OBJECT_EXTENSION";
            if (devObjExt.Type != IO_TYPE_DEVICE_OBJECT_EXTENSION) {
                lpType = L"! Must be IO_TYPE_DEVICE_OBJECT_EXTENSION";
                BgColor = CLR_WARN;
            }
            //Type
            ObDumpUlong(g_TreeList, h_tviRootItem, L"Type", lpType, devObjExt.Type, TRUE, TRUE, BgColor, 0);
            //Size
            ObDumpUlong(g_TreeList, h_tviRootItem, L"Size", NULL, devObjExt.Size, TRUE, TRUE, 0, 0);

            //DeviceObject
            lpType = NULL;
            BgColor = 0;
            if (devObjExt.DeviceObject != NULL) {
                LookupObject = ObListFindByAddress(&g_kdctx.ObjectList, (ULONG_PTR)devObjExt.DeviceObject);
                if (LookupObject != NULL) {
                    lpType = LookupObject->ObjectName;
                }
                else {
                    lpType = L"Unnamed";
                    BgColor = CLR_LGRY;
                }
            }
            ObDumpAddress(g_TreeList, h_tviRootItem, L"DeviceObject", lpType, devObjExt.DeviceObject, BgColor, 0);

            //PowerFlags
            ObDumpUlong(g_TreeList, h_tviRootItem, L"PowerFlags", NULL, devObjExt.PowerFlags, TRUE, FALSE, 0, 0);

            //Dope
            lpType = L"PDEVICE_OBJECT_POWER_EXTENSION";
            ObDumpAddress(g_TreeList, h_tviRootItem, L"Dope", lpType, devObjExt.Dope, 0, 0);

            //ExtensionFlags
            ObDumpUlong(g_TreeList, h_tviRootItem, L"ExtensionFlags", NULL, devObjExt.ExtensionFlags, TRUE, FALSE, 0, 0);

            //DeviceNode
            lpType = L"PDEVICE_NODE";
            ObDumpAddress(g_TreeList, h_tviRootItem, L"DeviceNode", lpType, devObjExt.DeviceNode, 0, 0);

            //AttachedTo
            lpType = NULL;
            BgColor = 0;
            if (devObjExt.AttachedTo != NULL) {
                LookupObject = ObListFindByAddress(&g_kdctx.ObjectList, (ULONG_PTR)devObjExt.AttachedTo);
                if (LookupObject != NULL) {
                    lpType = LookupObject->ObjectName;
                }
                else {
                    lpType = T_UNNAMED;
                    BgColor = CLR_LGRY;
                }
            }
            ObDumpAddress(g_TreeList, h_tviRootItem, L"AttachedTo", lpType, devObjExt.AttachedTo, BgColor, 0);
        }
    }
    __except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
        return;
    }
}

/*
* ObDumpDirectoryObject
*
* Purpose:
*
* Dump OBJECT_DIRECTORY members to the treelist.
*
*/
VOID ObDumpDirectoryObject(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    INT                     i;
    HTREEITEM               h_tviRootItem, h_tviSubItem, h_tviEntry;
    LPWSTR                  lpType;
    OBJECT_DIRECTORY        dirObject;
    OBJECT_DIRECTORY_ENTRY  dirEntry;
    LIST_ENTRY              ChainLink;
    TL_SUBITEMS_FIXED       subitems;
    WCHAR                   szId[MAX_PATH + 1], szValue[MAX_PATH + 1];

    if (Context == NULL) {
        return;
    }

    __try {

        //dump dirObject
        RtlSecureZeroMemory(&dirObject, sizeof(dirObject));
        if (!kdReadSystemMemory(Context->ObjectInfo.ObjectAddress, &dirObject, sizeof(dirObject))) {
            ObDumpShowError(hwndDlg);
            return;
        }

        g_TreeList = 0;
        g_TreeListAtom = 0;
        if (!supInitTreeListForDump(hwndDlg, &g_TreeListAtom, &g_TreeList)) {
            ObDumpShowError(hwndDlg);
            return;
        }

        //
        //OBJECT_DIRECTORY
        //
        h_tviRootItem = TreeListAddItem(g_TreeList, NULL, TVIF_TEXT | TVIF_STATE, TVIS_EXPANDED,
            TVIS_EXPANDED, T_OBJECT_DIRECTORY, NULL);

        RtlSecureZeroMemory(&subitems, sizeof(subitems));
        subitems.Count = 1;
        subitems.Text[0] = L"{...}";
        h_tviSubItem = TreeListAddItem(g_TreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0,
            0, L"HashBuckets", &subitems);

        for (i = 0; i < 37; i++) {
            RtlSecureZeroMemory(&subitems, sizeof(subitems));
            subitems.Count = 2;

            RtlSecureZeroMemory(szId, sizeof(szId));
            wsprintf(szId, L"[ %i ]", i);

            if (dirObject.HashBuckets[i]) {
                RtlSecureZeroMemory(szValue, sizeof(szValue));
                szValue[0] = L'0';
                szValue[1] = L'x';
                u64tohex((ULONG_PTR)dirObject.HashBuckets[i], &szValue[2]);
                subitems.Text[0] = szValue;
                subitems.Text[1] = T_POBJECT_DIRECTORY_ENTRY;
            }
            else {
                subitems.Text[0] = T_NULL;
            }
            h_tviEntry = TreeListAddItem(g_TreeList, h_tviSubItem, TVIF_TEXT | TVIF_STATE, 0,
                0, szId, &subitems);

            //dump entry if available
            if (dirObject.HashBuckets[i]) {
                RtlSecureZeroMemory(&dirEntry, sizeof(dirEntry));
                if (kdReadSystemMemory((ULONG_PTR)dirObject.HashBuckets[i], &dirEntry, sizeof(dirEntry))) {

                    ChainLink.Blink = NULL;
                    ChainLink.Flink = NULL;
                    lpType = L"ChainLink";
                    if (dirEntry.ChainLink == NULL) {
                        ObDumpAddress(g_TreeList, h_tviEntry, lpType, T_PLIST_ENTRY, NULL, 0, 0);
                    }
                    else {
                        if (kdReadSystemMemory((ULONG_PTR)dirEntry.ChainLink, &ChainLink, sizeof(ChainLink))) {
                            ObDumpListEntry(g_TreeList, h_tviEntry, lpType, &ChainLink);
                        }
                        else {
                            ObDumpAddress(g_TreeList, h_tviEntry, lpType, T_PLIST_ENTRY, dirEntry.ChainLink, 0, 0);
                        }
                    }
                    ObDumpAddress(g_TreeList, h_tviEntry, L"Object", NULL, dirEntry.Object, 0, 0);
                    ObDumpUlong(g_TreeList, h_tviEntry, L"HashValue", NULL, dirEntry.HashValue, TRUE, FALSE, 0, 0);
                }
            }
        }

        //EX_PUSH_LOCK
        RtlSecureZeroMemory(&subitems, sizeof(subitems));
        subitems.Count = 2;
        subitems.Text[1] = T_EX_PUSH_LOCK;

        h_tviSubItem = TreeListAddItem(g_TreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0,
            0, L"Lock", &subitems);
        ObDumpAddress(g_TreeList, h_tviSubItem, L"Ptr", NULL, dirObject.Lock.Ptr, 0, 0);

        //DeviceMap
        ObDumpAddress(g_TreeList, h_tviRootItem, L"DeviceMap", T_PDEVICE_MAP, dirObject.DeviceMap, 0, 0);
        /*
            //ShadowDirectory (?) consider removal
            //leave as is, ep 30.03.2015
            RtlSecureZeroMemory(&subitems, sizeof(subitems));
            subitems.Count = 2;
            if (dirObject.DeviceMap) {
                RtlSecureZeroMemory(szValue, sizeof(szValue));
                szValue[0] = L'0';
                szValue[1] = L'x';
                u64tohex((ULONG_PTR)dirObject.DeviceMap, &szValue[2]);
                subitems.Text[0] = szValue;
                subitems.Text[1] = L"POBJECT_DIRECTORY_ENTRY";
            }
            else {
                subitems.Text[0] = T_NULL;
            }
            h_tviEntry = TreeListAddItem(g_TreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0,
                0, L"ShadowDirectory", &subitems);

            //dump entry if available
            if (dirObject.DeviceMap) {
                RtlSecureZeroMemory(&dirEntry, sizeof(dirEntry));
                if (kdReadSystemMemory((ULONG_PTR)dirObject.DeviceMap, &dirEntry, sizeof(dirEntry))) {
                    ObDumpAddress(g_TreeList, h_tviEntry, L"ChainLink", L"PLIST_ENTRY", dirEntry.ChainLink, 0, 0);
                    ObDumpAddress(g_TreeList, h_tviEntry, L"Object", NULL, dirEntry.Object, 0, 0);
                    ObDumpUlong(g_TreeList, h_tviEntry, L"HashValue", NULL, dirEntry.HashValue, TRUE, FALSE, 0, 0);
                }
            }*/

            //all the rest
        ObDumpUlong(g_TreeList, h_tviRootItem, L"SessionId", NULL, dirObject.SessionId, TRUE, FALSE, 0, 0);
        ObDumpAddress(g_TreeList, h_tviRootItem, L"NamespaceEntry", NULL, dirObject.NamespaceEntry, 0, 0);
        ObDumpUlong(g_TreeList, h_tviRootItem, L"Flags", NULL, dirObject.Flags, TRUE, FALSE, 0, 0);
    }
    __except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
        return;
    }
}

/*
* ObDumpSyncObject
*
* Purpose:
*
* Dump KEVENT/KMUTANT/KSEMAPHORE/KTIMER members to the treelist.
*
*/
VOID ObDumpSyncObject(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    HTREEITEM            h_tviRootItem;
    LPWSTR               lpType = NULL, lpDescType = NULL, lpDesc1 = NULL, lpDesc2 = NULL;
    KMUTANT             *Mutant = NULL;
    KEVENT              *Event = NULL;
    KSEMAPHORE          *Semaphore = NULL;
    KTIMER              *Timer = NULL;
    DISPATCHER_HEADER   *Header = NULL;
    PVOID                Object = NULL;
    ULONG                ObjectSize = 0UL;
    WCHAR                szValue[MAX_PATH + 1];

    if (Context == NULL) {
        return;
    }

    __try {

        switch (Context->TypeIndex) {

        case TYPE_EVENT:
            ObjectSize = sizeof(KEVENT);
            break;

        case TYPE_MUTANT:
            ObjectSize = sizeof(KMUTANT);
            break;

        case TYPE_SEMAPHORE:
            ObjectSize = sizeof(KSEMAPHORE);
            break;

        case TYPE_TIMER:
            ObjectSize = sizeof(KTIMER);
            break;

        }

        Object = supHeapAlloc(ObjectSize);
        if (Object == NULL) {
            ObDumpShowError(hwndDlg);
            return;
        }

        //dump object
        if (!kdReadSystemMemory(Context->ObjectInfo.ObjectAddress, Object, ObjectSize)) {
            ObDumpShowError(hwndDlg);
            supHeapFree(Object);
            return;
        }

        g_TreeList = 0;
        g_TreeListAtom = 0;
        if (!supInitTreeListForDump(hwndDlg, &g_TreeListAtom, &g_TreeList)) {
            ObDumpShowError(hwndDlg);
            supHeapFree(Object);
            return;
        }

        //
        //Object name
        //
        Header = NULL;
        switch (Context->TypeIndex) {
        case TYPE_EVENT:
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
                lpDesc2 = L"sizeof(KEVENT)/sizeof(ULONG)";
            }
            break;

        case TYPE_MUTANT:
            lpType = T_KMUTANT;
            Mutant = (KMUTANT*)Object;
            Header = &Mutant->Header;
            lpDesc1 = L"Not Held";
            RtlSecureZeroMemory(szValue, sizeof(szValue));
            if (Mutant->OwnerThread != NULL) {
                wsprintf(szValue, L"Held %d times", Header->SignalState);
                lpDesc1 = szValue;
            }

            lpDesc2 = NULL;
            if (Header->Size == (sizeof(KMUTANT) / sizeof(ULONG))) {
                lpDesc2 = L"sizeof(KMUTANT)/sizeof(ULONG)";
            }
            break;

        case TYPE_SEMAPHORE:
            lpType = T_KSEMAPHORE;
            Semaphore = (KSEMAPHORE*)Object;
            Header = &Semaphore->Header;

            lpDesc1 = L"Count";
            lpDesc2 = NULL;
            if (Header->Size == (sizeof(KSEMAPHORE) / sizeof(ULONG))) {
                lpDesc2 = L"sizeof(KSEMAPHORE)/sizeof(ULONG)";
            }
            break;

        case TYPE_TIMER:
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
            ObDumpShowError(hwndDlg);
            supHeapFree(Object);
            return;
        }

        h_tviRootItem = TreeListAddItem(g_TreeList, NULL, TVIF_TEXT | TVIF_STATE, TVIS_EXPANDED,
            TVIS_EXPANDED, lpType, NULL);

        //Header
        ObDumpDispatcherHeader(h_tviRootItem, Header, lpDescType, lpDesc1, lpDesc2);

        //type specific values
        switch (Context->TypeIndex) {
        case TYPE_MUTANT:
            if (Mutant) {
                ObDumpListEntry(g_TreeList, h_tviRootItem, L"MutantListEntry", &Mutant->MutantListEntry);
                ObDumpAddress(g_TreeList, h_tviRootItem, L"OwnerThread", T_PKTHREAD, Mutant->OwnerThread, 0, 0);
                ObDumpByte(g_TreeList, h_tviRootItem, L"Abandoned", NULL, Mutant->Abandoned, 0, 0, TRUE);
                ObDumpByte(g_TreeList, h_tviRootItem, L"ApcDisable", NULL, Mutant->ApcDisable, 0, 0, FALSE);
            }
            break;

        case TYPE_SEMAPHORE:
            if (Semaphore) {
                ObDumpUlong(g_TreeList, h_tviRootItem, L"Limit", NULL, Semaphore->Limit, TRUE, FALSE, 0, 0);
            }
            break;

        case TYPE_TIMER:
            if (Timer) {
                ObDumpULargeInteger(g_TreeList, h_tviRootItem, L"DueTime", &Timer->DueTime); //dumped as hex, not important
                ObDumpListEntry(g_TreeList, h_tviRootItem, L"TimerListEntry", &Timer->TimerListEntry);
                ObDumpAddress(g_TreeList, h_tviRootItem, L"Dpc", T_PKDPC, Timer->Dpc, 0, 0);
                ObDumpUlong(g_TreeList, h_tviRootItem, L"Processor", NULL, Timer->Processor, TRUE, FALSE, 0, 0);
                ObDumpUlong(g_TreeList, h_tviRootItem, L"Period", NULL, Timer->Period, TRUE, FALSE, 0, 0);
            }
            break;

        }

        supHeapFree(Object);
    }
    __except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
        return;
    }
}

VOID ObDumpObjectType(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    BOOL                    cond, bOkay;
    INT                     i, j;
    HTREEITEM               h_tviRootItem, h_tviSubItem, h_tviGenericMapping;
    LPWSTR                  lpType = NULL;
    POBJINFO                pObject = NULL;
    PRTL_PROCESS_MODULES    pModulesList = NULL;
    OBJECT_TYPE_COMPATIBLE  ObjectTypeDump;
    TL_SUBITEMS_FIXED       subitems;
    WCHAR                   szValue[MAX_PATH + 1];
    PVOID                   TypeProcs[MAX_KNOWN_OBJECT_TYPE_PROCEDURES];
    PVOID                   SelfDriverBase;
    ULONG                   SelfDriverSize;

    if (Context == NULL) {
        return;
    }

    __try {

        pModulesList = supGetSystemInfo(SystemModuleInformation);
        if (pModulesList == NULL)
            return;

        bOkay = FALSE;
        cond = FALSE;

        do {
            //query current object
            pObject = ObQueryObject(T_OBJECTTYPES, Context->lpObjectName);
            if (pObject == NULL)
                break;

            //dump actual state of current object
            RtlSecureZeroMemory(&ObjectTypeDump, sizeof(ObjectTypeDump));
            if (!ObDumpTypeInfo(pObject->ObjectAddress, &ObjectTypeDump))
                break;

            g_TreeList = 0;
            g_TreeListAtom = 0;
            if (!supInitTreeListForDump(hwndDlg, &g_TreeListAtom, &g_TreeList))
                break;

            bOkay = TRUE;

        } while (cond);

        //we don't need it anymore
        if (pObject) {
            supHeapFree(pObject);
        }

        //
        //pObject is NULL, ObDumpTypeInfo failure, list init failure or pModules
        //allocation failure - show error and leave
        //
        if (bOkay == FALSE) {
            ObDumpShowError(hwndDlg);
            return;
        }

        //
        //OBJECT_TYPE
        //
        h_tviRootItem = TreeListAddItem(g_TreeList, NULL, TVIF_TEXT | TVIF_STATE, TVIS_EXPANDED,
            TVIS_EXPANDED, T_OBJECT_TYPE, NULL);

        ObDumpListEntry(g_TreeList, h_tviRootItem, L"TypeList", &ObjectTypeDump.TypeList);
        ObDumpUnicodeString(h_tviRootItem, L"Name", &ObjectTypeDump.Name, FALSE);
        ObDumpAddress(g_TreeList, h_tviRootItem, L"DefaultObject", NULL, ObjectTypeDump.DefaultObject, 0, 0);
        ObDumpByte(g_TreeList, h_tviRootItem, T_TYPEINDEX, NULL, ObjectTypeDump.Index, 0, 0, FALSE);
        ObDumpUlong(g_TreeList, h_tviRootItem, L"TotalNumberOfObjects", NULL, ObjectTypeDump.TotalNumberOfObjects, TRUE, FALSE, 0, 0);
        ObDumpUlong(g_TreeList, h_tviRootItem, L"TotalNumberOfHandles", NULL, ObjectTypeDump.TotalNumberOfHandles, TRUE, FALSE, 0, 0);
        ObDumpUlong(g_TreeList, h_tviRootItem, L"HighWaterNumberOfObjects", NULL, ObjectTypeDump.HighWaterNumberOfObjects, TRUE, FALSE, 0, 0);
        ObDumpUlong(g_TreeList, h_tviRootItem, L"HighWaterNumberOfHandles", NULL, ObjectTypeDump.HighWaterNumberOfHandles, TRUE, FALSE, 0, 0);

        //
        //OBJECT_TYPE_INITIALIZER
        //
        RtlSecureZeroMemory(&subitems, sizeof(subitems));

        subitems.Count = 2;
        subitems.Text[1] = T_OBJECT_TYPE_INITIALIZER;
        h_tviSubItem = TreeListAddItem(g_TreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0,
            0, L"TypeInfo", &subitems);

        ObDumpUlong(g_TreeList, h_tviSubItem, T_LENGTH, NULL, ObjectTypeDump.TypeInfo.Length, TRUE, FALSE, 0, 0);

        RtlSecureZeroMemory(&szValue, sizeof(szValue));
        RtlSecureZeroMemory(&subitems, sizeof(subitems));
        subitems.Count = 2;

        j = 0;
        lpType = NULL;
        if (ObjectTypeDump.TypeInfo.ObjectTypeFlags) {

            for (i = 0; i < 8; i++) {
                if (GET_BIT(ObjectTypeDump.TypeInfo.ObjectTypeFlags, i)) {
                    lpType = (LPWSTR)T_ObjectTypeFlags[i];
                    subitems.Text[0] = NULL;
                    if (j == 0) {
                        wsprintf(szValue, FORMAT_HEXBYTE, ObjectTypeDump.TypeInfo.ObjectTypeFlags);
                        subitems.Text[0] = szValue;
                    }
                    subitems.Text[1] = lpType;
                    TreeListAddItem(g_TreeList, h_tviSubItem, TVIF_TEXT | TVIF_STATE, 0,
                        0, (j == 0) ? T_OBJECTYPEFLAGS : NULL, &subitems);
                    j++;
                }
            }
        }
        else {
            ObDumpByte(g_TreeList, h_tviSubItem, T_OBJECTYPEFLAGS, NULL, ObjectTypeDump.TypeInfo.ObjectTypeFlags, 0, 0, FALSE);
        }
        ObDumpUlong(g_TreeList, h_tviSubItem, L"ObjectTypeCode", NULL, ObjectTypeDump.TypeInfo.ObjectTypeCode, TRUE, FALSE, 0, 0);
        ObDumpUlong(g_TreeList, h_tviSubItem, L"InvalidAttributes", NULL, ObjectTypeDump.TypeInfo.InvalidAttributes, TRUE, FALSE, 0, 0);


        RtlSecureZeroMemory(&subitems, sizeof(subitems));
        subitems.Count = 2;
        subitems.Text[1] = T_GENERIC_MAPPING;
        h_tviGenericMapping = TreeListAddItem(g_TreeList, h_tviSubItem, TVIF_TEXT | TVIF_STATE, 0,
            0, L"GenericMapping", &subitems);

        ObDumpUlong(g_TreeList, h_tviGenericMapping, L"GenericRead", NULL, ObjectTypeDump.TypeInfo.GenericMapping.GenericRead, TRUE, FALSE, 0, 0);
        ObDumpUlong(g_TreeList, h_tviGenericMapping, L"GenericWrite", NULL, ObjectTypeDump.TypeInfo.GenericMapping.GenericWrite, TRUE, FALSE, 0, 0);
        ObDumpUlong(g_TreeList, h_tviGenericMapping, L"GenericExecute", NULL, ObjectTypeDump.TypeInfo.GenericMapping.GenericExecute, TRUE, FALSE, 0, 0);
        ObDumpUlong(g_TreeList, h_tviGenericMapping, L"GenericAll", NULL, ObjectTypeDump.TypeInfo.GenericMapping.GenericAll, TRUE, FALSE, 0, 0);

        ObDumpUlong(g_TreeList, h_tviSubItem, L"ValidAccessMask", NULL, ObjectTypeDump.TypeInfo.ValidAccessMask, TRUE, FALSE, 0, 0);
        ObDumpUlong(g_TreeList, h_tviSubItem, L"RetainAccess", NULL, ObjectTypeDump.TypeInfo.RetainAccess, TRUE, FALSE, 0, 0);

        //Pool Type
        lpType = T_Unknown;
        for (i = 0; i < MAX_KNOWN_POOL_TYPES; i++) {
            if (ObjectTypeDump.TypeInfo.PoolType == (POOL_TYPE)a_PoolTypes[i].dwValue) {
                lpType = a_PoolTypes[i].lpDescription;
                break;
            }
        }
        ObDumpUlong(g_TreeList, h_tviSubItem, L"PoolType", lpType, ObjectTypeDump.TypeInfo.PoolType, TRUE, FALSE, 0, 0);
        ObDumpUlong(g_TreeList, h_tviSubItem, L"DefaultPagedPoolCharge", NULL, ObjectTypeDump.TypeInfo.DefaultPagedPoolCharge, TRUE, FALSE, 0, 0);
        ObDumpUlong(g_TreeList, h_tviSubItem, L"DefaultNonPagedPoolCharge", NULL, ObjectTypeDump.TypeInfo.DefaultNonPagedPoolCharge, TRUE, FALSE, 0, 0);

        //list callback procedures

        //copy type procedures to temp array, assume DumpProcedure always first
        RtlSecureZeroMemory(TypeProcs, sizeof(TypeProcs));
        supCopyMemory(&TypeProcs,
            sizeof(TypeProcs),
            &ObjectTypeDump.TypeInfo.DumpProcedure,
            sizeof(TypeProcs)
        );

        //assume ntoskrnl first in list and list initialized
        SelfDriverBase = pModulesList->Modules[0].ImageBase;
        SelfDriverSize = pModulesList->Modules[0].ImageSize;

        for (i = 0; i < MAX_KNOWN_OBJECT_TYPE_PROCEDURES; i++) {
            RtlSecureZeroMemory(szValue, sizeof(szValue));
            if (TypeProcs[i]) {
                ObDumpAddressWithModule(h_tviSubItem, T_TYPEPROCEDURES[i], TypeProcs[i],
                    pModulesList, SelfDriverBase, SelfDriverSize);
            }
            else {
                ObDumpAddress(g_TreeList, h_tviSubItem, T_TYPEPROCEDURES[i], NULL, TypeProcs[i], 0, 0);
            }
        }

        supHeapFree(pModulesList);
    }
    __except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
        return;
    }
}

/*
* ObDumpQueueObject
*
* Purpose:
*
* Dump KQUEUE members to the treelist.
*
*/
VOID ObDumpQueueObject(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    HTREEITEM h_tviRootItem;
    LPWSTR    lpDesc2;
    KQUEUE    Queue;

    if (Context == NULL) {
        return;
    }

    __try {

        //dump Queue object
        RtlSecureZeroMemory(&Queue, sizeof(Queue));
        if (!kdReadSystemMemory(Context->ObjectInfo.ObjectAddress, &Queue, sizeof(Queue))) {
            ObDumpShowError(hwndDlg);
            return;
        }

        g_TreeList = 0;
        g_TreeListAtom = 0;
        if (!supInitTreeListForDump(hwndDlg, &g_TreeListAtom, &g_TreeList)) {
            ObDumpShowError(hwndDlg);
            return;
        }

        lpDesc2 = NULL;
        if (Queue.Header.Size == (sizeof(KQUEUE) / sizeof(ULONG))) {
            lpDesc2 = L"sizeof(KQUEUE)/sizeof(ULONG)";
        }

        h_tviRootItem = TreeListAddItem(g_TreeList, NULL, TVIF_TEXT | TVIF_STATE, TVIS_EXPANDED,
            TVIS_EXPANDED, T_KQUEUE, NULL);

        //Header
        ObDumpDispatcherHeader(h_tviRootItem, &Queue.Header, NULL, NULL, lpDesc2);
        //EntryListHead
        ObDumpListEntry(g_TreeList, h_tviRootItem, L"EntryListHead", &Queue.EntryListHead);

        //CurrentCount
        ObDumpUlong(g_TreeList, h_tviRootItem, L"CurrentCount", NULL, Queue.CurrentCount, TRUE, FALSE, 0, 0);

        //MaximumCount
        ObDumpUlong(g_TreeList, h_tviRootItem, L"MaximumCount", NULL, Queue.MaximumCount, TRUE, FALSE, 0, 0);

        //ThreadListHead
        ObDumpListEntry(g_TreeList, h_tviRootItem, L"ThreadListHead", &Queue.ThreadListHead);

    }
    __except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
        return;
    }
}

/*
* ObDumpFltServerPort
*
* Purpose:
*
* Dump FLT_SERVER_PORT_OBJECT members to the treelist.
*
*/
VOID ObDumpFltServerPort(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    HTREEITEM h_tviRootItem;
    PVOID pModules = NULL;
    FLT_SERVER_PORT_OBJECT FltServerPortObject;

    if (Context == NULL) {
        return;
    }

    __try {
        //dump PortObject
        RtlSecureZeroMemory(&FltServerPortObject, sizeof(FltServerPortObject));
        if (!kdReadSystemMemory(Context->ObjectInfo.ObjectAddress, &FltServerPortObject, sizeof(FltServerPortObject))) {
            ObDumpShowError(hwndDlg);
            return;
        }

        g_TreeList = 0;
        g_TreeListAtom = 0;
        if (!supInitTreeListForDump(hwndDlg, &g_TreeListAtom, &g_TreeList)) {
            ObDumpShowError(hwndDlg);
            return;
        }

        pModules = supGetSystemInfo(SystemModuleInformation);
        if (pModules == NULL) {
            ObDumpShowError(hwndDlg);
            return;
        }

        h_tviRootItem = TreeListAddItem(g_TreeList, NULL, TVIF_TEXT | TVIF_STATE, TVIS_EXPANDED,
            TVIS_EXPANDED, T_FLT_SERVER_PORT_OBJECT, NULL);

        ObDumpListEntry(g_TreeList, h_tviRootItem, L"FilterLink", &FltServerPortObject.FilterLink);

        ObDumpAddressWithModule(h_tviRootItem, L"ConnectNotify",
            FltServerPortObject.ConnectNotify, pModules, NULL, 0);

        ObDumpAddressWithModule(h_tviRootItem, L"DisconnectNotify",
            FltServerPortObject.DisconnectNotify, pModules, NULL, 0);

        ObDumpAddressWithModule(h_tviRootItem, L"MessageNotify",
            FltServerPortObject.MessageNotify, pModules, NULL, 0);

        ObDumpAddress(g_TreeList, h_tviRootItem, L"Filter", T_PFLT_FILTER, FltServerPortObject.Filter, 0, 0);
        ObDumpAddress(g_TreeList, h_tviRootItem, L"Cookie", NULL, FltServerPortObject.Cookie, 0, 0);
        ObDumpUlong(g_TreeList, h_tviRootItem, L"Flags", NULL, FltServerPortObject.Flags, TRUE, FALSE, 0, 0);
        ObDumpUlong(g_TreeList, h_tviRootItem, L"NumberOfConnections", NULL, FltServerPortObject.NumberOfConnections, TRUE, FALSE, 0, 0);
        ObDumpUlong(g_TreeList, h_tviRootItem, L"MaxConnections", NULL, FltServerPortObject.MaxConnections, TRUE, FALSE, 0, 0);

        supHeapFree(pModules);
    }
    __except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
        return;
    }
}


/*
* ObjectDumpHandlePopupMenu
*
* Purpose:
*
* Object dump popup construction
*
*/
VOID ObjectDumpHandlePopupMenu(
    _In_ HWND hwndDlg
)
{
    POINT pt1;
    HMENU hMenu;

    if (GetCursorPos(&pt1) == FALSE)
        return;

    hMenu = CreatePopupMenu();
    if (hMenu) {
        InsertMenu(hMenu, 0, MF_BYCOMMAND, ID_OBJECT_COPY, T_COPYVALUE);
        TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, pt1.x, pt1.y, 0, hwndDlg, NULL);
        DestroyMenu(hMenu);
    }
}

/*
* ObjectDumpCopyValue
*
* Purpose:
*
* Copy selected value to the clipboard.
*
*/
VOID ObjectDumpCopyValue(
    VOID
)
{
    SIZE_T             cbText;
    LPWSTR             lpText;
    TL_SUBITEMS_FIXED *subitems;
    TVITEMEX           itemex;
    WCHAR              textbuf[MAX_PATH + 1];

    __try {

        RtlSecureZeroMemory(&itemex, sizeof(itemex));
        RtlSecureZeroMemory(textbuf, sizeof(textbuf));
        subitems = NULL;
        itemex.mask = TVIF_TEXT;
        itemex.hItem = TreeView_GetSelection(g_TreeList);
        itemex.pszText = textbuf;
        itemex.cchTextMax = MAX_PATH;

        TreeList_GetTreeItem(g_TreeList, &itemex, &subitems);

        if (subitems) {
            lpText = subitems->Text[0];
            if (lpText) {
                cbText = _strlen(lpText) * sizeof(WCHAR);
                supClipboardCopy(lpText, cbText);
            }
        }
    }
    __except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
        return;
    }
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
    PROPSHEETPAGE    *pSheet = NULL;
    PROP_OBJECT_INFO *Context = NULL;

    UNREFERENCED_PARAMETER(wParam);

    switch (uMsg) {

    case WM_CONTEXTMENU:
        ObjectDumpHandlePopupMenu(hwndDlg);
        break;

    case WM_COMMAND:

        if (LOWORD(wParam) == ID_OBJECT_COPY) {
            ObjectDumpCopyValue();
        }
        break;

    case WM_INITDIALOG:
        Context = NULL;
        pSheet = (PROPSHEETPAGE *)lParam;
        if (pSheet) {

            Context = (PROP_OBJECT_INFO*)pSheet->lParam;
            if (Context) {

                switch (Context->TypeIndex) {

                case TYPE_DIRECTORY:
                    ObDumpDirectoryObject(Context, hwndDlg);
                    break;

                case TYPE_DRIVER:
                    ObDumpDriverObject(Context, hwndDlg);
                    break;

                case TYPE_DEVICE:
                    ObDumpDeviceObject(Context, hwndDlg);
                    break;

                case TYPE_EVENT:
                case TYPE_MUTANT:
                case TYPE_SEMAPHORE:
                case TYPE_TIMER:
                    ObDumpSyncObject(Context, hwndDlg);
                    break;

                case TYPE_IOCOMPLETION:
                    ObDumpQueueObject(Context, hwndDlg);
                    break;

                case TYPE_FLTCONN_PORT:
                    ObDumpFltServerPort(Context, hwndDlg);
                    break;

                case TYPE_TYPE:
                    ObDumpObjectType(Context, hwndDlg);
                    break;
                }
            }
        }
        return 1;
        break;

    }
    return 0;
}
