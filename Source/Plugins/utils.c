/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2026
*
*  TITLE:       UTILS.C
*
*  VERSION:     1.21
*
*  DATE:        07 Mar 2026
*
*  Shared plugins runtime support functions and prototypes.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "utils.h"

/*
* supSetWaitCursor
*
* Purpose:
*
* Sets cursor state.
*
*/
VOID supSetWaitCursor(
    _In_ BOOL fSet
)
{
    HCURSOR h = LoadCursor(NULL, fSet ? IDC_WAIT : IDC_ARROW);
    if (h) {
        SetCursor(h);
    }
}

/*
* supMapSection
*
* Purpose:
*
* Return pointer to section mapped view.
*
*/
NTSTATUS supMapSection(
    _In_ HANDLE SectionHandle,
    _Out_ PVOID* BaseAddress,
    _Out_ SIZE_T* ViewSize
)
{
    NTSTATUS ntStatus;
    SECTION_BASIC_INFORMATION sbi;
    SIZE_T bytesReturned;

    *BaseAddress = NULL;
    *ViewSize = 0;

    __try {

        //
        // Check if this is image mapped file.
        //
        ntStatus = NtQuerySection(SectionHandle,
            SectionBasicInformation,
            (PVOID)&sbi,
            sizeof(SECTION_BASIC_INFORMATION),
            &bytesReturned);

        if (!NT_SUCCESS(ntStatus))
            __leave;

        if (!((sbi.AllocationAttributes & SEC_IMAGE) &&
            (sbi.AllocationAttributes & SEC_FILE)))
        {
            ntStatus = STATUS_NOT_SUPPORTED;
            __leave;
        }

        ntStatus = NtMapViewOfSection(SectionHandle,
            NtCurrentProcess(),
            BaseAddress,
            0,
            0,
            NULL,
            ViewSize,
            ViewUnmap,
            0,
            PAGE_READONLY);

    }
    __finally {
        if (AbnormalTermination())
            ntStatus = STATUS_ACCESS_VIOLATION;
    }

    return ntStatus;
}

/*
* supSaveDialogExecute
*
* Purpose:
*
* Display SaveDialog.
*
*/
BOOL supSaveDialogExecute(
    _In_ HWND OwnerWindow,
    _Inout_ LPWSTR SaveFileName,
    _In_ LPWSTR lpDialogFilter
)
{
    OPENFILENAME tag1;

    RtlSecureZeroMemory(&tag1, sizeof(OPENFILENAME));

    tag1.lStructSize = sizeof(OPENFILENAME);
    tag1.hwndOwner = OwnerWindow;
    tag1.lpstrFilter = lpDialogFilter;
    tag1.lpstrFile = SaveFileName;
    tag1.nMaxFile = MAX_PATH;
    tag1.lpstrInitialDir = NULL;
    tag1.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;

    return GetSaveFileName(&tag1);
}

size_t supxEscStrlen(wchar_t* s)
{
    size_t result, quoteCount;
    wchar_t* s0;

    if (s == NULL)
        return 0;

    s0 = s;
    result = 2;
    quoteCount = 0;

    while (*s) {
        if (*s == L'"')
            ++quoteCount;
        ++s;
    }

    return result + (s - s0) + quoteCount;
}

wchar_t* supxEscStrcpy(wchar_t* dst, wchar_t* src)
{
    if (dst == NULL || src == NULL)
        return dst;

    *(dst++) = L'"';

    while (*src != L'\0') {
        if (*src == L'"') {
            *(dst++) = L'"';
            *(dst++) = L'"';
            ++src;
        }
        else {
            *(dst++) = *src;
            ++src;
        }
    }

    *(dst++) = L'"';
    *dst = L'\0';

    return dst;
}

/*
* supxListViewExportCSV
*
* Purpose:
*
* Export listview entries into file in csv format.
*
*/
BOOL supxListViewExportCSV(
    _In_ HWND List,
    _In_ PWCHAR FileName)
{
    HWND hdr;
    int pass, i, c, col_count, icount;
    HDITEM ih;
    LVITEM lvi;
    PWCHAR text, buffer0, buffer;
    BOOL result;
    SIZE_T total_length, field_length;
    DWORD iobytes;
    HANDLE f;
    WORD bom;

    if (!List || !FileName)
        return FALSE;

    hdr = ListView_GetHeader(List);
    if (!hdr)
        return FALSE;

    col_count = Header_GetItemCount(hdr);
    if (col_count <= 0)
        return FALSE;

    icount = 1 + ListView_GetItemCount(List);

    text = (PWCHAR)ntsupVirtualAlloc(32768 * sizeof(WCHAR));
    if (!text)
        return FALSE;

    buffer0 = NULL;
    buffer = NULL;
    result = FALSE;

    RtlZeroMemory(&ih, sizeof(HDITEM));
    RtlZeroMemory(&lvi, sizeof(LVITEM));

    ih.pszText = lvi.pszText = text;
    ih.cchTextMax = lvi.cchTextMax = 32767;

    for (pass = 0; pass < 2; ++pass) {
        total_length = 0;

        for (i = 0; i < icount; ++i) {
            for (c = 0; c < col_count; ++c) {
                text[0] = L'\0';

                if (i == 0) {
                    ih.mask = HDI_TEXT | HDI_ORDER;
                    ih.iOrder = c;
                    Header_GetItem(hdr, c, &ih);
                }
                else {
                    lvi.mask = LVIF_TEXT;
                    lvi.iItem = i - 1;
                    lvi.iSubItem = c;
                    ListView_GetItem(List, &lvi);
                }

                field_length = supxEscStrlen(text);
                total_length += field_length;

                if (buffer) {
                    buffer = supxEscStrcpy(buffer, text);
                }

                if (c != col_count - 1) {
                    total_length += 1;
                    if (buffer) {
                        *(buffer++) = L',';
                    }
                }
                else {
                    total_length += 2;
                    if (buffer) {
                        *(buffer++) = L'\r';
                        *(buffer++) = L'\n';
                    }
                }
            }
        }

        if (buffer0 == NULL) {
            buffer0 = (PWCHAR)ntsupVirtualAlloc((1 + total_length) * sizeof(WCHAR));
            if (!buffer0)
                break;
            buffer = buffer0;
        }
        else {
            f = CreateFile(FileName,
                GENERIC_WRITE | SYNCHRONIZE,
                FILE_SHARE_READ,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL);

            if (f != INVALID_HANDLE_VALUE) {
                bom = 0xFEFF;
                if (WriteFile(f, &bom, sizeof(WORD), &iobytes, NULL) &&
                    iobytes == sizeof(WORD) &&
                    WriteFile(f, buffer0, (DWORD)(total_length * sizeof(WCHAR)), &iobytes, NULL) &&
                    iobytes == (DWORD)(total_length * sizeof(WCHAR)))
                {
                    result = TRUE;
                }
                CloseHandle(f);
                result = TRUE;
            }
            ntsupVirtualFree(buffer0);
            buffer0 = NULL;
        }
    }

    if (buffer0)
        ntsupVirtualFree(buffer0);

    ntsupVirtualFree(text);
    return result;
}

/*
* supListViewExportToFile
*
* Purpose:
*
* Export listview contents to the specified file.
*
*/
BOOL supListViewExportToFile(
    _In_ LPWSTR FileName,
    _In_ HWND WindowHandle,
    _In_ HWND ListView,
    _In_ LPWSTR FileFilter
)
{
    BOOL bResult = FALSE;
    WCHAR szExportFileName[MAX_PATH + 1];

    RtlSecureZeroMemory(&szExportFileName, sizeof(szExportFileName));

    _strcpy(szExportFileName, FileName);
    if (supSaveDialogExecute(WindowHandle,
        (LPWSTR)&szExportFileName,
        FileFilter))
    {
        SetCapture(WindowHandle);
        supSetWaitCursor(TRUE);

        bResult = supxListViewExportCSV(ListView, szExportFileName);

        supSetWaitCursor(FALSE);
        ReleaseCapture();
    }

    return bResult;
}

/*
* supStatusBarSetText
*
* Purpose:
*
* Display status in status bar part.
*
*/
VOID supStatusBarSetText(
    _In_ HWND hwndStatusBar,
    _In_ WPARAM partIndex,
    _In_ LPWSTR lpText
)
{
    SendMessage(hwndStatusBar, SB_SETTEXT, partIndex, (LPARAM)lpText);
}

/*
* supTreeListAddItem
*
* Purpose:
*
* Insert new treelist item.
*
*/
HTREEITEM supTreeListAddItem(
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
    tvitem.hInsertAfter = TVI_LAST;
    return TreeList_InsertTreeItem(TreeList, &tvitem, si);
}

/*
* supAddListViewColumn
*
* Purpose:
*
* Insert list view column.
*
*/
INT supAddListViewColumn(
    _In_ HWND ListViewHwnd,
    _In_ INT ColumnIndex,
    _In_ INT SubItemIndex,
    _In_ INT OrderIndex,
    _In_ INT ImageIndex,
    _In_ INT Format,
    _In_ LPWSTR Text,
    _In_ INT Width,
    _In_ INT DpiValue
)
{
    LVCOLUMN column;

    column.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
    column.fmt = Format;
    column.cx = ScaleDPI(Width, DpiValue);
    column.pszText = Text;
    column.iSubItem = SubItemIndex;
    column.iOrder = OrderIndex;
    column.iImage = ImageIndex;

    return ListView_InsertColumn(ListViewHwnd, ColumnIndex, &column);
}

/*
* supTreeListAddCopyValueItem
*
* Purpose:
*
* Add copy to clipboard menu item depending on hit treelist header item.
*
*/
BOOL supTreeListAddCopyValueItem(
    _In_ HMENU hMenu,
    _In_ HWND hwndTreeList,
    _In_ UINT uId,
    _In_ UINT uPos,
    _In_ LPARAM lParam,
    _In_ INT* pSubItemHit
)
{
    HDHITTESTINFO hti;
    HD_ITEM hdItem;
    WCHAR szHeaderText[MAX_PATH + 1];
    WCHAR szItem[MAX_PATH * 2];

    *pSubItemHit = -1;

    hti.iItem = -1;
    hti.pt.x = LOWORD(lParam);
    hti.pt.y = HIWORD(lParam);
    ScreenToClient(hwndTreeList, &hti.pt);

    hti.pt.y = 1;
    if (TreeList_HeaderHittest(hwndTreeList, &hti) < 0)
        return FALSE;

    RtlSecureZeroMemory(&hdItem, sizeof(hdItem));

    szHeaderText[0] = 0;
    hdItem.mask = HDI_TEXT;

    hdItem.cchTextMax = RTL_NUMBER_OF(szHeaderText);

    hdItem.pszText = szHeaderText;
    if (TreeList_GetHeaderItem(hwndTreeList, hti.iItem, &hdItem)) {
        *pSubItemHit = hti.iItem;
        StringCchPrintf(szItem, RTL_NUMBER_OF(szItem), TEXT("Copy \"%ws\""), szHeaderText);
        if (InsertMenu(hMenu, uPos, MF_BYCOMMAND, uId, szItem)) {
            return TRUE;
        }
    }

    return FALSE;
}

/*
* supGetItemText
*
* Purpose:
*
* Returns buffer with text from the given listview item.
*
* Returned buffer must be freed with supHeapFree after usage.
*
*/
LPWSTR supGetItemText(
    _In_ HWND ListView,
    _In_ INT nItem,
    _In_ INT nSubItem,
    _Out_opt_ PSIZE_T lpSize
)
{
    INT len;
    LPARAM sz = 0;
    LV_ITEM item;

    RtlSecureZeroMemory(&item, sizeof(item));

    item.iItem = nItem;
    item.iSubItem = nSubItem;
    len = 128;

    do {
        len *= 2;
        item.cchTextMax = len;
        if (item.pszText) {
            supHeapFree(item.pszText);
            item.pszText = NULL;
        }
        item.pszText = (LPWSTR)supHeapAlloc(len * sizeof(WCHAR));
        if (item.pszText == NULL)
            break;

        sz = SendMessage(ListView, LVM_GETITEMTEXT, (WPARAM)item.iItem, (LPARAM)&item);
    } while (sz == (LPARAM)len - 1);

    if (sz == 0) {
        if (item.pszText) {
            supHeapFree(item.pszText);
            item.pszText = NULL;
        }
    }

    if (lpSize) {
        *lpSize = sz * sizeof(WCHAR);
    }

    return item.pszText;
}

/*
* supGetItemText2
*
* Purpose:
*
* Returns text from the given listview item.
*
*/
LPWSTR supGetItemText2(
    _In_ HWND ListView,
    _In_ INT nItem,
    _In_ INT nSubItem,
    _In_ WCHAR* pszText,
    _In_ UINT cchText
)
{
    LV_ITEM item;

    RtlSecureZeroMemory(&item, sizeof(item));

    item.iItem = nItem;
    item.iSubItem = nSubItem;
    item.pszText = pszText;
    item.cchTextMax = (SIZE_T)cchText;
    SendMessage(ListView, LVM_GETITEMTEXT, (WPARAM)item.iItem, (LPARAM)&item);

    return item.pszText;
}

/*
* supClipboardCopy
*
* Purpose:
*
* Copy text to the clipboard.
*
*/
VOID supClipboardCopy(
    _In_ LPWSTR lpText,
    _In_ SIZE_T cbText
)
{
    LPWSTR  lptstrCopy;
    HGLOBAL hglbCopy = NULL;
    SIZE_T  dwSize;
    BOOL    dataSet = FALSE;

    if (!OpenClipboard(NULL))
        return;

    __try {
        EmptyClipboard();
        dwSize = cbText + sizeof(UNICODE_NULL);
        hglbCopy = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, dwSize);
        if (hglbCopy == NULL)
            __leave;

        lptstrCopy = (LPWSTR)GlobalLock(hglbCopy);
        if (lptstrCopy == NULL)
            __leave;

        RtlCopyMemory(lptstrCopy, lpText, cbText);
        GlobalUnlock(hglbCopy);

        dataSet = SetClipboardData(CF_UNICODETEXT, hglbCopy) != NULL;
        if (dataSet) {
            hglbCopy = NULL;
        }
    }
    __finally {
        CloseClipboard();
        if (hglbCopy != NULL) {
            GlobalFree(hglbCopy);
        }
    }
}

/*
* supListViewCopyItemValueToClipboard
*
* Purpose:
*
* Copy selected item text to the clipboard.
*
*/
BOOL supListViewCopyItemValueToClipboard(
    _In_ HWND hwndListView,
    _In_ INT iItem,
    _In_ INT iSubItem
)
{
    SIZE_T cbText;
    LPWSTR lpText;

    if ((iSubItem < 0) || (iItem < 0))
        return FALSE;

    lpText = supGetItemText(hwndListView,
        iItem,
        iSubItem,
        NULL);

    if (lpText) {
        cbText = _strlen(lpText) * sizeof(WCHAR);
        supClipboardCopy(lpText, cbText);
        supHeapFree(lpText);
        return TRUE;
    }
    else {
        if (OpenClipboard(NULL)) {
            EmptyClipboard();
            CloseClipboard();
        }
    }

    return FALSE;
}

/*
* supFreeDuplicatedUnicodeString
*
* Purpose:
*
* Release memory allocated for duplicated string.
*
*/
_Success_(return)
BOOL supFreeDuplicatedUnicodeString(
    _In_ HANDLE HeapHandle,
    _Inout_ PUNICODE_STRING DuplicatedString,
    _In_ BOOL DoZeroMemory
)
{
    BOOL bResult = FALSE;
    if (DuplicatedString->Buffer) {
        bResult = RtlFreeHeap(HeapHandle, 0, DuplicatedString->Buffer);
        if (DoZeroMemory) {
            DuplicatedString->Buffer = NULL;
            DuplicatedString->Length = DuplicatedString->MaximumLength = 0;
        }
    }
    return bResult;
}

/*
* supDuplicateUnicodeString
*
* Purpose:
*
* Duplicate existing UNICODE_STRING to another without RtlDuplicateUnicodeString.
*
* Note: Use supFreeDuplicatedUnicodeString to release allocated memory.
*
*/
_Success_(return)
BOOL supDuplicateUnicodeString(
    _In_ HANDLE HeapHandle,
    _Out_ PUNICODE_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString
)
{
    USHORT maxLength = SourceString->MaximumLength;
    PWCHAR strBuffer;

    if (maxLength == 0 || maxLength < SourceString->Length)
        return FALSE;

    strBuffer = (PWCHAR)RtlAllocateHeap(HeapHandle, HEAP_ZERO_MEMORY, (SIZE_T)maxLength);
    if (strBuffer) {
        DestinationString->Buffer = strBuffer;
        DestinationString->MaximumLength = maxLength;
        RtlCopyUnicodeString(DestinationString, SourceString);
        return TRUE;
    }

    return FALSE;
}

//
// Conversion buffer size
//
#define CONVERT_NTNAME_BUFFER_SIZE 512

/*
* supConvertFileName
*
* Purpose:
*
* Translate Nt path name to Dos path name.
*
*/
BOOL supConvertFileName(
    _In_ LPWSTR NtFileName,
    _Inout_ LPWSTR DosFileName,
    _In_ SIZE_T ccDosFileName
)
{
    BOOL bFound = FALSE;

    SIZE_T nLen;

    WCHAR szDrive[3];
    WCHAR szName[MAX_PATH];
    WCHAR szTemp[CONVERT_NTNAME_BUFFER_SIZE];
    WCHAR* pszTemp;

    //
    // All input parameters are validated by caller before.
    //

    //
    // Drive template.
    //
    szDrive[0] = L'X';
    szDrive[1] = L':';
    szDrive[2] = 0;

    //
    // Query array of logical disk drive strings.
    //
    szTemp[0] = 0;
    if (GetLogicalDriveStrings(RTL_NUMBER_OF(szTemp), szTemp) == 0)
        return FALSE;

    pszTemp = szTemp;

    do {

        //
        // Copy the drive letter to the template string.
        //
        *szDrive = *pszTemp;
        szName[0] = 0;

        //
        // Lookup each device name.
        //
        if (QueryDosDevice(szDrive, szName, MAX_PATH)) {

            nLen = _strlen(szName);

            if (nLen < MAX_PATH) {

                //
                // Match device name.
                //
                bFound = ((_strncmpi(NtFileName, szName, nLen) == 0)
                    && *(NtFileName + nLen) == L'\\');

                if (bFound) {

                    //
                    // Build output name.
                    //
                    StringCchPrintf(
                        DosFileName,
                        ccDosFileName,
                        TEXT("%ws%ws"),
                        szDrive,
                        NtFileName + nLen);

                }

            }

        }

        //
        // Go to the next NULL character, i.e. the next drive name.
        //
        while (*pszTemp++);

    } while (!bFound && *pszTemp);

    return bFound;
}

/*
* supGetWin32FileName
*
* Purpose:
*
* Query filename by handle.
*
* Input buffer must be at least MAX_PATH length.
*
*/
BOOL supGetWin32FileName(
    _In_ LPWSTR FileName,
    _Inout_ LPWSTR Win32FileName,
    _In_ SIZE_T ccWin32FileName
)
{
    BOOL                bResult = FALSE;
    NTSTATUS            status = STATUS_UNSUCCESSFUL;
    HANDLE              hFile = NULL;
    UNICODE_STRING      NtFileName;
    OBJECT_ATTRIBUTES   obja;
    IO_STATUS_BLOCK     iost;
    ULONG               memIO;
    BYTE* Buffer = NULL;

    if ((Win32FileName == NULL) || (ccWin32FileName < MAX_PATH)) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    do {

        RtlInitUnicodeString(&NtFileName, FileName);
        InitializeObjectAttributes(&obja, &NtFileName, OBJ_CASE_INSENSITIVE, 0, NULL);

        status = NtCreateFile(&hFile, SYNCHRONIZE, &obja, &iost, NULL, 0,
            FILE_SHARE_VALID_FLAGS, FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

        if (!NT_SUCCESS(status))
            break;

        memIO = 0;
        status = NtQueryObject(hFile, ObjectNameInformation, NULL, 0, &memIO);
        if (status != STATUS_INFO_LENGTH_MISMATCH)
            break;

        Buffer = (BYTE*)supHeapAlloc(memIO);
        if (Buffer == NULL)
            break;

        status = NtQueryObject(hFile, ObjectNameInformation, Buffer, memIO, NULL);
        if (!NT_SUCCESS(status))
            break;

        if (!supConvertFileName(((PUNICODE_STRING)Buffer)->Buffer, Win32FileName, ccWin32FileName))
            break;

        bResult = TRUE;

    } while (FALSE);

    if (hFile)
        NtClose(hFile);

    if (Buffer != NULL)
        supHeapFree(Buffer);

    return bResult;
}

/*
* supGetMaxCompareTwoFixedStrings
*
* Purpose:
*
* Returned value used in listview comparer functions.
*
*/
INT supGetMaxCompareTwoFixedStrings(
    _In_ HWND ListView,
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort,
    _In_ BOOL Inverse
)
{
    INT       nResult;
    LPWSTR    lpItem1 = NULL, lpItem2 = NULL, FirstToCompare, SecondToCompare;
    WCHAR     szString1[MAX_PATH + 1], szString2[MAX_PATH + 1];

    szString1[0] = 0;

    lpItem1 = supGetItemText2(
        ListView,
        (INT)lParam1,
        (INT)lParamSort,
        szString1,
        MAX_PATH);

    szString2[0] = 0;

    lpItem2 = supGetItemText2(
        ListView,
        (INT)lParam2,
        (INT)lParamSort,
        szString2,
        MAX_PATH);

    if (Inverse) {
        FirstToCompare = lpItem2;
        SecondToCompare = lpItem1;
    }
    else {
        FirstToCompare = lpItem1;
        SecondToCompare = lpItem2;
    }

    nResult = _strcmpi(FirstToCompare, SecondToCompare);

    return nResult;
}

/*
* supGetMaxOfTwoU64FromHex
*
* Purpose:
*
* Returned value used in listview comparer functions.
*
*/
INT supGetMaxOfTwoU64FromHex(
    _In_ HWND ListView,
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort,
    _In_ BOOL Inverse
)
{
    INT       nResult = 0;
    LPWSTR    lpItem1 = NULL, lpItem2 = NULL;
    ULONG_PTR ad1, ad2;
    WCHAR     szText[32];

    RtlSecureZeroMemory(&szText, sizeof(szText));

    lpItem1 = supGetItemText2(
        ListView,
        (INT)lParam1,
        (INT)lParamSort,
        szText,
        RTL_NUMBER_OF(szText));

    ad1 = hextou64(&lpItem1[2]);

    RtlSecureZeroMemory(&szText, sizeof(szText));

    lpItem2 = supGetItemText2(
        ListView,
        (INT)lParam2,
        (INT)lParamSort,
        szText,
        RTL_NUMBER_OF(szText));

    ad2 = hextou64(&lpItem2[2]);

    if (ad1 < ad2)
        nResult = -1;
    else if (ad1 > ad2)
        nResult = 1;

    if (Inverse)
        nResult = -nResult;

    return nResult;
}

/*
* supTreeListCopyItemValueToClipboard
*
* Purpose:
*
* Copy selected treelist item text to the clipboard.
*
*/
BOOL supTreeListCopyItemValueToClipboard(
    _In_ HWND hwndTreeList,
    _In_ INT tlSubItemHit
)
{
    INT         nIndex;
    LPWSTR      lpCopyData = NULL;
    SIZE_T      cbCopyData = 0;
    TVITEMEX    itemex;
    WCHAR       szText[MAX_PATH + 1];

    TL_SUBITEMS_FIXED* pSubItems = NULL;

    szText[0] = 0;
    RtlSecureZeroMemory(&itemex, sizeof(itemex));
    itemex.mask = TVIF_TEXT;
    itemex.hItem = TreeList_GetSelection(hwndTreeList);
    itemex.pszText = szText;
    itemex.cchTextMax = MAX_PATH;

    if (TreeList_GetTreeItem(hwndTreeList, &itemex, &pSubItems)) {

        if ((tlSubItemHit > 0) && (pSubItems != NULL)) {

            nIndex = (tlSubItemHit - 1);
            if (nIndex < (INT)pSubItems->Count) {

                lpCopyData = pSubItems->Text[nIndex];
                cbCopyData = _strlen(lpCopyData) * sizeof(WCHAR);

            }

        }
        else {
            if (tlSubItemHit == 0) {
                lpCopyData = szText;
                cbCopyData = sizeof(szText); // copy everything
            }
        }

        if (lpCopyData && cbCopyData) {
            supClipboardCopy(lpCopyData, cbCopyData);
            return TRUE;
        }
        else {
            if (OpenClipboard(NULL)) {
                EmptyClipboard();
                CloseClipboard();
            }
        }
    }

    return FALSE;
}

/*
* supListViewAddCopyValueItem
*
* Purpose:
*
* Add copy to clipboard menu item depending on hit column.
*
*/
BOOL supListViewAddCopyValueItem(
    _In_ HMENU hMenu,
    _In_ HWND hwndLv,
    _In_ UINT uId,
    _In_ UINT uPos,
    _In_ POINT * lpPoint,
    _Out_ INT * pItemHit,
    _Out_ INT * pColumnHit
)
{
    LVHITTESTINFO lvht;
    LVCOLUMN lvc;
    WCHAR szItem[MAX_PATH * 2];
    WCHAR szColumn[MAX_PATH + 1];

    *pColumnHit = -1;
    *pItemHit = -1;

    RtlSecureZeroMemory(&lvht, sizeof(lvht));
    lvht.pt.x = lpPoint->x;
    lvht.pt.y = lpPoint->y;
    ScreenToClient(hwndLv, &lvht.pt);
    if (ListView_SubItemHitTest(hwndLv, &lvht) == -1)
        return FALSE;

    RtlSecureZeroMemory(&lvc, sizeof(lvc));
    RtlSecureZeroMemory(&szColumn, sizeof(szColumn));

    lvc.mask = LVCF_TEXT;
    lvc.pszText = szColumn;
    lvc.cchTextMax = MAX_PATH;
    if (ListView_GetColumn(hwndLv, lvht.iSubItem, &lvc)) {
        _strcpy(szItem, TEXT("Copy \""));
        _strcat(szItem, szColumn);
        _strcat(szItem, TEXT("\""));
        if (InsertMenu(hMenu, uPos, MF_BYCOMMAND, uId, szItem)) {
            *pColumnHit = lvht.iSubItem;
            *pItemHit = lvht.iItem;
            return TRUE;
        }
    }

    return FALSE;
}
