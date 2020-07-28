/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       SUP.C
*
*  VERSION:     1.00
*
*  DATE:        11 July 2020
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* supHeapAlloc
*
* Purpose:
*
* RtlAllocateHeap wrapper.
*
*/
PVOID supHeapAlloc(
    _In_ SIZE_T Size
)
{
    return RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Size);
}

/*
* supHeapFree
*
* Purpose:
*
* RtlFreeHeap wrapper.
*
*/
BOOL supHeapFree(
    _In_ PVOID Memory
)
{
    return RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Memory);
}

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
    ShowCursor(fSet);
    SetCursor(LoadCursor(NULL, fSet ? IDC_WAIT : IDC_ARROW));
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
    HANDLE dirHandle = NULL;
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
        if (dirHandle)
            NtClose(dirHandle);
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
    size_t  result = 2;
    wchar_t* s0 = s;

    while (*s)
    {
        if (*s == L'"')
            ++result;
        ++s;
    }

    return result + (s - s0);
}

wchar_t* supxEscStrcpy(wchar_t* dst, wchar_t* src)
{
    *(dst++) = L'"';

    while ((*dst = *src) != L'\0')
    {
        if (*src == L'"')
            *(++dst) = L'"';

        ++src;
        ++dst;
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
    _In_ INT ColumnCount,
    _In_ PWCHAR FileName)
{
    HWND            hdr = ListView_GetHeader(List);
    int             pass, i, c, col_count, icount = 1 + ListView_GetItemCount(List);
    HDITEM          ih;
    LVITEM          lvi;
    PWCHAR          text, buffer0 = NULL, buffer = NULL;
    BOOL            result = FALSE;
    SIZE_T          total_lenght;
    DWORD           iobytes;
    HANDLE          f;

    text = (PWCHAR)ntsupVirtualAlloc(32768 * sizeof(WCHAR));
    if (!text)
        return FALSE;

    if (ColumnCount < 0)
        col_count = Header_GetItemCount(hdr);
    else
        col_count = ColumnCount;

    RtlZeroMemory(&ih, sizeof(HDITEM));
    RtlZeroMemory(&lvi, sizeof(LVITEM));

    ih.pszText = lvi.pszText = text;
    ih.cchTextMax = lvi.cchTextMax = 32767;

    for (pass = 0; pass < 2; ++pass)
    {
        total_lenght = 0;

        for (i = 0; i < icount; ++i)
        {
            for (c = 0; c < col_count; ++c)
            {
                text[0] = L'\0';
                if (i == 0)
                {
                    ih.mask = HDI_TEXT | HDI_ORDER;
                    ih.iOrder = c;
                    Header_GetItem(hdr, c, &ih);
                }
                else
                {
                    lvi.mask = LVIF_TEXT;
                    lvi.iItem = i - 1;
                    lvi.iSubItem = c;
                    ListView_GetItem(List, &lvi);
                }
                total_lenght += supxEscStrlen(text) + 1;

                if (buffer)
                {
                    buffer = supxEscStrcpy(buffer, text);
                    if (c != col_count - 1)
                    {
                        *(buffer++) = L',';
                    }
                    else
                    {
                        *(buffer++) = L'\r';
                        *(buffer++) = L'\n';
                    }
                }
            }
            ++total_lenght;
        }

        if (buffer0 == NULL)
        {
            buffer0 = (PWCHAR)ntsupVirtualAlloc((1 + total_lenght) * sizeof(WCHAR));
            if (!buffer0)
                break;
        }
        else
        {
            f = CreateFile(FileName, GENERIC_WRITE | SYNCHRONIZE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (f != INVALID_HANDLE_VALUE)
            {
                WriteFile(f, buffer0, (DWORD)(total_lenght * sizeof(WCHAR)), &iobytes, NULL);
                CloseHandle(f);
                result = TRUE;
            }
            ntsupVirtualFree(buffer0);
        }
        buffer = buffer0;
    }

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
    _In_ INT ColumnCount
)
{
    BOOL bResult = FALSE;
    WCHAR szExportFileName[MAX_PATH + 1];

    RtlSecureZeroMemory(&szExportFileName, sizeof(szExportFileName));

    _strcpy(szExportFileName, FileName);
    if (supSaveDialogExecute(WindowHandle,
        (LPWSTR)&szExportFileName,
        T_CSV_FILE_FILTER))
    {
        SetCapture(WindowHandle);
        supSetWaitCursor(TRUE);

        bResult = supxListViewExportCSV(ListView, ColumnCount, szExportFileName);

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
