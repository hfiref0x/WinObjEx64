/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2020
*
*  TITLE:       EXTRASSL.C
*
*  VERSION:     1.87
*
*  DATE:        28 June 2020
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "extras.h"

UINT g_SLCacheImageIndex;

/*
* SLCacheListCompareFunc
*
* Purpose:
*
* Listview comparer function.
*
*/
INT CALLBACK SLCacheListCompareFunc(
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort
)
{
    EXTRASCONTEXT* pDlgContext = (EXTRASCONTEXT*)lParamSort;

    return supListViewBaseComparer(pDlgContext->ListView,
        pDlgContext->bInverseSort,
        lParam1,
        lParam2,
        pDlgContext->lvColumnToSort);
}

/*
* xxxSLCacheGetSelectedDescriptor
*
* Purpose:
*
* Query selected listview item associated data.
*
*/
SL_KMEM_CACHE_VALUE_DESCRIPTOR* xxxSLCacheGetSelectedDescriptor(
    _In_ HWND hwndListView,
    _In_ INT iItem)
{
    SL_KMEM_CACHE_VALUE_DESCRIPTOR* CacheDescriptor = NULL;

    //
    // Query associated data.
    //
    if (!supGetListViewItemParam(hwndListView,
        iItem,
        (PVOID*)&CacheDescriptor))
    {
        return NULL;
    }

    return CacheDescriptor;
}

/*
* xxxSLCacheGetDescriptorDataType
*
* Purpose:
*
* Return data type as string constant.
*
*/
LPWSTR xxxSLCacheGetDescriptorDataType(
    _In_ SL_KMEM_CACHE_VALUE_DESCRIPTOR* CacheDescriptor
)
{
    LPWSTR DataType;

    switch (CacheDescriptor->Type) {
    case SL_DATA_SZ:
        DataType = TEXT("SL_DATA_SZ");
        break;
    case SL_DATA_DWORD:
        DataType = TEXT("SL_DATA_DWORD");
        break;
    case SL_DATA_BINARY:
        DataType = TEXT("SL_DATA_BINARY");
        break;
    case SL_DATA_MULTI_SZ:
        DataType = TEXT("SL_DATA_MULTI_SZ");
        break;
    case SL_DATA_SUM:
        DataType = TEXT("SL_DATA_SUM");
        break;

    default:
        DataType = NULL;
        break;
    }
    return DataType;
}

/*
* SLCacheDialogDisplayDescriptorData
*
* Purpose:
*
* Output descriptor data to controls.
*
*/
VOID SLCacheDialogDisplayDescriptorData(
    _In_ HWND hwndDlg,
    _In_ HWND hwndListView,
    _In_ INT iItem
)
{
    SL_KMEM_CACHE_VALUE_DESCRIPTOR* CacheDescriptor;

    LPWSTR lpText, DataType;
    PCHAR DataPtr;
    WCHAR szBuffer[32];

    //
    // Reset output controls.
    //
    SetDlgItemText(hwndDlg, IDC_SLVALUE, TEXT(""));
    SetDlgItemText(hwndDlg, ID_SLDESCRIPTOR_SIZE, TEXT("0"));
    SetDlgItemText(hwndDlg, ID_SLDESCRIPTOR_DATALENGTH, TEXT("0"));
    SetDlgItemText(hwndDlg, ID_SLDESCRIPTOR_ATTRIBUTES, TEXT("0"));
    SetDlgItemText(hwndDlg, ID_SLDESCRIPTOR_TYPE, T_CannotQuery);
    SetDlgItemText(hwndDlg, IDC_SLVALUE_NAME, TEXT(""));
    EnableWindow(GetDlgItem(hwndDlg, IDC_SLVALUE_VIEWWITH), FALSE);

    CacheDescriptor = xxxSLCacheGetSelectedDescriptor(hwndListView, iItem);
    if (CacheDescriptor == NULL)
        return;

    //
    // Attributes.
    //
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    ultostr(CacheDescriptor->Attributes, szBuffer);
    SetDlgItemText(hwndDlg, ID_SLDESCRIPTOR_ATTRIBUTES, szBuffer);

    //
    // Size and DataLength.
    //
    szBuffer[0] = 0;
    ultostr(CacheDescriptor->Size, szBuffer);
    SetDlgItemText(hwndDlg, ID_SLDESCRIPTOR_SIZE, szBuffer);

    szBuffer[0] = 0;
    ultostr(CacheDescriptor->DataLength, szBuffer);
    SetDlgItemText(hwndDlg, ID_SLDESCRIPTOR_DATALENGTH, szBuffer);

    //
    // Data type.
    //
    DataType = xxxSLCacheGetDescriptorDataType(CacheDescriptor);
    if (DataType == NULL) DataType = T_CannotQuery;
    SetDlgItemText(hwndDlg, ID_SLDESCRIPTOR_TYPE, DataType);

    //
    // Name.
    //
    lpText = (LPWSTR)supHeapAlloc(CacheDescriptor->NameLength + sizeof(WCHAR));
    if (lpText) {
        RtlCopyMemory(lpText, CacheDescriptor->Name, CacheDescriptor->NameLength);
        SetDlgItemText(hwndDlg, IDC_SLVALUE_NAME, lpText);
        supHeapFree(lpText);
    }

    //
    // Display Data.
    //
    switch (CacheDescriptor->Type) {

    case SL_DATA_DWORD:

        DataPtr = RtlOffsetToPointer(CacheDescriptor,
            (ULONG_PTR)FIELD_OFFSET(SL_KMEM_CACHE_VALUE_DESCRIPTOR, Name) + CacheDescriptor->NameLength);

        szBuffer[0] = 0;
        ultostr((ULONG)*DataPtr, szBuffer);
        SetDlgItemText(hwndDlg, IDC_SLVALUE, szBuffer);

        break;

    case SL_DATA_SZ:
        lpText = (LPWSTR)supHeapAlloc(CacheDescriptor->DataLength + sizeof(WCHAR));
        if (lpText) {

            DataPtr = RtlOffsetToPointer(CacheDescriptor,
                (ULONG_PTR)FIELD_OFFSET(SL_KMEM_CACHE_VALUE_DESCRIPTOR, Name) + CacheDescriptor->NameLength);

            RtlCopyMemory(lpText, DataPtr, CacheDescriptor->DataLength);

            SetDlgItemText(hwndDlg, IDC_SLVALUE, lpText);

            supHeapFree(lpText);
        }
        break;

    case SL_DATA_BINARY:
        SetDlgItemText(hwndDlg, IDC_SLVALUE, TEXT("Binary data, use \"View\" button to open an external viewer"));
        EnableWindow(GetDlgItem(hwndDlg, IDC_SLVALUE_VIEWWITH), TRUE);
        break;

    default:
        break;
    }

}

/*
* SLCacheDialogViewBinaryData
*
* Purpose:
*
* Save selected binary data to disk and open it with external viewer (or spawn OpenWith dialog).
*
*/
VOID SLCacheDialogViewBinaryData(
    _In_ HWND hwndListView,
    _In_ INT iSelectedItem
)
{
    SL_KMEM_CACHE_VALUE_DESCRIPTOR* CacheDescriptor;
    PCHAR DataPtr;

    WCHAR szFileName[MAX_PATH * 2];

    CacheDescriptor = xxxSLCacheGetSelectedDescriptor(hwndListView, iSelectedItem);
    if (CacheDescriptor == NULL)
        return;

    //
    // Only for SL_DATA_BINARY.
    //
    if (CacheDescriptor->Type != SL_DATA_BINARY)
        return;

    DataPtr = RtlOffsetToPointer(CacheDescriptor,
        (ULONG_PTR)FIELD_OFFSET(SL_KMEM_CACHE_VALUE_DESCRIPTOR, Name) + CacheDescriptor->NameLength);

    _strcpy(szFileName, g_WinObj.szTempDirectory);
    _strcat(szFileName, TEXT("\\SLData"));
    u64tohex((ULONG_PTR)CacheDescriptor, _strend(szFileName));
    _strcat(szFileName, TEXT(".bin"));

    if (CacheDescriptor->DataLength == supWriteBufferToFile(szFileName,
        (PVOID)DataPtr,
        (SIZE_T)CacheDescriptor->DataLength,
        TRUE,
        FALSE))
    {
        supShellExecInExplorerProcess(szFileName);
    }

}

/*
* SLCacheDialogHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for listview.
*
*/
BOOL SLCacheDialogHandleNotify(
    _In_ HWND hwndDlg,
    _In_ LPNMLISTVIEW pListView
)
{
    INT nImageIndex;
    EXTRASCONTEXT* pDlgContext;

    if (pListView == NULL)
        return FALSE;

    if (pListView->hdr.idFrom == ID_SLCACHELIST) {

        switch (pListView->hdr.code) {

        case LVN_COLUMNCLICK:

            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
            if (pDlgContext) {

                pDlgContext->bInverseSort = !pDlgContext->bInverseSort;
                pDlgContext->lvColumnToSort = pListView->iSubItem;
                ListView_SortItemsEx(pDlgContext->ListView, &SLCacheListCompareFunc, pDlgContext);

                nImageIndex = ImageList_GetImageCount(g_ListViewImages);
                if (pDlgContext->bInverseSort)
                    nImageIndex -= 2;
                else
                    nImageIndex -= 1;

                supUpdateLvColumnHeaderImage(
                    pDlgContext->ListView,
                    pDlgContext->lvColumnCount,
                    pDlgContext->lvColumnToSort,
                    nImageIndex);

            }
            break;

        case LVN_ITEMCHANGED:
            if (pListView->uNewState & LVNI_FOCUSED &&
                pListView->uNewState & LVNI_SELECTED)
            {
                SLCacheDialogDisplayDescriptorData(hwndDlg,
                    pListView->hdr.hwndFrom,
                    pListView->iItem);
            }
            break;

        default:
            return FALSE;
        }
    }

    return TRUE;
}

/*
* SLCacheDialogProc
*
* Purpose:
*
* SoftwareLicensingCache Dialog window procedure.
*
*/
INT_PTR CALLBACK SLCacheDialogProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam
)
{
    EXTRASCONTEXT* pDlgContext;
    LPNMLISTVIEW nhdr = (LPNMLISTVIEW)lParam;

    switch (uMsg) {

    case WM_NOTIFY:
        return SLCacheDialogHandleNotify(hwndDlg, nhdr);

    case WM_INITDIALOG:
        SetProp(hwndDlg, T_DLGCONTEXT, (HANDLE)lParam);
        supCenterWindow(hwndDlg);
        break;

    case WM_CLOSE:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            g_WinObj.AuxDialogs[wobjSLCacheDlgId] = NULL;

            //
            // Free SL cache data
            //
            if (pDlgContext->Reserved) {
                supHeapFree((PVOID)pDlgContext->Reserved);
            }

            supHeapFree(pDlgContext);
        }
        RemoveProp(hwndDlg, T_DLGCONTEXT);
        return DestroyWindow(hwndDlg);

    case WM_COMMAND:

        switch (GET_WM_COMMAND_ID(wParam, lParam)) {

        case IDCANCEL:
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            return TRUE;

        case IDC_SLVALUE_VIEWWITH:
            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
            if (pDlgContext) {
                SLCacheDialogViewBinaryData(pDlgContext->ListView,
                    ListView_GetSelectionMark(pDlgContext->ListView));
            }
            return TRUE;
        }
        break;

    default:
        return FALSE;

    }

    return TRUE;
}

/*
* SLCacheEnumerateCallback
*
* Purpose:
*
* Callback used to output cache descriptor.
*
*/
BOOL CALLBACK SLCacheEnumerateCallback(
    _In_ SL_KMEM_CACHE_VALUE_DESCRIPTOR* CacheDescriptor,
    _In_opt_ PVOID Context
)
{
    INT lvItemIndex;
    LPWSTR EntryName, EntryType;
    EXTRASCONTEXT* pDlgContext = (EXTRASCONTEXT*)Context;
    LVITEM lvItem;

    WCHAR szBuffer[100];

    if (pDlgContext == NULL)
        return FALSE;

    EntryName = (LPWSTR)supHeapAlloc(CacheDescriptor->NameLength + sizeof(WCHAR));
    if (EntryName) {

        RtlCopyMemory(EntryName, CacheDescriptor->Name, CacheDescriptor->NameLength);

        //Name
        RtlSecureZeroMemory(&lvItem, sizeof(lvItem));
        lvItem.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
        lvItem.iItem = MAXINT;
        lvItem.iImage = g_SLCacheImageIndex;
        lvItem.pszText = EntryName;
        lvItem.lParam = (LPARAM)CacheDescriptor;
        lvItemIndex = ListView_InsertItem(pDlgContext->ListView, &lvItem);

        EntryType = xxxSLCacheGetDescriptorDataType(CacheDescriptor);
        if (EntryType == NULL) {
            szBuffer[0] = 0;
            ultostr(CacheDescriptor->Type, szBuffer);
            EntryType = (LPWSTR)&szBuffer;
        }

        //Type
        lvItem.mask = LVIF_TEXT;
        lvItem.iSubItem = 1;
        lvItem.pszText = EntryType;
        lvItem.iItem = lvItemIndex;
        ListView_SetItem(pDlgContext->ListView, &lvItem);

        supHeapFree(EntryName);

    }
    return FALSE;
}

/*
* extrasCreateSLCacheDialog
*
* Purpose:
*
* Create and initialize SoftwareLicensingCache Dialog.
*
*/
VOID extrasCreateSLCacheDialog(
    _In_ HWND hwndParent
)
{
    INT             nCount;
    PVOID           SLCacheData;

    HWND            hwndDlg;
    EXTRASCONTEXT* pDlgContext;

    ENUMCHILDWNDDATA ChildWndData;
    WCHAR szBuffer[100];

    //
    // Allow only one dialog, if it already open - activate it.
    //
    ENSURE_DIALOG_UNIQUE_WITH_RESTORE(g_WinObj.AuxDialogs[wobjSLCacheDlgId]);

    pDlgContext = (EXTRASCONTEXT*)supHeapAlloc(sizeof(EXTRASCONTEXT));
    if (pDlgContext == NULL)
        return;

    hwndDlg = CreateDialogParam(
        g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_SLCACHE),
        hwndParent,
        &SLCacheDialogProc,
        (LPARAM)pDlgContext);

    if (hwndDlg == NULL) {
        return;
    }

    pDlgContext->hwndDlg = hwndDlg;
    g_WinObj.AuxDialogs[wobjSLCacheDlgId] = hwndDlg;

    extrasSetDlgIcon(hwndDlg);

    //
    // Read and enumerate cache.
    //
    SLCacheData = supSLCacheRead();
    if (SLCacheData) {

        //
        // Initialize main listview.
        //
        pDlgContext->ListView = GetDlgItem(pDlgContext->hwndDlg, ID_SLCACHELIST);
        if (pDlgContext->ListView) {

            //
            // Set listview imagelist, style flags and theme.
            //
            ListView_SetImageList(pDlgContext->ListView, g_ListViewImages, LVSIL_SMALL);
            ListView_SetExtendedListViewStyle(
                pDlgContext->ListView,
                LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

            SetWindowTheme(pDlgContext->ListView, TEXT("Explorer"), NULL);

            //
            // Create ListView columns.
            //

            supAddListViewColumn(pDlgContext->ListView, 0, 0, 0,
                ImageList_GetImageCount(g_ListViewImages) - 1,
                LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
                TEXT("Name"), 450);

            supAddListViewColumn(pDlgContext->ListView, 1, 1, 1,
                I_IMAGENONE,
                LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
                TEXT("Type"), 120);

            //
            // Remember columns count.
            //
            pDlgContext->lvColumnCount = SLLIST_COLUMN_COUNT;

            //
            // Remember image index.
            //
            g_SLCacheImageIndex = ObManagerGetImageIndexByTypeIndex(ObjectTypeToken);

            pDlgContext->Reserved = (ULONG_PTR)SLCacheData;
            supSLCacheEnumerate(SLCacheData, SLCacheEnumerateCallback, pDlgContext);

            nCount = ListView_GetItemCount(pDlgContext->ListView);
            _strcpy(szBuffer, TEXT("SLCache, number of descriptors = "));
            itostr(nCount, _strend(szBuffer));
            SetWindowText(pDlgContext->hwndDlg, szBuffer);
        }
    }
    else {

        //
        // Hide all controls in case of error and display warning.
        //
        if (GetWindowRect(pDlgContext->hwndDlg, &ChildWndData.Rect)) {
            ChildWndData.nCmdShow = SW_HIDE;
            EnumChildWindows(pDlgContext->hwndDlg, supCallbackShowChildWindow, (LPARAM)&ChildWndData);
        }
        ShowWindow(GetDlgItem(pDlgContext->hwndDlg, ID_SLCACHEINFO), SW_SHOW);
        SetDlgItemText(pDlgContext->hwndDlg, ID_SLCACHEINFO, TEXT("Unable to read SL cache!"));
    }
}
