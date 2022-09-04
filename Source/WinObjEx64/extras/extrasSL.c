/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2022
*
*  TITLE:       EXTRASSL.C
*
*  VERSION:     2.00
*
*  DATE:        19 Jun 2022
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "extras.h"

typedef struct _SL_ENUM_CONTEXT {
    EXTRASCONTEXT* DialogContext;
    LPCWSTR lpFilterByName;
} SL_ENUM_CONTEXT, * PSL_ENUM_CONTEXT;

#define T_SLCACHE_READ_FAIL TEXT("Unable to read SL cache!")

static HANDLE SLCacheDlgThreadHandle = NULL;
static FAST_EVENT SLCacheDlgInitializedEvent = FAST_EVENT_INIT;

UINT g_SLCacheImageIndex;

/*
* SLCacheOnReadFailed
*
* Purpose:
*
* Hide controls in case of cache read general error.
*
*/
VOID SLCacheOnReadFailed(
    _In_ EXTRASCONTEXT* Context
)
{
    ENUMCHILDWNDDATA ChildWndData;

    //
    // Hide all controls in case of error and display warning.
    //
    if (GetWindowRect(Context->hwndDlg, &ChildWndData.Rect)) {
        ChildWndData.nCmdShow = SW_HIDE;
        EnumChildWindows(Context->hwndDlg, supCallbackShowChildWindow, (LPARAM)&ChildWndData);
    }
    ShowWindow(GetDlgItem(Context->hwndDlg, ID_SLCACHEINFO), SW_SHOW);
    SetDlgItemText(Context->hwndDlg, ID_SLCACHEINFO, T_SLCACHE_READ_FAIL);

}

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
    LPWSTR DataType = NULL;

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
        FALSE,
        NULL))
    {
        supShellExecInExplorerProcess(szFileName, NULL);
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

                pDlgContext->bInverseSort = (~pDlgContext->bInverseSort) & 1;
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

            if ((pListView->uNewState & LVIS_SELECTED) &&
                !(pListView->uOldState & LVIS_SELECTED))
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
* SLCacheDialogHandlePopup
*
* Purpose:
*
* List popup construction.
*
*/
VOID SLCacheDialogHandlePopup(
    _In_ HWND hwndDlg,
    _In_ LPPOINT lpPoint,
    _In_ PVOID lpUserParam
)
{
    HMENU hMenu;
    EXTRASCONTEXT* Context = (EXTRASCONTEXT*)lpUserParam;

    hMenu = CreatePopupMenu();
    if (hMenu) {

        if (supListViewAddCopyValueItem(hMenu,
            Context->ListView,
            ID_OBJECT_COPY,
            0,
            lpPoint,
            &Context->lvItemHit,
            &Context->lvColumnHit))
        {
            TrackPopupMenu(hMenu,
                TPM_RIGHTBUTTON | TPM_LEFTALIGN,
                lpPoint->x,
                lpPoint->y,
                0,
                hwndDlg,
                NULL);
        }
        DestroyMenu(hMenu);
    }
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
    _In_ SL_ENUM_CONTEXT* Context
)
{
    INT lvItemIndex;
    LPWSTR EntryName, EntryType;
    LVITEM lvItem;

    WCHAR szBuffer[100];

    EntryName = (LPWSTR)supHeapAlloc(CacheDescriptor->NameLength + sizeof(WCHAR));
    if (EntryName) {

        RtlCopyMemory(EntryName, CacheDescriptor->Name, CacheDescriptor->NameLength);

        if (Context->lpFilterByName) {

            if (_strstri(EntryName, Context->lpFilterByName) == NULL) {
                supHeapFree(EntryName);
                return FALSE;
            }
        }

        //Name
        RtlSecureZeroMemory(&lvItem, sizeof(lvItem));
        lvItem.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
        lvItem.iItem = MAXINT;
        lvItem.iImage = g_SLCacheImageIndex;
        lvItem.pszText = EntryName;
        lvItem.lParam = (LPARAM)CacheDescriptor;
        lvItemIndex = ListView_InsertItem(Context->DialogContext->ListView, &lvItem);

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
        ListView_SetItem(Context->DialogContext->ListView, &lvItem);

        supHeapFree(EntryName);

    }
    return FALSE;
}

PVOID xxxSLCacheUpdateData(
    _In_ EXTRASCONTEXT* Context
)
{
    PVOID SLCacheData = (PVOID)Context->Reserved;
    if (SLCacheData) {
        supHeapFree(SLCacheData);
        Context->Reserved = 0;
    }
    SLCacheData = (PVOID)supSLCacheRead();
    if (SLCacheData)
        Context->Reserved = (ULONG_PTR)SLCacheData;

    return SLCacheData;
}

/*
* SLCacheListItems
*
* Purpose:
*
* Read and output SL cache items.
*
*/
VOID SLCacheListItems(
    _In_ EXTRASCONTEXT* Context,
    _In_opt_ LPCWSTR FilterByName,
    _In_ BOOL RefreshList
)
{
    PVOID SLCacheData = (PVOID)Context->Reserved;
    WCHAR szBuffer[100];

    SL_ENUM_CONTEXT enumContext;

    if (RefreshList) {
        ListView_DeleteAllItems(Context->ListView);
        SLCacheData = xxxSLCacheUpdateData(Context);
    }

    if (SLCacheData == NULL) {
        MessageBox(Context->hwndDlg, T_SLCACHE_READ_FAIL, NULL, MB_ICONERROR);
        return;
    }

    supListViewEnableRedraw(Context->ListView, FALSE);

    enumContext.lpFilterByName = FilterByName;
    enumContext.DialogContext = Context;

    supSLCacheEnumerate(SLCacheData,
        (PENUMERATE_SL_CACHE_VALUE_DESCRIPTORS_CALLBACK)SLCacheEnumerateCallback,
        &enumContext);

    RtlStringCchPrintfSecure(szBuffer, ARRAYSIZE(szBuffer),
        TEXT("Software Licensing Cache, descriptors: %i"),
        ListView_GetItemCount(Context->ListView));

    SetWindowText(Context->hwndDlg, szBuffer);

    supListViewEnableRedraw(Context->ListView, TRUE);
}

/*
* SLCacheDialogOnInit
*
* Purpose:
*
* SoftwareLicensingCache Dialog WM_INITDIALOG handler.
*
*/
VOID SLCacheDialogOnInit(
    _In_  HWND hwndDlg,
    _In_  LPARAM lParam
)
{
    INT iImage = ImageList_GetImageCount(g_ListViewImages) - 1;
    PVOID SLCacheData;
    EXTRASCONTEXT* pDlgContext = (EXTRASCONTEXT*)lParam;
    LVCOLUMNS_DATA columnData[] =
    {
        { L"Name", 450, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  iImage },
        { L"Type", 120, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  I_IMAGENONE }
    };

    SetProp(hwndDlg, T_DLGCONTEXT, (HANDLE)lParam);
    supCenterWindowSpecifyParent(hwndDlg, g_hwndMain);

    pDlgContext->hwndDlg = hwndDlg;
    pDlgContext->lvItemHit = -1;
    pDlgContext->lvColumnHit = -1;

    extrasSetDlgIcon(pDlgContext);

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

            SendDlgItemMessage(pDlgContext->hwndDlg, IDC_SLSEARCH,
                EM_SETLIMITTEXT, (WPARAM)MAX_PATH, (LPARAM)0);

            //
            // Remember image index.
            //
            g_SLCacheImageIndex = ObManagerGetImageIndexByTypeIndex(ObjectTypeToken);
            pDlgContext->Reserved = (ULONG_PTR)SLCacheData;
            SLCacheListItems(pDlgContext, NULL, FALSE);

        }
    }
    else {
        SLCacheOnReadFailed(pDlgContext);
    }
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
    LPCWSTR lpFilter = NULL;
    WCHAR szFilterOption[MAX_PATH + 1];

    if (uMsg == g_WinObj.SettingsChangeMessage) {
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            extrasHandleSettingsChange(pDlgContext);
        }
        return TRUE;
    }

    switch (uMsg) {

    case WM_NOTIFY:
        return SLCacheDialogHandleNotify(hwndDlg, nhdr);

    case WM_INITDIALOG:
        SLCacheDialogOnInit(hwndDlg, lParam);
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    case WM_CLOSE:
        pDlgContext = (EXTRASCONTEXT*)RemoveProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {

            extrasRemoveDlgIcon(pDlgContext);

            //
            // Free SL cache data
            //
            if (pDlgContext->Reserved) {
                supHeapFree((PVOID)pDlgContext->Reserved);
            }

            supHeapFree(pDlgContext);
        }
        return DestroyWindow(hwndDlg);

    case WM_CONTEXTMENU:

        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            supHandleContextMenuMsgForListView(hwndDlg,
                wParam,
                lParam,
                pDlgContext->ListView,
                (pfnPopupMenuHandler)SLCacheDialogHandlePopup,
                (PVOID)pDlgContext);
        }
        break;

    case WM_COMMAND:

        switch (GET_WM_COMMAND_ID(wParam, lParam)) {

        case IDCANCEL:
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            break;

        case IDC_SLVALUE_VIEWWITH:
            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
            if (pDlgContext) {
                SLCacheDialogViewBinaryData(pDlgContext->ListView,
                    ListView_GetSelectionMark(pDlgContext->ListView));
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

        case IDC_SLSEARCH:

            if (GET_WM_COMMAND_CMD(wParam, lParam) == EN_CHANGE) {

                pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
                if (pDlgContext) {

                    RtlSecureZeroMemory(szFilterOption, sizeof(szFilterOption));
                    if (GetDlgItemText(hwndDlg,
                        IDC_SLSEARCH,
                        szFilterOption,
                        MAX_PATH))
                    {
                        if (szFilterOption[0] != 0) {
                            lpFilter = szFilterOption;
                        }
                    }

                    SLCacheListItems(pDlgContext, lpFilter, TRUE);
                }
            }
            break;

        }
    }

    return FALSE;
}

/*
* extrasSLCacheDialogWorkerThread
*
* Purpose:
*
* SoftwareLicensingCache Dialog worker thread.
*
*/
DWORD extrasSLCacheDialogWorkerThread(
    _In_ PVOID Parameter
)
{
    BOOL bResult;
    MSG message;
    HWND hwndDlg;
    EXTRASCONTEXT* pDlgContext = (EXTRASCONTEXT*)Parameter;

    hwndDlg = CreateDialogParam(
        g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_SLCACHE),
        0,
        &SLCacheDialogProc,
        (LPARAM)pDlgContext);

    supSetFastEvent(&SLCacheDlgInitializedEvent);

    do {

        bResult = GetMessage(&message, NULL, 0, 0);
        if (bResult == -1)
            break;

        if (!IsDialogMessage(hwndDlg, &message)) {
            TranslateMessage(&message);
            DispatchMessage(&message);
        }

    } while (bResult != 0);

    supResetFastEvent(&SLCacheDlgInitializedEvent);

    if (SLCacheDlgThreadHandle) {
        NtClose(SLCacheDlgThreadHandle);
        SLCacheDlgThreadHandle = NULL;
    }

    return 0;
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
    VOID
)
{
    EXTRASCONTEXT* pDlgContext;

    if (!SLCacheDlgThreadHandle) {

        pDlgContext = (EXTRASCONTEXT*)supHeapAlloc(sizeof(EXTRASCONTEXT));
        if (pDlgContext) {

            SLCacheDlgThreadHandle = supCreateDialogWorkerThread(extrasSLCacheDialogWorkerThread, pDlgContext, 0);
            supWaitForFastEvent(&SLCacheDlgInitializedEvent, NULL);

        }

    }
}
