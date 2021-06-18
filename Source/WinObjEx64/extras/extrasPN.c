/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2021
*
*  TITLE:       EXTRASPN.C
*
*  VERSION:     1.90
*
*  DATE:        28 May 2021
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "extras.h"
#include "extrasPN.h"
#include "propDlg.h"

EXTRASCONTEXT PnDlgContext;
OBJECT_COLLECTION PNSCollection;
ULONG PNSNumberOfObjects = 0;

#ifdef _USE_OWN_DRIVER
#define T_NAMESPACE_QUERY_FAILED TEXT("Unable to list namespaces! Make sure you run this program as Admin.")
#else
#define T_NAMESPACE_QUERY_FAILED TEXT("Unable to list namespaces! Make sure you run this program as Admin and Windows is in a DEBUG mode.")
#endif

#define T_NAMESPACE_NOTHING TEXT("No private namespaces found.")

#define COLUMN_PNLIST_ROOTDIRADDRESS 2

/*
* PNDlgResetOutput
*
* Purpose:
*
* Resets controls output.
*
*/
VOID PNDlgResetOutput()
{
    SetDlgItemText(PnDlgContext.hwndDlg, ID_NAMESPACE_ROOT, T_EmptyString);
    SetDlgItemText(PnDlgContext.hwndDlg, ID_OBJECT_ADDR, T_EmptyString);
    SetDlgItemText(PnDlgContext.hwndDlg, ID_SIZEOFBOUNDARYINFO, T_EmptyString);
    SetDlgItemText(PnDlgContext.hwndDlg, ID_BDESCRIPTOR_ADDRESS, T_EmptyString);
    SetDlgItemText(PnDlgContext.hwndDlg, ID_BDESCRIPTOR_NAME, T_EmptyString);
    SetDlgItemText(PnDlgContext.hwndDlg, ID_BDESCRIPTOR_SID_ACCOUNT, T_CannotQuery);
    SetDlgItemText(PnDlgContext.hwndDlg, ID_INTEGRITYLABEL, T_CannotQuery);
    SetDlgItemText(PnDlgContext.hwndDlg, ID_BDESCRIPTOR_ENTRIES, TEXT("0"));
    SendDlgItemMessage(PnDlgContext.hwndDlg, ID_BDESCRIPTOR_SID, CB_RESETCONTENT, (WPARAM)0, (LPARAM)0);
    EnableWindow(GetDlgItem(PnDlgContext.hwndDlg, ID_BDESCRIPTOR_SID_COPY), FALSE);
}

/*
* PNDlgShowObjectProperties
*
* Purpose:
*
* Show selected object properties.
*
*/
VOID PNDlgShowObjectProperties(
    _In_ INT iItem
)
{
    LPWSTR              lpType, lpName;
    POBJREF             objRef = NULL;

    OBJREFPNS           pnsInfo;
    PROP_NAMESPACE_INFO propNamespace;
    PROP_DIALOG_CREATE_SETTINGS propSettings;

    //
    // Only one namespace object properties dialog at the same time allowed.
    //
    ENSURE_DIALOG_UNIQUE(g_NamespacePropWindow);

    __try {

        //
        //  Get ref to object, failure here is critical.
        //
        if (!supGetListViewItemParam(PnDlgContext.ListView, iItem, (PVOID*)&objRef))
            return;

        RtlCopyMemory(&pnsInfo, &objRef->PrivateNamespace, sizeof(OBJREFPNS));
        RtlSecureZeroMemory(&propNamespace, sizeof(propNamespace));

        propNamespace.ObjectAddress = objRef->ObjectAddress;

        //
        // Dump boundary descriptor, failure here is critical.
        //
        if (!NT_SUCCESS(ObCopyBoundaryDescriptor((OBJECT_NAMESPACE_ENTRY*)pnsInfo.NamespaceLookupEntry,
            &propNamespace.BoundaryDescriptor,
            &propNamespace.SizeOfBoundaryDescriptor)))
        {
            return;
        }

        lpName = supGetItemText(PnDlgContext.ListView, iItem, 0, NULL);
        if (lpName) {
            lpType = supGetItemText(PnDlgContext.ListView, iItem, 1, NULL);
            if (lpType) {

                RtlSecureZeroMemory(&propSettings, sizeof(propSettings));

                propSettings.lpObjectName = lpName;
                propSettings.lpObjectType = lpType;
                propSettings.NamespaceObject = &propNamespace;

                propCreateDialog(&propSettings);

                supHeapFree(lpType);
            }
            supHeapFree(lpName);
        }

    }
    __except (WOBJ_EXCEPTION_FILTER_LOG)
    {
        return;
    }
    //
    // propNamespace.BoundaryDescriptor will be freed by propDestroyContext.
    // 
}

/*
* PNListCompareFunc
*
* Purpose:
*
* Main window listview comparer function.
*
*/
INT CALLBACK PNListCompareFunc(
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort
)
{
    //
    // Sort addresses.
    //
    if (lParamSort == COLUMN_PNLIST_ROOTDIRADDRESS) {
        return supGetMaxOfTwoU64FromHex(PnDlgContext.ListView,
            lParam1,
            lParam2,
            lParamSort,
            PnDlgContext.bInverseSort);
    }

    return supListViewBaseComparer(PnDlgContext.ListView,
        PnDlgContext.bInverseSort,
        lParam1,
        lParam2,
        lParamSort);
}

/*
* PNDlgEnumerateCallback
*
* Purpose:
*
* Callback for private namespaces output.
*
*/
BOOL CALLBACK PNDlgEnumerateCallback(
    _In_ POBJREF Entry,
    _In_opt_ PVOID Context
)
{
    INT     lvItemIndex;
    UINT    ConvertedTypeIndex;
    LPCWSTR TypeName;

    LVITEM  lvItem;
    WCHAR   szBuffer[MAX_PATH + 1];

    UNREFERENCED_PARAMETER(Context);

    ConvertedTypeIndex = supGetObjectNameIndexByTypeIndex((PVOID)Entry->ObjectAddress, Entry->TypeIndex);
    TypeName = ObManagerGetNameByIndex(ConvertedTypeIndex);

    //Name
    RtlSecureZeroMemory(&lvItem, sizeof(lvItem));
    lvItem.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
    lvItem.iItem = MAXINT;
    lvItem.iImage = ObManagerGetImageIndexByTypeIndex(ConvertedTypeIndex);
    lvItem.pszText = Entry->ObjectName;
    lvItem.lParam = (LPARAM)Entry;
    lvItemIndex = ListView_InsertItem(PnDlgContext.ListView, &lvItem);

    //Type
    lvItem.mask = LVIF_TEXT;
    lvItem.iSubItem = 1;
    lvItem.pszText = (LPWSTR)TypeName;
    lvItem.iItem = lvItemIndex;
    ListView_SetItem(PnDlgContext.ListView, &lvItem);

    //RootDirectory address
    szBuffer[0] = L'0';
    szBuffer[1] = L'x';
    szBuffer[2] = 0;
    u64tohex(Entry->PrivateNamespace.NamespaceDirectoryAddress, &szBuffer[2]);

    lvItem.iSubItem = 2;
    lvItem.pszText = szBuffer;
    ListView_SetItem(PnDlgContext.ListView, &lvItem);

    PNSNumberOfObjects++;

    return FALSE;
}

/*
* PNDlgQueryInfo
*
* Purpose:
*
* Query and ouput private namespaces info.
*
*/
BOOL PNDlgQueryInfo(
    _In_ HWND hwndDlg
)
{
#ifndef _DEBUG
    HWND hwndBanner;
#endif
    BOOL bResult = FALSE;

    PNSNumberOfObjects = 0;

#ifndef _DEBUG
    hwndBanner = supDisplayLoadBanner(
        hwndDlg,
        TEXT("Loading private namespaces information, please wait"),
        NULL,
        FALSE);
#else
    UNREFERENCED_PARAMETER(hwndDlg);
#endif

    __try {

        bResult = ObCollectionCreate(&PNSCollection, TRUE, FALSE);
        if (bResult) {

            bResult = ObCollectionEnumerate(
                &PNSCollection,
                PNDlgEnumerateCallback,
                NULL);

        }
    }
    __finally {
#ifndef _DEBUG
        SendMessage(hwndBanner, WM_CLOSE, 0, 0);
#endif
    }

    return bResult;
}

#define MAX_LOOKUP_NAME 256

/*
* PNDlgOutputSelectedSidInformation
*
* Purpose:
*
* Output selected Sid information.
*
*/
VOID PNDlgOutputSelectedSidInformation(
    _In_ HWND hwndDlg,
    _In_opt_ PSID Sid
)
{
    BOOL bNeedFree = FALSE;
    HWND hComboBox;
    LRESULT nSelected;
    PSID pSid = NULL;
    LPWSTR lpSidType, lpEnd, lpSidValue;
    SIZE_T sidLength;

    DWORD cAccountName = 0, cReferencedDomainName = 0;

    WCHAR szName[MAX_LOOKUP_NAME];
    WCHAR szDomain[MAX_LOOKUP_NAME];
    WCHAR szAccountInfo[MAX_LOOKUP_NAME * 3];

    ULONG peUse;


    //
    // No SID specified, get current selection in combobox and use it as SID.
    //
    if (Sid == NULL) {
        hComboBox = GetDlgItem(hwndDlg, ID_BDESCRIPTOR_SID);

        nSelected = SendMessage(hComboBox, 
            CB_GETCURSEL, 
            (WPARAM)0, 
            (LPARAM)0);
        
        if (nSelected != CB_ERR) {

            sidLength = SendMessage(hComboBox,
                CB_GETLBTEXTLEN, 
                (WPARAM)nSelected, 
                0);
            
            if (sidLength) {

                lpSidValue = (LPWSTR)supHeapAlloc((1 + sidLength) * sizeof(WCHAR));
                if (lpSidValue) {

                    if (CB_ERR != SendMessage(hComboBox, 
                        CB_GETLBTEXT, 
                        nSelected, 
                        (LPARAM)lpSidValue)) 
                    {
                        bNeedFree = ConvertStringSidToSid(lpSidValue, &pSid);
                    }

                    supHeapFree(lpSidValue);
                }
            }
        }
    }
    else {
        pSid = Sid;
    }

    //
    // Convertion failure.
    //
    if (pSid == NULL)
        return;

    //
    // SID account domain\name (type).
    //
    RtlSecureZeroMemory(szName, sizeof(szName));
    RtlSecureZeroMemory(szDomain, sizeof(szDomain));
    cAccountName = MAX_LOOKUP_NAME;
    cReferencedDomainName = MAX_LOOKUP_NAME;
    RtlSecureZeroMemory(szAccountInfo, sizeof(szAccountInfo));

    if (LookupAccountSid(NULL,
        pSid,
        szName,
        &cAccountName,
        szDomain,
        &cReferencedDomainName,
        (SID_NAME_USE*)&peUse))
    {
        _strcpy(szAccountInfo, szDomain);
        if (cAccountName && cReferencedDomainName) {
            _strcat(szAccountInfo, TEXT("\\"));
        }
        lpEnd = _strcat(szAccountInfo, szName);

        //
        // Type of the account.
        //
        lpSidType = supGetSidNameUse((SID_NAME_USE)peUse);

        RtlStringCchPrintfSecure(lpEnd, 
            MAX_PATH, 
            TEXT(" (%ws)"),
            lpSidType);

    }
    else {
        _strcpy(szAccountInfo, T_CannotQuery);
    }

    SetDlgItemText(hwndDlg, ID_BDESCRIPTOR_SID_ACCOUNT, szAccountInfo);

    if (bNeedFree)
        LocalFree(pSid);
}

/*
* PNDlgBoundaryDescriptorCallback
*
* Purpose:
*
* Boundary descriptor enumerator callback.
*
*/
BOOL CALLBACK PNDlgBoundaryDescriptorCallback(
    _In_ OBJECT_BOUNDARY_ENTRY* Entry,
    _In_ PVOID Context
)
{
    PWSTR pString, lpName;
    PSID Sid;
    HWND hwndDlg = (HWND)Context;
    DWORD dwIL;

    WCHAR szBuffer[MAX_PATH];

    switch (Entry->EntryType) {

    case OBNS_Name:

        if (Entry->EntrySize <= sizeof(OBJECT_BOUNDARY_ENTRY))
            break;

        pString = (PWSTR)RtlOffsetToPointer(Entry, sizeof(OBJECT_BOUNDARY_ENTRY));
        lpName = (PWSTR)supHeapAlloc(Entry->EntrySize);
        if (lpName) {
            RtlCopyMemory(lpName, pString, Entry->EntrySize - sizeof(OBJECT_BOUNDARY_ENTRY));
            SetDlgItemText(hwndDlg, ID_BDESCRIPTOR_NAME, lpName);
            supHeapFree(lpName);
        }
        break;

    case OBNS_SID:

        Sid = (PSID)RtlOffsetToPointer(Entry, sizeof(OBJECT_BOUNDARY_ENTRY));
        if (ConvertSidToStringSid(Sid, &pString)) {

            SendDlgItemMessage(hwndDlg, ID_BDESCRIPTOR_SID,
                CB_ADDSTRING, (WPARAM)0, (LPARAM)pString);

            LocalFree(pString);
        }

        PNDlgOutputSelectedSidInformation(hwndDlg, Sid);
        break;

    case OBNS_IntegrityLabel:

        Sid = (PSID)RtlOffsetToPointer(Entry, sizeof(OBJECT_BOUNDARY_ENTRY));

        dwIL = *RtlSubAuthoritySid(Sid,
            (DWORD)(UCHAR)(*RtlSubAuthorityCountSid(Sid) - 1));

        pString = supIntegrityToString(dwIL);

        RtlStringCchPrintfSecure(szBuffer, MAX_PATH,
            TEXT("%ws (0x%lX)"),
            pString,
            dwIL);

        SetDlgItemText(hwndDlg, ID_INTEGRITYLABEL, szBuffer);
        break;

    default:
        break;
    }
    return FALSE;
}

/*
* PNDlgShowNamespaceInfo
*
* Purpose:
*
* Display selected private namespace info.
*
*/
VOID PNDlgShowNamespaceInfo(
    _In_ HWND hwndDlg,
    _In_ INT iItem
)
{
    NTSTATUS    ntStatus;
    LPARAM      nSid;
    ULONG_PTR   BoundaryDescriptorAddress = 0;
    POBJREF     objRef = NULL;
    OBJREFPNS   pnsInfo;

    POBJECT_BOUNDARY_DESCRIPTOR BoundaryDescriptor = NULL;

    WCHAR szBuffer[200];

    PNDlgResetOutput();

    if (iItem == -1)
        return;

    __try {

        if (!supGetListViewItemParam(PnDlgContext.ListView, iItem, (PVOID*)&objRef))
            return;

        RtlCopyMemory(&pnsInfo, &objRef->PrivateNamespace, sizeof(OBJREFPNS));

        //
        // Boundary Descriptor Entries.
        //
        ntStatus = ObCopyBoundaryDescriptor(
            (OBJECT_NAMESPACE_ENTRY*)pnsInfo.NamespaceLookupEntry,
            &BoundaryDescriptor,
            NULL);

        if (NT_SUCCESS(ntStatus)) {

            //
            // Namespace root directory.
            //
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            szBuffer[0] = L'0';
            szBuffer[1] = L'x';
            u64tohex(pnsInfo.NamespaceDirectoryAddress, &szBuffer[2]);
            SetDlgItemText(hwndDlg, ID_NAMESPACE_ROOT, szBuffer);

            //
            // Namespace Lookup table entry.
            //
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            szBuffer[0] = L'0';
            szBuffer[1] = L'x';
            u64tohex(pnsInfo.NamespaceLookupEntry, &szBuffer[2]);
            SetDlgItemText(hwndDlg, ID_OBJECT_ADDR, szBuffer);

            //
            // SizeOfBoundaryInformation.
            //
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            szBuffer[0] = L'0';
            szBuffer[1] = L'x';
            ultohex(pnsInfo.SizeOfBoundaryInformation, &szBuffer[2]);
            SetDlgItemText(hwndDlg, ID_SIZEOFBOUNDARYINFO, szBuffer);

            //
            // Boundary Descriptor Address.
            //
            BoundaryDescriptorAddress = (ULONG_PTR)RtlOffsetToPointer(
                pnsInfo.NamespaceLookupEntry,
                sizeof(OBJECT_NAMESPACE_ENTRY));

            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            szBuffer[0] = L'0';
            szBuffer[1] = L'x';
            u64tohex(BoundaryDescriptorAddress, &szBuffer[2]);
            SetDlgItemText(hwndDlg, ID_BDESCRIPTOR_ADDRESS, szBuffer);

            //
            // Number of entries.
            //
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            ultostr(BoundaryDescriptor->Items, &szBuffer[0]);
            SetDlgItemText(hwndDlg, ID_BDESCRIPTOR_ENTRIES, szBuffer);

            ObEnumerateBoundaryDescriptorEntries(BoundaryDescriptor,
                PNDlgBoundaryDescriptorCallback,
                (PVOID)hwndDlg);

            //
            // Select first SID if present.
            //
            nSid = SendDlgItemMessage(hwndDlg, ID_BDESCRIPTOR_SID, CB_GETCOUNT, 0, 0);
            
            EnableWindow(GetDlgItem(hwndDlg, ID_BDESCRIPTOR_SID), (nSid > 0) ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, ID_BDESCRIPTOR_SID_COPY), (nSid > 0) ? TRUE : FALSE);

            SendDlgItemMessage(hwndDlg, ID_BDESCRIPTOR_SID, CB_SETCURSEL, (WPARAM)0, (LPARAM)0);

            supHeapFree(BoundaryDescriptor);
        }
        else {

            RtlStringCchPrintfSecure(szBuffer, 100,
                TEXT("%ws, error query PN for %p (NTSTATUS 0x%lX)"),
                __FUNCTIONW__,
                (PVOID)pnsInfo.NamespaceLookupEntry,
                ntStatus);

            logAdd(WOBJ_LOG_ENTRY_ERROR, szBuffer);
        }

    }
    __except (WOBJ_EXCEPTION_FILTER_LOG)
    {
        return;
    }
}

/*
* PNDlgHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for PNDialog listview.
*
*/
VOID PNDlgHandleNotify(
    _In_ HWND hwndDlg,
    _In_ LPARAM lParam
)
{
    INT nImageIndex;
    NM_LISTVIEW* pListView = (NM_LISTVIEW*)lParam;

    if (pListView == NULL)
        return;

    if (pListView->hdr.idFrom == ID_NAMESPACELIST) {

        switch (pListView->hdr.code) {

        case LVN_COLUMNCLICK:

            PnDlgContext.bInverseSort = !PnDlgContext.bInverseSort;
            PnDlgContext.lvColumnToSort = pListView->iSubItem;
            ListView_SortItemsEx(PnDlgContext.ListView, &PNListCompareFunc, PnDlgContext.lvColumnToSort);

            nImageIndex = ImageList_GetImageCount(g_ListViewImages);
            if (PnDlgContext.bInverseSort)
                nImageIndex -= 2;
            else
                nImageIndex -= 1;

            supUpdateLvColumnHeaderImage(PnDlgContext.ListView,
                PnDlgContext.lvColumnCount,
                PnDlgContext.lvColumnToSort,
                nImageIndex);

            break;

        case LVN_ITEMCHANGED:

            if ((pListView->uNewState & LVIS_SELECTED) &&
                !(pListView->uOldState & LVIS_SELECTED))
            {
                PNDlgShowNamespaceInfo(hwndDlg, pListView->iItem);
            }
            break;

        case NM_DBLCLK:
            PNDlgShowObjectProperties(pListView->iItem);
            break;

        default:
            break;
        }
    }

}

/*
* PNDlgCopySelectedSid
*
* Purpose:
*
* Take selected sid entry and copy it as text to clipboard.
*
*/
VOID PNDlgCopySelectedSid(
    _In_ HWND hwndDlg
)
{
    HWND hComboBox = GetDlgItem(hwndDlg, ID_BDESCRIPTOR_SID);
    LPARAM nSelected = SendMessage(hComboBox, CB_GETCURSEL, 0, 0);
    LPARAM TextLength;
    PWCHAR lpStringSid;

    if (nSelected >= 0) {
        TextLength = SendMessage(hComboBox, CB_GETLBTEXTLEN, (WPARAM)nSelected, 0);
        if (TextLength) {
            lpStringSid = (PWCHAR)supHeapAlloc((1 + TextLength) * sizeof(WCHAR));
            if (lpStringSid) {
                SendMessage(hComboBox, CB_GETLBTEXT, nSelected, (LPARAM)lpStringSid);

                supClipboardCopy(lpStringSid, (TextLength * sizeof(WCHAR)));

                supHeapFree(lpStringSid);
            }
        }
    }
}

/*
* PNDialogShowInfo
*
* Purpose:
*
* Display information about private namespaces or message if there is none or error.
*
*/
VOID PNDialogShowInfo(
    _In_ BOOLEAN bRefresh)
{
    ENUMCHILDWNDDATA ChildWndData;

    if (bRefresh) {
        ListView_DeleteAllItems(PnDlgContext.ListView);
        ObCollectionDestroy(&PNSCollection);
        PNDlgResetOutput();
    }

    if (PNDlgQueryInfo(PnDlgContext.hwndDlg)) {
        ListView_SortItemsEx(PnDlgContext.ListView, &PNListCompareFunc, 0);
    }
    else {
        if (GetWindowRect(PnDlgContext.hwndDlg, &ChildWndData.Rect)) {
            ChildWndData.nCmdShow = SW_HIDE;
            EnumChildWindows(PnDlgContext.hwndDlg, supCallbackShowChildWindow, (LPARAM)&ChildWndData);
        }
        ShowWindow(GetDlgItem(PnDlgContext.hwndDlg, ID_PNAMESPACESINFO), SW_SHOW);

        if (PNSNumberOfObjects == 0) {
            SetDlgItemText(PnDlgContext.hwndDlg, ID_PNAMESPACESINFO, T_NAMESPACE_NOTHING);
        }
        else {
            SetDlgItemText(PnDlgContext.hwndDlg, ID_PNAMESPACESINFO, T_NAMESPACE_QUERY_FAILED);
        }
    }
}

/*
* PNDialogHandlePopup
*
* Purpose:
*
* List popup construction.
*
*/
VOID PNDialogHandlePopup(
    _In_ HWND hwndDlg,
    _In_ LPPOINT lpPoint,
    _In_ PVOID lpUserParam
)
{
    HMENU hMenu;
    UINT uPos = 0;
    EXTRASCONTEXT* Context = (EXTRASCONTEXT*)lpUserParam;

    hMenu = CreatePopupMenu();
    if (hMenu) {

        if (supListViewAddCopyValueItem(hMenu,
            Context->ListView,
            ID_OBJECT_COPY,
            uPos,
            lpPoint,
            &Context->lvItemHit,
            &Context->lvColumnHit))
        {
            InsertMenu(hMenu, ++uPos, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
            InsertMenu(hMenu, uPos++, MF_BYCOMMAND, ID_VIEW_REFRESH, T_VIEW_REFRESH);

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
* PNDialogProc
*
* Purpose:
*
* Private Namespace Dialog window procedure.
*
*/
INT_PTR CALLBACK PNDialogProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam
)
{
    if (uMsg == g_WinObj.SettingsChangeMessage) {
        extrasHandleSettingsChange(&PnDlgContext);
        return TRUE;
    }

    switch (uMsg) {
    case WM_NOTIFY:
        PNDlgHandleNotify(hwndDlg, lParam);
        break;

    case WM_INITDIALOG:
        supCenterWindow(hwndDlg);
        break;

    case WM_CONTEXTMENU:

        supHandleContextMenuMsgForListView(hwndDlg,
            wParam,
            lParam,
            PnDlgContext.ListView,
            (pfnPopupMenuHandler)PNDialogHandlePopup,
            (PVOID)&PnDlgContext);

        break;

    case WM_CLOSE:
        DestroyWindow(hwndDlg);
        ObCollectionDestroy(&PNSCollection);
        g_WinObj.AuxDialogs[wobjPNSDlgId] = NULL;
        break;

    case WM_COMMAND:

        switch (GET_WM_COMMAND_ID(wParam, lParam)) {

        case IDCANCEL:
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            break;

        case ID_VIEW_REFRESH:
            PNDialogShowInfo(TRUE);
            break;

        case ID_BDESCRIPTOR_SID:
            if (HIWORD(wParam) == CBN_SELCHANGE) {
                PNDlgOutputSelectedSidInformation(hwndDlg, NULL);
            }
            break;

            //copy selected sid value to clipboard
        case ID_BDESCRIPTOR_SID_COPY: 
            PNDlgCopySelectedSid(hwndDlg);
            break;

        case ID_OBJECT_COPY:
            supListViewCopyItemValueToClipboard(PnDlgContext.ListView,
                PnDlgContext.lvItemHit,
                PnDlgContext.lvColumnHit);
            break;

        default:
            break;
        }

        break;

    default:
        return FALSE;
    }
    return TRUE;
}

/*
* extrasCreatePNDialog
*
* Purpose:
*
* Create and initialize Private Namespaces Dialog.
*
*/
VOID extrasCreatePNDialog(
    _In_ HWND hwndParent
)
{
    INT iImage = ImageList_GetImageCount(g_ListViewImages) - 1;
    LVCOLUMNS_DATA columnData[] =
    {
        { L"Name", 280, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  iImage },
        { L"Type", 100, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  I_IMAGENONE },
        { L"RootDirectory", 140, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  I_IMAGENONE }
    };

    //
    // Allow only one dialog.
    //
    ENSURE_DIALOG_UNIQUE(g_WinObj.AuxDialogs[wobjPNSDlgId]);

    RtlSecureZeroMemory(&PnDlgContext, sizeof(PnDlgContext));
    PnDlgContext.hwndDlg = CreateDialogParam(g_WinObj.hInstance, MAKEINTRESOURCE(IDD_DIALOG_PNAMESPACE),
        hwndParent, &PNDialogProc, 0);

    if (PnDlgContext.hwndDlg == NULL)
        return;

    RtlSecureZeroMemory(&PNSCollection, sizeof(OBJECT_COLLECTION));

    g_WinObj.AuxDialogs[wobjPNSDlgId] = PnDlgContext.hwndDlg;

    PnDlgContext.ListView = GetDlgItem(PnDlgContext.hwndDlg, ID_NAMESPACELIST);
    if (PnDlgContext.ListView) {

        PnDlgContext.lvColumnHit = -1;
        PnDlgContext.lvItemHit = -1;

        //
        // Set listview imagelist, style flags and theme.
        //
        supSetListViewSettings(PnDlgContext.ListView,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP,
            FALSE,
            TRUE,
            g_ListViewImages,
            LVSIL_SMALL);

        //
        // And columns and remember their count.
        //
        PnDlgContext.lvColumnCount = supAddLVColumnsFromArray(
            PnDlgContext.ListView,
            columnData,
            RTL_NUMBER_OF(columnData));

        //
        // Initial call, nothing to refresh.
        //
        PNDialogShowInfo(FALSE);
    }
}
